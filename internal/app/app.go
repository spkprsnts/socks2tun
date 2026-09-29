// Package app wires the tunnel descriptor, the userspace stack, the tunnel
// resolver, the SOCKS5 server and stdin control together.
package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/spkprsnts/socks2tun/internal/control"
	"github.com/spkprsnts/socks2tun/internal/logx"
	"github.com/spkprsnts/socks2tun/internal/netstack"
	"github.com/spkprsnts/socks2tun/internal/resolver"
	"github.com/spkprsnts/socks2tun/internal/socks5"
	"github.com/spkprsnts/socks2tun/internal/tunlink"
)

// Config is the complete runtime configuration.
type Config struct {
	Listen string

	// Exactly one tunnel source: TunUDS (socketpair handed to the core),
	// TunFD (inherited descriptor) or TunFile (tests).
	TunUDS  string
	TunFD   int
	TunFile *os.File

	Net control.Config // initial address/DNS/MTU; IP and DNS may be empty

	User, Pass     string
	UDSTimeout     time.Duration // 0 = retry forever
	ConnectTimeout time.Duration
	TCPIdle        time.Duration
	UDPIdle        time.Duration
	MaxConns       int

	// Control is read line by line for runtime commands (stdin); nil disables.
	Control io.Reader
	// OnListen is called with the SOCKS5 listener address (tests).
	OnListen func(net.Addr)
	// OnConfig is called after a configuration is applied (tests).
	OnConfig func(control.Config)
}

type app struct {
	cfg  Config
	link *tunlink.Link
	st   *netstack.Stack
	res  *resolver.Resolver

	mu  sync.Mutex
	net control.Config
}

// Run serves until ctx is cancelled (returns nil) or the tunnel descriptor
// is irrecoverably lost (returns an error).
func Run(ctx context.Context, cfg Config) error {
	if cfg.Net.MTU == 0 {
		cfg.Net.MTU = 1280
	}
	link := tunlink.New(cfg.Net.MTU)
	st, err := netstack.New(link)
	if err != nil {
		return err
	}
	defer st.Close()
	a := &app{cfg: cfg, link: link, st: st, res: resolver.New(st)}
	a.net.MTU = cfg.Net.MTU
	if err := a.apply(cfg.Net); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	logx.Infof("socks5 listening on %s", ln.Addr())
	if cfg.OnListen != nil {
		cfg.OnListen(ln.Addr())
	}
	srv := socks5.NewServer(socks5.Config{
		Dialer:         st,
		Resolver:       a.res,
		User:           cfg.User,
		Pass:           cfg.Pass,
		ConnectTimeout: cfg.ConnectTimeout,
		TCPIdle:        cfg.TCPIdle,
		UDPIdle:        cfg.UDPIdle,
		MaxConns:       cfg.MaxConns,
	})
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	defer srv.Close()

	if cfg.Control != nil {
		go a.controlLoop(cfg.Control)
	}

	tunErr := make(chan error, 1)
	go func() { tunErr <- a.runTun(ctx) }()
	select {
	case err := <-tunErr:
		if ctx.Err() != nil {
			return nil
		}
		return err
	case err := <-serveErr:
		return fmt.Errorf("socks5 server: %w", err)
	}
}

// apply switches to next and logs the resulting configuration.
func (a *app) apply(next control.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	cur := a.net
	if next.MTU != 0 && next.MTU != cur.MTU {
		if err := a.st.SetMTU(next.MTU); err != nil {
			return err
		}
		cur.MTU = next.MTU
	}
	if !slices.Equal(next.DNS, cur.DNS) {
		a.res.SetServers(next.DNS)
		cur.DNS = slices.Clone(next.DNS)
	}
	if next.IP != cur.IP {
		if err := a.st.SetAddress(next.IP); err != nil {
			return err
		}
		cur.IP = next.IP
	}
	a.net = cur
	logx.Infof("%s", cur)
	if a.cfg.OnConfig != nil {
		a.cfg.OnConfig(cur)
	}
	return nil
}

func (a *app) controlLoop(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		a.mu.Lock()
		cur := a.net
		a.mu.Unlock()
		next, ok, err := control.Apply(cur, sc.Text())
		if err != nil {
			logx.Errorf("control: %v", err)
			continue
		}
		if ok {
			if err := a.apply(next); err != nil {
				logx.Errorf("control: %v", err)
			}
		}
	}
	if err := sc.Err(); err != nil {
		// E.g. a line over 64 KiB or a broken stdin: runtime commands stop,
		// the tunnel keeps working with the current configuration.
		logx.Errorf("control: read stdin: %v", err)
		return
	}
	logx.Debugf("control input closed")
}

func (a *app) runTun(ctx context.Context) error {
	switch {
	case a.cfg.TunFile != nil:
		return a.runFixed(ctx, a.cfg.TunFile)
	case a.cfg.TunUDS == "":
		f, err := tunlink.FileFromFD(a.cfg.TunFD, "tun")
		if err != nil {
			return err
		}
		return a.runFixed(ctx, f)
	}
	for {
		ours, theirs, err := tunlink.NewPair()
		if err != nil {
			return err
		}
		err = tunlink.SendFDRetry(ctx, a.cfg.TunUDS, theirs, a.cfg.UDSTimeout)
		tunlink.CloseFD(theirs) // the core holds its own duplicate now
		if err != nil {
			ours.Close()
			return err
		}
		err = a.link.Run(ctx, ours)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logx.Errorf("tun fd lost (%v), sending a new one", describe(err))
	}
}

func (a *app) runFixed(ctx context.Context, f *os.File) error {
	err := a.link.Run(ctx, f)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("tun fd closed: %s", describe(err))
}

func describe(err error) string {
	if errors.Is(err, io.EOF) {
		return "closed by core"
	}
	return err.Error()
}
