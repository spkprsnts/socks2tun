// Command socks2tun is a "reverse tun2socks": it serves SOCKS5 and turns the
// connections into raw IPv4 packets on a descriptor that a TUN-only core
// treats as its TUN device.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spkprsnts/socks2tun/internal/app"
	"github.com/spkprsnts/socks2tun/internal/control"
	"github.com/spkprsnts/socks2tun/internal/logx"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		cfg     app.Config
		ip, dns string
		mtu     uint
		debug   bool
		showVer bool
	)
	fs := flag.NewFlagSet("socks2tun", flag.ContinueOnError)
	fs.StringVar(&cfg.Listen, "listen", "127.0.0.1:1080", "SOCKS5 listen address")
	fs.StringVar(&cfg.TunUDS, "tun-uds", "", "abstract Unix socket `name` of the core to hand the TUN descriptor to")
	fs.IntVar(&cfg.TunFD, "fd", -1, "use an inherited packet descriptor `N` instead of --tun-uds")
	fs.StringVar(&ip, "ip", "", "tunnel IPv4 address (can be set later via stdin)")
	fs.StringVar(&dns, "dns", "", "tunnel DNS servers, comma separated (can be set later via stdin)")
	fs.UintVar(&mtu, "mtu", 1280, "tunnel MTU")
	fs.StringVar(&cfg.User, "user", "", "SOCKS5 username (enables RFC 1929 authentication)")
	fs.StringVar(&cfg.Pass, "pass", "", "SOCKS5 password")
	fs.BoolVar(&cfg.NoAck, "no-ack", false, "the core takes the descriptor without a one-byte ack (closes the connection instead)")
	fs.DurationVar(&cfg.UDSTimeout, "uds-timeout", 60*time.Second, "give up delivering the descriptor after this long (0 = never)")
	fs.DurationVar(&cfg.ConnectTimeout, "connect-timeout", 15*time.Second, "DNS + TCP connect timeout")
	fs.DurationVar(&cfg.TCPIdle, "tcp-idle", 5*time.Minute, "idle timeout of CONNECT relays (0 = none)")
	fs.DurationVar(&cfg.UDPIdle, "udp-idle", 2*time.Minute, "idle timeout of UDP associations (0 = none)")
	fs.IntVar(&cfg.MaxConns, "max-conns", 1024, "maximum concurrent SOCKS5 connections (0 = unlimited)")
	fs.BoolVar(&debug, "debug", false, "log per-connection details")
	fs.BoolVar(&showVer, "version", false, "print version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if showVer {
		fmt.Println("socks2tun", version)
		return 0
	}
	logx.SetDebug(debug)

	fail := func(format string, args ...any) int {
		logx.Errorf(format, args...)
		return 2
	}
	switch {
	case cfg.TunUDS == "" && cfg.TunFD < 0:
		return fail("one of --tun-uds or --fd is required")
	case cfg.TunUDS != "" && cfg.TunFD >= 0:
		return fail("--tun-uds and --fd are mutually exclusive")
	}
	var err error
	if ip != "" {
		if cfg.Net.IP, err = control.ParseIP(ip); err != nil {
			return fail("--ip: %v", err)
		}
	}
	if cfg.Net.DNS, err = control.ParseDNS(dns); err != nil {
		return fail("--dns: %v", err)
	}
	if cfg.Net.MTU, err = control.ParseMTU(fmt.Sprint(mtu)); err != nil {
		return fail("--mtu: %v", err)
	}
	cfg.Control = os.Stdin

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := app.Run(ctx, cfg); err != nil {
		logx.Errorf("%v", err)
		return 1
	}
	logx.Infof("stopped")
	return 0
}
