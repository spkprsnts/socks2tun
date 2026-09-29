// Package socks5 implements a SOCKS5 server (RFC 1928, RFC 1929) with
// CONNECT and UDP ASSOCIATE whose outbound side is a pluggable Dialer.
package socks5

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spkprsnts/socks2tun/internal/logx"
)

// Dialer opens outbound connections (through the tunnel in production).
// Errors should wrap syscall errnos so ReplyCode can map them.
type Dialer interface {
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// ListenUDP returns an unconnected socket used with *net.UDPAddr peers.
	ListenUDP() (net.PacketConn, error)
}

// Resolver turns domain names into IPv4 addresses.
type Resolver interface {
	LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error)
}

// Config configures a Server. Zero durations disable the respective timeout
// except ConnectTimeout and HandshakeTimeout, which get defaults.
type Config struct {
	Dialer   Dialer
	Resolver Resolver

	// User and Pass enable RFC 1929 authentication (required when set).
	User, Pass string

	HandshakeTimeout time.Duration // greeting + request
	ConnectTimeout   time.Duration // DNS + TCP connect
	TCPIdle          time.Duration // CONNECT relay idle timeout
	UDPIdle          time.Duration // UDP ASSOCIATE idle timeout
	MaxConns         int           // concurrent client connections, 0 = unlimited
}

// Server is a SOCKS5 server.
type Server struct {
	cfg  Config
	sem  chan struct{}
	seq  atomic.Uint64
	wg   sync.WaitGroup
	lim  logx.Limiter
	done chan struct{}

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
}

// NewServer creates a server; call Serve to start accepting.
func NewServer(cfg Config) *Server {
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 15 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 15 * time.Second
	}
	s := &Server{
		cfg:   cfg,
		conns: make(map[net.Conn]struct{}),
		lim:   logx.Limiter{Interval: 10 * time.Second},
		done:  make(chan struct{}),
	}
	if cfg.MaxConns > 0 {
		s.sem = make(chan struct{}, cfg.MaxConns)
	}
	return s
}

// Serve accepts connections on ln until Close. It returns nil after Close.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return nil
	}
	s.ln = ln
	s.mu.Unlock()

	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && !errors.Is(err, net.ErrClosed) {
				// Temporary failure such as EMFILE: back off and keep serving.
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				logx.Errorf("accept: %v", err)
				time.Sleep(backoff)
				continue
			}
			return err
		}
		backoff = 0
		if s.sem != nil {
			select {
			case s.sem <- struct{}{}:
			default:
				if s.lim.Allow("limit") {
					logx.Errorf("connection limit %d reached, rejecting clients", s.cfg.MaxConns)
				}
				c.Close()
				continue
			}
		}
		if !s.add(c) {
			c.Close()
			s.release()
			continue
		}
		s.wg.Add(1)
		go s.serveConn(c)
	}
}

// Close stops accepting, closes all client connections and waits for their
// handlers to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	if s.ln != nil {
		s.ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *Server) add(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) release() {
	if s.sem != nil {
		<-s.sem
	}
}

func (s *Server) serveConn(c net.Conn) {
	id := s.seq.Add(1)
	defer func() {
		if r := recover(); r != nil {
			logx.Errorf("panic in connection #%d: %v", id, r)
			logx.Debugf("%s", debug.Stack())
		}
		c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		s.release()
		s.wg.Done()
	}()
	s.handle(id, c)
}

func (s *Server) handle(id uint64, c net.Conn) {
	c.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	buf := make([]byte, 512)

	// Greeting: VER NMETHODS METHODS...
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		logx.Debugf("#%d %s: greeting: %v", id, c.RemoteAddr(), err)
		return
	}
	if buf[0] != version5 {
		logx.Debugf("#%d %s: unsupported version %d", id, c.RemoteAddr(), buf[0])
		return
	}
	methods := buf[2 : 2+int(buf[1])]
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	method := s.chooseMethod(methods)
	if _, err := c.Write([]byte{version5, method}); err != nil || method == methodNoAcceptable {
		logx.Debugf("#%d %s: no acceptable auth method", id, c.RemoteAddr())
		return
	}
	if method == methodUserPass && !s.authenticate(id, c, buf) {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(c, buf[:3]); err != nil {
		logx.Debugf("#%d %s: request: %v", id, c.RemoteAddr(), err)
		return
	}
	if buf[0] != version5 {
		return
	}
	cmd := buf[1]
	dst, err := readAddr(c, buf)
	if err != nil {
		if errors.Is(err, errAddrType) {
			logx.Debugf("#%d %s: address type not supported", id, c.RemoteAddr())
			writeReply(c, RepAddrNotSupported, netip.AddrPort{})
		}
		return
	}
	switch cmd {
	case cmdConnect:
		s.connect(id, c, dst)
	case cmdUDPAssociate:
		s.udpAssociate(id, c, dst)
	default:
		logx.Debugf("#%d %s: command %d not supported", id, c.RemoteAddr(), cmd)
		writeReply(c, RepCommandNotSupported, netip.AddrPort{})
	}
}

func (s *Server) chooseMethod(offered []byte) byte {
	has := func(m byte) bool {
		for _, o := range offered {
			if o == m {
				return true
			}
		}
		return false
	}
	switch {
	case s.cfg.User != "" || s.cfg.Pass != "":
		if has(methodUserPass) {
			return methodUserPass
		}
	case has(methodNoAuth):
		return methodNoAuth
	case has(methodUserPass):
		// No credentials configured: accept any for clients that insist.
		return methodUserPass
	}
	return methodNoAcceptable
}

func (s *Server) authenticate(id uint64, c net.Conn, buf []byte) bool {
	// VER ULEN UNAME PLEN PASSWD
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != userPassVersion {
		return false
	}
	ulen := int(buf[1])
	if _, err := io.ReadFull(c, buf[:ulen+1]); err != nil {
		return false
	}
	user := string(buf[:ulen])
	plen := int(buf[ulen])
	if _, err := io.ReadFull(c, buf[:plen]); err != nil {
		return false
	}
	pass := string(buf[:plen])
	ok := s.cfg.User == "" && s.cfg.Pass == "" ||
		subtle.ConstantTimeCompare([]byte(user), []byte(s.cfg.User)) == 1 &&
			subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.Pass)) == 1
	status := byte(0)
	if !ok {
		status = 1
		logx.Debugf("#%d %s: authentication failed for user %q", id, c.RemoteAddr(), user)
	}
	if _, err := c.Write([]byte{userPassVersion, status}); err != nil {
		return false
	}
	return ok
}

// resolve turns a request address into an IPv4 destination.
func (s *Server) resolve(ctx context.Context, a addr) (netip.AddrPort, error) {
	if a.ip.IsValid() {
		return netip.AddrPortFrom(a.ip, a.port), nil
	}
	if ip, err := netip.ParseAddr(a.host); err == nil {
		if ip = ip.Unmap(); !ip.Is4() {
			return netip.AddrPort{}, fmt.Errorf("%s: %w", a.host, syscall.EAFNOSUPPORT)
		}
		return netip.AddrPortFrom(ip, a.port), nil
	}
	if s.cfg.Resolver == nil {
		return netip.AddrPort{}, fmt.Errorf("no resolver for %s: %w", a.host, syscall.EHOSTUNREACH)
	}
	ips, err := s.cfg.Resolver.LookupIPv4(ctx, a.host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s: no addresses: %w", a.host, syscall.EHOSTUNREACH)
	}
	return netip.AddrPortFrom(ips[0], a.port), nil
}

func (s *Server) connect(id uint64, c net.Conn, a addr) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ConnectTimeout)
	defer cancel()
	// Abort DNS/connect if the server is shutting down.
	go func() {
		select {
		case <-s.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	dst, err := s.resolve(ctx, a)
	if err != nil {
		rep := ReplyCode(err)
		if rep == RepGeneralFailure {
			rep = RepHostUnreachable
		}
		logx.Debugf("#%d connect %s: resolve: %v (reply %d)", id, a, err, rep)
		writeReply(c, rep, netip.AddrPort{})
		return
	}
	remote, err := s.cfg.Dialer.DialTCP(ctx, dst)
	if err != nil {
		rep := ReplyCode(err)
		logx.Debugf("#%d connect %s (%s): %v (reply %d)", id, a, dst, err, rep)
		writeReply(c, rep, netip.AddrPort{})
		return
	}
	defer remote.Close()
	if err := writeReply(c, RepSuccess, addrPortOf(remote.LocalAddr())); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	logx.Debugf("#%d connect %s (%s) from %s", id, a, dst, c.RemoteAddr())
	up, down := relay(c, remote, s.cfg.TCPIdle)
	logx.Debugf("#%d closed %s: up %d, down %d bytes", id, a, up, down)
}

// idleTimer calls onIdle once no activity was recorded for d.
type idleTimer struct {
	start  time.Time
	d      time.Duration
	last   atomic.Int64
	t      *time.Timer
	onIdle func()
}

func newIdleTimer(d time.Duration, onIdle func()) *idleTimer {
	it := &idleTimer{start: time.Now(), d: d, onIdle: onIdle}
	if d > 0 {
		it.t = time.AfterFunc(d, it.fire)
	}
	return it
}

func (it *idleTimer) touch() {
	if it.t != nil {
		it.last.Store(int64(time.Since(it.start)))
	}
}

func (it *idleTimer) fire() {
	quiet := time.Since(it.start) - time.Duration(it.last.Load())
	if quiet >= it.d {
		it.onIdle()
		return
	}
	it.t.Reset(it.d - quiet)
}

func (it *idleTimer) stop() {
	if it.t != nil {
		it.t.Stop()
	}
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}

// relay copies both directions until both are finished, propagating
// half-closes. Any error or the idle timeout tears down both connections.
func relay(client, remote net.Conn, idle time.Duration) (up, down int64) {
	var once sync.Once
	abort := func() {
		once.Do(func() {
			client.Close()
			remote.Close()
		})
	}
	it := newIdleTimer(idle, abort)
	defer it.stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		up = pipe(remote, client, it, abort)
	}()
	down = pipe(client, remote, it, abort)
	<-done
	return up, down
}

type closeWriter interface{ CloseWrite() error }

// pipe copies src to dst. On EOF it half-closes dst; on error it aborts both.
func pipe(dst, src net.Conn, it *idleTimer, abort func()) int64 {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			it.touch()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				abort()
				return total
			}
			total += int64(n)
		}
		if rerr != nil {
			if rerr != io.EOF {
				abort()
				return total
			}
			if cw, ok := dst.(closeWriter); ok {
				if cw.CloseWrite() == nil {
					return total
				}
			}
			abort()
			return total
		}
	}
}
