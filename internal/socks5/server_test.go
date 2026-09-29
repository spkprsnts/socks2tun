package socks5_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/spkprsnts/socks2tun/internal/socks5"
	"github.com/spkprsnts/socks2tun/internal/socks5/socks5test"
)

// fakeDialer connects every CONNECT to target (a loopback echo server) or
// fails with err; UDP goes to real loopback sockets.
type fakeDialer struct {
	target  string
	err     error
	block   bool // wait for ctx instead of dialing
	panics  bool
	lastDst atomic.Value
	udp     []net.PacketConn
	mu      sync.Mutex
}

func (d *fakeDialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	d.lastDst.Store(dst)
	switch {
	case d.panics:
		panic("boom")
	case d.block:
		<-ctx.Done()
		return nil, ctx.Err()
	case d.err != nil:
		return nil, d.err
	}
	return net.Dial("tcp", d.target)
}

func (d *fakeDialer) ListenUDP() (net.PacketConn, error) {
	if d.err != nil {
		return nil, d.err
	}
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err == nil {
		d.mu.Lock()
		d.udp = append(d.udp, c)
		d.mu.Unlock()
	}
	return c, err
}

type fakeResolver map[string]netip.Addr

func (r fakeResolver) LookupIPv4(_ context.Context, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return []netip.Addr{a}, nil
	}
	return nil, errors.New("no such host")
}

func tcpEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func udpEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			c.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return c
}

func startServer(t *testing.T, cfg socks5.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := socks5.NewServer(cfg)
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String()
}

func TestConnectEchoHalfClose(t *testing.T) {
	d := &fakeDialer{target: tcpEcho(t)}
	srv := startServer(t, socks5.Config{Dialer: d, Resolver: fakeResolver{"echo.test": netip.MustParseAddr("192.0.2.7")}})

	for _, dst := range []string{"192.0.2.1:7", "echo.test:7"} {
		c, err := socks5test.Connect(srv, dst, "", "")
		if err != nil {
			t.Fatalf("%s: %v", dst, err)
		}
		msg := bytes.Repeat([]byte("hello"), 100000)
		go func() {
			c.Write(msg)
			c.(*net.TCPConn).CloseWrite()
		}()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(c) // ends with EOF only if the FIN came back
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%s: echo mismatch: %d bytes, err %v", dst, len(got), err)
		}
		c.Close()
	}
	if got := d.lastDst.Load().(netip.AddrPort).String(); got != "192.0.2.7:7" {
		t.Fatalf("domain resolved to %s", got)
	}
}

func TestAuthentication(t *testing.T) {
	d := &fakeDialer{target: tcpEcho(t)}
	srv := startServer(t, socks5.Config{Dialer: d, User: "u", Pass: "p"})

	if _, err := socks5test.Connect(srv, "192.0.2.1:7", "u", "p"); err != nil {
		t.Fatalf("valid credentials: %v", err)
	}
	if _, err := socks5test.Connect(srv, "192.0.2.1:7", "u", "wrong"); err == nil || err.Error() != "authentication failed" {
		t.Fatalf("wrong password: %v", err)
	}
	// A client offering only "no authentication" is refused with 0xFF.
	c, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	var b [2]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b != [2]byte{5, 0xff} {
		t.Fatalf("no-auth offer: got %v, %v", b, err)
	}
}

func TestNoAuthServerAcceptsUserPassOnlyClient(t *testing.T) {
	d := &fakeDialer{target: tcpEcho(t)}
	srv := startServer(t, socks5.Config{Dialer: d})
	if _, err := socks5test.Connect(srv, "192.0.2.1:7", "any", "thing"); err != nil {
		t.Fatal(err)
	}
}

func TestReplyCodes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		dst  string
		cmd  byte
		want byte
	}{
		{"refused", syscall.ECONNREFUSED, "192.0.2.1:1", 1, socks5.RepConnectionRefused},
		{"host unreachable", syscall.EHOSTUNREACH, "192.0.2.1:1", 1, socks5.RepHostUnreachable},
		{"net unreachable", fmt.Errorf("no tunnel address yet: %w", syscall.ENETUNREACH), "192.0.2.1:1", 1, socks5.RepNetworkUnreachable},
		{"timeout", syscall.ETIMEDOUT, "192.0.2.1:1", 1, socks5.RepTTLExpired},
		{"deadline", context.DeadlineExceeded, "192.0.2.1:1", 1, socks5.RepTTLExpired},
		{"other", errors.New("weird"), "192.0.2.1:1", 1, socks5.RepGeneralFailure},
		{"unresolvable", nil, "nx.test:80", 1, socks5.RepHostUnreachable},
		{"ipv6", nil, "[2001:db8::1]:80", 1, socks5.RepAddrNotSupported},
		{"ipv6 literal as domain", nil, "::1:80", 1, socks5.RepAddrNotSupported},
		{"bind", nil, "192.0.2.1:1", 2, socks5.RepCommandNotSupported},
		{"unknown command", nil, "192.0.2.1:1", 9, socks5.RepCommandNotSupported},
		{"udp no address", fmt.Errorf("x: %w", syscall.ENETUNREACH), "0.0.0.0:0", 3, socks5.RepNetworkUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDialer{target: tcpEcho(t), err: tc.err}
			srv := startServer(t, socks5.Config{Dialer: d, Resolver: fakeResolver{}})
			c, err := net.Dial("tcp", srv)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := socks5test.Handshake(c, "", ""); err != nil {
				t.Fatal(err)
			}
			var rerr error
			if tc.name == "ipv6 literal as domain" {
				// Send the literal as a domain name (ATYP 3).
				c.Write(append([]byte{5, 1, 0, 3, 3}, []byte("::1\x00\x50")...))
				_, rerr = socks5test.ReadReply(c)
			} else {
				_, rerr = socks5test.Request(c, tc.cmd, tc.dst)
			}
			var re socks5test.ReplyError
			if !errors.As(rerr, &re) || byte(re) != tc.want {
				t.Fatalf("got %v, want reply %d", rerr, tc.want)
			}
		})
	}
}

func TestConnectTimeout(t *testing.T) {
	d := &fakeDialer{block: true}
	srv := startServer(t, socks5.Config{Dialer: d, ConnectTimeout: 200 * time.Millisecond})
	_, err := socks5test.Connect(srv, "192.0.2.1:80", "", "")
	var re socks5test.ReplyError
	if !errors.As(err, &re) || byte(re) != socks5.RepTTLExpired {
		t.Fatalf("got %v, want TTL expired", err)
	}
}

func TestPanicDoesNotKillServer(t *testing.T) {
	d := &fakeDialer{panics: true}
	srv := startServer(t, socks5.Config{Dialer: d})
	for range 2 {
		_, err := socks5test.Connect(srv, "192.0.2.1:80", "", "")
		if err == nil {
			t.Fatal("expected failure")
		}
	}
}

func TestMaxConns(t *testing.T) {
	d := &fakeDialer{target: tcpEcho(t)}
	srv := startServer(t, socks5.Config{Dialer: d, MaxConns: 1})
	first, err := socks5test.Connect(srv, "192.0.2.1:7", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := socks5test.Connect(srv, "192.0.2.1:7", "", ""); err == nil {
		t.Fatal("second connection accepted over the limit")
	}
	first.Close()
	// The slot is released once the first handler finishes.
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := socks5test.Connect(srv, "192.0.2.1:7", "", "")
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not released: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTCPIdleTimeout(t *testing.T) {
	d := &fakeDialer{target: tcpEcho(t)}
	srv := startServer(t, socks5.Config{Dialer: d, TCPIdle: 300 * time.Millisecond})
	c, err := socks5test.Connect(srv, "192.0.2.1:7", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the idle connection to be closed")
	}
	if el := time.Since(start); el < 250*time.Millisecond || el > 3*time.Second {
		t.Fatalf("closed after %v", el)
	}
}

func TestUDPAssociate(t *testing.T) {
	echo := udpEcho(t)
	echoAddr := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	d := &fakeDialer{}
	srv := startServer(t, socks5.Config{Dialer: d, Resolver: fakeResolver{"echo.test": echoAddr.Addr()}})

	ctrl, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	if err := socks5test.Handshake(ctrl, "", ""); err != nil {
		t.Fatal(err)
	}
	relay, err := socks5test.Request(ctrl, 3, "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	if relay.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("relay address %s, want the control connection's local IP", relay)
	}
	uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	// A fragment must be dropped; the following datagrams must be echoed.
	frag := socks5test.UDPDatagram(echoAddr.Addr().String(), echoAddr.Port(), []byte("fragment"))
	frag[2] = 1
	uc.Write(frag)
	uc.Write(socks5test.UDPDatagram(echoAddr.Addr().String(), echoAddr.Port(), []byte("by-ip")))
	uc.Write(socks5test.UDPDatagram("echo.test", echoAddr.Port(), []byte("by-name")))

	buf := make([]byte, 2048)
	for _, want := range []string{"by-ip", "by-name"} {
		uc.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := uc.Read(buf)
		if err != nil {
			t.Fatalf("waiting for %q: %v", want, err)
		}
		from, payload, err := socks5test.ParseUDPDatagram(buf[:n])
		if err != nil || string(payload) != want || from != echoAddr {
			t.Fatalf("got %q from %s (%v), want %q from %s", payload, from, err, want, echoAddr)
		}
	}

	// Closing the control connection ends the association.
	ctrl.Close()
	time.Sleep(200 * time.Millisecond)
	d.mu.Lock()
	up := d.udp[0]
	d.mu.Unlock()
	if _, err := up.WriteTo([]byte("x"), echo.LocalAddr()); err == nil {
		t.Fatal("upstream socket still open after control connection closed")
	}
}

func TestReplyCodeMapping(t *testing.T) {
	if socks5.ReplyCode(nil) != socks5.RepSuccess {
		t.Fatal("nil error must map to success")
	}
	if socks5.ReplyCode(fmt.Errorf("dial: %w", syscall.ECONNREFUSED)) != socks5.RepConnectionRefused {
		t.Fatal("wrapped ECONNREFUSED")
	}
}
