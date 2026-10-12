package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/spkprsnts/socks2tun/internal/app"
	"github.com/spkprsnts/socks2tun/internal/control"
	"github.com/spkprsnts/socks2tun/internal/socks5"
	"github.com/spkprsnts/socks2tun/internal/socks5/socks5test"
	"github.com/spkprsnts/socks2tun/internal/tunlink"
)

var (
	echoIP = netip.MustParseAddr("203.0.113.10") // TCP/UDP echo :7, whoami :80
	dnsIP  = netip.MustParseAddr("203.0.113.53") // DNS :53 (UDP and TCP)
)

// internet is the "server side" of the tunnel: a second gVisor stack on the
// other end of the socketpair, standing in for the core and the Internet.
type internet struct {
	s    *stack.Stack
	link *tunlink.Link
}

func newInternet(t *testing.T) *internet {
	t.Helper()
	link := tunlink.New(1500)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.Cleanup(s.Close)
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	for _, a := range []netip.Addr{echoIP, dnsIP} {
		pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr(a).WithPrefix()}
		if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	n := &internet{s: s, link: link}

	n.serveTCP(t, echoIP, 7, func(c net.Conn) {
		io.Copy(c, c)
		c.(*gonet.TCPConn).CloseWrite()
		io.Copy(io.Discard, c)
	})
	n.serveTCP(t, echoIP, 80, func(c net.Conn) {
		io.WriteString(c, c.RemoteAddr().(*net.TCPAddr).IP.String())
	})
	n.serveTCP(t, dnsIP, 53, func(c net.Conn) {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := dnsAnswer(q, true)
		c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
	})
	n.serveUDP(t, echoIP, 7, func(b []byte) []byte { return b })
	n.serveUDP(t, dnsIP, 53, func(b []byte) []byte { return dnsAnswer(b, false) })
	return n
}

func addr(a netip.Addr) tcpip.Address { return tcpip.AddrFrom4(a.As4()) }

func (n *internet) serveTCP(t *testing.T, ip netip.Addr, port uint16, h func(net.Conn)) {
	ln, err := gonet.ListenTCP(n.s, tcpip.FullAddress{NIC: 1, Addr: addr(ip), Port: port}, ipv4.ProtocolNumber)
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
			go func() { defer c.Close(); h(c) }()
		}
	}()
}

func (n *internet) serveUDP(t *testing.T, ip netip.Addr, port uint16, h func([]byte) []byte) {
	c, err := gonet.DialUDP(n.s, &tcpip.FullAddress{NIC: 1, Addr: addr(ip), Port: port}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := h(buf[:n]); resp != nil {
				c.WriteTo(resp, from)
			}
		}
	}()
}

// attach runs the internet side on f until the returned stop is called.
func (n *internet) attach(f *os.File) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); n.link.Run(ctx, f) }()
	return func() { cancel(); <-done }
}

// dnsAnswer: echo.test -> echoIP; big.test is truncated over UDP (forcing
// the TCP fallback) and answered over TCP; everything else is NXDOMAIN.
func dnsAnswer(q []byte, overTCP bool) []byte {
	if len(q) < 13 {
		return nil
	}
	var labels []string
	off := 12
	for off < len(q) && q[off] != 0 {
		l := int(q[off])
		if off+1+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[off+1:off+1+l]))
		off += 1 + l
	}
	qend := off + 5
	if qend > len(q) {
		return nil
	}
	name := strings.Join(labels, ".")
	resp := append([]byte(nil), q[:2]...)
	flags, an := uint16(0x8180), uint16(0)
	switch {
	case name == "echo.test", name == "big.test" && overTCP:
		an = 1
	case name == "big.test":
		flags |= 0x0200
	default:
		flags |= 3
	}
	resp = binary.BigEndian.AppendUint16(resp, flags)
	resp = append(resp, 0, 1, 0, byte(an), 0, 0, 0, 0)
	resp = append(resp, q[12:qend]...)
	if an == 1 {
		ip := echoIP.As4()
		resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		resp = append(resp, ip[:]...)
	}
	return resp
}

type harness struct {
	socks  string
	ctrl   *io.PipeWriter
	cfgs   chan control.Config
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, cfg app.Config) *harness {
	t.Helper()
	r, w := io.Pipe()
	h := &harness{ctrl: w, cfgs: make(chan control.Config, 16), done: make(chan error, 1)}
	listening := make(chan net.Addr, 1)
	cfg.Listen = "127.0.0.1:0"
	cfg.Control = r
	cfg.OnListen = func(a net.Addr) { listening <- a }
	cfg.OnConfig = func(c control.Config) { h.cfgs <- c }
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 2 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- app.Run(ctx, cfg) }()
	select {
	case a := <-listening:
		h.socks = a.String()
	case err := <-h.done:
		t.Fatalf("app exited: %v", err)
	}
	<-h.cfgs // initial configuration
	t.Cleanup(func() {
		h.stop(t)
		w.Close()
	})
	return h
}

func (h *harness) stop(t *testing.T) {
	h.cancel()
	select {
	case err, ok := <-h.done:
		if ok && err != nil {
			t.Errorf("app.Run returned %v", err)
		}
		close(h.done)
	case <-time.After(5 * time.Second):
		t.Error("app did not stop")
	}
}

func (h *harness) command(t *testing.T, line string, want func(control.Config) bool) {
	t.Helper()
	fmt.Fprintln(h.ctrl, line)
	for {
		select {
		case c := <-h.cfgs:
			if want(c) {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("configuration from %q not applied", line)
		}
	}
}

func whoami(t *testing.T, socks string) string {
	t.Helper()
	c, err := socks5test.Connect(socks, echoIP.String()+":80", "", "")
	if err != nil {
		t.Fatalf("whoami connect: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("whoami read: %v", err)
	}
	return string(b)
}

func wantReply(t *testing.T, err error, code byte) {
	t.Helper()
	var re socks5test.ReplyError
	if !errors.As(err, &re) || byte(re) != code {
		t.Fatalf("got %v, want reply %d", err, code)
	}
}

func pair(t *testing.T) (ours, theirs *os.File) {
	t.Helper()
	ours, fd, err := tunlink.NewPair()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err = tunlink.FileFromFD(fd, "core")
	if err != nil {
		t.Fatal(err)
	}
	return ours, theirs
}

func TestEndToEnd(t *testing.T) {
	ours, theirs := pair(t)
	inet := newInternet(t)
	// Registered before start: cleanups run LIFO, so the core side goes away
	// only after the app has been stopped.
	t.Cleanup(inet.attach(theirs))
	h := start(t, app.Config{TunFile: ours, Net: control.Config{MTU: 1280}})

	// Before the core reports an address, CONNECT fails with "network unreachable".
	_, err := socks5test.Connect(h.socks, echoIP.String()+":7", "", "")
	wantReply(t, err, socks5.RepNetworkUnreachable)

	h.command(t, "ip 10.0.0.2 dns "+dnsIP.String(), func(c control.Config) bool {
		return c.IP == netip.MustParseAddr("10.0.0.2")
	})

	t.Run("connect by name, bulk data and half-close", func(t *testing.T) {
		c, err := socks5test.Connect(h.socks, "echo.test:7", "", "")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		msg := make([]byte, 4<<20)
		rand.Read(msg)
		go func() {
			c.Write(msg)
			c.(*net.TCPConn).CloseWrite()
		}()
		c.SetDeadline(time.Now().Add(20 * time.Second))
		start := time.Now()
		got, err := io.ReadAll(c) // returns only after the echo's FIN arrives
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo: %d of %d bytes, %v", len(got), len(msg), err)
		}
		t.Logf("4 MiB echoed in %v", time.Since(start))
	})

	t.Run("source address", func(t *testing.T) {
		if got := whoami(t, h.socks); got != "10.0.0.2" {
			t.Fatalf("server saw %q", got)
		}
	})

	t.Run("dns tcp fallback", func(t *testing.T) {
		c, err := socks5test.Connect(h.socks, "big.test:80", "", "")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	})

	t.Run("error replies", func(t *testing.T) {
		_, err := socks5test.Connect(h.socks, echoIP.String()+":9", "", "")
		wantReply(t, err, socks5.RepConnectionRefused)
		_, err = socks5test.Connect(h.socks, "nx.test:80", "", "")
		wantReply(t, err, socks5.RepHostUnreachable)
		_, err = socks5test.Connect(h.socks, "[2001:db8::1]:80", "", "")
		wantReply(t, err, socks5.RepAddrNotSupported)
		// Nobody answers for this address: the connect times out.
		_, err = socks5test.Connect(h.socks, "203.0.113.99:80", "", "")
		wantReply(t, err, socks5.RepTTLExpired)
	})

	t.Run("udp associate", func(t *testing.T) {
		ctrl, err := net.Dial("tcp", h.socks)
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
		uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		buf := make([]byte, 65535)
		// 1400 bytes exceed the tunnel MTU (1280), so the datagram is
		// fragmented and reassembled inside the stacks. Larger sizes are
		// avoided: WSL2 mirrored networking drops loopback UDP > 1472 bytes.
		sizes := []int{100, 100, 1400, 1400}
		for i, host := range []string{echoIP.String(), "echo.test", "echo.test", echoIP.String()} {
			payload := bytes.Repeat([]byte{byte('a' + i)}, sizes[i])
			if _, err := uc.Write(socks5test.UDPDatagram(host, 7, payload)); err != nil {
				t.Fatalf("#%d write: %v", i, err)
			}
			uc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := uc.Read(buf)
			if err != nil {
				t.Fatalf("#%d %s: %v", i, host, err)
			}
			from, got, err := socks5test.ParseUDPDatagram(buf[:n])
			if err != nil || !bytes.Equal(got, payload) || from != netip.AddrPortFrom(echoIP, 7) {
				t.Fatalf("%s: got %d bytes from %s (%v)", host, len(got), from, err)
			}
		}
	})

	t.Run("address change via stdin", func(t *testing.T) {
		old, err := socks5test.Connect(h.socks, echoIP.String()+":7", "", "")
		if err != nil {
			t.Fatal(err)
		}
		defer old.Close()
		h.command(t, "ip 10.0.0.3", func(c control.Config) bool {
			return c.IP == netip.MustParseAddr("10.0.0.3")
		})
		old.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := old.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection from the old address is still open")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("connection from the old address was not closed")
		}
		if got := whoami(t, h.socks); got != "10.0.0.3" {
			t.Fatalf("server saw %q after address change", got)
		}
		h.command(t, "mtu 1400", func(c control.Config) bool { return c.MTU == 1400 })
		if got := whoami(t, h.socks); got != "10.0.0.3" {
			t.Fatalf("after mtu change: %q", got)
		}
	})

	t.Run("concurrent connections", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 32)
		for i := range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := socks5test.Connect(h.socks, "echo.test:7", "", "")
				if err != nil {
					errs <- err
					return
				}
				defer c.Close()
				msg := bytes.Repeat([]byte{byte(i)}, 64<<10)
				go func() { c.Write(msg); c.(*net.TCPConn).CloseWrite() }()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				got, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(got, msg) {
					errs <- fmt.Errorf("conn %d: %d bytes, %v", i, len(got), err)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

func TestTunUDSReplacement(t *testing.T) {
	name := fmt.Sprintf("s2t-app-test-%d-%d", os.Getpid(), mrand.Uint64())
	inet := newInternet(t)

	// The app starts first; the "core" listener appears a little later.
	h := start(t, app.Config{
		TunUDS:     name,
		UDSTimeout: 10 * time.Second,
		Net: control.Config{
			IP:  netip.MustParseAddr("10.0.0.2"),
			DNS: []netip.Addr{dnsIP},
			MTU: 1280,
		},
	})
	time.Sleep(300 * time.Millisecond)
	lfd := listenAbstract(t, name)

	f1 := receiveFD(t, lfd, true)
	stop1 := inet.attach(f1)
	if got := whoami(t, h.socks); got != "10.0.0.2" {
		t.Fatalf("first descriptor: server saw %q", got)
	}

	// The core drops its descriptor (e.g. restarts): socks2tun must create a
	// new pair and hand it over again.
	stop1()
	f2 := receiveFD(t, lfd, true)
	defer inet.attach(f2)()
	if got := whoami(t, h.socks); got != "10.0.0.2" {
		t.Fatalf("replacement descriptor: server saw %q", got)
	}
}

// A PaperFlux-style core takes the descriptor, closes the connection without
// an ack and stops listening. With NoAck the app must start using its end.
func TestTunUDSNoAck(t *testing.T) {
	name := fmt.Sprintf("s2t-noack-test-%d-%d", os.Getpid(), mrand.Uint64())
	inet := newInternet(t)
	// Not listenAbstract: this listener is closed by the test itself.
	lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(lfd, &unix.SockaddrUnix{Name: "@" + name}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(lfd, 4); err != nil {
		t.Fatal(err)
	}
	h := start(t, app.Config{
		TunUDS:     name,
		NoAck:      true,
		UDSTimeout: 10 * time.Second,
		Net: control.Config{
			IP:  netip.MustParseAddr("10.0.0.2"),
			DNS: []netip.Addr{dnsIP},
			MTU: 1280,
		},
	})
	f := receiveFD(t, lfd, false)
	unix.Close(lfd) // the core stops listening after the first descriptor
	t.Cleanup(inet.attach(f))
	if got := whoami(t, h.socks); got != "10.0.0.2" {
		t.Fatalf("server saw %q", got)
	}
}

func listenAbstract(t *testing.T, name string) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: "@" + name}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		t.Fatal(err)
	}
	return fd
}

// receiveFD does what CSQTT's FdReceiver does: accept, receive the byte and
// descriptor, acknowledge with one byte (unless ack is false, as PaperFlux).
func receiveFD(t *testing.T, lfd int, ack bool) *os.File {
	t.Helper()
	tv := unix.NsecToTimeval((10 * time.Second).Nanoseconds())
	unix.SetsockoptTimeval(lfd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	c, _, err := unix.Accept(lfd)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer unix.Close(c)
	buf, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(c, buf, oob, 0)
	if err != nil || n != 1 {
		t.Fatalf("recvmsg: %d, %v", n, err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		t.Fatalf("cmsg: %v", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		t.Fatalf("rights: %v", err)
	}
	if ack {
		if _, err := unix.Write(c, []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	f, err := tunlink.FileFromFD(fds[0], "core")
	if err != nil {
		t.Fatal(err)
	}
	return f
}
