package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDNS answers on loopback UDP and TCP. Behaviour depends on the name:
//
//	a.test     A 192.0.2.1 (ttl 60)
//	cname.test CNAME a.test + A 192.0.2.3 (compressed names)
//	big.test   truncated over UDP, A 192.0.2.2 over TCP
//	slow.test  no UDP answer, A 192.0.2.4 over TCP
//	anything else: NXDOMAIN
type fakeDNS struct {
	udp     *net.UDPConn
	tcp     net.Listener
	udpHits atomic.Int32
	tcpHits atomic.Int32
}

func newFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{udp: u, tcp: l}
	t.Cleanup(func() { u.Close(); l.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := u.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			f.udpHits.Add(1)
			if resp := answer(buf[:n], false); resp != nil {
				u.WriteToUDPAddrPort(resp, from)
			}
		}
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.tcpHits.Add(1)
			go func() {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := answer(q, true)
				c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(resp))))
				c.Write(resp)
			}()
		}
	}()
	return f
}

func (f *fakeDNS) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if dst.Port() != 53 {
		return nil, errors.New("unexpected port")
	}
	return net.DialUDP("udp", nil, f.udp.LocalAddr().(*net.UDPAddr))
}

func (f *fakeDNS) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.tcp.Addr().String())
}

func answer(q []byte, tcp bool) []byte {
	name, qend, err := readName(q, 12)
	if err != nil {
		return nil
	}
	question := q[12 : qend+4]
	resp := make([]byte, 12, 512)
	copy(resp, q[:2])
	resp = append(resp, question...)
	binary.BigEndian.PutUint16(resp[4:], 1)
	flags := uint16(0x8180)
	rr := func(ip [4]byte) {
		resp = append(resp, 0xc0, 12, 0, typeA, 0, classIN, 0, 0, 0, 60, 0, 4)
		resp = append(resp, ip[:]...)
	}
	switch {
	case name == "a.test":
		rr([4]byte{192, 0, 2, 1})
		binary.BigEndian.PutUint16(resp[6:], 1)
	case name == "cname.test":
		// CNAME pointing to "a.test" spelled out, then A for it via pointer.
		target := len(resp) + 12
		resp = append(resp, 0xc0, 12, 0, 5, 0, classIN, 0, 0, 0, 30, 0, 8, 1, 'a', 4, 't', 'e', 's', 't', 0)
		resp = append(resp, 0xc0, byte(target), 0, typeA, 0, classIN, 0, 0, 0, 20, 0, 4, 192, 0, 2, 3)
		binary.BigEndian.PutUint16(resp[6:], 2)
	case name == "big.test" && !tcp:
		flags |= 0x0200
	case name == "big.test":
		rr([4]byte{192, 0, 2, 2})
		binary.BigEndian.PutUint16(resp[6:], 1)
	case name == "slow.test" && !tcp:
		return nil
	case name == "slow.test":
		rr([4]byte{192, 0, 2, 4})
		binary.BigEndian.PutUint16(resp[6:], 1)
	default:
		flags |= rcodeNXDomain
	}
	binary.BigEndian.PutUint16(resp[2:], flags)
	return resp
}

func lookup(t *testing.T, r *Resolver, name string) ([]netip.Addr, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return r.LookupIPv4(ctx, name)
}

func TestLookup(t *testing.T) {
	udpWait = 200 * time.Millisecond
	f := newFakeDNS(t)
	r := New(f)
	r.SetServers([]netip.Addr{netip.MustParseAddr("192.0.2.53")})

	cases := map[string]string{
		"a.test":     "192.0.2.1",
		"A.Test.":    "192.0.2.1",
		"cname.test": "192.0.2.3",
		"big.test":   "192.0.2.2",
		"slow.test":  "192.0.2.4",
		"192.0.2.99": "192.0.2.99",
	}
	for name, want := range cases {
		addrs, err := lookup(t, r, name)
		if err != nil || len(addrs) == 0 || addrs[0].String() != want {
			t.Errorf("%s: got %v, %v; want %s", name, addrs, err, want)
		}
	}
	if _, err := lookup(t, r, "nx.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("nx.test: %v", err)
	}
	if _, err := lookup(t, r, "::1"); err == nil {
		t.Error("IPv6 literal must fail")
	}
}

func TestCacheAndSingleflight(t *testing.T) {
	f := newFakeDNS(t)
	r := New(f)
	r.SetServers([]netip.Addr{netip.MustParseAddr("192.0.2.53")})

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := lookup(t, r, "a.test"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	lookup(t, r, "a.test")
	lookup(t, r, "nx.test")
	lookup(t, r, "nx.test") // negative answers are cached too
	if n := f.udpHits.Load(); n != 2 {
		t.Fatalf("%d UDP queries, want 2 (cache/singleflight broken)", n)
	}
	r.SetServers([]netip.Addr{netip.MustParseAddr("192.0.2.54")}) // flushes the cache
	lookup(t, r, "a.test")
	if n := f.udpHits.Load(); n != 3 {
		t.Fatalf("%d UDP queries after server change, want 3", n)
	}
}

func TestNoServers(t *testing.T) {
	r := New(newFakeDNS(t))
	if _, err := lookup(t, r, "a.test"); !errors.Is(err, ErrNoServers) {
		t.Fatalf("got %v", err)
	}
}

func TestParseResponseRejectsGarbage(t *testing.T) {
	q, _ := buildQuery(7, "a.test")
	for _, m := range [][]byte{nil, q[:5], q} { // q itself is not a response
		if _, _, err := parseResponse(m, 7, "a.test"); err == nil {
			t.Errorf("accepted %x", m)
		}
	}
	resp := answer(q, false)
	if _, _, err := parseResponse(resp, 8, "a.test"); err == nil {
		t.Error("accepted mismatched ID")
	}
	// Compression loop must not hang.
	loop := append([]byte(nil), resp...)
	loop[12] = 0xc0
	loop[13] = 12
	if _, _, err := parseResponse(loop, 7, "a.test"); err == nil {
		t.Error("accepted compression loop")
	}
	addrs, ttl, err := parseResponse(resp, 7, "a.test")
	if err != nil || len(addrs) != 1 || ttl != 60*time.Second {
		t.Errorf("valid response: %v %v %v", addrs, ttl, err)
	}
}
