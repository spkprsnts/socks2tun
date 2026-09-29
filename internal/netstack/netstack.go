// Package netstack wraps a gVisor userspace TCP/IP stack with a single
// point-to-point IPv4 NIC and dials TCP/UDP from the tunnel address.
package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/spkprsnts/socks2tun/internal/logx"
)

const nicID tcpip.NICID = 1

// TCP buffer sizing: small by default (many idle connections on a phone),
// auto-tuned up to max for bulk transfers.
const (
	tcpBufMin     = 4 << 10
	tcpBufDefault = 256 << 10
	tcpBufMax     = 4 << 20
	udpRcvBuf     = 1 << 20
)

// ErrNoAddress is returned while the tunnel has no IPv4 address.
var ErrNoAddress = fmt.Errorf("no tunnel address yet: %w", syscall.ENETUNREACH)

// Stack is a userspace IPv4 stack bound to one link endpoint.
type Stack struct {
	s *stack.Stack

	mu    sync.Mutex
	addr  netip.Addr // zero until configured
	conns map[tracked]netip.Addr

	noAddrLog logx.Limiter
}

type tracked interface{ Close() error }

// New creates the stack on top of ep (a *tunlink.Link in production).
func New(ep stack.LinkEndpoint) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	opts := []tcpip.SettableTransportProtocolOption{
		ptr(tcpip.TCPSACKEnabled(true)),
		ptr(tcpip.TCPModerateReceiveBufferOption(true)),
		ptr(tcpip.CongestionControlOption("cubic")),
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: tcpBufMin, Default: tcpBufDefault, Max: tcpBufMax},
		&tcpip.TCPSendBufferSizeRangeOption{Min: tcpBufMin, Default: tcpBufDefault, Max: tcpBufMax},
	}
	for _, o := range opts {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, o); err != nil {
			s.Close()
			return nil, fmt.Errorf("tcp option %T: %s", o, err)
		}
	}
	if err := s.CreateNIC(nicID, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("create NIC: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return &Stack{
		s:         s,
		conns:     make(map[tracked]netip.Addr),
		noAddrLog: logx.Limiter{Interval: time.Second},
	}, nil
}

func ptr[T any](v T) *T { return &v }

// Address returns the current tunnel address (zero if none).
func (st *Stack) Address() netip.Addr {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.addr
}

// SetAddress replaces the tunnel address (/32). A zero addr removes it.
// Connections opened from the previous address are closed.
func (st *Stack) SetAddress(addr netip.Addr) error {
	if addr.IsValid() && !addr.Is4() {
		return fmt.Errorf("tunnel address %s is not IPv4", addr)
	}
	st.mu.Lock()
	old := st.addr
	if old == addr {
		st.mu.Unlock()
		return nil
	}
	if old.IsValid() {
		if err := st.s.RemoveAddress(nicID, tcpip.AddrFrom4(old.As4())); err != nil {
			st.mu.Unlock()
			return fmt.Errorf("remove address %s: %s", old, err)
		}
	}
	if addr.IsValid() {
		pa := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix(),
		}
		if err := st.s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			st.addr = netip.Addr{}
			st.mu.Unlock()
			return fmt.Errorf("add address %s: %s", addr, err)
		}
	}
	st.addr = addr
	var stale []tracked
	for c, a := range st.conns {
		if a != addr {
			stale = append(stale, c)
		}
	}
	st.mu.Unlock()

	if len(stale) > 0 {
		logx.Debugf("closing %d connection(s) from old address %s", len(stale), old)
	}
	for _, c := range stale {
		c.Close()
	}
	return nil
}

// SetMTU changes the NIC MTU; it applies to connections opened afterwards.
func (st *Stack) SetMTU(mtu uint32) error {
	if err := st.s.SetNICMTU(nicID, mtu); err != nil {
		return fmt.Errorf("set mtu %d: %s", mtu, err)
	}
	return nil
}

// Close closes all tracked connections and shuts the stack down.
func (st *Stack) Close() {
	st.mu.Lock()
	conns := st.conns
	st.conns = make(map[tracked]netip.Addr)
	st.mu.Unlock()
	for c := range conns {
		c.Close()
	}
	st.s.Close()
}

func (st *Stack) localAddr() (netip.Addr, error) {
	st.mu.Lock()
	a := st.addr
	st.mu.Unlock()
	if !a.IsValid() {
		if st.noAddrLog.Allow("") {
			logx.Infof("no tunnel address yet")
		}
		return a, ErrNoAddress
	}
	return a, nil
}

func (st *Stack) track(c tracked, local netip.Addr) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.addr != local {
		return false // address changed while dialing
	}
	st.conns[c] = local
	return true
}

func (st *Stack) untrack(c tracked) {
	st.mu.Lock()
	delete(st.conns, c)
	st.mu.Unlock()
}

// DialTCP opens a TCP connection from the tunnel address to dst. Errors wrap
// syscall errnos (ECONNREFUSED, EHOSTUNREACH, ENETUNREACH, ETIMEDOUT...) or
// the context error, so callers can map them to protocol reply codes.
func (st *Stack) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().Is4() {
		return nil, fmt.Errorf("dial %s: %w", dst, syscall.EAFNOSUPPORT)
	}
	local, err := st.localAddr()
	if err != nil {
		return nil, err
	}
	var wq waiter.Queue
	ep, terr := st.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, fmt.Errorf("tcp endpoint: %s", terr)
	}
	we, notify := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)

	if terr := ep.Bind(tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(local.As4())}); terr != nil {
		ep.Close()
		return nil, dialError(dst, terr)
	}
	terr = ep.Connect(fullAddr(dst))
	if _, ok := terr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, fmt.Errorf("dial %s: %w", dst, ctx.Err())
		case <-notify:
		}
		terr = ep.LastError()
	}
	if terr != nil {
		ep.Close()
		return nil, dialError(dst, terr)
	}
	c := &tcpConn{TCPConn: gonet.NewTCPConn(&wq, ep), st: st}
	if !st.track(c, local) {
		c.TCPConn.Close()
		return nil, fmt.Errorf("dial %s: tunnel address changed: %w", dst, syscall.ENETUNREACH)
	}
	return c, nil
}

// DialUDP opens a connected UDP socket from the tunnel address to dst.
func (st *Stack) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().Is4() {
		return nil, fmt.Errorf("dial %s: %w", dst, syscall.EAFNOSUPPORT)
	}
	return st.udp(&dst)
}

// ListenUDP opens an unconnected UDP socket on the tunnel address (ephemeral
// port) for ReadFrom/WriteTo with *net.UDPAddr peers.
func (st *Stack) ListenUDP() (net.PacketConn, error) {
	return st.udp(nil)
}

func (st *Stack) udp(dst *netip.AddrPort) (*udpConn, error) {
	local, err := st.localAddr()
	if err != nil {
		return nil, err
	}
	var wq waiter.Queue
	ep, terr := st.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, fmt.Errorf("udp endpoint: %s", terr)
	}
	ep.SocketOptions().SetReceiveBufferSize(udpRcvBuf, true)
	if terr := ep.Bind(tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(local.As4())}); terr != nil {
		ep.Close()
		return nil, fmt.Errorf("udp bind %s: %s", local, terr)
	}
	if dst != nil {
		if terr := ep.Connect(fullAddr(*dst)); terr != nil {
			ep.Close()
			return nil, dialError(*dst, terr)
		}
	}
	c := &udpConn{UDPConn: gonet.NewUDPConn(&wq, ep), st: st}
	if !st.track(c, local) {
		c.UDPConn.Close()
		return nil, fmt.Errorf("udp: tunnel address changed: %w", syscall.ENETUNREACH)
	}
	return c, nil
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(ap.Addr().As4()), Port: ap.Port()}
}

func dialError(dst netip.AddrPort, terr tcpip.Error) error {
	var errno error
	switch terr.(type) {
	case *tcpip.ErrConnectionRefused:
		errno = syscall.ECONNREFUSED
	case *tcpip.ErrHostUnreachable, *tcpip.ErrHostDown:
		errno = syscall.EHOSTUNREACH
	case *tcpip.ErrNetworkUnreachable, *tcpip.ErrNoNet:
		errno = syscall.ENETUNREACH
	case *tcpip.ErrTimeout:
		errno = syscall.ETIMEDOUT
	case *tcpip.ErrConnectionReset:
		errno = syscall.ECONNRESET
	case *tcpip.ErrConnectionAborted, *tcpip.ErrAborted:
		errno = syscall.ECONNABORTED
	default:
		return fmt.Errorf("dial %s: %s", dst, terr)
	}
	return fmt.Errorf("dial %s: %w", dst, errno)
}

type tcpConn struct {
	*gonet.TCPConn
	st   *Stack
	once sync.Once
}

func (c *tcpConn) Close() error {
	c.once.Do(func() { c.st.untrack(c) })
	return c.TCPConn.Close()
}

type udpConn struct {
	*gonet.UDPConn
	st   *Stack
	once sync.Once
}

func (c *udpConn) Close() error {
	c.once.Do(func() { c.st.untrack(c) })
	return c.UDPConn.Close()
}
