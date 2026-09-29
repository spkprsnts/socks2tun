package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spkprsnts/socks2tun/internal/logx"
)

const (
	maxUDP       = 65535
	udpHeaderV4  = 10 // RSV(2) FRAG ATYP IPv4(4) PORT(2)
	udpResolveTO = 5 * time.Second
)

// udpAssociate serves UDP ASSOCIATE: a local UDP relay socket on the address
// the control connection arrived at, bridged to an unconnected UDP socket in
// the tunnel. It lives until the control connection closes or goes idle.
func (s *Server) udpAssociate(id uint64, ctrl net.Conn, req addr) {
	clientIP := addrPortOf(ctrl.RemoteAddr()).Addr().Unmap()
	localIP := addrPortOf(ctrl.LocalAddr()).Addr()

	relayConn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(localIP, 0)))
	if err != nil {
		logx.Errorf("udp relay listen: %v", err)
		writeReply(ctrl, RepGeneralFailure, netip.AddrPort{})
		return
	}
	defer relayConn.Close()
	upstream, err := s.cfg.Dialer.ListenUDP()
	if err != nil {
		rep := ReplyCode(err)
		logx.Debugf("#%d udp associate: %v (reply %d)", id, err, rep)
		writeReply(ctrl, rep, netip.AddrPort{})
		return
	}
	defer upstream.Close()
	if err := writeReply(ctrl, RepSuccess, addrPortOf(relayConn.LocalAddr())); err != nil {
		return
	}
	ctrl.SetDeadline(time.Time{})
	logx.Debugf("#%d udp associate from %s, relay %s", id, ctrl.RemoteAddr(), relayConn.LocalAddr())

	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			relayConn.Close()
			upstream.Close()
			ctrl.Close()
		})
	}
	it := newIdleTimer(s.cfg.UDPIdle, closeAll)
	defer it.stop()

	a := &association{
		s:          s,
		relay:      relayConn,
		upstream:   upstream,
		clientIP:   clientIP,
		clientPort: req.port,
		it:         it,
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer closeAll(); a.clientToTunnel() }()
	go func() { defer wg.Done(); defer closeAll(); a.tunnelToClient() }()
	// The association ends with its control connection.
	io.Copy(io.Discard, ctrl)
	closeAll()
	wg.Wait()
	logx.Debugf("#%d udp associate closed: up %d, down %d datagrams", id, a.up.Load(), a.down.Load())
}

type association struct {
	s          *Server
	relay      *net.UDPConn
	upstream   net.PacketConn
	clientIP   netip.Addr
	clientPort uint16 // expected source port from the request, 0 = any
	client     atomic.Pointer[netip.AddrPort]
	it         *idleTimer
	up, down   atomic.Uint64
}

func (a *association) clientToTunnel() {
	buf := make([]byte, maxUDP)
	for {
		n, from, err := a.relay.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		// Only the client that owns the association may use the relay.
		if from.Addr() != a.clientIP || a.clientPort != 0 && from.Port() != a.clientPort {
			continue
		}
		if cur := a.client.Load(); cur == nil {
			a.client.Store(&from)
		} else if *cur != from {
			continue
		}
		dst, payload, err := parseUDPHeader(buf[:n])
		if err != nil {
			continue // includes FRAG != 0 and IPv6
		}
		var ap netip.AddrPort
		if dst.ip.IsValid() {
			ap = netip.AddrPortFrom(dst.ip, dst.port)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), udpResolveTO)
			ap, err = a.s.resolve(ctx, dst)
			cancel()
			if err != nil {
				continue
			}
		}
		if _, err := a.upstream.WriteTo(payload, net.UDPAddrFromAddrPort(ap)); err != nil {
			continue
		}
		a.up.Add(1)
		a.it.touch()
	}
}

func (a *association) tunnelToClient() {
	buf := make([]byte, udpHeaderV4+maxUDP)
	for {
		n, from, err := a.upstream.ReadFrom(buf[udpHeaderV4:])
		if err != nil {
			return
		}
		client := a.client.Load()
		src := addrPortOf(from)
		if client == nil || !src.Addr().Is4() {
			continue
		}
		h := buf[:udpHeaderV4]
		h[0], h[1], h[2], h[3] = 0, 0, 0, atypIPv4
		ip4 := src.Addr().As4()
		copy(h[4:8], ip4[:])
		binary.BigEndian.PutUint16(h[8:], src.Port())
		if _, err := a.relay.WriteToUDPAddrPort(buf[:udpHeaderV4+n], *client); err != nil {
			continue
		}
		a.down.Add(1)
		a.it.touch()
	}
}
