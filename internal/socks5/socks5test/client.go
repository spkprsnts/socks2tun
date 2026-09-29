// Package socks5test is a minimal SOCKS5 client for tests.
package socks5test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// ReplyError is a non-zero SOCKS5 reply code.
type ReplyError byte

func (e ReplyError) Error() string { return fmt.Sprintf("socks5 reply %d", byte(e)) }

// Handshake performs the greeting (and RFC 1929 auth when user != "").
func Handshake(c net.Conn, user, pass string) error {
	method := byte(0x00)
	if user != "" || pass != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	var b [2]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return err
	}
	if b[0] != 5 || b[1] != method {
		return fmt.Errorf("server chose method %#x", b[1])
	}
	if method == 0x02 {
		msg := []byte{1, byte(len(user))}
		msg = append(msg, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err := c.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return err
		}
		if b[1] != 0 {
			return errors.New("authentication failed")
		}
	}
	return nil
}

// Request sends a request for host:port ("host" may be an IP) and returns
// the bound address from a successful reply.
func Request(c net.Conn, cmd byte, hostport string) (netip.AddrPort, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, _ := strconv.Atoi(ps)
	msg := []byte{5, cmd, 0}
	msg = AppendAddr(msg, host, uint16(port))
	if _, err := c.Write(msg); err != nil {
		return netip.AddrPort{}, err
	}
	return ReadReply(c)
}

// AppendAddr appends ATYP/ADDR/PORT, choosing IPv4, IPv6 or domain.
func AppendAddr(b []byte, host string, port uint16) []byte {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			a := ip.As4()
			b = append(append(b, 1), a[:]...)
		} else {
			a := ip.As16()
			b = append(append(b, 4), a[:]...)
		}
	} else {
		b = append(append(b, 3, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

// ReadReply reads a reply; a non-zero code is returned as ReplyError.
func ReadReply(c net.Conn) (netip.AddrPort, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return netip.AddrPort{}, err
	}
	var ip netip.Addr
	switch h[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return netip.AddrPort{}, err
		}
		ip = netip.AddrFrom4(a)
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return netip.AddrPort{}, err
		}
		ip = netip.AddrFrom16(a)
	default:
		return netip.AddrPort{}, fmt.Errorf("unexpected reply atyp %d", h[3])
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return netip.AddrPort{}, err
	}
	if h[1] != 0 {
		return netip.AddrPort{}, ReplyError(h[1])
	}
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(p[:])), nil
}

// Connect dials server and issues CONNECT to hostport.
func Connect(server, hostport, user, pass string) (net.Conn, error) {
	c, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	if err := Handshake(c, user, pass); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := Request(c, 1, hostport); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// UDPDatagram builds a SOCKS5 UDP datagram for host:port.
func UDPDatagram(host string, port uint16, payload []byte) []byte {
	b := AppendAddr([]byte{0, 0, 0}, host, port)
	return append(b, payload...)
}

// ParseUDPDatagram parses an IPv4 SOCKS5 UDP datagram from the server.
func ParseUDPDatagram(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 10 || b[3] != 1 {
		return netip.AddrPort{}, nil, errors.New("bad datagram")
	}
	ap := netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[8:]))
	return ap, b[10:], nil
}
