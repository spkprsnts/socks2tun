package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
)

// Protocol constants (RFC 1928, RFC 1929).
const (
	version5 = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xff

	userPassVersion = 0x01

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Reply codes.
const (
	RepSuccess             = 0x00
	RepGeneralFailure      = 0x01
	RepNotAllowed          = 0x02
	RepNetworkUnreachable  = 0x03
	RepHostUnreachable     = 0x04
	RepConnectionRefused   = 0x05
	RepTTLExpired          = 0x06
	RepCommandNotSupported = 0x07
	RepAddrNotSupported    = 0x08
)

// ReplyCode maps a dial error to a SOCKS5 reply code.
func ReplyCode(err error) byte {
	var ne net.Error
	switch {
	case err == nil:
		return RepSuccess
	case errors.Is(err, syscall.ENETUNREACH):
		return RepNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return RepHostUnreachable
	case errors.Is(err, syscall.ECONNREFUSED):
		return RepConnectionRefused
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return RepTTLExpired
	case errors.Is(err, syscall.EAFNOSUPPORT):
		return RepAddrNotSupported
	}
	return RepGeneralFailure
}

// addr is a SOCKS5 address: either an IP or a domain name, plus a port.
type addr struct {
	ip   netip.Addr
	host string
	port uint16
}

func (a addr) String() string {
	h := a.host
	if a.ip.IsValid() {
		h = a.ip.String()
	}
	return net.JoinHostPort(h, strconv.Itoa(int(a.port)))
}

// errAddrType marks an address type we cannot serve (IPv6, unknown).
var errAddrType = errors.New("address type not supported")

// readAddr reads ATYP, DST.ADDR and DST.PORT from r.
func readAddr(r io.Reader, buf []byte) (addr, error) {
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return addr{}, err
	}
	var a addr
	switch buf[0] {
	case atypIPv4:
		if _, err := io.ReadFull(r, buf[:6]); err != nil {
			return a, err
		}
		a.ip = netip.AddrFrom4([4]byte(buf[:4]))
		a.port = binary.BigEndian.Uint16(buf[4:])
	case atypDomain:
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return a, err
		}
		n := int(buf[0])
		if _, err := io.ReadFull(r, buf[:n+2]); err != nil {
			return a, err
		}
		a.host = string(buf[:n])
		a.port = binary.BigEndian.Uint16(buf[n:])
		if a.host == "" {
			return a, errAddrType
		}
	case atypIPv6:
		// Consume the address so the 0x08 reply is not lost to a RST caused
		// by closing with unread data.
		if _, err := io.ReadFull(r, buf[:18]); err != nil {
			return a, err
		}
		return a, errAddrType
	default:
		return a, errAddrType
	}
	return a, nil
}

// parseUDPHeader splits a SOCKS5 UDP datagram into destination and payload.
func parseUDPHeader(b []byte) (a addr, payload []byte, err error) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 {
		return a, nil, errors.New("bad udp header")
	}
	if b[2] != 0 {
		return a, nil, errors.New("fragmented datagram")
	}
	switch b[3] {
	case atypIPv4:
		if len(b) < 10 {
			return a, nil, errors.New("short udp header")
		}
		a.ip = netip.AddrFrom4([4]byte(b[4:8]))
		a.port = binary.BigEndian.Uint16(b[8:])
		return a, b[10:], nil
	case atypDomain:
		if len(b) < 5 {
			return a, nil, errors.New("short udp header")
		}
		n := int(b[4])
		if n == 0 || len(b) < 5+n+2 {
			return a, nil, errors.New("short udp header")
		}
		a.host = string(b[5 : 5+n])
		a.port = binary.BigEndian.Uint16(b[5+n:])
		return a, b[5+n+2:], nil
	}
	return a, nil, errAddrType
}

// appendAddr appends ATYP, BND.ADDR and BND.PORT for ap.
func appendAddr(b []byte, ap netip.AddrPort) []byte {
	ip := ap.Addr().Unmap()
	if ip.Is4() {
		a4 := ip.As4()
		b = append(b, atypIPv4)
		b = append(b, a4[:]...)
	} else if ip.Is6() {
		a16 := ip.As16()
		b = append(b, atypIPv6)
		b = append(b, a16[:]...)
	} else {
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func writeReply(w io.Writer, rep byte, bnd netip.AddrPort) error {
	b := make([]byte, 0, 22)
	b = append(b, version5, rep, 0)
	b = appendAddr(b, bnd)
	_, err := w.Write(b)
	return err
}

func addrPortOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.AddrPort()
	case *net.UDPAddr:
		return v.AddrPort()
	}
	if a == nil {
		return netip.AddrPort{}
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}
