// Package control parses runtime configuration commands read from stdin:
//
//	ip <IPv4>[/32] | ip none
//	dns <ip>[,<ip>...] | dns none
//	mtu <n>
//
// Several commands may share a line ("ip 10.0.0.2 dns 1.1.1.1 mtu 1280").
// A CSQTT log line "Tunnel IP: X/32 | DNS: Y" is accepted as well.
package control

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// MinMTU and MaxMTU bound the accepted MTU.
const (
	MinMTU = 576
	MaxMTU = 65535
)

// Config is the tunnel configuration controlled at runtime.
type Config struct {
	IP  netip.Addr // zero: no address yet
	DNS []netip.Addr
	MTU uint32
}

// String renders the configuration in the stable log format.
func (c Config) String() string {
	ip := "none"
	if c.IP.IsValid() {
		ip = c.IP.String() + "/32"
	}
	return fmt.Sprintf("address %s dns %s mtu %d", ip, FormatDNS(c.DNS), c.MTU)
}

// FormatDNS renders a server list as "a,b" or "none".
func FormatDNS(dns []netip.Addr) string {
	if len(dns) == 0 {
		return "none"
	}
	s := make([]string, len(dns))
	for i, a := range dns {
		s[i] = a.String()
	}
	return strings.Join(s, ",")
}

// Apply parses line and returns cur with the commands applied. ok is false
// for blank lines and comments.
func Apply(cur Config, line string) (next Config, ok bool, err error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return cur, false, nil
	}
	next = cur
	next.DNS = append([]netip.Addr(nil), cur.DNS...)
	if i := strings.Index(line, "Tunnel IP:"); i >= 0 {
		return applyCSQTT(next, line[i:])
	}

	tok := strings.Fields(line)
	for i := 0; i < len(tok); {
		key := strings.ToLower(tok[i])
		i++
		if i >= len(tok) {
			return cur, true, fmt.Errorf("%s: missing value", key)
		}
		switch key {
		case "ip":
			if next.IP, err = ParseIP(tok[i]); err != nil {
				return cur, true, err
			}
			i++
		case "dns":
			// Values run until the next keyword; commas and spaces both work.
			var vals []string
			for ; i < len(tok) && !isKeyword(tok[i]); i++ {
				vals = append(vals, tok[i])
			}
			if next.DNS, err = ParseDNS(strings.Join(vals, ",")); err != nil {
				return cur, true, err
			}
		case "mtu":
			if next.MTU, err = ParseMTU(tok[i]); err != nil {
				return cur, true, err
			}
			i++
		default:
			return cur, true, fmt.Errorf("unknown command %q", key)
		}
	}
	return next, true, nil
}

func isKeyword(s string) bool {
	switch strings.ToLower(s) {
	case "ip", "dns", "mtu":
		return true
	}
	return false
}

// applyCSQTT handles "Tunnel IP: 10.0.0.2/32 | DNS: 1.1.1.1".
func applyCSQTT(next Config, s string) (Config, bool, error) {
	s = strings.TrimPrefix(s, "Tunnel IP:")
	ipPart, dnsPart, _ := strings.Cut(s, "|")
	ip, err := ParseIP(strings.TrimSpace(ipPart))
	if err != nil {
		return next, true, err
	}
	next.IP = ip
	if _, v, found := strings.Cut(dnsPart, "DNS:"); found {
		if next.DNS, err = ParseDNS(v); err != nil {
			return next, true, err
		}
	}
	return next, true, nil
}

// ParseIP parses a tunnel address: IPv4, optionally with /32; "none" clears.
func ParseIP(s string) (netip.Addr, error) {
	if strings.EqualFold(s, "none") {
		return netip.Addr{}, nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Bits() != 32 {
			return netip.Addr{}, fmt.Errorf("tunnel address %s: only /32 is supported", s)
		}
		s = p.Addr().String()
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Unmap().Is4() || a.Unmap().IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 tunnel address %q", s)
	}
	return a.Unmap(), nil
}

// ParseDNS parses a comma/space separated IPv4 list; "none" or "" clears.
func ParseDNS(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for f := range strings.FieldsFuncSeq(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\t' }) {
		if strings.EqualFold(f, "none") {
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil || !a.Unmap().Is4() {
			return nil, fmt.Errorf("invalid IPv4 DNS server %q", f)
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// ParseMTU parses and range-checks an MTU.
func ParseMTU(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n < MinMTU || n > MaxMTU {
		return 0, fmt.Errorf("invalid mtu %q (want %d..%d)", s, MinMTU, MaxMTU)
	}
	return uint32(n), nil
}
