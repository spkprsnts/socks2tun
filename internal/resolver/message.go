package resolver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	typeA   = 1
	typeOPT = 41
	classIN = 1

	rcodeNXDomain = 3
)

var (
	errTruncated = errors.New("truncated response")
	errMalformed = errors.New("malformed response")
)

func checkName(name string) error {
	if name == "" || len(name) > 253 {
		return errors.New("invalid host name length")
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("invalid host name label")
		}
	}
	return nil
}

// buildQuery encodes an A/IN query with recursion desired and an EDNS0 OPT
// record advertising a larger UDP payload.
func buildQuery(id uint16, name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	b := make([]byte, 12, 12+len(name)+2+4+11)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(b[10:], 1)     // ARCOUNT (OPT)
	for label := range strings.SplitSeq(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, typeA, 0, classIN)
	// OPT: root name, type, UDP size, extended rcode/flags, empty rdata.
	b = append(b, 0, 0, typeOPT, byte(ednsUDPSize>>8), byte(ednsUDPSize&0xff), 0, 0, 0, 0, 0, 0)
	return b, nil
}

// parseResponse extracts A records for name from a response to query id.
func parseResponse(m []byte, id uint16, name string) ([]netip.Addr, time.Duration, error) {
	if len(m) < 12 {
		return nil, 0, errMalformed
	}
	if binary.BigEndian.Uint16(m) != id {
		return nil, 0, errors.New("response ID mismatch")
	}
	flags := binary.BigEndian.Uint16(m[2:])
	if flags&0x8000 == 0 {
		return nil, 0, errMalformed
	}
	if flags&0x0200 != 0 {
		return nil, 0, errTruncated
	}
	switch rcode := flags & 0x000f; rcode {
	case 0:
	case rcodeNXDomain:
		return nil, 0, ErrNotFound
	default:
		return nil, 0, fmt.Errorf("server returned rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	an := int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	for range qd {
		qname, next, err := readName(m, off)
		if err != nil {
			return nil, 0, err
		}
		if !strings.EqualFold(qname, name) {
			return nil, 0, errors.New("response question mismatch")
		}
		off = next + 4
	}
	var addrs []netip.Addr
	ttl := maxTTL
	for range an {
		_, next, err := readName(m, off)
		if err != nil {
			return nil, 0, err
		}
		off = next
		if off+10 > len(m) {
			return nil, 0, errMalformed
		}
		typ := binary.BigEndian.Uint16(m[off:])
		class := binary.BigEndian.Uint16(m[off+2:])
		rrTTL := time.Duration(binary.BigEndian.Uint32(m[off+4:])) * time.Second
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdlen > len(m) {
			return nil, 0, errMalformed
		}
		// A recursive resolver returns the whole CNAME chain; every A record
		// in the answer section belongs to it.
		if typ == typeA && class == classIN && rdlen == 4 {
			addrs = append(addrs, netip.AddrFrom4([4]byte(m[off:off+4])))
			ttl = min(ttl, rrTTL)
		}
		off += rdlen
	}
	if len(addrs) == 0 {
		return nil, 0, ErrNotFound
	}
	return addrs, max(ttl, minTTL), nil
}

// readName decodes a possibly compressed name starting at off and returns it
// with the offset just past it in the original message.
func readName(m []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1
	for jumps := 0; ; {
		if off >= len(m) {
			return "", 0, errMalformed
		}
		l := int(m[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return sb.String(), end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(m) {
				return "", 0, errMalformed
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > 32 {
				return "", 0, errMalformed
			}
			off = int(binary.BigEndian.Uint16(m[off:]) & 0x3fff)
		case l&0xc0 != 0:
			return "", 0, errMalformed
		default:
			if off+1+l > len(m) {
				return "", 0, errMalformed
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(m[off+1 : off+1+l])
			off += 1 + l
		}
	}
}
