// Package resolver resolves host names to IPv4 addresses through the
// tunnel's DNS servers (UDP, falling back to TCP), with a small TTL cache.
// The system resolver is never used: it would bypass the tunnel.
package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Dialer opens connections through the tunnel.
type Dialer interface {
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
}

var (
	// ErrNotFound is returned for NXDOMAIN or a name without A records.
	ErrNotFound = errors.New("no such host")
	// ErrNoServers is returned before any DNS server is configured.
	ErrNoServers = errors.New("no tunnel DNS servers configured")
)

const (
	minTTL      = 5 * time.Second
	maxTTL      = time.Hour
	negativeTTL = 30 * time.Second
	maxEntries  = 2048
	tcpWait     = 3 * time.Second
	ednsUDPSize = 1232
)

// udpWait is the wait for a UDP answer per try (two tries per server).
var udpWait = 1500 * time.Millisecond

// Resolver is safe for concurrent use.
type Resolver struct {
	dialer Dialer

	mu       sync.Mutex
	servers  []netip.Addr
	cache    map[string]entry
	inflight map[string]*call
	gen      uint64 // bumped on server change to drop in-flight results
}

type entry struct {
	addrs   []netip.Addr // empty: negative entry
	expires time.Time
}

type call struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// New creates a resolver without servers.
func New(d Dialer) *Resolver {
	return &Resolver{dialer: d, cache: make(map[string]entry), inflight: make(map[string]*call)}
}

// SetServers replaces the DNS servers and flushes the cache.
func (r *Resolver) SetServers(servers []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.servers = append([]netip.Addr(nil), servers...)
	r.cache = make(map[string]entry)
	r.gen++
}

// LookupIPv4 returns the IPv4 addresses of host. An IPv4 literal is returned
// as is.
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Is4() || a.Is4In6() {
			return []netip.Addr{a.Unmap()}, nil
		}
		return nil, fmt.Errorf("lookup %s: IPv6 is not supported", host)
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if err := checkName(name); err != nil {
		return nil, fmt.Errorf("lookup %q: %w", host, err)
	}

	r.mu.Lock()
	if e, ok := r.cache[name]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		if len(e.addrs) == 0 {
			return nil, fmt.Errorf("lookup %s: %w", name, ErrNotFound)
		}
		return e.addrs, nil
	}
	c, ok := r.inflight[name]
	if !ok {
		c = &call{done: make(chan struct{})}
		r.inflight[name] = c
		servers, gen := r.servers, r.gen
		r.mu.Unlock()
		go r.resolve(name, c, servers, gen)
	} else {
		r.mu.Unlock()
	}

	select {
	case <-c.done:
		return c.addrs, c.err
	case <-ctx.Done():
		return nil, fmt.Errorf("lookup %s: %w", name, ctx.Err())
	}
}

// resolve runs detached from any single caller so that a cancelled caller
// does not fail others waiting on the same name.
func (r *Resolver) resolve(name string, c *call, servers []netip.Addr, gen uint64) {
	addrs, ttl, err := r.query(name, servers)
	if err != nil && !errors.Is(err, ErrNotFound) {
		err = fmt.Errorf("lookup %s: %w", name, err)
	} else if err != nil {
		err = fmt.Errorf("lookup %s: %w", name, ErrNotFound)
		ttl = negativeTTL
	}
	c.addrs, c.err = addrs, err

	r.mu.Lock()
	delete(r.inflight, name)
	if gen == r.gen && (err == nil || errors.Is(err, ErrNotFound)) {
		if len(r.cache) >= maxEntries {
			r.evictLocked()
		}
		r.cache[name] = entry{addrs: addrs, expires: time.Now().Add(ttl)}
	}
	r.mu.Unlock()
	close(c.done)
}

func (r *Resolver) evictLocked() {
	now := time.Now()
	for k, e := range r.cache {
		if now.After(e.expires) {
			delete(r.cache, k)
		}
	}
	if len(r.cache) >= maxEntries {
		clear(r.cache)
	}
}

func (r *Resolver) query(name string, servers []netip.Addr) ([]netip.Addr, time.Duration, error) {
	if len(servers) == 0 {
		return nil, 0, ErrNoServers
	}
	var lastErr error
	for _, s := range servers {
		server := netip.AddrPortFrom(s, 53)
		id := uint16(rand.Uint32())
		q, err := buildQuery(id, name)
		if err != nil {
			return nil, 0, err
		}
		resp, err := r.exchangeUDP(server, q)
		if err == nil {
			addrs, ttl, perr := parseResponse(resp, id, name)
			if !errors.Is(perr, errTruncated) {
				if perr == nil || errors.Is(perr, ErrNotFound) {
					return addrs, ttl, perr
				}
				lastErr = fmt.Errorf("%s: %w", server, perr)
				continue // server failure: try the next one
			}
		}
		// UDP failed or the answer was truncated: retry over TCP.
		resp, err = r.exchangeTCP(server, q)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", server, err)
			continue
		}
		addrs, ttl, perr := parseResponse(resp, id, name)
		if perr == nil || errors.Is(perr, ErrNotFound) {
			return addrs, ttl, perr
		}
		lastErr = fmt.Errorf("%s: %w", server, perr)
	}
	return nil, 0, lastErr
}

func (r *Resolver) exchangeUDP(server netip.AddrPort, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*udpWait)
	defer cancel()
	c, err := r.dialer.DialUDP(ctx, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	buf := make([]byte, 4096)
	for try := 0; try < 2; try++ {
		if _, err := c.Write(q); err != nil {
			return nil, err
		}
		c.SetReadDeadline(time.Now().Add(udpWait))
		for {
			n, err := c.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break // resend
				}
				return nil, err
			}
			// Ignore stray datagrams with a different ID.
			if n >= 2 && binary.BigEndian.Uint16(buf) == binary.BigEndian.Uint16(q) {
				return buf[:n], nil
			}
		}
	}
	return nil, errors.New("udp query timed out")
}

func (r *Resolver) exchangeTCP(server netip.AddrPort, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpWait)
	defer cancel()
	c, err := r.dialer.DialTCP(ctx, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(tcpWait))
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
