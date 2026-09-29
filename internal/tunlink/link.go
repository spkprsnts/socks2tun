// Package tunlink connects a gVisor stack to a packet descriptor that a
// TUN-only core treats as its TUN device: one read/write is one IPv4 packet.
package tunlink

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/spkprsnts/socks2tun/internal/logx"
)

// queueLen is the number of outbound packets buffered while the descriptor
// is busy (or detached); further packets are dropped and TCP retransmits.
const queueLen = 1024

// maxPacket bounds a single read; larger packets are truncated by the kernel
// and then rejected by the stack.
const maxPacket = 65535

var dropLog = logx.Limiter{Interval: 10 * time.Second}

// Link is a stack.LinkEndpoint whose packets go to and come from a
// descriptor. The descriptor can be replaced at runtime (Run is called again
// with a new one) without recreating the NIC.
type Link struct {
	*channel.Endpoint

	// runMu serialises Run calls: only one descriptor is attached at a time.
	runMu sync.Mutex
}

// New creates a detached link with the given MTU.
func New(mtu uint32) *Link {
	return &Link{Endpoint: channel.New(queueLen, mtu, "")}
}

// Run attaches f and pumps packets until the peer closes it, an I/O error
// occurs or ctx is cancelled. f is closed on return. The returned error is
// io.EOF when the peer closed its end and ctx.Err() on cancellation.
func (l *Link) Run(parent context.Context, f *os.File) error {
	l.runMu.Lock()
	defer l.runMu.Unlock()

	ctx, cancel := context.WithCancel(parent)
	var closeOnce sync.Once
	closeFile := func() { closeOnce.Do(func() { f.Close() }) }

	var wg sync.WaitGroup
	var writeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		closeFile() // unblocks the reader and a blocked writer
	}()
	go func() {
		defer wg.Done()
		writeErr = l.writeLoop(ctx, f)
		cancel()
	}()

	readErr := l.readLoop(f)
	cancel()
	wg.Wait()
	// Packets queued for the old descriptor are stale; TCP will retransmit.
	l.Drain()

	switch {
	case parent.Err() != nil:
		return parent.Err()
	case writeErr != nil:
		return writeErr
	}
	return readErr
}

func (l *Link) readLoop(f *os.File) error {
	buf := make([]byte, maxPacket)
	for {
		n, err := f.Read(buf)
		if err != nil {
			return err
		}
		if n < header.IPv4MinimumSize || header.IPVersion(buf[:n]) != header.IPv4Version {
			continue // IPv4-only tunnel: silently drop anything else
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf[:n]),
		})
		l.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

func (l *Link) writeLoop(ctx context.Context, f *os.File) error {
	buf := make([]byte, maxPacket)
	for {
		pkt := l.ReadContext(ctx)
		if pkt == nil {
			return nil // ctx cancelled
		}
		n := 0
		for _, s := range pkt.AsSlices() {
			n += copy(buf[n:], s)
		}
		pkt.DecRef()
		if _, err := f.Write(buf[:n]); err != nil {
			switch {
			case errors.Is(err, os.ErrClosed):
				return nil
			case errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNRESET),
				errors.Is(err, syscall.ENOTCONN), errors.Is(err, syscall.EBADF):
				return err
			default:
				// ENOBUFS, EMSGSIZE and the like: drop this packet only.
				if dropLog.Allow(err.Error()) {
					logx.Debugf("tun write dropped packet: %v", err)
				}
			}
		}
	}
}
