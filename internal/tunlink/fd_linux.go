package tunlink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/spkprsnts/socks2tun/internal/logx"
)

// pairBuffer is the socket buffer requested for both ends of the pair. The
// kernel caps it at net.core.[rw]mem_max.
const pairBuffer = 1 << 20

// NewPair creates a SOCK_SEQPACKET socketpair. ours is ready for Link.Run
// (non-blocking, registered with the Go poller); theirs is the raw descriptor
// to hand to the core, which the caller must close after sending.
func NewPair() (ours *os.File, theirs int, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, -1, fmt.Errorf("socketpair: %w", err)
	}
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, pairBuffer)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, pairBuffer)
	}
	f, err := FileFromFD(fds[0], "tun")
	if err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		return nil, -1, err
	}
	return f, fds[1], nil
}

// FileFromFD wraps a packet descriptor (socket or TUN device) for Link.Run.
func FileFromFD(fd int, name string) (*os.File, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("set nonblock on fd %d: %w", fd, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// ackTimeout bounds the wait for the core's one-byte acknowledgement.
const ackTimeout = 5 * time.Second

// SendFD passes fd to the core listening on the abstract Unix socket @name:
// one data byte 0x01 with SCM_RIGHTS, then a one-byte ack from the core.
func SendFD(name string, fd int) error {
	s, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(s)
	tv := unix.NsecToTimeval(ackTimeout.Nanoseconds())
	_ = unix.SetsockoptTimeval(s, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(s, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)

	// A leading '@' selects the abstract namespace in x/sys/unix.
	if err := unix.Connect(s, &unix.SockaddrUnix{Name: "@" + name}); err != nil {
		return fmt.Errorf("connect @%s: %w", name, err)
	}
	if err := unix.Sendmsg(s, []byte{1}, unix.UnixRights(fd), nil, unix.MSG_NOSIGNAL); err != nil {
		return fmt.Errorf("sendmsg: %w", err)
	}
	var ack [1]byte
	for {
		n, err := unix.Read(s, ack[:])
		switch {
		case err == unix.EINTR:
			continue
		case err == unix.EAGAIN:
			return errors.New("no ack from core (timeout)")
		case err != nil:
			return fmt.Errorf("read ack: %w", err)
		case n == 0:
			return errors.New("core closed connection without ack")
		}
		return nil
	}
}

// retryPause is the delay between attempts to reach a core that is not
// listening yet.
var retryPause = 250 * time.Millisecond

// SendFDRetry repeats SendFD until it succeeds, ctx is done or timeout
// (0 = no limit) elapses. Failures are logged, repeats of the same error at
// most every few seconds.
func SendFDRetry(ctx context.Context, name string, fd int, timeout time.Duration) error {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	limiter := logx.Limiter{Interval: 5 * time.Second}
	for {
		err := SendFD(name, fd)
		if err == nil {
			logx.Infof("tun fd sent to @%s", name)
			return nil
		}
		if limiter.Allow(err.Error()) {
			logx.Infof("tun fd send failed: %v", err)
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return fmt.Errorf("tun fd not delivered to @%s within %s: %w", name, timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryPause):
		}
	}
}
