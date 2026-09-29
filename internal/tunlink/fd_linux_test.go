package tunlink

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fdListener mimics CSQTT's FdReceiver: an abstract SOCK_STREAM listener that
// accepts, receives one byte with SCM_RIGHTS and acknowledges with one byte.
type fdListener struct {
	fd   int
	name string
}

func uniqueName() string {
	return fmt.Sprintf("s2t-test-%d-%d", os.Getpid(), rand.Uint64())
}

func listenAbstract(t *testing.T, name string) *fdListener {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: "@" + name}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		t.Fatal(err)
	}
	l := &fdListener{fd: fd, name: name}
	t.Cleanup(func() { unix.Close(fd) })
	return l
}

// receive accepts one sender and returns the passed descriptor. If ack is
// false the connection is closed without acknowledging.
func (l *fdListener) receive(t *testing.T, ack bool) int {
	t.Helper()
	c, _, err := unix.Accept(l.fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(c)
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(c, buf, oob, 0)
	if err != nil || n != 1 || buf[0] != 1 {
		t.Fatalf("recvmsg: n=%d data=%v err=%v", n, buf, err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		t.Fatalf("control messages: %v %v", msgs, err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		t.Fatalf("rights: %v %v", fds, err)
	}
	if ack {
		unix.Write(c, []byte{1})
	}
	return fds[0]
}

func sameFile(t *testing.T, a, b int) bool {
	t.Helper()
	var sa, sb unix.Stat_t
	if unix.Fstat(a, &sa) != nil || unix.Fstat(b, &sb) != nil {
		t.Fatal("fstat failed")
	}
	return sa.Dev == sb.Dev && sa.Ino == sb.Ino
}

func TestSendFDWithRetryAndReplacement(t *testing.T) {
	retryPause = 50 * time.Millisecond
	name := uniqueName()

	ours, theirs, err := NewPair()
	if err != nil {
		t.Fatal(err)
	}
	defer ours.Close()
	defer unix.Close(theirs)

	// The core starts after us: the sender must keep retrying.
	sent := make(chan error, 1)
	go func() { sent <- SendFDRetry(context.Background(), name, theirs, 5*time.Second) }()
	time.Sleep(300 * time.Millisecond)
	l := listenAbstract(t, name)
	got := l.receive(t, true)
	defer unix.Close(got)
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
	if !sameFile(t, got, theirs) {
		t.Fatal("received descriptor is not the one sent")
	}

	// The received end must be connected to ours as SEQPACKET.
	if _, err := unix.Write(got, []byte("packet-1")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	ours.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := ours.Read(buf); err != nil || string(buf[:n]) != "packet-1" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}

	// Replacement: a second descriptor on the same listener.
	ours2, theirs2, err := NewPair()
	if err != nil {
		t.Fatal(err)
	}
	defer ours2.Close()
	defer unix.Close(theirs2)
	go func() { sent <- SendFD(name, theirs2) }()
	got2 := l.receive(t, true)
	defer unix.Close(got2)
	if err := <-sent; err != nil {
		t.Fatalf("replacement send: %v", err)
	}
	if !sameFile(t, got2, theirs2) || sameFile(t, got2, got) {
		t.Fatal("replacement descriptor mismatch")
	}
}

func TestSendFDWithoutAck(t *testing.T) {
	name := uniqueName()
	l := listenAbstract(t, name)
	_, theirs, err := NewPair()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(theirs)
	sent := make(chan error, 1)
	go func() { sent <- SendFD(name, theirs) }()
	unix.Close(l.receive(t, false))
	if err := <-sent; err == nil || !strings.Contains(err.Error(), "without ack") {
		t.Fatalf("got %v, want missing ack error", err)
	}
}

func TestSendFDRetryTimeout(t *testing.T) {
	retryPause = 50 * time.Millisecond
	start := time.Now()
	err := SendFDRetry(context.Background(), uniqueName(), 0, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("took %v", el)
	}
}
