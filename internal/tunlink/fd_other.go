//go:build !linux

package tunlink

import (
	"context"
	"errors"
	"os"
	"time"
)

// Descriptor passing needs Linux (Android included). These stubs keep the
// module compiling elsewhere, e.g. for editor tooling on Windows.

var errUnsupported = errors.New("tun descriptors are supported only on Linux and Android")

func NewPair() (ours *os.File, theirs int, err error) { return nil, -1, errUnsupported }

func FileFromFD(fd int, name string) (*os.File, error) { return nil, errUnsupported }

func CloseFD(fd int) error { return errUnsupported }

func SendFD(name string, fd int) error { return errUnsupported }

func SendFDRetry(ctx context.Context, name string, fd int, timeout time.Duration) error {
	return errUnsupported
}
