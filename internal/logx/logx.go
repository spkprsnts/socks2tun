// Package logx writes the stable, line-oriented log format parsed by WireTurn.
//
// Every line starts with "[S2T] ". Errors are "[S2T] error: ...", verbose
// per-connection lines (enabled by --debug) are "[S2T] debug: ...".
package logx

import (
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	logger = log.New(os.Stderr, "[S2T] ", 0)
	debug  atomic.Bool
)

// SetOutput redirects the log (used by tests).
func SetOutput(w io.Writer) { logger.SetOutput(w) }

// SetDebug enables or disables debug lines.
func SetDebug(on bool) { debug.Store(on) }

// DebugEnabled reports whether debug lines are enabled.
func DebugEnabled() bool { return debug.Load() }

// Infof logs an informational line.
func Infof(format string, args ...any) { logger.Printf(format, args...) }

// Errorf logs an error line.
func Errorf(format string, args ...any) { logger.Printf("error: "+format, args...) }

// Debugf logs a debug line if debug output is enabled.
func Debugf(format string, args ...any) {
	if debug.Load() {
		logger.Printf("debug: "+format, args...)
	}
}

// Limiter suppresses repeats of the same message within an interval.
type Limiter struct {
	Interval time.Duration

	mu   sync.Mutex
	last time.Time
	msg  string
}

// Allow reports whether msg should be logged now.
func (l *Limiter) Allow(msg string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if msg == l.msg && now.Sub(l.last) < l.Interval {
		return false
	}
	l.msg, l.last = msg, now
	return true
}
