// Package grant holds the signer's grants, in memory, on CLOCK_BOOTTIME so
// that a suspend counts against them.
package grant

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Anchor struct {
	Pid   int
	Start uint64
}

type Key struct {
	Anchor Anchor
	Host   string
	KeyFP  string
	Fwd    bool
}

// Grants maps a Key to the boottime its grant ends at.
type Grants struct {
	now     func() time.Duration
	mu      sync.Mutex
	until   map[Key]time.Duration
	changed chan struct{}
}

func New() *Grants {
	return newWithClock(Now)
}

func newWithClock(now func() time.Duration) *Grants {
	return &Grants{now: now, until: map[Key]time.Duration{}, changed: make(chan struct{})}
}

// Now is CLOCK_BOOTTIME, the clock until is read on.
func Now() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		panic(err)
	}
	return time.Duration(ts.Nano())
}

// Grant lets k sign until then; a second grant for k keeps the later end.
// Every channel Changed returned before it is closed.
func (g *Grants) Grant(k Key, until time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for old, end := range g.until {
		if end <= now {
			delete(g.until, old)
		}
	}
	if until > g.until[k] {
		g.until[k] = until
	}
	close(g.changed)
	g.changed = make(chan struct{})
}

func (g *Grants) Use(k Key) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.now() < g.until[k]
}

// Changed is closed by the next Grant, so a waiting row can call Use again.
func (g *Grants) Changed() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.changed
}
