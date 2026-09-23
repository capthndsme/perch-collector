package portal

import (
	"sync"
	"time"
)

// Clock is the portal's wall clock in epoch milliseconds. Deadlines come
// from the controller with serverNow; a router without NTP may be off, so:
//
//   - the offset to the controller's clock (serverNow − local now) is applied
//     when it exceeds SkewTolerance;
//   - after a reboot without NTP (local clock earlier than the last
//     snapshot's savedAt) time runs on from savedAt at the monotonic rate,
//     so a deadline is never extended by a clock that jumped back.
type Clock struct {
	mu      sync.Mutex
	skew    int64
	floor   int64
	started time.Time
	// now replaces time.Now (tests).
	now func() time.Time
}

// SkewTolerance is the controller offset the router ignores.
const SkewTolerance = 2000

// NewClock returns a clock; floor is the last savedAt (0 = none).
func NewClock(floor int64, skew int64) *Clock {
	c := &Clock{floor: floor, skew: skew, now: time.Now}
	c.started = c.now()
	return c
}

// Now is the current time in epoch milliseconds.
func (c *Clock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now()
	wall := t.UnixMilli() + c.skew
	if c.floor > 0 && wall < c.floor {
		return c.floor + t.Sub(c.started).Milliseconds()
	}
	return wall
}

// Observe takes a serverNow from an accepted controller message.
func (c *Clock) Observe(serverNow int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := serverNow - c.now().UnixMilli()
	if d > SkewTolerance || d < -SkewTolerance {
		c.skew = d
	} else {
		c.skew = 0
	}
	// A controller clock supersedes the reboot floor.
	c.floor = 0
}

// Skew is the applied offset.
func (c *Clock) Skew() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.skew
}
