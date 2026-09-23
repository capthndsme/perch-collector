package portal

import (
	"sync"
	"time"
)

// Window is a bounded sliding-window counter per key (plan 4 §8: failed
// guest attempts per MAC and per portal, relay requests per client). At
// most MaxKeys keys are tracked; the least recently used goes first.
type Window struct {
	mu      sync.Mutex
	span    time.Duration
	limit   int
	maxKeys int
	keys    map[string]*windowEntry
	seq     uint64
}

type windowEntry struct {
	hits []time.Time
	used uint64
}

// DefaultMaxKeys bounds every limiter map.
const DefaultMaxKeys = 4096

// NewWindow allows limit hits per span per key.
func NewWindow(limit int, span time.Duration) *Window {
	return &Window{span: span, limit: limit, maxKeys: DefaultMaxKeys, keys: map[string]*windowEntry{}}
}

// SetLimit changes the limit (settings from the controller).
func (w *Window) SetLimit(limit int) {
	w.mu.Lock()
	w.limit = limit
	w.mu.Unlock()
}

func (w *Window) prune(e *windowEntry, now time.Time) {
	cut := now.Add(-w.span)
	i := 0
	for i < len(e.hits) && !e.hits[i].After(cut) {
		i++
	}
	e.hits = e.hits[i:]
}

// Blocked reports whether key is at its limit, and when it frees up.
func (w *Window) Blocked(key string, now time.Time) (bool, time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	e, ok := w.keys[key]
	if !ok || w.limit <= 0 {
		return false, 0
	}
	w.prune(e, now)
	if len(e.hits) < w.limit {
		return false, 0
	}
	retry := e.hits[len(e.hits)-w.limit].Add(w.span).Sub(now)
	if retry < time.Second {
		retry = time.Second
	}
	return true, retry
}

// Hit records one event for key.
func (w *Window) Hit(key string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seq++
	e, ok := w.keys[key]
	if !ok {
		if len(w.keys) >= w.maxKeys {
			w.evict()
		}
		e = &windowEntry{}
		w.keys[key] = e
	}
	w.prune(e, now)
	e.hits = append(e.hits, now)
	if max := w.limit * 2; max > 0 && len(e.hits) > max {
		e.hits = e.hits[len(e.hits)-max:]
	}
	e.used = w.seq
}

// Allow is Blocked + Hit for limiters that count every request.
func (w *Window) Allow(key string, now time.Time) (bool, time.Duration) {
	if blocked, retry := w.Blocked(key, now); blocked {
		return false, retry
	}
	w.Hit(key, now)
	return true, 0
}

func (w *Window) evict() {
	var oldest string
	var min uint64
	first := true
	for k, e := range w.keys {
		if first || e.used < min {
			oldest, min, first = k, e.used, false
		}
	}
	delete(w.keys, oldest)
}

// Len is the number of tracked keys (tests).
func (w *Window) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.keys)
}
