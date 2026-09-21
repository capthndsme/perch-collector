// Package flow provides a bounded, idle-evicting concurrent flow table
// keyed on a normalized 5-tuple (src/dst IP+port + transport proto).
//
// It is consumed by stateful classifiers (notably nDPI) that need to
// carry per-flow detection state across multiple packets, while keeping
// memory bounded under packet floods or scanning workloads.
//
// The table is intentionally classifier-agnostic — it holds an
// `unsafe.Pointer` `UserData` per entry that the owner uses to attach
// foreign-allocated state (e.g. a cgo-allocated `ndpi_flow_struct`).
// When an entry is evicted (by idle sweep, cap eviction, or Stop), the
// caller-provided `onEvict` callback runs so the owner can free the
// foreign memory.
package flow

import (
	"bytes"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Key is a normalized 5-tuple. Both directions of the same conversation
// (A→B and B→A) produce the same Key, so per-flow state is tracked once
// per flow rather than twice.
//
// IPs are stored in a fixed 16-byte buffer; IPv4 addresses occupy the
// last 4 bytes (the leading 12 bytes are zero), matching Go's
// `net.IP.To16()` representation for v4-in-v6.
type Key struct {
	Lo     [16]byte
	Hi     [16]byte
	LoPort uint16
	HiPort uint16
	Proto  uint8
	_      [3]byte // pad so the struct is a multiple of 8 bytes
}

// MakeKey builds a normalized Key from a raw 5-tuple. `srcIP` and `dstIP`
// may be 4-byte IPv4 or 16-byte IPv6 slices; anything else is left-padded
// into the buffer. Lexicographic ordering on (ip, port) decides which
// endpoint becomes Lo vs Hi.
func MakeKey(srcIP, dstIP []byte, srcPort, dstPort uint16, proto uint8) Key {
	k, _ := MakeKeyDir(srcIP, dstIP, srcPort, dstPort, proto)
	return k
}

// MakeKeyDir is MakeKey plus this packet's direction relative to the
// normalized key: `dstIsHi` reports whether the packet's destination
// endpoint is the key's Hi side. Comparing it against Entry.ServerHi tells
// a caller whether the packet flows client → server.
func MakeKeyDir(srcIP, dstIP []byte, srcPort, dstPort uint16, proto uint8) (Key, bool) {
	var s, d [16]byte
	copyIntoIP(s[:], srcIP)
	copyIntoIP(d[:], dstIP)

	cmp := bytes.Compare(s[:], d[:])
	if cmp < 0 || (cmp == 0 && srcPort <= dstPort) {
		return Key{Lo: s, Hi: d, LoPort: srcPort, HiPort: dstPort, Proto: proto}, true
	}
	return Key{Lo: d, Hi: s, LoPort: dstPort, HiPort: srcPort, Proto: proto}, false
}

// Entry holds per-flow state. UserData is opaque to the table: the
// classifier owns its lifetime and frees it in the onEvict callback.
//
// Ownership of the fields is split between two locks. Key and LastSeen
// belong to the table and are only written under Table.mu (LastSeen is
// refreshed by every GetOrCreate, so a long-lived flow is never idle
// while packets keep arriving). Everything else belongs to the owner,
// which guards it with its own lock; the table never reads or writes
// those fields, and onEvict is the only table-side code that hands an
// Entry to the owner.
type Entry struct {
	Key         Key
	LastSeen    time.Time
	PacketCount uint32
	// PartialAt is the PacketCount at which the classifier first had a
	// usable partial label for the flow (0 = not yet). It bounds how much
	// longer per-flow inspection state is kept.
	PartialAt uint32
	// Done is set once classification has reached a final decision (either
	// a confident protocol match or ndpi_detection_giveup). Subsequent
	// packets on this flow short-circuit to the cached Label.
	Done  bool
	Label string
	// ServerName is the TLS SNI / HTTP Host / QUIC SNI learned for the flow
	// ("" until known). ServerHi records which side of the normalized key is
	// the server (true = Hi), fixed when the entry is created.
	ServerName string
	ServerHi   bool
	// Category is the application category the classifier settled on for
	// the flow ("" until known / when the classifier has none).
	Category string
	// NameExpected records that the finalized protocol family carries a
	// server name (see classifier.Result.NameExpected).
	NameExpected bool
	// UserData is reserved for the caller. The table never dereferences
	// it; it is passed back verbatim to onEvict so the caller can free
	// any foreign-allocated payload.
	UserData unsafe.Pointer

	// evicted is set, under Table.mu and before onEvict runs, once the
	// entry has been removed from the table. An owner that looked the
	// entry up and then took its own lock checks it before attaching new
	// foreign state, since nothing would ever free state attached to a
	// dead entry.
	evicted atomic.Bool
}

// Evicted reports whether the entry has been removed from its table (by
// idle sweep, cap eviction or Stop). Safe to call without any lock.
func (e *Entry) Evicted() bool {
	return e.evicted.Load()
}

// Table is a concurrent flow table with bounded size and idle expiry.
//
// Lifecycle:
//
//	t := NewTable(50_000, 120*time.Second, onEvict)
//	t.Run()              // start sweeper
//	t.GetOrCreate(key)   // hot path, per packet
//	t.Stop()             // drains and calls onEvict for every remaining entry
type Table struct {
	mu       sync.Mutex
	entries  map[Key]*Entry
	maxFlows int
	idle     time.Duration
	onEvict  func(*Entry)

	// sweepInterval can be overridden by tests to avoid waiting 30s.
	sweepInterval time.Duration

	running atomic.Bool // Run was called; Stop only waits for the sweeper then
	stop    chan struct{}
	done    chan struct{}
}

// NewTable returns an unstarted Table. Call Run to begin background
// sweeping; without it the table still functions but never expires
// idle flows.
func NewTable(maxFlows int, idle time.Duration, onEvict func(*Entry)) *Table {
	if maxFlows <= 0 {
		maxFlows = 50_000
	}
	if idle <= 0 {
		idle = 120 * time.Second
	}
	return &Table{
		entries:       make(map[Key]*Entry, 1024),
		maxFlows:      maxFlows,
		idle:          idle,
		onEvict:       onEvict,
		sweepInterval: 30 * time.Second,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
}

// GetOrCreate returns the entry for `k`, creating one if absent, and
// stamps its LastSeen with the current time. The `created` return is
// true when a new entry was inserted; the caller typically uses this to
// allocate per-flow foreign state on first sight.
//
// When the table is at capacity, the oldest entry (by LastSeen) is
// evicted to make room.
func (t *Table) GetOrCreate(k Key) (e *Entry, created bool) {
	return t.GetOrCreateAt(k, time.Now())
}

// GetOrCreateAt is GetOrCreate with the caller's clock reading, so a
// per-packet caller that already has one avoids a second time.Now().
func (t *Table) GetOrCreateAt(k Key, now time.Time) (e *Entry, created bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.entries[k]; ok {
		existing.LastSeen = now
		return existing, false
	}
	if len(t.entries) >= t.maxFlows {
		t.evictOldestLocked(1)
	}
	e = &Entry{Key: k, LastSeen: now}
	t.entries[k] = e
	return e, true
}

// SetSweepInterval changes how often the sweeper looks for idle flows
// (default 30s). Must be called before Run; tests use it to make
// eviction happen within milliseconds.
func (t *Table) SetSweepInterval(d time.Duration) {
	if d > 0 {
		t.sweepInterval = d
	}
}

// Run starts the background sweeper. Safe to call once per Table; calling
// again is a no-op once Stop has been called.
func (t *Table) Run() {
	if t.running.CompareAndSwap(false, true) {
		go t.sweepLoop()
	}
}

// Stop terminates the sweeper, drains every remaining entry through
// onEvict, and clears the map. Idempotent.
func (t *Table) Stop() {
	select {
	case <-t.stop:
		return // already stopped
	default:
		close(t.stop)
	}
	if t.running.Load() {
		<-t.done
	}

	t.mu.Lock()
	for k, e := range t.entries {
		t.evictLocked(k, e)
	}
	t.mu.Unlock()
}

// evictLocked removes e from the table and hands it to onEvict. The
// evicted flag is raised first so an owner racing with the eviction
// (it looked the entry up before we took t.mu) sees a dead entry and
// attaches nothing to it. Caller must hold t.mu.
func (t *Table) evictLocked(k Key, e *Entry) {
	e.evicted.Store(true)
	delete(t.entries, k)
	if t.onEvict != nil {
		t.onEvict(e)
	}
}

// Len returns the current number of tracked flows. Intended for metrics
// and tests.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

func (t *Table) sweepLoop() {
	defer close(t.done)
	ticker := time.NewTicker(t.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case now := <-ticker.C:
			t.sweep(now)
		}
	}
}

// sweep evicts every entry whose LastSeen is older than `idle`.
func (t *Table) sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := now.Add(-t.idle)
	for k, e := range t.entries {
		if e.LastSeen.Before(cutoff) {
			t.evictLocked(k, e)
		}
	}
}

// evictOldestLocked drops the n oldest entries by LastSeen. Called when
// the cap is hit and we need to make room for a new flow. Caller must
// hold t.mu.
//
// O(n log n) on the current table; only runs on overflow so we accept
// the cost rather than maintaining a parallel heap.
func (t *Table) evictOldestLocked(n int) {
	if n <= 0 || len(t.entries) == 0 {
		return
	}
	type pair struct {
		k  Key
		ls time.Time
	}
	cands := make([]pair, 0, len(t.entries))
	for k, e := range t.entries {
		cands = append(cands, pair{k: k, ls: e.LastSeen})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].ls.Before(cands[j].ls) })
	if n > len(cands) {
		n = len(cands)
	}
	for i := 0; i < n; i++ {
		k := cands[i].k
		if e, ok := t.entries[k]; ok {
			t.evictLocked(k, e)
		}
	}
}

// copyIntoIP normalizes a Go IP byte slice into a 16-byte buffer using
// the v4-in-v6 layout for IPv4 (leading 12 bytes zero, address in last 4).
func copyIntoIP(dst []byte, src []byte) {
	switch len(src) {
	case 4:
		copy(dst[12:], src)
	case 16:
		copy(dst, src)
	default:
		// Caller passed something unusual (e.g. nil for a non-IP packet);
		// leave the buffer zeroed so the resulting Key is at least stable.
		if len(src) > 0 && len(src) <= 16 {
			copy(dst[16-len(src):], src)
		}
	}
}
