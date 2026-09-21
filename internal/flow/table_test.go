package flow

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestMakeKeyNormalizesDirections(t *testing.T) {
	a := []byte{10, 0, 0, 1}
	b := []byte{10, 0, 0, 2}

	fwd := MakeKey(a, b, 1234, 443, 6)
	rev := MakeKey(b, a, 443, 1234, 6)
	if fwd != rev {
		t.Fatalf("expected forward and reverse keys to be identical, got\n  fwd=%+v\n  rev=%+v", fwd, rev)
	}
}

func TestMakeKeyIPv4InIPv6Layout(t *testing.T) {
	k := MakeKey([]byte{10, 0, 0, 1}, []byte{8, 8, 8, 8}, 1024, 53, 17)
	// 8.8.8.8 lexicographically < 10.0.0.1 in v4-in-v6 layout.
	wantLo := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}
	if k.Lo != wantLo {
		t.Errorf("Lo: got %v, want %v", k.Lo, wantLo)
	}
	if k.LoPort != 53 || k.HiPort != 1024 {
		t.Errorf("ports: got lo=%d hi=%d, want lo=53 hi=1024", k.LoPort, k.HiPort)
	}
}

func TestTableGetOrCreate(t *testing.T) {
	tbl := NewTable(10, time.Minute, nil)

	k := MakeKey([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, 100, 200, 6)
	e1, created := tbl.GetOrCreate(k)
	if !created {
		t.Fatal("first GetOrCreate: expected created=true")
	}
	e2, created := tbl.GetOrCreate(k)
	if created {
		t.Fatal("second GetOrCreate: expected created=false")
	}
	if e1 != e2 {
		t.Fatal("second call returned a different *Entry")
	}
	if tbl.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", tbl.Len())
	}
}

func TestTableCapEvictsOldest(t *testing.T) {
	var evicted int32
	tbl := NewTable(2, time.Minute, func(*Entry) {
		atomic.AddInt32(&evicted, 1)
	})

	// Insert two flows.
	tbl.GetOrCreate(MakeKey([]byte{1}, []byte{2}, 1, 2, 6))
	time.Sleep(2 * time.Millisecond) // make sure LastSeen differs
	tbl.GetOrCreate(MakeKey([]byte{3}, []byte{4}, 3, 4, 6))

	// Insert a third; the cap is 2 so the oldest must be evicted.
	tbl.GetOrCreate(MakeKey([]byte{5}, []byte{6}, 5, 6, 6))

	if tbl.Len() != 2 {
		t.Fatalf("Len after overflow: got %d, want 2", tbl.Len())
	}
	if got := atomic.LoadInt32(&evicted); got != 1 {
		t.Fatalf("onEvict invocations: got %d, want 1", got)
	}
}

func TestTableSweepEvictsIdleFlows(t *testing.T) {
	var evicted int32
	tbl := NewTable(100, 10*time.Millisecond, func(*Entry) {
		atomic.AddInt32(&evicted, 1)
	})

	e, _ := tbl.GetOrCreate(MakeKey([]byte{1}, []byte{2}, 1, 2, 6))
	// Backdate the entry so it's already idle.
	tbl.mu.Lock()
	e.LastSeen = time.Now().Add(-1 * time.Second)
	tbl.mu.Unlock()

	tbl.sweep(time.Now())
	if got := atomic.LoadInt32(&evicted); got != 1 {
		t.Fatalf("onEvict invocations after sweep: got %d, want 1", got)
	}
	if tbl.Len() != 0 {
		t.Fatalf("Len after sweep: got %d, want 0", tbl.Len())
	}
}

func TestTableStopDrainsRemainingEntries(t *testing.T) {
	var evicted int32
	tbl := NewTable(100, time.Hour, func(*Entry) {
		atomic.AddInt32(&evicted, 1)
	})
	tbl.Run()
	tbl.GetOrCreate(MakeKey([]byte{1}, []byte{2}, 1, 2, 6))
	tbl.GetOrCreate(MakeKey([]byte{3}, []byte{4}, 3, 4, 6))

	tbl.Stop()
	if got := atomic.LoadInt32(&evicted); got != 2 {
		t.Fatalf("onEvict invocations after Stop: got %d, want 2", got)
	}
	if tbl.Len() != 0 {
		t.Fatalf("Len after Stop: got %d, want 0", tbl.Len())
	}
	// Stop is idempotent.
	tbl.Stop()
}

func TestMakeKeyDirReportsDirection(t *testing.T) {
	a := []byte{10, 0, 0, 1}
	b := []byte{10, 0, 0, 2}
	fwd, fwdDstHi := MakeKeyDir(a, b, 1234, 443, 6)
	rev, revDstHi := MakeKeyDir(b, a, 443, 1234, 6)
	if fwd != rev {
		t.Fatalf("both directions must share a key")
	}
	if !fwdDstHi || revDstHi {
		t.Fatalf("a→b must report dst=Hi (got %v), b→a must not (got %v)", fwdDstHi, revDstHi)
	}
}

func TestTableLookupRefreshesLastSeen(t *testing.T) {
	tbl := NewTable(10, time.Minute, nil)
	k := MakeKey([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, 100, 200, 6)

	t0 := time.Now().Add(-time.Hour)
	e, _ := tbl.GetOrCreateAt(k, t0)
	if !e.LastSeen.Equal(t0) {
		t.Fatalf("created LastSeen = %v, want %v", e.LastSeen, t0)
	}
	t1 := t0.Add(30 * time.Minute)
	if _, created := tbl.GetOrCreateAt(k, t1); created {
		t.Fatal("second lookup reported created=true")
	}
	if !e.LastSeen.Equal(t1) {
		t.Fatalf("lookup did not refresh LastSeen: got %v, want %v", e.LastSeen, t1)
	}
	// Still touched within the idle window, so a sweep keeps it.
	tbl.sweep(t1.Add(30 * time.Second))
	if tbl.Len() != 1 {
		t.Fatalf("sweep evicted a flow that was looked up %v ago", 30*time.Second)
	}
	// Under the cap, the untouched flow goes first, not the older-created one.
	other, _ := tbl.GetOrCreateAt(MakeKey([]byte{9}, []byte{9}, 1, 1, 6), t0.Add(time.Minute))
	tbl.maxFlows = 2
	tbl.GetOrCreateAt(MakeKey([]byte{8}, []byte{8}, 1, 1, 6), t1.Add(time.Second))
	if !other.Evicted() || e.Evicted() {
		t.Fatalf("cap eviction dropped the recently looked-up flow (e.evicted=%v other.evicted=%v)", e.Evicted(), other.Evicted())
	}
}

func TestTableEvictionMarksEntryBeforeCallback(t *testing.T) {
	var seen *Entry
	var wasEvicted bool
	tbl := NewTable(100, 10*time.Millisecond, func(e *Entry) {
		seen, wasEvicted = e, e.Evicted()
	})
	e, _ := tbl.GetOrCreateAt(MakeKey([]byte{1}, []byte{2}, 1, 2, 6), time.Now().Add(-time.Second))
	if e.Evicted() {
		t.Fatal("fresh entry reports evicted")
	}
	tbl.sweep(time.Now())
	if seen != e || !wasEvicted {
		t.Fatalf("onEvict saw entry=%p (want %p) with evicted=%v (want true)", seen, e, wasEvicted)
	}
	if !e.Evicted() {
		t.Fatal("entry not marked evicted after sweep")
	}
	// A fresh lookup for the same key yields a new, live entry.
	e2, created := tbl.GetOrCreate(e.Key)
	if !created || e2 == e || e2.Evicted() {
		t.Fatalf("re-lookup: created=%v same=%v evicted=%v", created, e2 == e, e2.Evicted())
	}
	tbl.Stop()
	if !e2.Evicted() {
		t.Fatal("Stop did not mark the drained entry evicted")
	}
}

func TestTableSweeperRunsAtConfiguredInterval(t *testing.T) {
	var evicted atomic.Int32
	tbl := NewTable(100, 20*time.Millisecond, func(*Entry) { evicted.Add(1) })
	tbl.SetSweepInterval(2 * time.Millisecond)
	tbl.Run()
	defer tbl.Stop()
	tbl.GetOrCreate(MakeKey([]byte{1}, []byte{2}, 1, 2, 6))
	deadline := time.Now().Add(2 * time.Second)
	for evicted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if evicted.Load() != 1 || tbl.Len() != 0 {
		t.Fatalf("sweeper did not evict the idle flow: evicted=%d len=%d", evicted.Load(), tbl.Len())
	}
}
