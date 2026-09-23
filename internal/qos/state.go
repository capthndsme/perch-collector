package qos

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// State is what the agent keeps between reconciles (in /tmp/perch-qos, so
// it survives an agent restart but not a reboot, like the kernel objects
// it describes): the class minors and filter handles it allocated, the
// dynamic devices, and the fingerprint of what was applied last.
type State struct {
	Version int `json:"version"`
	// Epoch names this generation of kernel objects: counters start over
	// when it changes (a reboot, the ifbs re-created).
	Epoch string `json:"epoch"`
	// Minors maps an allocation key ("d:<mac>|<parent>", "n:<network>") to
	// its class minor in 0x200-0xfffe.
	Minors map[string]uint16 `json:"minors"`
	// Handles maps a MAC to its flower filter handle.
	Handles map[string]uint32 `json:"handles"`
	// Dynamic are the MACs that got their own leaf from a network default.
	Dynamic map[string]*DynamicDevice `json:"dynamic"`
	// Applied is the fingerprint of the last desired state the kernel took.
	Applied   string    `json:"applied"`
	AppliedAt time.Time `json:"appliedAt"`
	// Devices are the LAN devices the agent put filters on.
	Devices []string `json:"devices"`
}

// DynamicDevice is a MAC shaped by its network's per-device caps.
type DynamicDevice struct {
	Network   string    `json:"network"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	// Bytes is the class byte count last seen (both directions), for the
	// idle check.
	Bytes uint64 `json:"bytes"`
}

const stateVersion = 1

// NewState is an empty state with a fresh epoch.
func NewState(epoch string) *State {
	return &State{
		Version: stateVersion,
		Epoch:   epoch,
		Minors:  map[string]uint16{},
		Handles: map[string]uint32{},
		Dynamic: map[string]*DynamicDevice{},
	}
}

// DecodeState reads a state file.
func DecodeState(data []byte) (*State, error) {
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("state: version %d, want %d", s.Version, stateVersion)
	}
	if s.Minors == nil {
		s.Minors = map[string]uint16{}
	}
	if s.Handles == nil {
		s.Handles = map[string]uint32{}
	}
	if s.Dynamic == nil {
		s.Dynamic = map[string]*DynamicDevice{}
	}
	return &s, nil
}

// allocator hands out class minors and filter handles for one plan: keys
// used in this plan keep theirs, keys not used are released at the end
// (retain), and a minor still present in the kernel (busy) is never handed
// out again in the same plan, because its class is deleted only after the
// new objects are in place.
type allocator struct {
	s         *State
	busy      map[uint16]bool
	usedMinor map[uint16]bool
	usedHdl   map[uint32]bool
	keptMinor map[string]bool
	keptHdl   map[string]bool
	nextMinor uint32
	nextHdl   uint32
}

func newAllocator(s *State, busy map[uint16]bool) *allocator {
	a := &allocator{s: s, busy: busy, usedMinor: map[uint16]bool{}, usedHdl: map[uint32]bool{},
		keptMinor: map[string]bool{}, keptHdl: map[string]bool{}, nextMinor: DeviceMinorMin, nextHdl: 1}
	for k, m := range s.Minors {
		if m < DeviceMinorMin || m > DeviceMinorMax || a.usedMinor[m] {
			delete(s.Minors, k) // corrupt or duplicate: forget it
			continue
		}
		a.usedMinor[m] = true
	}
	for k, h := range s.Handles {
		if h == 0 || a.usedHdl[h] {
			delete(s.Handles, k)
			continue
		}
		a.usedHdl[h] = true
	}
	return a
}

// minor returns key's class minor, allocating the lowest free one; false
// when the range is exhausted.
func (a *allocator) minor(key string) (uint16, bool) {
	a.keptMinor[key] = true
	if m, ok := a.s.Minors[key]; ok {
		return m, true
	}
	for n := a.nextMinor; n <= DeviceMinorMax; n++ {
		m := uint16(n)
		if a.usedMinor[m] || a.busy[m] {
			continue
		}
		a.usedMinor[m] = true
		a.s.Minors[key] = m
		a.nextMinor = n + 1
		return m, true
	}
	delete(a.keptMinor, key)
	return 0, false
}

// handle returns the MAC's filter handle.
func (a *allocator) handle(mac string) uint32 {
	a.keptHdl[mac] = true
	if h, ok := a.s.Handles[mac]; ok {
		return h
	}
	for a.usedHdl[a.nextHdl] {
		a.nextHdl++
	}
	h := a.nextHdl
	a.usedHdl[h] = true
	a.s.Handles[mac] = h
	return h
}

// retain releases what this plan did not use.
func (a *allocator) retain() {
	for k := range a.s.Minors {
		if !a.keptMinor[k] {
			delete(a.s.Minors, k)
		}
	}
	for k := range a.s.Handles {
		if !a.keptHdl[k] {
			delete(a.s.Handles, k)
		}
	}
}

// sortedKeys returns a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
