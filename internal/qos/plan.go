package qos

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Dir is a direction: Down (the LAN device's egress, ifb-pdn) or Up (its
// ingress, ifb-pup).
type Dir int

const (
	Down Dir = 0
	Up   Dir = 1
)

var dirs = [2]Dir{Down, Up}

func (d Dir) String() string {
	if d == Down {
		return "down"
	}
	return "up"
}

// Ifb is the direction's Perch ifb.
func (d Dir) Ifb() string {
	if d == Down {
		return IfbDown
	}
	return IfbUp
}

// Hook is the clsact hook of a LAN device that feeds the direction.
func (d Dir) Hook() string {
	if d == Down {
		return "egress"
	}
	return "ingress"
}

// The two Perch ifbs (plan 3 section 3.2).
const (
	IfbDown = "ifb-pdn"
	IfbUp   = "ifb-pup"
)

// RootKbit is the root class 1:1: far above any real link.
const RootKbit = 10_000_000

// Filter priorities on a LAN device's clsact hooks. Lower runs first.
//
// A VLAN-tagged frame on a device is a VLAN device's frame on its way to or
// from the port below it (lan.132 over lan): it was shaped, or will be, on
// the VLAN device. The first two priorities let it pass, else a device's
// MAC filter on both would shape and count it twice (2026-09-24: half the
// cap, quotas used up at half the traffic). Before that fix the priorities
// were ARP 1 … exempt v6 7; every old one is among these, so an upgrade
// clears them.
const (
	PrefTaggedQ    = 1   // 802.1Q-tagged frames: a VLAN device's, pass
	PrefTaggedAD   = 2   // 802.1ad (QinQ) likewise
	PrefARP        = 3   // ARP: never shaped
	PrefMulticast  = 4   // multicast and broadcast frames
	PrefRouterV4   = 5   // to/from the router's own addresses
	PrefRouterV6   = 6   //
	PrefIncludeLan = 7   // MACs whose LAN traffic is shaped too (decision 13)
	PrefExemptV4   = 8   // LAN↔LAN: the router's non-WAN prefixes, each exact
	PrefExemptV6   = 9   //
	PrefDevice     = 10  // one per MAC with an entry
	PrefDefault    = 100 // the network default (flower without keys)
)

// ourPrefs are the priorities this agent owns on a LAN device.
var ourPrefs = map[uint16]bool{PrefTaggedQ: true, PrefTaggedAD: true, PrefARP: true, PrefMulticast: true,
	PrefRouterV4: true, PrefRouterV6: true, PrefIncludeLan: true, PrefExemptV4: true, PrefExemptV6: true,
	PrefDevice: true, PrefDefault: true}

// lanChain is the chain LAN↔LAN traffic continues in on a device whose
// network default shapes LAN traffic too (a default with include_lan).
const lanChain = 1

// LAN is one of the router's LAN networks.
type LAN struct {
	Network string `json:"network"`
	Device  string `json:"device"`
	// Prefixes are the network's own, exact (never summarised).
	Prefixes []netip.Prefix `json:"prefixes"`
	// Addrs are the router's addresses on it.
	Addrs []netip.Addr `json:"-"`
	// Conflict names why the device cannot be shaped ("" = it can).
	Conflict string `json:"conflict,omitempty"`
}

// Neighbor is a device in the router's neighbour table.
type Neighbor struct {
	MAC    string
	Device string
	// Confirmed: the kernel recently confirmed it (reachable, delay, probe,
	// permanent), which keeps a dynamic leaf alive.
	Confirmed bool
}

// Inputs are what one plan is made from.
type Inputs struct {
	Config    *Config
	Entries   []Entry
	LANs      []LAN
	Neighbors []Neighbor
	Now       time.Time
	// Zone is the router's local time (schedules); nil = UTC.
	Zone *Zone
	// ClockSynced: without it no schedule is in force (amendment section 6).
	ClockSynced bool
	// Exhausted quotas (enforced): MAC → true.
	Exhausted map[string]bool
	// Busy are the class minors the kernel has now.
	Busy map[uint16]bool
	// ClassBytes are the kernel's byte counters per class minor (both
	// directions summed), for the dynamic devices' idle check.
	ClassBytes map[uint16]uint64
}

// HTBRate is one class's parameters in one direction, in kbit/s.
type HTBRate struct {
	RateKbit int64 `json:"rateKbit"`
	CeilKbit int64 `json:"ceilKbit"`
}

// Class kinds.
const (
	KindBucket   = "bucket"
	KindRest     = "rest"
	KindDevice   = "device"
	KindOverflow = "overflow"
)

// Leaf qdisc kinds ("" = an inner class).
const (
	LeafNone    = ""
	LeafFqCodel = "fq_codel"
	LeafCake    = "cake"
)

// DClass is a desired HTB class; the tree is the same on both ifbs, with
// each direction's rates.
type DClass struct {
	Minor  uint16
	Parent uint16
	// Key names what the class shapes in the push: b:<policy>, r:<policy>,
	// d:<mac>, n:<network>.
	Key     string
	Kind    string
	Rate    [2]HTBRate
	Leaf    string
	Flows   int // fq_codel flows
	Network string
	MAC     string
	Dynamic bool
}

// Filter actions (canonical form, also what the kernel reader produces).
const (
	ActPass = "pass"
	ActDrop = "drop"
	ActLAN  = "goto:1" // continue in the LAN chain
)

// actClass is the action that puts a packet in class minor.
func actClass(minor uint16) string { return "class:" + strconv.FormatUint(uint64(minor), 16) }

// DFilter is a desired flower filter on a LAN device.
type DFilter struct {
	Hook   string
	Chain  int
	Pref   uint16
	Proto  string // all | ip | ipv6 | arp
	Handle uint32
	// Match in canonical form: "", "dst_mac=…", "src_ip=…/n", …
	Match  string
	Action string
}

// Key identifies the filter's slot.
func (f DFilter) Key() string {
	return fmt.Sprintf("%s/%d/%d/%s/%d", f.Hook, f.Chain, f.Pref, f.Proto, f.Handle)
}

// Placement is where one MAC ended up (the push's devices).
type Placement struct {
	MAC     string `json:"mac"`
	ClassID string `json:"classId"` // "1:2a0", the rest leaf, or "" (pass / drop)
	Network string `json:"network"`
	Dynamic bool   `json:"dynamic"`
	// State: shaped, unshaped, blocked, throttled.
	State string `json:"state"`
	minor uint16
}

// MarshalJSON writes classId and network as null when unknown.
func (p Placement) MarshalJSON() ([]byte, error) {
	var cls, network *string
	if p.ClassID != "" {
		cls = &p.ClassID
	}
	if p.Network != "" {
		network = &p.Network
	}
	return json.Marshal(struct {
		MAC     string  `json:"mac"`
		ClassID *string `json:"classId"`
		Network *string `json:"network"`
		Dynamic bool    `json:"dynamic"`
		State   string  `json:"state"`
	}{p.MAC, cls, network, p.Dynamic, p.State})
}

// ScheduleState is a schedule's window state (push `schedules`).
type ScheduleState struct {
	Name   string     `json:"name"`
	Active bool       `json:"active"`
	Since  *time.Time `json:"since"`
	Until  *time.Time `json:"until"`
}

// Desired is the plan: the kernel objects the agent wants.
type Desired struct {
	// Active is false when there is nothing to shape (or shaping is off):
	// then no Perch object may exist.
	Active  bool
	Classes []DClass
	// Filters by LAN device.
	Filters    map[string][]DFilter
	LANs       []LAN
	Placements []Placement
	Schedules  []ScheduleState
	Issues     []Issue
	Config     *Config
	// Fingerprint identifies the plan (a reconcile with the same one and a
	// kernel that matches does nothing).
	Fingerprint string
}

// effective is what a MAC or a network default is given after schedules
// and quotas.
type effective struct {
	bucket     string
	caps       *Rate
	includeLan bool
	action     string // "" classify | pass | drop
	throttled  bool
}

func schedByName(c *Config, names []string, active map[string]bool) *Schedule {
	for _, n := range names {
		if active[n] {
			if s := c.Schedule(n); s != nil {
				return s
			}
		}
	}
	return nil
}

// override applies a schedule's limit to one rate (nil = keep).
func override(base int64, v *int64) int64 {
	if v == nil {
		return base
	}
	return *v
}

func withEach(caps *Rate, s *Schedule) *Rate {
	var r Rate
	if caps != nil {
		r = *caps
	}
	r.Down = override(r.Down, s.EachDown)
	r.Up = override(r.Up, s.EachUp)
	if r.Down == 0 && r.Up == 0 {
		return nil
	}
	return &r
}

func eachOf(s *Schedule) *Rate {
	var r Rate
	if s.EachDown != nil {
		r.Down = *s.EachDown
	}
	if s.EachUp != nil {
		r.Up = *s.EachUp
	}
	if r.Down == 0 && r.Up == 0 {
		return nil
	}
	return &r
}

// applySchedule changes an entry's or a network default's shaping for the
// schedule in force (docs/gateway/qos.md section 3.4).
func applySchedule(e effective, s *Schedule, network bool) effective {
	if s == nil {
		return e
	}
	if s.Assignment == "" {
		// A policy's schedule: its members' caps.
		switch s.Action {
		case "limit":
			e.caps = withEach(e.caps, s)
		case "unlimited":
			e.caps = nil
		}
		return e
	}
	switch s.Action {
	case "limit":
		e.caps = withEach(e.caps, s)
	case "unlimited":
		e.action, e.bucket, e.caps = ActPass, "", nil
	case "block":
		if !network {
			e.action = ActDrop
		}
	case "move":
		e.bucket, e.caps = s.Bucket, eachOf(s)
	}
	return e
}

func throttleRate(q *DeviceQuota) *Rate {
	var r Rate
	if q.ThrottleDownKbit != nil {
		r.Down = *q.ThrottleDownKbit
	}
	if q.ThrottleUpKbit != nil {
		r.Up = *q.ThrottleUpKbit
	}
	return &r
}

// ScheduleStates evaluates every schedule of the config at now.
func ScheduleStates(c *Config, now time.Time, zone *Zone, synced bool) []ScheduleState {
	if zone == nil {
		zone = UTCZone
	}
	wall := zone.Wall(now)
	var out []ScheduleState
	for _, s := range c.Schedules {
		st := ScheduleState{Name: s.Name}
		var since, until, next time.Time
		for _, w := range s.Windows {
			if start, end, ok := w.Occurrence(wall); ok {
				if !st.Active || end.After(until) {
					until = end
				}
				if !st.Active || start.Before(since) {
					since = start
				}
				st.Active = true
			}
			if n := w.NextStart(wall); !n.IsZero() && (next.IsZero() || n.Before(next)) {
				next = n
			}
		}
		if !synced {
			st.Active = false
			since, until = time.Time{}, time.Time{}
		}
		if st.Active {
			a, b := zone.Instant(since).UTC(), zone.Instant(until).UTC()
			st.Since, st.Until = &a, &b
		} else if synced && !next.IsZero() {
			n := zone.Instant(next).UTC()
			st.Until = &n // the next start
		}
		out = append(out, st)
	}
	return out
}

// Plan computes the desired kernel objects. It updates st: class minors,
// filter handles, dynamic devices.
func Plan(in Inputs, st *State) *Desired {
	c := in.Config
	d := &Desired{Config: c, Filters: map[string][]DFilter{}}
	if c == nil || !c.Present || !c.Enabled || !c.Valid() {
		return finish(d)
	}
	d.Schedules = ScheduleStates(c, in.Now, in.Zone, in.ClockSynced)
	active := map[string]bool{}
	for _, s := range d.Schedules {
		if s.Active {
			active[s.Name] = true
		}
	}
	if len(c.Schedules) > 0 && !in.ClockSynced {
		d.Issues = append(d.Issues, Issue{"schedule_clock_unsynced", "the router's clock is not synchronised yet: schedules are not applied"})
	}
	issue := func(code, format string, a ...any) {
		d.Issues = append(d.Issues, Issue{code, fmt.Sprintf(format, a...)})
	}

	// Shaped LAN devices: every LAN without a conflict.
	var lans []LAN
	lanByNet := map[string]LAN{}
	lanByDev := map[string]LAN{}
	for _, l := range in.LANs {
		if l.Conflict != "" {
			issue(l.Conflict, "%s (%s) is not shaped", l.Device, l.Network)
			continue
		}
		lans = append(lans, l)
		lanByNet[l.Network] = l
		lanByDev[l.Device] = l
	}
	sort.Slice(lans, func(i, j int) bool { return lans[i].Device < lans[j].Device })
	d.LANs = lans

	alloc := newAllocator(st, in.Busy)
	minDev := c.MinDeviceKbit

	// Buckets and their rest leaves.
	ceilOf := map[uint16][2]int64{RootMinor: {RootKbit, RootKbit}}
	add := func(cl DClass) {
		d.Classes = append(d.Classes, cl)
		ceilOf[cl.Minor] = [2]int64{cl.Rate[Down].CeilKbit, cl.Rate[Up].CeilKbit}
	}
	bucketKey := func(b *Bucket) string {
		if b.Policy != "" {
			return b.Policy
		}
		return b.Name
	}
	for _, b := range c.Buckets {
		rate := b.Rate
		if s := schedByName(c, b.Schedules, active); s != nil && s.Assignment == "" {
			switch s.Action {
			case "limit":
				rate.Down, rate.Up = override(rate.Down, s.Down), override(rate.Up, s.Up)
			case "unlimited":
				rate = Rate{}
			}
		}
		parent := uint16(RootMinor)
		if p := c.Bucket(b.Parent); p != nil {
			parent = p.Minor
		}
		cl := DClass{Minor: b.Minor, Parent: parent, Key: "b:" + bucketKey(b), Kind: KindBucket}
		for _, dir := range dirs {
			pc := ceilOf[parent][dir]
			v := rate.get(dir)
			if v <= 0 || v > pc {
				v = pc
			}
			cl.Rate[dir] = HTBRate{RateKbit: v, CeilKbit: v}
		}
		add(cl)
		rest := DClass{Minor: RestLeafBase | b.Minor, Parent: b.Minor, Key: "r:" + bucketKey(b), Kind: KindRest, Leaf: LeafCake}
		if b.Fairness == "per_flow" {
			rest.Leaf, rest.Flows = LeafFqCodel, 1024
		}
		for _, dir := range dirs {
			ceil := cl.Rate[dir].CeilKbit
			rest.Rate[dir] = HTBRate{RateKbit: minI(minDev, ceil), CeilKbit: ceil}
		}
		add(rest)
	}

	// A device leaf under parent (a bucket or the root) with caps.
	deviceClass := func(key string, parent uint16, caps *Rate) DClass {
		cl := DClass{Parent: parent, Key: key, Kind: KindDevice, Leaf: LeafFqCodel, Flows: c.LeafFlows}
		for _, dir := range dirs {
			pc := ceilOf[parent][dir]
			ceil := pc
			if caps != nil {
				if v := caps.get(dir); v > 0 && v < pc {
					ceil = v
				}
			}
			rate := ceil
			if parent != RootMinor {
				rate = minI(minDev, ceil)
			}
			cl.Rate[dir] = HTBRate{RateKbit: rate, CeilKbit: ceil}
		}
		return cl
	}
	bucketMinor := func(name, who string) (uint16, bool) {
		if name == "" {
			return 0, false
		}
		b := c.Bucket(name)
		if b == nil {
			issue("unknown_bucket", "%s names bucket %q, which perch-qos does not have", who, name)
			return 0, false
		}
		return b.Minor, true
	}

	// Static entries.
	static := map[string]bool{}
	type macFilter struct {
		mac     string
		include bool
		action  string
		devices []string // nil = every shaped LAN device
		lanPass bool     // also a pass in the LAN chain (static, not include_lan)
	}
	var macFilters []macFilter
	seenNet := map[string]string{} // MAC → network where the neighbour table has it
	for _, n := range in.Neighbors {
		if l, ok := lanByDev[n.Device]; ok {
			if _, dup := seenNet[n.MAC]; !dup {
				seenNet[n.MAC] = l.Network
			}
		}
	}
	for _, e := range in.Entries {
		if !e.Expires.IsZero() && !in.Now.Before(e.Expires) {
			continue // expired entries drop even while offline
		}
		static[e.MAC] = true
		ef := effective{bucket: e.Bucket, caps: e.Caps, includeLan: e.IncludeLan}
		ef = applySchedule(ef, schedByName(c, e.Schedules, active), false)
		if e.Quota != nil && in.Exhausted[e.MAC] {
			if e.Quota.OnExhausted == "block" {
				ef.action = ActDrop
			} else {
				ef.caps, ef.throttled = throttleRate(e.Quota), true
				if ef.action == ActPass {
					ef.action = ""
				}
			}
		}
		p := Placement{MAC: e.MAC, Network: seenNet[e.MAC], State: "shaped"}
		action := ef.action
		if action == "" {
			parent := uint16(RootMinor)
			bm, inBucket := bucketMinor(ef.bucket, "device "+e.MAC)
			if inBucket {
				parent = bm
			}
			switch {
			case ef.caps != nil || ef.throttled:
				m, ok := alloc.minor(fmt.Sprintf("d:%s|%x", e.MAC, parent))
				if !ok {
					issue("class_pool_exhausted", "no class id left for %s", e.MAC)
					action = ActPass
					break
				}
				cl := deviceClass("d:"+e.MAC, parent, ef.caps)
				cl.Minor, cl.MAC = m, e.MAC
				add(cl)
				action, p.minor = actClass(m), m
			case inBucket:
				action, p.minor = actClass(RestLeafBase|bm), RestLeafBase|bm
			default:
				action = ActPass
			}
		}
		switch {
		case action == ActDrop:
			p.State = "blocked"
		case action == ActPass:
			p.State = "unshaped"
		case ef.throttled:
			p.State = "throttled"
		}
		if p.minor != 0 {
			p.ClassID = classID(p.minor)
		}
		d.Placements = append(d.Placements, p)
		include := ef.includeLan && action != ActDrop
		macFilters = append(macFilters, macFilter{mac: e.MAC, include: include, action: action, lanPass: !include})
	}

	// Network defaults, dynamic devices and overflow classes.
	type netDefault struct {
		ef       effective
		target   string // action of the default filter ("" = none)
		dynamic  bool
		parent   uint16
		lan      LAN
		policyNW *NetworkDefault
	}
	defaults := map[string]*netDefault{} // by device
	for _, n := range c.Networks {
		l, ok := lanByNet[n.Name]
		if !ok {
			issue("unknown_network", "perch-qos network %s is not an active LAN of this router", n.Name)
			continue
		}
		ef := effective{bucket: n.Bucket, caps: n.Each, includeLan: n.IncludeLan}
		ef = applySchedule(ef, schedByName(c, n.Schedules, active), true)
		nd := &netDefault{ef: ef, lan: l, parent: RootMinor, policyNW: n}
		if ef.action == ActPass {
			continue // unshaped while the window is on
		}
		bm, inBucket := bucketMinor(ef.bucket, "network "+n.Name)
		if inBucket {
			nd.parent = bm
			nd.target = actClass(RestLeafBase | bm)
		}
		if ef.caps != nil {
			nd.dynamic = true
			if !inBucket {
				// Devices without a leaf yet (or over the pool) share one
				// class capped like a single device.
				m, ok := alloc.minor("n:" + n.Name)
				if ok {
					cl := deviceClass("n:"+n.Name, RootMinor, ef.caps)
					cl.Minor, cl.Kind, cl.Network, cl.Flows = m, KindOverflow, n.Name, 1024
					add(cl)
					nd.target = actClass(m)
				} else {
					issue("class_pool_exhausted", "no class id left for network %s", n.Name)
				}
			}
		}
		if nd.target == "" && !nd.dynamic {
			continue
		}
		defaults[l.Device] = nd
	}

	// Dynamic devices: update the set, then give each its leaf.
	updateDynamic(st, in, defaults2nets(defaults, func(nd *netDefault) (string, string, bool) {
		return nd.lan.Device, nd.lan.Network, nd.dynamic
	}), static, c.DynamicIdle)
	dynCount := 0
	var dynMACs []string
	for mac := range st.Dynamic {
		dynMACs = append(dynMACs, mac)
	}
	sort.Slice(dynMACs, func(i, j int) bool {
		a, b := st.Dynamic[dynMACs[i]], st.Dynamic[dynMACs[j]]
		if !a.FirstSeen.Equal(b.FirstSeen) {
			return a.FirstSeen.Before(b.FirstSeen)
		}
		return dynMACs[i] < dynMACs[j]
	})
	exhaustedNets := map[string]bool{}
	for _, mac := range dynMACs {
		dd := st.Dynamic[mac]
		l := lanByNet[dd.Network]
		nd := defaults[l.Device]
		if nd == nil || !nd.dynamic {
			continue
		}
		if dynCount >= c.DynamicLimit {
			exhaustedNets[dd.Network] = true
			continue
		}
		m, ok := alloc.minor(fmt.Sprintf("d:%s|%x", mac, nd.parent))
		if !ok {
			exhaustedNets[dd.Network] = true
			continue
		}
		dynCount++
		cl := deviceClass("d:"+mac, nd.parent, nd.ef.caps)
		cl.Minor, cl.MAC, cl.Dynamic, cl.Network = m, mac, true, dd.Network
		add(cl)
		d.Placements = append(d.Placements, Placement{MAC: mac, ClassID: classID(m), Network: dd.Network, Dynamic: true, State: "shaped", minor: m})
		macFilters = append(macFilters, macFilter{mac: mac, include: nd.ef.includeLan, action: actClass(m), devices: []string{l.Device}})
	}
	for _, n := range sortedKeys(exhaustedNets) {
		issue("pool_exhausted", "network %s: more devices than dynamic_limit %d; the rest share the network's class", n, c.DynamicLimit)
	}

	// Filters.
	d.Active = len(d.Classes) > 0 || len(macFilters) > 0 || len(defaults) > 0
	if !d.Active {
		alloc.retain()
		return finish(d)
	}
	var v4Own, v6Own, v4Ex, v6Ex []netip.Prefix
	for _, l := range lans {
		for _, a := range l.Addrs {
			p := netip.PrefixFrom(a, a.BitLen())
			if a.Is4() {
				v4Own = append(v4Own, p)
			} else {
				v6Own = append(v6Own, p)
			}
		}
		for _, p := range l.Prefixes {
			if p.Addr().Is4() {
				v4Ex = append(v4Ex, p)
			} else {
				v6Ex = append(v6Ex, p)
			}
		}
	}
	for _, l := range in.LANs { // a conflicted LAN's prefixes stay exempt
		if l.Conflict == "" {
			continue
		}
		for _, p := range l.Prefixes {
			if p.Addr().Is4() {
				v4Ex = append(v4Ex, p)
			} else {
				v6Ex = append(v6Ex, p)
			}
		}
	}
	v6Ex = append(v6Ex, netip.MustParsePrefix("fe80::/10"))
	for _, p := range c.Exempt {
		if p.Addr().Is4() {
			v4Ex = append(v4Ex, p)
		} else {
			v6Ex = append(v6Ex, p)
		}
	}
	v4Own, v6Own, v4Ex, v6Ex = uniqPrefixes(v4Own), uniqPrefixes(v6Own), uniqPrefixes(v4Ex), uniqPrefixes(v6Ex)

	for _, l := range lans {
		var fs []DFilter
		nd := defaults[l.Device]
		lanChainOn := nd != nil && nd.ef.includeLan && nd.target != ""
		for _, dir := range dirs {
			hook := dir.Hook()
			ipKey := "src_ip"
			macKey := "dst_mac"
			if dir == Up {
				ipKey, macKey = "dst_ip", "src_mac"
			}
			fs = append(fs,
				DFilter{Hook: hook, Pref: PrefTaggedQ, Proto: "802.1Q", Handle: 1, Action: ActPass},
				DFilter{Hook: hook, Pref: PrefTaggedAD, Proto: "802.1ad", Handle: 1, Action: ActPass},
				DFilter{Hook: hook, Pref: PrefARP, Proto: "arp", Handle: 1, Action: ActPass},
				DFilter{Hook: hook, Pref: PrefMulticast, Proto: "all", Handle: 1, Match: "dst_mac=01:00:00:00:00:00/01:00:00:00:00:00", Action: ActPass},
			)
			for i, p := range v4Own {
				fs = append(fs, DFilter{Hook: hook, Pref: PrefRouterV4, Proto: "ip", Handle: uint32(i + 1), Match: ipKey + "=" + p.String(), Action: ActPass})
			}
			for i, p := range v6Own {
				fs = append(fs, DFilter{Hook: hook, Pref: PrefRouterV6, Proto: "ipv6", Handle: uint32(i + 1), Match: ipKey + "=" + p.String(), Action: ActPass})
			}
			exAct := ActPass
			if lanChainOn {
				exAct = ActLAN
			}
			for i, p := range v4Ex {
				fs = append(fs, DFilter{Hook: hook, Pref: PrefExemptV4, Proto: "ip", Handle: uint32(i + 1), Match: ipKey + "=" + p.String(), Action: exAct})
			}
			for i, p := range v6Ex {
				fs = append(fs, DFilter{Hook: hook, Pref: PrefExemptV6, Proto: "ipv6", Handle: uint32(i + 1), Match: ipKey + "=" + p.String(), Action: exAct})
			}
			for _, mf := range macFilters {
				if mf.devices != nil && mf.devices[0] != l.Device {
					continue
				}
				h := alloc.handle(mf.mac)
				pref := uint16(PrefDevice)
				if mf.include {
					pref = PrefIncludeLan
				}
				fs = append(fs, DFilter{Hook: hook, Pref: pref, Proto: "all", Handle: h, Match: macKey + "=" + mf.mac, Action: mf.action})
				if lanChainOn && mf.lanPass {
					fs = append(fs, DFilter{Hook: hook, Chain: lanChain, Pref: PrefDevice, Proto: "all", Handle: h, Match: macKey + "=" + mf.mac, Action: ActPass})
				}
			}
			if nd != nil && nd.target != "" {
				fs = append(fs, DFilter{Hook: hook, Pref: PrefDefault, Proto: "all", Handle: 1, Action: nd.target})
				if lanChainOn {
					fs = append(fs, DFilter{Hook: hook, Chain: lanChain, Pref: PrefDefault, Proto: "all", Handle: 1, Action: nd.target})
				}
			}
		}
		sort.SliceStable(fs, func(i, j int) bool {
			a, b := fs[i], fs[j]
			if a.Hook != b.Hook {
				return a.Hook < b.Hook
			}
			if a.Chain != b.Chain {
				return a.Chain < b.Chain
			}
			if a.Pref != b.Pref {
				return a.Pref < b.Pref
			}
			return a.Handle < b.Handle
		})
		d.Filters[l.Device] = fs
	}
	alloc.retain()
	sort.Slice(d.Placements, func(i, j int) bool { return d.Placements[i].MAC < d.Placements[j].MAC })
	return finish(d)
}

func defaults2nets[T any](m map[string]T, f func(T) (dev, network string, dynamic bool)) map[string]string {
	out := map[string]string{}
	for _, v := range m {
		if dev, network, dyn := f(v); dyn {
			out[dev] = network
		}
	}
	return out
}

// updateDynamic adds the MACs the neighbour table shows on a network with
// per-device caps, refreshes their last-seen time (a confirmed neighbour
// entry or class bytes moving), and drops those idle for longer than idle
// or whose network no longer gives per-device caps.
func updateDynamic(st *State, in Inputs, dynNets map[string]string, static map[string]bool, idle time.Duration) {
	for _, n := range in.Neighbors {
		network, ok := dynNets[n.Device]
		if !ok || static[n.MAC] {
			continue
		}
		dd := st.Dynamic[n.MAC]
		if dd == nil {
			dd = &DynamicDevice{Network: network, FirstSeen: in.Now, LastSeen: in.Now}
			st.Dynamic[n.MAC] = dd
		}
		if dd.Network != network {
			dd.Network, dd.LastSeen = network, in.Now
		}
		if n.Confirmed {
			dd.LastSeen = in.Now
		}
	}
	nets := map[string]bool{}
	for _, network := range dynNets {
		nets[network] = true
	}
	for mac, dd := range st.Dynamic {
		if static[mac] || !nets[dd.Network] {
			delete(st.Dynamic, mac)
			continue
		}
		var bytes uint64
		for k, m := range st.Minors {
			if strings.HasPrefix(k, "d:"+mac+"|") {
				bytes += in.ClassBytes[m]
			}
		}
		if bytes != dd.Bytes {
			if bytes > dd.Bytes {
				dd.LastSeen = in.Now
			}
			dd.Bytes = bytes
		}
		if idle > 0 && in.Now.Sub(dd.LastSeen) > idle {
			delete(st.Dynamic, mac)
		}
	}
}

func finish(d *Desired) *Desired {
	h := sha256.New()
	fmt.Fprintf(h, "active=%v\n", d.Active)
	for _, c := range d.Classes {
		fmt.Fprintf(h, "c %x %x %s %s %v %s %d\n", c.Minor, c.Parent, c.Key, c.Kind, c.Rate, c.Leaf, c.Flows)
	}
	if d.Config != nil {
		fmt.Fprintf(h, "leaf %d %d %d %d\n", d.Config.LeafFlows, d.Config.LeafLimit, d.Config.LeafMemoryKB, d.Config.RestMemlimitKB)
	}
	for _, dev := range sortedKeys(d.Filters) {
		for _, f := range d.Filters[dev] {
			fmt.Fprintf(h, "f %s %s %s %s\n", dev, f.Key(), f.Match, f.Action)
		}
	}
	d.Fingerprint = hex.EncodeToString(h.Sum(nil))[:16]
	return d
}

// classID renders a class minor as tc does: "1:2a0".
func classID(minor uint16) string { return "1:" + strconv.FormatUint(uint64(minor), 16) }

func minI(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func uniqPrefixes(in []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, p := range in {
		p = p.Masked()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}
