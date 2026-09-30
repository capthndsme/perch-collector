package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// Part names one kind of observation: the key under `observe` in a push,
// and "observe.<part>" in the hello's capabilities.
type Part string

// The parts (gateway plan 2 section 3).
const (
	PartDHCP       Part = "dhcp"
	PartNeighbors  Part = "neighbors"
	PartInterfaces Part = "interfaces"
	PartUPnP       Part = "upnp"
	PartMWAN3      Part = "mwan3"
	PartResolver   Part = "resolver"
	PartSystem     Part = "system"
	// PartWireGuard and PartDDNS: gateway-sync protocol 6.1.
	PartWireGuard Part = "wireguard"
	PartDDNS      Part = "ddns"
)

// AllParts in wire order.
var AllParts = []Part{PartDHCP, PartNeighbors, PartInterfaces, PartUPnP, PartMWAN3, PartResolver, PartSystem, PartWireGuard, PartDDNS}

// ParsePart reads a part name; ok is false for an unknown one.
func ParsePart(s string) (Part, bool) {
	for _, p := range AllParts {
		if string(p) == s {
			return p, true
		}
	}
	return "", false
}

// Capability is the hello capability announcing a part.
func (p Part) Capability() string { return "observe." + string(p) }

// Section is the `observe` object of a push, of GET /api/v1/summary and
// the result of the gateway.observe request: one optional key per part. An
// absent part is not reported (the controller keeps what it has); a
// present one is a full snapshot of that part and replaces it.
type Section struct {
	// CollectedAt is set on the gateway.observe result (a push has its own).
	CollectedAt string `json:"collectedAt,omitempty"`
	// Full: every part the collector reports is present.
	Full bool `json:"full,omitempty"`

	DHCP       *DHCP        `json:"dhcp,omitempty"`
	Neighbors  *[]Neighbor  `json:"neighbors,omitempty"`
	Interfaces *[]Interface `json:"interfaces,omitempty"`
	UPnP       *UPnP        `json:"upnp,omitempty"`
	MWAN3      *MWAN3       `json:"mwan3,omitempty"`
	Resolver   *Resolver    `json:"resolver,omitempty"`
	System     *System      `json:"system,omitempty"`
	WireGuard  *WireGuard   `json:"wireguard,omitempty"`
	DDNS       *DDNS        `json:"ddns,omitempty"`
}

// Set puts a part's value (as returned by Observer.Read) in the section.
func (s *Section) Set(p Part, v any) {
	switch p {
	case PartDHCP:
		s.DHCP, _ = v.(*DHCP)
	case PartNeighbors:
		if l, ok := v.([]Neighbor); ok {
			s.Neighbors = &l
		}
	case PartInterfaces:
		if l, ok := v.([]Interface); ok {
			s.Interfaces = &l
		}
	case PartUPnP:
		s.UPnP, _ = v.(*UPnP)
	case PartMWAN3:
		s.MWAN3, _ = v.(*MWAN3)
	case PartResolver:
		s.Resolver, _ = v.(*Resolver)
	case PartSystem:
		s.System, _ = v.(*System)
	case PartWireGuard:
		s.WireGuard, _ = v.(*WireGuard)
	case PartDDNS:
		s.DDNS, _ = v.(*DDNS)
	}
}

// Empty reports whether no part is set.
func (s *Section) Empty() bool {
	return s.DHCP == nil && s.Neighbors == nil && s.Interfaces == nil && s.UPnP == nil && s.MWAN3 == nil &&
		s.Resolver == nil && s.System == nil && s.WireGuard == nil && s.DDNS == nil
}

// Item is one part's value and its fingerprint (hex SHA-256 of its JSON,
// counters that tick every second, such as uptimes, left out).
type Item struct {
	Value any
	FP    string
}

// Default re-read intervals: a part is read from the system at most this
// often; between those Read answers from its cache.
var defaultEvery = map[Part]time.Duration{
	PartDHCP:       0, // the reader watches its files itself
	PartNeighbors:  60 * time.Second,
	PartInterfaces: 5 * time.Second,
	PartUPnP:       15 * time.Second,
	PartMWAN3:      15 * time.Second,
	PartResolver:   60 * time.Second,
	PartSystem:     60 * time.Second,
	PartWireGuard:  30 * time.Second,
	PartDDNS:       60 * time.Second,
}

// Observer reads every enabled part. A nil reader = the part is off.
type Observer struct {
	DHCP       *Reader
	Neighbors  *NeighborReader
	Interfaces *InterfaceReader
	UPnP       *UPnPReader
	MWAN3      *MWAN3Reader
	Resolver   *ResolverReader
	System     *SystemReader
	WireGuard  *WireGuardReader
	DDNS       *DDNSReader
	// Every overrides the re-read interval per part (tests).
	Every map[Part]time.Duration
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time

	mu    sync.Mutex
	cache map[Part]cached
}

type cached struct {
	at   time.Time
	item Item
	ok   bool
}

// NewObserver builds an observer over env with the given parts on, the
// interfaces reader shared by the DHCP and neighbour readers for tagging.
// controllerHost is the controller URL's host, for the resolver part.
func NewObserver(env *Env, parts map[Part]bool, controllerHost string) *Observer {
	o := &Observer{}
	ifaces := &InterfaceReader{Env: env}
	if parts[PartInterfaces] {
		o.Interfaces = ifaces
	}
	if parts[PartDHCP] {
		o.DHCP = &Reader{Root: env.Root, Run: env.Run, Now: env.Now, Networks: ifaces.Subnets}
	}
	if parts[PartNeighbors] {
		o.Neighbors = &NeighborReader{Env: env, Networks: ifaces.Subnets}
	}
	if parts[PartUPnP] {
		o.UPnP = &UPnPReader{Env: env}
	}
	if parts[PartMWAN3] {
		o.MWAN3 = &MWAN3Reader{Env: env}
	}
	if parts[PartResolver] {
		o.Resolver = &ResolverReader{Env: env, ControllerHost: controllerHost}
	}
	if parts[PartSystem] {
		o.System = &SystemReader{Env: env}
	}
	if parts[PartWireGuard] {
		o.WireGuard = &WireGuardReader{Env: env}
	}
	if parts[PartDDNS] {
		o.DDNS = &DDNSReader{Env: env}
	}
	return o
}

// Parts are the parts this observer reports, in wire order.
func (o *Observer) Parts() []Part {
	if o == nil {
		return nil
	}
	var out []Part
	for _, p := range AllParts {
		if o.has(p) {
			out = append(out, p)
		}
	}
	return out
}

func (o *Observer) has(p Part) bool {
	switch p {
	case PartDHCP:
		return o.DHCP != nil
	case PartNeighbors:
		return o.Neighbors != nil
	case PartInterfaces:
		return o.Interfaces != nil
	case PartUPnP:
		return o.UPnP != nil
	case PartMWAN3:
		return o.MWAN3 != nil
	case PartResolver:
		return o.Resolver != nil
	case PartSystem:
		return o.System != nil
	case PartWireGuard:
		return o.WireGuard != nil
	case PartDDNS:
		return o.DDNS != nil
	}
	return false
}

func (o *Observer) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Read returns a part; ok is false when the part is off or has nothing to
// report (mwan3 not installed, no ubus). fresh skips the re-read interval.
func (o *Observer) Read(p Part, fresh bool) (Item, bool) {
	if o == nil || !o.has(p) {
		return Item{}, false
	}
	every, set := o.Every[p]
	if !set {
		every = defaultEvery[p]
	}
	now := o.now()
	o.mu.Lock()
	if o.cache == nil {
		o.cache = map[Part]cached{}
	}
	c, hit := o.cache[p]
	o.mu.Unlock()
	if hit && !fresh && every > 0 && now.Sub(c.at) < every {
		return c.item, c.ok
	}
	item, ok := o.read(p)
	o.mu.Lock()
	o.cache[p] = cached{at: now, item: item, ok: ok}
	o.mu.Unlock()
	return item, ok
}

func (o *Observer) read(p Part) (Item, bool) {
	switch p {
	case PartDHCP:
		d, fp := o.DHCP.Read()
		if d == nil {
			return Item{}, false
		}
		return Item{Value: d, FP: fp}, true
	case PartNeighbors:
		l, err := o.Neighbors.Read()
		if err != nil {
			return Item{}, false
		}
		return Item{Value: l, FP: Fingerprint(l)}, true
	case PartInterfaces:
		l, ok := o.Interfaces.Read()
		if !ok {
			return Item{}, false
		}
		stable := make([]Interface, len(l))
		for i, it := range l {
			it.UptimeSeconds = 0
			it.IPv6Prefixes = append([]IPv6Prefix(nil), it.IPv6Prefixes...)
			for j := range it.IPv6Prefixes {
				it.IPv6Prefixes[j].PreferredUntil, it.IPv6Prefixes[j].ValidUntil = nil, nil
			}
			stable[i] = it
		}
		return Item{Value: l, FP: Fingerprint(stable)}, true
	case PartUPnP:
		u := o.UPnP.Read()
		return Item{Value: u, FP: Fingerprint(u)}, true
	case PartMWAN3:
		m := o.MWAN3.Read()
		if m == nil {
			return Item{}, false
		}
		stable := *m
		stable.Interfaces = make([]MWAN3Interface, len(m.Interfaces))
		for i, it := range m.Interfaces {
			it.UptimeSeconds = 0
			stable.Interfaces[i] = it
		}
		return Item{Value: m, FP: Fingerprint(stable)}, true
	case PartResolver:
		r := o.Resolver.Read()
		return Item{Value: r, FP: Fingerprint(r)}, true
	case PartSystem:
		s := o.System.Read()
		if s == nil {
			return Item{}, false
		}
		stable := *s
		stable.UptimeSeconds = 0
		return Item{Value: s, FP: Fingerprint(stable)}, true
	case PartWireGuard:
		w := o.WireGuard.Read()
		if w == nil {
			return Item{}, false
		}
		return Item{Value: w, FP: Fingerprint(wgStable(w))}, true
	case PartDDNS:
		d := o.DDNS.Read()
		if d == nil {
			return Item{}, false
		}
		return Item{Value: d, FP: Fingerprint(d)}, true
	}
	return Item{}, false
}

// Section reads the given parts (nil = all) fresh, for the gateway.observe
// request and the local API.
func (o *Observer) Section(parts []Part, fresh bool) *Section {
	s := &Section{}
	if parts == nil {
		parts = o.Parts()
	}
	all := true
	for _, p := range o.Parts() {
		want := false
		for _, q := range parts {
			if q == p {
				want = true
			}
		}
		if !want {
			all = false
			continue
		}
		if item, ok := o.Read(p, fresh); ok {
			s.Set(p, item.Value)
		}
	}
	s.Full = all
	return s
}

// Fingerprint is the hex SHA-256 of v's JSON.
func Fingerprint(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Pacer decides which parts ride in a push (plan 2 section 3): a part is
// sent in the first push of a session, when its fingerprint changed (but
// not sooner than its MinGap after the last send), and every Refresh.
type Pacer struct {
	// Refresh resends an unchanged part; 0 = DefaultRefresh.
	Refresh time.Duration
	// RefreshOf overrides Refresh per part (dhcp_leases_refresh).
	RefreshOf map[Part]time.Duration
	// MinGap between two sends of a changed part (neighbors: 60 s).
	MinGap map[Part]time.Duration

	mu    sync.Mutex
	state map[Part]sent
}

// DefaultRefresh is the full resend interval.
const DefaultRefresh = 10 * time.Minute

// DefaultMinGap are the parts that change often by nature.
var DefaultMinGap = map[Part]time.Duration{PartNeighbors: 60 * time.Second}

type sent struct {
	gen uint64
	fp  string
	at  time.Time
}

// Due reports whether part (fingerprint fp) goes into a push of session gen.
func (p *Pacer) Due(gen uint64, part Part, fp string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.state[part]
	if !ok || s.gen != gen {
		return true
	}
	refresh := p.Refresh
	if r, ok := p.RefreshOf[part]; ok && r > 0 {
		refresh = r
	}
	if refresh <= 0 {
		refresh = DefaultRefresh
	}
	if now.Sub(s.at) >= refresh {
		return true
	}
	if s.fp == fp {
		return false
	}
	gap, ok := p.MinGap[part]
	if !ok {
		gap = DefaultMinGap[part]
	}
	return now.Sub(s.at) >= gap
}

// Sent records that part went out in a push of session gen.
func (p *Pacer) Sent(gen uint64, part Part, fp string, now time.Time) {
	p.mu.Lock()
	if p.state == nil {
		p.state = map[Part]sent{}
	}
	p.state[part] = sent{gen: gen, fp: fp, at: now}
	p.mu.Unlock()
}
