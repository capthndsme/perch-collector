package qos

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Class id scheme (plan 3 section 3.2, docs/gateway/qos.md section 3.1).
const (
	// RootMinor is the HTB root class 1:1 under the ifb's root qdisc 1:.
	RootMinor = 0x1
	// BucketMinorMin/Max bound the bucket classes (assigned by the controller).
	BucketMinorMin = 0x02
	BucketMinorMax = 0xff
	// RestLeafBase | bucket minor is the bucket's rest leaf.
	RestLeafBase = 0x100
	// DeviceMinorMin/Max bound the classes this agent allocates.
	DeviceMinorMin = 0x200
	DeviceMinorMax = 0xfffe
	// MaxBucketDepth is HTB's 8 levels minus the root class and the leaves
	// (amendment 2026-09-23 section 5).
	MaxBucketDepth = 4
	// MaxDeviceEntries bounds qos.devices.set.
	MaxDeviceEntries = 4096
)

// Rate is a pair of caps in kbit/s; 0 = unlimited that way.
type Rate struct {
	Down int64 `json:"downKbit"`
	Up   int64 `json:"upKbit"`
}

// get returns the rate of one direction.
func (r Rate) get(d Dir) int64 {
	if d == Down {
		return r.Down
	}
	return r.Up
}

// Config is /etc/config/perch-qos as the controller's planner renders it
// (metrics-be docs/gateway/qos.md section 3.5).
type Config struct {
	// Present is false when the file does not exist.
	Present bool
	// Enabled is globals.enabled; '0' is the router's local pause.
	Enabled bool
	// Revision is globals.revision (set by the config plane), "" without one.
	Revision string

	MinWanKbit     int64
	MinDeviceKbit  int64
	LeafFlows      int
	LeafLimit      int
	LeafMemoryKB   int
	RestMemlimitKB int
	DynamicIdle    time.Duration
	DynamicLimit   int
	// Exempt are the extra never-shaped prefixes (list exempt).
	Exempt []netip.Prefix

	// Buckets, parents before children.
	Buckets   []*Bucket
	Networks  []*NetworkDefault
	Schedules []*Schedule

	// Errors make the whole config unusable: the agent keeps what the
	// kernel has and reports them. Warnings are reported only.
	Errors   []Issue
	Warnings []Issue

	bucketByName   map[string]*Bucket
	scheduleByName map[string]*Schedule
}

// Issue is a problem found in the config or the device set.
type Issue struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (i Issue) String() string { return i.Code + ": " + i.Detail }

// Bucket is a `config bucket` section: a shared HTB class with a rest leaf.
type Bucket struct {
	Name       string
	Policy     string
	Minor      uint16
	Parent     string // "" = under the root class
	Rate       Rate
	Fairness   string // per_host | per_flow
	IncludeLan bool
	Schedules  []string
	Depth      int
}

// NetworkDefault is a `config network` section: what MACs without an entry
// get on that network.
type NetworkDefault struct {
	Name       string // UCI interface
	Policy     string
	Bucket     string // "" = none
	Each       *Rate  // nil = no dynamic per-MAC leaves
	IncludeLan bool
	Schedules  []string
}

// Schedule is a `config schedule` section, evaluated on the router's clock.
type Schedule struct {
	Name       string
	Windows    []Window
	Policy     string
	Assignment string
	// Action: limit | unlimited | block | move.
	Action string
	// Bucket is the bucket of a move ("" = none).
	Bucket string
	// Down/Up override a bucket's rates; EachDown/EachUp a member's caps.
	// nil = keep the target's own value (for move: no cap).
	Down, Up, EachDown, EachUp *int64
}

// Config defaults (metrics-be qos_settings.ts).
const (
	defaultMinWanKbit     = 1000
	defaultMinDeviceKbit  = 64
	defaultLeafFlows      = 64
	defaultLeafLimit      = 1000
	defaultLeafMemoryKB   = 1024
	defaultRestMemlimitKB = 4096
	defaultDynamicIdle    = 1800
	defaultDynamicLimit   = 1024
)

// DefaultConfig is a present, enabled config with nothing to shape.
func DefaultConfig() *Config {
	c := &Config{
		Present:        true,
		Enabled:        true,
		MinWanKbit:     defaultMinWanKbit,
		MinDeviceKbit:  defaultMinDeviceKbit,
		LeafFlows:      defaultLeafFlows,
		LeafLimit:      defaultLeafLimit,
		LeafMemoryKB:   defaultLeafMemoryKB,
		RestMemlimitKB: defaultRestMemlimitKB,
		DynamicIdle:    defaultDynamicIdle * time.Second,
		DynamicLimit:   defaultDynamicLimit,
	}
	c.index()
	return c
}

func (c *Config) index() {
	c.bucketByName = map[string]*Bucket{}
	for _, b := range c.Buckets {
		c.bucketByName[b.Name] = b
	}
	c.scheduleByName = map[string]*Schedule{}
	for _, s := range c.Schedules {
		c.scheduleByName[s.Name] = s
	}
}

// Bucket returns the named bucket, nil when there is none.
func (c *Config) Bucket(name string) *Bucket { return c.bucketByName[name] }

// Schedule returns the named schedule, nil when there is none.
func (c *Config) Schedule(name string) *Schedule { return c.scheduleByName[name] }

// Valid reports whether the config can be rendered.
func (c *Config) Valid() bool { return len(c.Errors) == 0 }

// ParseConfig reads /etc/config/perch-qos. It never fails: whatever is
// wrong is listed in Errors (the config is then not applied) or Warnings.
func ParseConfig(data []byte) *Config {
	c := DefaultConfig()
	sections, err := parseUCIFile(data)
	if err != nil {
		c.Errors = append(c.Errors, Issue{"config_syntax", err.Error()})
		return c
	}
	errf := func(code, format string, a ...any) {
		c.Errors = append(c.Errors, Issue{code, fmt.Sprintf(format, a...)})
	}
	warnf := func(code, format string, a ...any) {
		c.Warnings = append(c.Warnings, Issue{code, fmt.Sprintf(format, a...)})
	}
	c.Buckets, c.Networks, c.Schedules = nil, nil, nil
	seen := map[string]bool{}
	for _, s := range sections {
		if s.Type != "globals" && s.Name == "" {
			warnf("config_anonymous", "an anonymous %s section is ignored", s.Type)
			continue
		}
		if s.Name != "" {
			key := s.Type + "/" + s.Name
			if seen[key] {
				errf("config_duplicate", "%s %q is defined twice", s.Type, s.Name)
				continue
			}
			seen[key] = true
		}
		switch s.Type {
		case "globals":
			parseGlobals(c, s, errf, warnf)
		case "bucket":
			if b := parseBucket(s, errf); b != nil {
				c.Buckets = append(c.Buckets, b)
			}
		case "network":
			if n := parseNetwork(s, errf); n != nil {
				c.Networks = append(c.Networks, n)
			}
		case "schedule":
			if sc := parseSchedule(s, errf); sc != nil {
				c.Schedules = append(c.Schedules, sc)
			}
		default:
			warnf("config_unknown_section", "section type %q is not known to this agent", s.Type)
		}
	}
	c.index()
	validateBuckets(c, errf)
	for _, n := range c.Networks {
		if n.Bucket != "" && c.Bucket(n.Bucket) == nil {
			errf("config_unknown_bucket", "network %s names bucket %q, which does not exist", n.Name, n.Bucket)
		}
		for _, name := range n.Schedules {
			if c.Schedule(name) == nil {
				warnf("config_unknown_schedule", "network %s lists schedule %q, which does not exist", n.Name, name)
			}
		}
	}
	for _, b := range c.Buckets {
		for _, name := range b.Schedules {
			if c.Schedule(name) == nil {
				warnf("config_unknown_schedule", "bucket %s lists schedule %q, which does not exist", b.Name, name)
			}
		}
	}
	for _, s := range c.Schedules {
		if s.Action == "move" && s.Bucket != "" && c.Bucket(s.Bucket) == nil {
			errf("config_unknown_bucket", "schedule %s moves to bucket %q, which does not exist", s.Name, s.Bucket)
		}
	}
	return c
}

func parseGlobals(c *Config, s *uciSection, errf, warnf func(string, string, ...any)) {
	if v, ok := s.first("enabled"); ok {
		c.Enabled = uciBool(v, true)
	}
	c.Revision, _ = s.first("revision")
	intOpt := func(name string, dst *int64, min, max int64) {
		v, ok := s.first(name)
		if !ok || v == "" {
			return
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < min || n > max {
			warnf("config_bad_value", "globals.%s %q is not a number in %d-%d; the default stays", name, v, min, max)
			return
		}
		*dst = n
	}
	var flows, limit, mem, rest, idle, dynLimit int64 = int64(c.LeafFlows), int64(c.LeafLimit), int64(c.LeafMemoryKB), int64(c.RestMemlimitKB), int64(c.DynamicIdle / time.Second), int64(c.DynamicLimit)
	intOpt("min_wan_kbit", &c.MinWanKbit, 8, 100_000_000)
	intOpt("min_device_kbit", &c.MinDeviceKbit, 8, 100_000_000)
	intOpt("leaf_flows", &flows, 1, 65535)
	intOpt("leaf_limit", &limit, 16, 1_000_000)
	intOpt("leaf_memory_kb", &mem, 16, 1<<21)
	intOpt("rest_memlimit_kb", &rest, 64, 1<<21)
	intOpt("dynamic_idle", &idle, 10, 7*86400)
	intOpt("dynamic_limit", &dynLimit, 0, DeviceMinorMax-DeviceMinorMin)
	c.LeafFlows, c.LeafLimit, c.LeafMemoryKB, c.RestMemlimitKB = int(flows), int(limit), int(mem), int(rest)
	c.DynamicIdle, c.DynamicLimit = time.Duration(idle)*time.Second, int(dynLimit)
	for _, v := range s.Options["exempt"] {
		for _, w := range strings.Fields(v) {
			p, err := netip.ParsePrefix(w)
			if err != nil {
				// A bare address is a one-address prefix.
				if a, aerr := netip.ParseAddr(w); aerr == nil {
					p = netip.PrefixFrom(a, a.BitLen())
				} else {
					errf("config_bad_prefix", "globals.exempt %q is not an address prefix", w)
					continue
				}
			}
			c.Exempt = append(c.Exempt, p.Masked())
		}
	}
}

func parseBucket(s *uciSection, errf func(string, string, ...any)) *Bucket {
	b := &Bucket{Name: s.Name, Fairness: "per_host"}
	b.Policy, _ = s.first("policy")
	cls, _ := s.first("class")
	minor, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(cls), "0x"), 16, 16)
	if err != nil || !strings.HasPrefix(strings.ToLower(cls), "0x") || minor < BucketMinorMin || minor > BucketMinorMax {
		errf("config_bad_class", "bucket %s: class %q is not 0x02-0xff", s.Name, cls)
		return nil
	}
	b.Minor = uint16(minor)
	b.Parent, _ = s.first("parent")
	var ok bool
	if b.Rate.Down, ok = kbitOption(s, "down_kbit", 0); !ok {
		errf("config_bad_rate", "bucket %s: down_kbit is not a number", s.Name)
		return nil
	}
	if b.Rate.Up, ok = kbitOption(s, "up_kbit", 0); !ok {
		errf("config_bad_rate", "bucket %s: up_kbit is not a number", s.Name)
		return nil
	}
	if f, _ := s.first("fairness"); f != "" {
		if f != "per_host" && f != "per_flow" {
			errf("config_bad_value", "bucket %s: fairness %q is not per_host or per_flow", s.Name, f)
			return nil
		}
		b.Fairness = f
	}
	v, _ := s.first("include_lan")
	b.IncludeLan = uciBool(v, false)
	b.Schedules = listOption(s, "schedule")
	return b
}

func parseNetwork(s *uciSection, errf func(string, string, ...any)) *NetworkDefault {
	n := &NetworkDefault{Name: s.Name}
	n.Policy, _ = s.first("policy")
	n.Bucket, _ = s.first("bucket")
	d, dset := s.first("each_down_kbit")
	u, uset := s.first("each_up_kbit")
	if (dset && d != "") || (uset && u != "") {
		down, ok1 := kbitOption(s, "each_down_kbit", 0)
		up, ok2 := kbitOption(s, "each_up_kbit", 0)
		if !ok1 || !ok2 {
			errf("config_bad_rate", "network %s: each_down_kbit / each_up_kbit is not a number", s.Name)
			return nil
		}
		n.Each = &Rate{Down: down, Up: up}
	}
	v, _ := s.first("include_lan")
	n.IncludeLan = uciBool(v, false)
	n.Schedules = listOption(s, "schedule")
	return n
}

func parseSchedule(s *uciSection, errf func(string, string, ...any)) *Schedule {
	sc := &Schedule{Name: s.Name}
	for _, w := range s.Options["window"] {
		win, err := ParseWindow(w)
		if err != nil {
			errf("config_bad_window", "schedule %s: %v", s.Name, err)
			return nil
		}
		sc.Windows = append(sc.Windows, win)
	}
	if len(sc.Windows) == 0 {
		errf("config_bad_window", "schedule %s has no window", s.Name)
		return nil
	}
	sc.Policy, _ = s.first("policy")
	sc.Assignment, _ = s.first("assignment")
	sc.Action, _ = s.first("action")
	switch sc.Action {
	case "limit", "unlimited", "block", "move":
	case "":
		sc.Action = "limit"
	default:
		errf("config_bad_value", "schedule %s: action %q is not limit, unlimited, block or move", s.Name, sc.Action)
		return nil
	}
	sc.Bucket, _ = s.first("bucket")
	for _, o := range []struct {
		name string
		dst  **int64
	}{{"down_kbit", &sc.Down}, {"up_kbit", &sc.Up}, {"each_down_kbit", &sc.EachDown}, {"each_up_kbit", &sc.EachUp}} {
		v, _ := s.first(o.name)
		if v == "" {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			errf("config_bad_rate", "schedule %s: %s %q is not a number", s.Name, o.name, v)
			return nil
		}
		*o.dst = &n
	}
	return sc
}

// validateBuckets checks the tree (amendment section 5): parents exist, no
// cycles, depth ≤ 4, a child's ceiling within its parent's, and the
// children's rates within the parent's rate. It orders Buckets parents first.
func validateBuckets(c *Config, errf func(string, string, ...any)) {
	minors := map[uint16]string{}
	for _, b := range c.Buckets {
		if other, dup := minors[b.Minor]; dup {
			errf("config_duplicate_class", "buckets %s and %s share class 0x%x", other, b.Name, b.Minor)
		}
		minors[b.Minor] = b.Name
	}
	depth := map[string]int{}
	var depthOf func(b *Bucket, trail map[string]bool) int
	depthOf = func(b *Bucket, trail map[string]bool) int {
		if d, ok := depth[b.Name]; ok {
			return d
		}
		if b.Parent == "" {
			depth[b.Name] = 1
			return 1
		}
		p := c.Bucket(b.Parent)
		if p == nil {
			errf("config_unknown_bucket", "bucket %s: parent %q does not exist", b.Name, b.Parent)
			depth[b.Name] = 1
			return 1
		}
		if trail[b.Name] {
			errf("config_bucket_cycle", "bucket %s: its parents form a cycle", b.Name)
			depth[b.Name] = MaxBucketDepth + 1
			return depth[b.Name]
		}
		trail[b.Name] = true
		d := depthOf(p, trail) + 1
		depth[b.Name] = d
		return d
	}
	for _, b := range c.Buckets {
		b.Depth = depthOf(b, map[string]bool{})
		if b.Depth > MaxBucketDepth {
			errf("config_bucket_too_deep", "bucket %s is nested %d deep; the limit is %d", b.Name, b.Depth, MaxBucketDepth)
		}
	}
	for _, b := range c.Buckets {
		p := c.Bucket(b.Parent)
		if p == nil {
			continue
		}
		for _, d := range []Dir{Down, Up} {
			pc, cc := p.Rate.get(d), b.Rate.get(d)
			if pc > 0 && (cc == 0 || cc > pc) {
				errf("config_child_exceeds_parent", "bucket %s allows more %s than its parent %s", b.Name, d, p.Name)
			}
		}
	}
	for _, p := range c.Buckets {
		for _, d := range []Dir{Down, Up} {
			pr := p.Rate.get(d)
			if pr == 0 {
				continue
			}
			var sum int64
			for _, b := range c.Buckets {
				if b.Parent == p.Name {
					sum += b.Rate.get(d)
				}
			}
			if sum > pr {
				errf("config_children_exceed_parent", "the buckets inside %s add up to %d kbit/s %s, more than its %d", p.Name, sum, d, pr)
			}
		}
	}
	sort.SliceStable(c.Buckets, func(i, j int) bool {
		if c.Buckets[i].Depth != c.Buckets[j].Depth {
			return c.Buckets[i].Depth < c.Buckets[j].Depth
		}
		return c.Buckets[i].Minor < c.Buckets[j].Minor
	})
}

func kbitOption(s *uciSection, name string, def int64) (int64, bool) {
	v, _ := s.first(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func listOption(s *uciSection, name string) []string {
	var out []string
	for _, v := range s.Options[name] {
		out = append(out, strings.Fields(v)...)
	}
	return out
}

func uciBool(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "on", "true", "enabled":
		return true
	case "0", "no", "off", "false", "disabled":
		return false
	}
	return def
}
