package qos

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Batch is what one reconcile does: the ifbs to create or remove (links,
// done over rtnetlink) and the `tc -batch` lines, in order.
type Batch struct {
	CreateIfbs bool
	DeleteIfbs bool
	Lines      []string
}

// Empty reports whether the batch changes nothing.
func (b Batch) Empty() bool { return !b.CreateIfbs && !b.DeleteIfbs && len(b.Lines) == 0 }

// Text is the batch file (one tc command per line).
func (b Batch) Text() string {
	if len(b.Lines) == 0 {
		return ""
	}
	return strings.Join(b.Lines, "\n") + "\n"
}

// Render is the full batch for d on an empty kernel (the golden files, and
// `perch-collector qos render -full`).
func Render(d *Desired) Batch {
	return Diff(d, &Kernel{Devs: map[string]*DevState{}}, nil)
}

// Diff turns the gap between the desired and the kernel's objects into a
// batch. Rates and memberships change in place (`class change`, `filter
// replace`: hitless); a class that has to move to another parent is deleted
// with its subtree and added again; obsolete objects go last. extraDevs are
// devices that may still carry Perch filters (a LAN that is gone or no
// longer shaped).
func Diff(d *Desired, k *Kernel, extraDevs []string) Batch {
	var b Batch
	emit := func(format string, a ...any) { b.Lines = append(b.Lines, fmt.Sprintf(format, a...)) }

	shaped := map[string]bool{}
	if d.Active {
		for dev := range d.Filters {
			shaped[dev] = true
		}
	}
	// Devices that carry our filters but should not.
	var strip []string
	seenDev := map[string]bool{}
	for _, dev := range append(sortedKeys(k.Devs), extraDevs...) {
		if seenDev[dev] || shaped[dev] {
			continue
		}
		seenDev[dev] = true
		if ds := k.Devs[dev]; ds != nil && ds.Clsact && hasOurFilters(ds) {
			strip = append(strip, dev)
		}
	}

	if !d.Active {
		for _, dev := range strip {
			stripDevice(k.Devs[dev], dev, emit)
		}
		if k.Ifb[Down] != nil || k.Ifb[Up] != nil {
			b.DeleteIfbs = true
		}
		return b
	}
	if k.Ifb[Down] == nil || k.Ifb[Up] == nil {
		b.CreateIfbs = true
	}

	c := d.Config
	desired := map[uint16]DClass{}
	for _, cl := range d.Classes {
		desired[cl.Minor] = cl
	}

	var late []string // deletes of obsolete classes, run after the filters
	for _, dir := range dirs {
		ifb := dir.Ifb()
		ks := k.Ifb[dir]
		if ks == nil || ks.RootKind != "htb" || ks.RootHandle != "1:" {
			emit("qdisc replace dev %s root handle 1: htb default 0 r2q 10", ifb)
			ks = &IfbState{Classes: map[uint16]*KClass{}, Qdiscs: map[string]*KQdisc{}}
		}
		root := ks.Classes[RootMinor]
		rootLine := htbArgs(HTBRate{RootKbit, RootKbit})
		switch {
		case root == nil:
			emit("class add dev %s parent 1: classid 1:1 htb %s", ifb, rootLine)
		case root.Parent != 0 || !rateMatches(root, HTBRate{RootKbit, RootKbit}):
			emit("class change dev %s parent 1: classid 1:1 htb %s", ifb, rootLine)
		}

		// Classes to take out before adding: those whose parent changed,
		// with everything below them.
		children := map[uint16][]uint16{}
		for m, kc := range ks.Classes {
			children[kc.Parent] = append(children[kc.Parent], m)
		}
		removed := map[uint16]bool{}
		var collect func(m uint16)
		collect = func(m uint16) {
			if removed[m] {
				return
			}
			removed[m] = true
			for _, ch := range children[m] {
				collect(ch)
			}
		}
		for m, kc := range ks.Classes {
			if m == RootMinor {
				continue
			}
			if want, ok := desired[m]; ok && want.Parent != kc.Parent {
				collect(m)
			}
		}
		early := orderDeepestFirst(removed, ks)
		for _, m := range early {
			emit("class del dev %s classid 1:%x", ifb, m)
		}
		// Adds and changes, parents first (d.Classes is in that order).
		for _, cl := range d.Classes {
			kc := ks.Classes[cl.Minor]
			if kc == nil || removed[cl.Minor] {
				emit("class add dev %s parent 1:%x classid 1:%x htb %s", ifb, cl.Parent, cl.Minor, htbArgs(cl.Rate[dir]))
				if cl.Leaf != LeafNone {
					emit("qdisc add dev %s parent 1:%x handle %x: %s", ifb, cl.Minor, cl.Minor, leafArgs(cl, dir, c))
				}
				continue
			}
			if !rateMatches(kc, cl.Rate[dir]) {
				emit("class change dev %s parent 1:%x classid 1:%x htb %s", ifb, cl.Parent, cl.Minor, htbArgs(cl.Rate[dir]))
			}
			if cl.Leaf == LeafNone {
				continue
			}
			want := fmt.Sprintf("%x:", cl.Minor)
			kq := ks.Qdiscs[kc.Leaf]
			switch {
			case kc.Leaf != want || kq == nil || kq.Kind != cl.Leaf || !leafFixedMatches(kq, cl, c):
				if kc.Leaf != "" && kq != nil && kq.Kind != "pfifo" {
					emit("qdisc del dev %s parent 1:%x", ifb, cl.Minor)
				}
				emit("qdisc add dev %s parent 1:%x handle %x: %s", ifb, cl.Minor, cl.Minor, leafArgs(cl, dir, c))
			case !leafMatches(kq, cl, dir, c):
				emit("qdisc change dev %s parent 1:%x handle %x: %s", ifb, cl.Minor, cl.Minor, strings.Replace(leafArgs(cl, dir, c), fmt.Sprintf(" flows %d", leafFlows(cl, c)), "", 1))
			}
		}
		// Obsolete classes: after the filters stopped pointing at them.
		obsolete := map[uint16]bool{}
		for m := range ks.Classes {
			if _, ok := desired[m]; !ok && m != RootMinor && !removed[m] {
				obsolete[m] = true
			}
		}
		for _, m := range orderDeepestFirst(obsolete, ks) {
			late = append(late, fmt.Sprintf("class del dev %s classid 1:%x", ifb, m))
		}
	}

	// Filters, per shaped device.
	for _, dev := range sortedKeys(d.Filters) {
		ds := k.Devs[dev]
		if ds != nil && ds.Ingress {
			continue // sqm's ingress qdisc: the planner reports the conflict
		}
		if ds == nil || !ds.Clsact {
			emit("qdisc add dev %s clsact", dev)
			ds = &DevState{Clsact: true}
		}
		have := map[string]KFilter{}
		protoAt := map[string]string{} // "hook/chain/pref" → protocol in the kernel
		for _, f := range ds.Filters {
			have[f.Key()] = f
			protoAt[fmt.Sprintf("%s/%d/%d", f.Hook, f.Chain, f.Pref)] = f.Proto + "/" + f.Kind
		}
		want := map[string]bool{}
		cleared := map[string]bool{}
		for _, f := range d.Filters[dev] {
			want[f.Key()] = true
			slot := fmt.Sprintf("%s/%d/%d", f.Hook, f.Chain, f.Pref)
			if p, ok := protoAt[slot]; ok && p != f.Proto+"/flower" && !cleared[slot] {
				// Another protocol or classifier holds this priority (a
				// hand-made filter): clear it.
				emit("filter del dev %s %s%s pref %d", dev, f.Hook, chainArg(f.Chain), f.Pref)
				cleared[slot] = true
				for key, kf := range have {
					if fmt.Sprintf("%s/%d/%d", kf.Hook, kf.Chain, kf.Pref) == slot {
						delete(have, key)
					}
				}
			}
			kf, ok := have[f.Key()]
			wantAct := kernelAction(f)
			switch {
			case !ok:
				emit("filter add dev %s %s", dev, filterArgs(f))
			case kf.Match != f.Match || kf.Action != wantAct:
				emit("filter replace dev %s %s", dev, filterArgs(f))
			}
		}
		var stale []KFilter
		for key, kf := range have {
			if !want[key] && ourPrefs[kf.Pref] {
				stale = append(stale, kf)
			}
		}
		sort.Slice(stale, func(i, j int) bool { return stale[i].Key() < stale[j].Key() })
		for _, kf := range stale {
			emit("filter del dev %s %s%s pref %d protocol %s handle %d %s", dev, kf.Hook, chainArg(kf.Chain), kf.Pref, kf.Proto, kf.Handle, kf.Kind)
		}
	}
	for _, dev := range strip {
		stripDevice(k.Devs[dev], dev, emit)
	}
	b.Lines = append(b.Lines, late...)
	return b
}

// kernelAction is how the kernel reader renders the planner's action.
func kernelAction(f DFilter) string {
	if strings.HasPrefix(f.Action, "class:") {
		ifb := IfbDown
		if f.Hook == "ingress" {
			ifb = IfbUp
		}
		return f.Action + "@" + ifb
	}
	return f.Action
}

func hasOurFilters(ds *DevState) bool {
	for _, f := range ds.Filters {
		if ourPrefs[f.Pref] {
			return true
		}
	}
	return false
}

// stripDevice removes Perch's filters from a device: the whole clsact when
// nothing else uses it, else Perch's priorities one by one.
func stripDevice(ds *DevState, dev string, emit func(string, ...any)) {
	foreign := false
	for _, f := range ds.Filters {
		if !ourPrefs[f.Pref] {
			foreign = true
		}
	}
	if !foreign {
		emit("qdisc del dev %s clsact", dev)
		return
	}
	done := map[string]bool{}
	for _, f := range ds.Filters {
		slot := fmt.Sprintf("%s%s pref %d", f.Hook, chainArg(f.Chain), f.Pref)
		if ourPrefs[f.Pref] && !done[slot] {
			done[slot] = true
			emit("filter del dev %s %s", dev, slot)
		}
	}
}

func chainArg(chain int) string {
	if chain == 0 {
		return ""
	}
	return " chain " + strconv.Itoa(chain)
}

// orderDeepestFirst sorts classes so children come before their parents.
func orderDeepestFirst(set map[uint16]bool, ks *IfbState) []uint16 {
	depth := func(m uint16) int {
		n := 0
		for cur := m; cur != 0 && n < 16; n++ {
			kc := ks.Classes[cur]
			if kc == nil {
				break
			}
			cur = kc.Parent
		}
		return n
	}
	out := make([]uint16, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		di, dj := depth(out[i]), depth(out[j])
		if di != dj {
			return di > dj
		}
		return out[i] < out[j]
	})
	return out
}

// burstBytes is plan 3's HTB burst: max(1600 B, rate × 1 ms).
func burstBytes(kbit int64) int64 {
	b := kbit / 8 // kbit/s × 1 ms = kbit/8 bytes
	if b < 1600 {
		b = 1600
	}
	return b
}

func htbArgs(r HTBRate) string {
	return fmt.Sprintf("rate %dkbit ceil %dkbit burst %d cburst %d quantum 1514", r.RateKbit, r.CeilKbit, burstBytes(r.RateKbit), burstBytes(r.CeilKbit))
}

// rateMatches compares a kernel class with the wanted rates (bytes/s vs
// kbit/s) and bursts (within 2 %: the kernel stores the burst as time).
func rateMatches(kc *KClass, r HTBRate) bool {
	if kc.RateBps != uint64(r.RateKbit)*125 || kc.CeilBps != uint64(r.CeilKbit)*125 {
		return false
	}
	near := func(have uint64, want int64) bool {
		d := int64(have) - want
		if d < 0 {
			d = -d
		}
		return d*50 <= want
	}
	return near(kc.Burst, burstBytes(r.RateKbit)) && near(kc.Cburst, burstBytes(r.CeilKbit))
}

// fqCodelTarget is plan 3's leaf tuning: target = max(5 ms, 1.5 × the
// time one 1514-byte packet takes at the ceiling), interval = 100 ms +
// (target − 5 ms). In microseconds.
func fqCodelTarget(ceilKbit int64) (target, interval int64) {
	target = 5000
	if ceilKbit > 0 {
		if t := 1514 * 8 * 1000 * 3 / 2 / ceilKbit; t > target { // µs
			target = t
		}
	}
	return target, 100000 + target - 5000
}

func leafArgs(cl DClass, dir Dir, c *Config) string {
	switch cl.Leaf {
	case LeafCake:
		iso := "dual-dsthost"
		if dir == Up {
			iso = "dual-srchost"
		}
		return fmt.Sprintf("cake unlimited besteffort %s memlimit %d", iso, c.RestMemlimitKB*1024)
	default:
		t, iv := fqCodelTarget(cl.Rate[dir].CeilKbit)
		flows := cl.Flows
		if flows <= 0 {
			flows = c.LeafFlows
		}
		return fmt.Sprintf("fq_codel limit %d flows %d memory_limit %d target %dus interval %dus", c.LeafLimit, flows, c.LeafMemoryKB*1024, t, iv)
	}
}

func optNum(o map[string]any, key string) (int64, bool) {
	v, ok := o[key].(float64)
	return int64(v), ok
}

func leafFlows(cl DClass, c *Config) int {
	if cl.Flows > 0 {
		return cl.Flows
	}
	return c.LeafFlows
}

// leafFixedMatches compares what `qdisc change` cannot change (fq_codel's
// flows): a difference there replaces the leaf.
func leafFixedMatches(kq *KQdisc, cl DClass, c *Config) bool {
	if cl.Leaf != LeafFqCodel {
		return true
	}
	kf, _ := optNum(kq.Options, "flows")
	return kf == int64(leafFlows(cl, c))
}

// leafMatches compares a kernel leaf qdisc with the wanted parameters.
func leafMatches(kq *KQdisc, cl DClass, dir Dir, c *Config) bool {
	o := kq.Options
	switch cl.Leaf {
	case LeafCake:
		iso := "dual-dsthost"
		if dir == Up {
			iso = "dual-srchost"
		}
		mem, _ := optNum(o, "memlimit")
		return o["flowmode"] == iso && o["diffserv"] == "besteffort" && o["bandwidth"] == "unlimited" && mem == int64(c.RestMemlimitKB)*1024
	default:
		flows := cl.Flows
		if flows <= 0 {
			flows = c.LeafFlows
		}
		t, iv := fqCodelTarget(cl.Rate[dir].CeilKbit)
		kf, _ := optNum(o, "flows")
		kl, _ := optNum(o, "limit")
		km, _ := optNum(o, "memory_limit")
		kt, _ := optNum(o, "target")
		ki, _ := optNum(o, "interval")
		within := func(have, want int64) bool {
			d := have - want
			if d < 0 {
				d = -d
			}
			return d*100 <= want
		}
		return kf == int64(flows) && kl == int64(c.LeafLimit) && km == int64(c.LeafMemoryKB)*1024 && within(kt, t) && within(ki, iv)
	}
}

// matchArgs turns a canonical match into flower arguments.
func matchArgs(m string) string {
	if m == "" {
		return ""
	}
	var parts []string
	for _, kv := range strings.Split(m, ",") {
		k, v, _ := strings.Cut(kv, "=")
		parts = append(parts, k+" "+v)
	}
	return " " + strings.Join(parts, " ")
}

func actionArgs(f DFilter) string {
	switch {
	case f.Action == ActPass:
		return "action pass"
	case f.Action == ActDrop:
		return "action drop"
	case strings.HasPrefix(f.Action, "goto:"):
		return "action goto chain " + strings.TrimPrefix(f.Action, "goto:")
	case strings.HasPrefix(f.Action, "class:"):
		ifb := IfbDown
		if f.Hook == "ingress" {
			ifb = IfbUp
		}
		return fmt.Sprintf("action skbedit priority 1:%s pipe action mirred egress redirect dev %s", strings.TrimPrefix(f.Action, "class:"), ifb)
	}
	return "action pass"
}

func filterArgs(f DFilter) string {
	return fmt.Sprintf("%s%s pref %d protocol %s handle %d flower%s %s", f.Hook, chainArg(f.Chain), f.Pref, f.Proto, f.Handle, matchArgs(f.Match), actionArgs(f))
}
