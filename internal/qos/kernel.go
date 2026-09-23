package qos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kernel is what the kernel has, read with `tc -s -j` (one tc process for
// every device, through -batch).
type Kernel struct {
	Ifb  [2]*IfbState
	Devs map[string]*DevState
}

// Counters are a qdisc's or class's statistics.
type Counters struct {
	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	Drops      uint64 `json:"drops"`
	Overlimits uint64 `json:"overlimits"`
	Backlog    uint64 `json:"backlog"`
}

// IfbState is one Perch ifb: its root qdisc and HTB classes.
type IfbState struct {
	RootKind   string
	RootHandle string
	Classes    map[uint16]*KClass
	// Qdiscs by handle ("201:").
	Qdiscs map[string]*KQdisc
}

// KClass is an HTB class.
type KClass struct {
	Minor, Parent uint16
	RateBps       uint64
	CeilBps       uint64
	Burst, Cburst uint64
	// Leaf is the handle of the class's qdisc ("201:"), "" for an inner class.
	Leaf  string
	Stats Counters
}

// KQdisc is a qdisc.
type KQdisc struct {
	Kind    string
	Handle  string
	Parent  string
	Options map[string]any
	Stats   Counters
	// Cake/sqm extras.
	BandwidthBps *uint64
	ECNMarks     uint64
	PeakDelayUs  uint64
}

// DevState is a LAN device's clsact filters.
type DevState struct {
	// Qdiscs by kind ("clsact", "ingress", the root's kind …).
	Clsact  bool
	Ingress bool
	Root    *KQdisc
	Filters []KFilter
}

// KFilter is a filter on a device's clsact hook.
type KFilter struct {
	Hook   string
	Chain  int
	Pref   uint16
	Proto  string
	Handle uint32
	Kind   string
	Match  string
	Action string
	Bytes  uint64
	// Packets through the filter's first action.
	Packets uint64
}

// Key is the filter's slot, as DFilter.Key.
func (f KFilter) Key() string {
	return fmt.Sprintf("%s/%d/%d/%s/%d", f.Hook, f.Chain, f.Pref, f.Proto, f.Handle)
}

// readCommands are the `tc -s -j -batch` commands that read the Perch ifbs
// and the given devices, in order.
func readCommands(devs []string, withFilters bool) []string {
	var cmds []string
	for _, d := range dirs {
		cmds = append(cmds, "qdisc show dev "+d.Ifb(), "class show dev "+d.Ifb())
	}
	for _, dev := range devs {
		cmds = append(cmds, "qdisc show dev "+dev)
		if withFilters {
			cmds = append(cmds, "filter show dev "+dev+" egress", "filter show dev "+dev+" ingress")
		}
	}
	return cmds
}

var failedLine = regexp.MustCompile(`Command failed [^:]*:(\d+)`)

// parseBatchOutput splits `tc -j -force -batch` output into one JSON
// document per command; a command that failed (named in stderr) has none.
func parseBatchOutput(cmds []string, stdout, stderr []byte) ([]json.RawMessage, error) {
	failed := map[int]bool{}
	for _, m := range failedLine.FindAllSubmatch(stderr, -1) {
		n, _ := strconv.Atoi(string(m[1]))
		failed[n] = true
	}
	out := make([]json.RawMessage, len(cmds))
	dec := json.NewDecoder(bytes.NewReader(stdout))
	for i := range cmds {
		if failed[i+1] {
			continue
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				return out, fmt.Errorf("tc: %d answers for %d commands", i, len(cmds))
			}
			return out, fmt.Errorf("tc: answer %d: %v", i+1, err)
		}
		out[i] = raw
	}
	return out, nil
}

// parseKernel builds a Kernel from the answers to readCommands.
func parseKernel(cmds []string, answers []json.RawMessage) (*Kernel, error) {
	k := &Kernel{Devs: map[string]*DevState{}}
	for i, cmd := range cmds {
		f := strings.Fields(cmd)
		if len(f) < 4 {
			continue
		}
		obj, dev := f[0], f[3]
		raw := answers[i]
		ifb := -1
		for _, d := range dirs {
			if dev == d.Ifb() {
				ifb = int(d)
			}
		}
		switch {
		case ifb >= 0 && obj == "qdisc":
			if raw == nil {
				continue // no such ifb
			}
			st := &IfbState{Classes: map[uint16]*KClass{}, Qdiscs: map[string]*KQdisc{}}
			qs, err := parseQdiscs(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", cmd, err)
			}
			for _, q := range qs {
				if q.Parent == "" {
					st.RootKind, st.RootHandle = q.Kind, q.Handle
				}
				st.Qdiscs[q.Handle] = q
			}
			k.Ifb[ifb] = st
		case ifb >= 0 && obj == "class":
			if raw == nil || k.Ifb[ifb] == nil {
				continue
			}
			cls, err := parseClasses(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", cmd, err)
			}
			for _, c := range cls {
				k.Ifb[ifb].Classes[c.Minor] = c
			}
		case obj == "qdisc":
			if raw == nil {
				continue // no such device
			}
			ds := &DevState{}
			qs, err := parseQdiscs(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", cmd, err)
			}
			for _, q := range qs {
				switch {
				case q.Kind == "clsact":
					ds.Clsact = true
				case q.Kind == "ingress":
					ds.Ingress = true
				case q.Parent == "":
					ds.Root = q
				}
			}
			k.Devs[dev] = ds
		case obj == "filter":
			ds := k.Devs[dev]
			if raw == nil || ds == nil || len(f) < 5 {
				continue
			}
			fs, err := parseFilters(raw, f[4])
			if err != nil {
				return nil, fmt.Errorf("%s: %v", cmd, err)
			}
			ds.Filters = append(ds.Filters, fs...)
		}
	}
	return k, nil
}

type jsonStats struct {
	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	Drops      uint64 `json:"drops"`
	Overlimits uint64 `json:"overlimits"`
	Backlog    uint64 `json:"backlog"`
}

func (s jsonStats) counters() Counters {
	return Counters{Bytes: s.Bytes, Packets: s.Packets, Drops: s.Drops, Overlimits: s.Overlimits, Backlog: s.Backlog}
}

func parseQdiscs(raw json.RawMessage) ([]*KQdisc, error) {
	var list []struct {
		Kind    string         `json:"kind"`
		Handle  string         `json:"handle"`
		Parent  string         `json:"parent"`
		Root    bool           `json:"root"`
		Options map[string]any `json:"options"`
		jsonStats
		Tins []struct {
			ECNMark     uint64 `json:"ecn_mark"`
			PeakDelayUs uint64 `json:"peak_delay_us"`
		} `json:"tins"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	var out []*KQdisc
	for _, q := range list {
		kq := &KQdisc{Kind: q.Kind, Handle: q.Handle, Parent: q.Parent, Options: q.Options, Stats: q.jsonStats.counters()}
		if q.Root {
			kq.Parent = ""
		}
		if bw, ok := q.Options["bandwidth"].(float64); ok {
			v := uint64(bw)
			kq.BandwidthBps = &v
		}
		for _, t := range q.Tins {
			kq.ECNMarks += t.ECNMark
			if t.PeakDelayUs > kq.PeakDelayUs {
				kq.PeakDelayUs = t.PeakDelayUs
			}
		}
		out = append(out, kq)
	}
	return out, nil
}

// parseHandle reads "1:2a0" → (1, 0x2a0).
func parseHandle(s string) (major, minor uint16, ok bool) {
	a, b, found := strings.Cut(s, ":")
	if !found {
		return 0, 0, false
	}
	ma, err1 := strconv.ParseUint(a, 16, 16)
	var mi uint64
	var err2 error
	if b != "" {
		mi, err2 = strconv.ParseUint(b, 16, 16)
	}
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uint16(ma), uint16(mi), true
}

func parseClasses(raw json.RawMessage) ([]*KClass, error) {
	var list []struct {
		Class  string    `json:"class"`
		Handle string    `json:"handle"`
		Parent string    `json:"parent"`
		Root   bool      `json:"root"`
		Leaf   string    `json:"leaf"`
		Rate   uint64    `json:"rate"`
		Ceil   uint64    `json:"ceil"`
		Burst  uint64    `json:"burst"`
		Cburst uint64    `json:"cburst"`
		Stats  jsonStats `json:"stats"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	var out []*KClass
	for _, c := range list {
		if c.Class != "htb" {
			continue
		}
		_, minor, ok := parseHandle(c.Handle)
		if !ok {
			continue
		}
		kc := &KClass{Minor: minor, RateBps: c.Rate, CeilBps: c.Ceil, Burst: c.Burst, Cburst: c.Cburst, Stats: c.Stats.counters()}
		if !c.Root {
			if _, p, ok := parseHandle(c.Parent); ok {
				kc.Parent = p
			}
		}
		if c.Leaf != "" {
			// "0x201" → "201:"
			if n, err := strconv.ParseUint(strings.TrimPrefix(c.Leaf, "0x"), 16, 32); err == nil {
				kc.Leaf = strconv.FormatUint(n>>16, 16) + ":"
				if n>>16 == 0 {
					kc.Leaf = strconv.FormatUint(n, 16) + ":"
				}
			}
		}
		out = append(out, kc)
	}
	return out, nil
}

type jsonAction struct {
	Kind          string `json:"kind"`
	Priority      string `json:"priority"`
	MirredAction  string `json:"mirred_action"`
	Direction     string `json:"direction"`
	ToDev         string `json:"to_dev"`
	ControlAction struct {
		Type  string `json:"type"`
		Chain *int   `json:"chain"`
	} `json:"control_action"`
	Stats jsonStats `json:"stats"`
}

func parseFilters(raw json.RawMessage, hook string) ([]KFilter, error) {
	var list []struct {
		Protocol string `json:"protocol"`
		Pref     uint16 `json:"pref"`
		Kind     string `json:"kind"`
		Chain    int    `json:"chain"`
		Options  *struct {
			Handle  uint32            `json:"handle"`
			Keys    map[string]any    `json:"keys"`
			Actions []json.RawMessage `json:"actions"`
		} `json:"options"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	var out []KFilter
	for _, f := range list {
		if f.Options == nil {
			continue // the tp header line
		}
		kf := KFilter{Hook: hook, Chain: f.Chain, Pref: f.Pref, Proto: f.Protocol, Handle: f.Options.Handle, Kind: f.Kind}
		kf.Match = canonicalKeys(f.Options.Keys)
		var acts []jsonAction
		for _, a := range f.Options.Actions {
			var ja jsonAction
			if json.Unmarshal(a, &ja) == nil {
				acts = append(acts, ja)
			}
		}
		kf.Action = canonicalAction(acts)
		if len(acts) > 0 {
			kf.Bytes, kf.Packets = acts[0].Stats.Bytes, acts[0].Stats.Packets
		}
		out = append(out, kf)
	}
	return out, nil
}

// canonicalKeys renders flower keys like the planner's Match: sorted
// "key=value" pairs; an address without a length gets its full length;
// eth_type (implied by the protocol) is left out.
func canonicalKeys(keys map[string]any) string {
	var parts []string
	for k, v := range keys {
		if k == "eth_type" {
			continue
		}
		s := fmt.Sprint(v)
		if k == "src_ip" || k == "dst_ip" {
			if p, err := netip.ParsePrefix(s); err == nil {
				s = p.Masked().String()
			} else if a, err := netip.ParseAddr(s); err == nil {
				s = netip.PrefixFrom(a, a.BitLen()).String()
			}
		}
		parts = append(parts, k+"="+strings.ToLower(s))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// canonicalAction renders a filter's actions like the planner's Action.
func canonicalAction(acts []jsonAction) string {
	switch {
	case len(acts) == 1 && acts[0].Kind == "gact":
		switch acts[0].ControlAction.Type {
		case "pass", "drop":
			return acts[0].ControlAction.Type
		case "goto":
			if acts[0].ControlAction.Chain != nil {
				return "goto:" + strconv.Itoa(*acts[0].ControlAction.Chain)
			}
		}
	case len(acts) == 2 && acts[0].Kind == "skbedit" && acts[1].Kind == "mirred" && acts[1].MirredAction == "redirect":
		if major, minor, ok := parseHandle(acts[0].Priority); ok && major == 1 {
			return "class:" + strconv.FormatUint(uint64(minor), 16) + "@" + acts[1].ToDev
		}
	}
	var kinds []string
	for _, a := range acts {
		kinds = append(kinds, a.Kind+"/"+a.ControlAction.Type)
	}
	return "other:" + strings.Join(kinds, "+")
}
