package qos

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// Section is the `qos` object of collector.push (plan 3 section 6, with
// the amendment's schedules). Counters are cumulative; the controller
// derives rates from deltas, and a new epoch (or a counter going back)
// starts them over.
type Section struct {
	Epoch string `json:"epoch"`
	// State: active | paused | error.
	State string `json:"state"`
	// PausedBy: "config" (perch-qos globals.enabled '0': the controller's
	// pause or the router's, the config plane tells which), "local"
	// (`perch-collector qos stop`), or null.
	PausedBy        *string          `json:"pausedBy"`
	ConfigRevision  *string          `json:"configRevision"`
	DevicesRevision *int64           `json:"devicesRevision"`
	CollectedAt     string           `json:"collectedAt"`
	Wan             []WanQueue       `json:"wan"`
	Classes         []ClassStats     `json:"classes"`
	Devices         []Placement      `json:"devices"`
	Quotas          []QuotaReport    `json:"quotas"`
	Schedules       []ScheduleReport `json:"schedules"`
	Errors          []Issue          `json:"errors"`
}

// WanQueue is one sqm queue and its live qdiscs.
type WanQueue struct {
	Device  string      `json:"device"`
	Section string      `json:"section"`
	Enabled bool        `json:"enabled"`
	Egress  *QdiscStats `json:"egress"`
	Ingress *QdiscStats `json:"ingress"`
}

// QdiscStats is a WAN qdisc's counters (the REST QdiscStats less the rate,
// which the controller derives).
type QdiscStats struct {
	Kind          string  `json:"kind"`
	BandwidthKbit *int64  `json:"bandwidthKbit"`
	Bytes         uint64  `json:"bytes"`
	Packets       uint64  `json:"packets"`
	Drops         uint64  `json:"drops"`
	Overlimits    uint64  `json:"overlimits"`
	BacklogBytes  uint64  `json:"backlogBytes"`
	ECNMarks      *uint64 `json:"ecnMarks"`
	PeakDelayUs   *uint64 `json:"peakDelayUs"`
}

// ClassStats is one class in one direction.
type ClassStats struct {
	ID           string `json:"id"`
	Key          string `json:"key"`
	Dir          string `json:"dir"`
	RateKbit     int64  `json:"rateKbit"`
	CeilKbit     int64  `json:"ceilKbit"`
	Bytes        uint64 `json:"bytes"`
	Packets      uint64 `json:"packets"`
	Drops        uint64 `json:"drops"`
	Overlimits   uint64 `json:"overlimits"`
	BacklogBytes uint64 `json:"backlogBytes"`
}

// QuotaReport is one MAC's quota.
type QuotaReport struct {
	MAC        string `json:"mac"`
	UsedBytes  int64  `json:"usedBytes"`
	LimitBytes int64  `json:"limitBytes"`
	Exhausted  bool   `json:"exhausted"`
	// Enforced is false while quotas fail open (after a reboot, until the
	// controller sends its set).
	Enforced bool `json:"enforced"`
}

// ScheduleReport is a schedule's state (amendment section 6).
type ScheduleReport struct {
	Name   string  `json:"name"`
	Active bool    `json:"active"`
	Since  *string `json:"since"`
	Until  *string `json:"until"`
}

// MaxClasses bounds the classes of one push.
const MaxClasses = 4096

// capHit tuning: a device class running at ≥ 90 % of its ceiling for three
// reads in a row, then quiet for 15 minutes per MAC and direction.
const (
	capHitRatio = 0.9
	capHitRuns  = 3
	capHitHold  = 15 * time.Minute
)

// Section reads the kernel's counters and builds the push section; nil
// when shaping is not set up on this router (then the push has no `qos`).
// The daemon's section also counts quotas and raises events.
func (e *Engine) Section() *Section {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshConfigLocked()
	if e.cfg == nil || !e.cfg.Present {
		return nil
	}
	now := e.sys.Now()
	d := e.desired
	var devs []string
	if d != nil {
		devs = sortedKeys(d.Filters)
	}
	var extra []string
	for _, q := range e.sqm {
		if q.Device != "" {
			extra = append(extra, q.Device, sqmIfb(q.Device))
		}
	}
	withFilters := len(e.devices.Quotas) > 0
	k, err := e.readKernel(devs, extra, withFilters)
	s := &Section{Epoch: e.epoch, State: "active", CollectedAt: now.UTC().Format(time.RFC3339),
		Wan: []WanQueue{}, Classes: []ClassStats{}, Devices: []Placement{}, Quotas: []QuotaReport{},
		Schedules: []ScheduleReport{}, Errors: []Issue{}}
	if s.Epoch == "" {
		s.Epoch = "none"
	}
	if e.cfg.Revision != "" {
		r := e.cfg.Revision
		s.ConfigRevision = &r
	}
	if e.devices.SetAt.IsZero() && len(e.devices.Entries) == 0 {
		s.DevicesRevision = nil
	} else {
		r := e.devices.Revision
		s.DevicesRevision = &r
	}
	if by := e.pausedByLocked(); by != "" {
		s.State, s.PausedBy = "paused", &by
	}
	if err != nil {
		s.State = "error"
		s.Errors = append(s.Errors, Issue{"stats_unreadable", err.Error()})
		return s
	}
	e.kernel, e.kernelAt = k, now

	// WAN queues (sqm), reported as they are: never reverted (decision 15).
	for _, q := range e.sqm {
		w := WanQueue{Device: q.Device, Section: q.Section, Enabled: q.Enabled}
		if ds := k.Devs[q.Device]; ds != nil && ds.Root != nil {
			w.Egress = qdiscStats(ds.Root)
		}
		if ds := k.Devs[sqmIfb(q.Device)]; ds != nil && ds.Root != nil {
			w.Ingress = qdiscStats(ds.Root)
		}
		s.Wan = append(s.Wan, w)
		switch {
		case !q.Enabled:
			s.Errors = append(s.Errors, Issue{"sqm_paused", fmt.Sprintf("sqm queue %s on %s is disabled on the router", q.Section, q.Device)})
		case (q.Download > 0 && q.Download < e.cfg.MinWanKbit) || (q.Upload > 0 && q.Upload < e.cfg.MinWanKbit):
			s.Errors = append(s.Errors, Issue{"sqm_below_floor", fmt.Sprintf("sqm queue %s on %s is below min_wan_kbit %d", q.Section, q.Device, e.cfg.MinWanKbit)})
		}
	}

	if d != nil {
		for _, cl := range d.Classes {
			for _, dir := range dirs {
				ifb := k.Ifb[dir]
				if ifb == nil {
					continue
				}
				kc := ifb.Classes[cl.Minor]
				if kc == nil {
					continue
				}
				cs := ClassStats{ID: classID(cl.Minor), Key: cl.Key, Dir: dir.String(),
					RateKbit: cl.Rate[dir].RateKbit, CeilKbit: cl.Rate[dir].CeilKbit,
					Bytes: kc.Stats.Bytes, Packets: kc.Stats.Packets, Drops: kc.Stats.Drops,
					Overlimits: kc.Stats.Overlimits, BacklogBytes: kc.Stats.Backlog}
				if q := ifb.Qdiscs[kc.Leaf]; q != nil {
					cs.Drops += q.Stats.Drops
					cs.BacklogBytes += q.Stats.Backlog
				}
				if len(s.Classes) < MaxClasses {
					s.Classes = append(s.Classes, cs)
				}
				if cl.Kind == KindDevice {
					e.capCheckLocked(cl, dir, kc.Stats.Bytes, now)
				}
			}
		}
		s.Devices = append(s.Devices, d.Placements...)
		s.Errors = append(s.Errors, d.Issues...)
		for _, st := range d.Schedules {
			r := ScheduleReport{Name: st.Name, Active: st.Active}
			if st.Since != nil {
				v := st.Since.Format(time.RFC3339)
				r.Since = &v
			}
			if st.Until != nil {
				v := st.Until.Format(time.RFC3339)
				r.Until = &v
			}
			s.Schedules = append(s.Schedules, r)
		}
	}
	if !e.cfg.Valid() {
		s.State = "error"
		s.Errors = append(s.Errors, e.cfg.Errors...)
	}
	s.Errors = append(s.Errors, e.cfg.Warnings...)
	if len(e.result.Errors) > 0 {
		s.State = "error"
		for _, m := range e.result.Errors {
			s.Errors = append(s.Errors, Issue{"apply_failed", m})
		}
	}
	for _, r := range e.rejected {
		s.Errors = append(s.Errors, Issue{"device_rejected", r.MAC + ": " + r.Error})
	}

	if withFilters && e.daemon {
		e.countQuotasLocked(k)
	}
	enforced := !e.devices.FromFlash
	for _, en := range e.entries {
		if en.Quota == nil {
			continue
		}
		q := e.devices.Quotas[en.MAC]
		if q == nil {
			continue
		}
		s.Quotas = append(s.Quotas, QuotaReport{MAC: en.MAC, UsedBytes: q.Used, LimitBytes: en.Quota.LimitBytes,
			Exhausted: !q.ExhaustedAt.IsZero(), Enforced: enforced})
	}
	return s
}

func qdiscStats(q *KQdisc) *QdiscStats {
	out := &QdiscStats{Kind: q.Kind, Bytes: q.Stats.Bytes, Packets: q.Stats.Packets, Drops: q.Stats.Drops,
		Overlimits: q.Stats.Overlimits, BacklogBytes: q.Stats.Backlog}
	if q.BandwidthBps != nil {
		v := int64(*q.BandwidthBps * 8 / 1000)
		out.BandwidthKbit = &v
	}
	if q.Kind == "cake" {
		ecn, peak := q.ECNMarks, q.PeakDelayUs
		out.ECNMarks, out.PeakDelayUs = &ecn, &peak
	}
	return out
}

// countQuotasLocked adds the bytes each quota MAC's filters passed since
// the last read (both hooks, every device; a filter replaced since starts
// over) and checks the limits.
func (e *Engine) countQuotasLocked(k *Kernel) {
	st := e.loadState()
	handleOf := map[uint32]string{}
	for mac := range e.devices.Quotas {
		if h, ok := st.Handles[mac]; ok {
			handleOf[h] = mac
		}
	}
	seen := map[string]bool{}
	changed := false
	for dev, ds := range k.Devs {
		for _, f := range ds.Filters {
			if f.Chain != 0 || (f.Pref != PrefDevice && f.Pref != PrefIncludeLan) {
				continue
			}
			mac, ok := handleOf[f.Handle]
			if !ok {
				continue
			}
			key := fmt.Sprintf("%s/%s/%d/%d/%s", dev, f.Hook, f.Pref, f.Handle, f.Action)
			seen[key] = true
			prev, had := e.filterBy[key]
			e.filterBy[key] = f.Bytes
			var delta uint64
			switch {
			case !had:
				// A filter first seen after the first read was installed
				// since: all its bytes are new. At the first read after
				// the agent started they were counted before (state kept).
				if e.quotaPrimed {
					delta = f.Bytes
				}
			case f.Bytes >= prev:
				delta = f.Bytes - prev
			default:
				delta = f.Bytes // replaced: counts start over
			}
			if delta > 0 {
				e.devices.Quotas[mac].Used += int64(delta)
				changed = true
			}
		}
	}
	for key := range e.filterBy {
		if !seen[key] {
			delete(e.filterBy, key)
		}
	}
	e.quotaPrimed = true
	if changed {
		e.quotaDirty = true
		e.checkQuotasLocked()
		data, _ := json.Marshal(e.devices)
		if err := e.sys.WriteFile(runtimeDevices, data, 0o600); err != nil {
			log.Printf("qos: quota counters: %v", err)
		}
		e.devStamp = e.stamp(runtimeDevices)
	}
}

// checkQuotasLocked marks quotas that reached their limit and reports each
// once; a reconcile then throttles or blocks the MAC.
func (e *Engine) checkQuotasLocked() {
	now := e.sys.Now().UTC()
	kick := false
	for _, en := range e.entries {
		if en.Quota == nil {
			continue
		}
		q := e.devices.Quotas[en.MAC]
		if q == nil || !q.ExhaustedAt.IsZero() || q.Used < en.Quota.LimitBytes {
			continue
		}
		q.ExhaustedAt = now
		kick = true
		e.emitLocked(EventQuotaExhausted, en.MAC, map[string]any{"usedBytes": q.Used, "limitBytes": en.Quota.LimitBytes,
			"onExhausted": en.Quota.OnExhausted, "enforced": !e.devices.FromFlash})
	}
	if kick {
		e.inputsFP = ""
		select {
		case e.kick <- struct{}{}:
		default:
		}
	}
}

// capCheckLocked raises cap_hit when a device class runs at its ceiling.
func (e *Engine) capCheckLocked(cl DClass, dir Dir, bytes uint64, now time.Time) {
	if !e.daemon || cl.MAC == "" {
		return
	}
	key := cl.MAC + "/" + dir.String()
	prev, ok := e.prevRate[key]
	e.prevRate[key] = classSample{bytes: bytes, at: now}
	if !ok || bytes < prev.bytes || now.Sub(prev.at) < time.Second {
		return
	}
	kbit := float64(bytes-prev.bytes) * 8 / 1000 / now.Sub(prev.at).Seconds()
	ceil := float64(cl.Rate[dir].CeilKbit)
	if ceil <= 0 || ceil >= RootKbit || kbit < capHitRatio*ceil {
		e.capRuns[key] = 0
		return
	}
	e.capRuns[key]++
	if e.capRuns[key] < capHitRuns || now.Sub(e.capSent[key]) < capHitHold {
		return
	}
	e.capSent[key] = now
	e.emitLocked(EventCapHit, cl.MAC, map[string]any{"dir": dir.String(), "classId": classID(cl.Minor),
		"ceilKbit": cl.Rate[dir].CeilKbit, "rateKbit": int64(kbit)})
}

// Status is `perch-collector qos status`: the push section plus what the
// last reconcile did and the plan's shape.
type Status struct {
	Section *Section    `json:"qos"`
	Last    ApplyResult `json:"lastApply"`
	LANs    []LAN       `json:"lans"`
	Summary string      `json:"summary"`
}

// StatusReport builds the CLI status.
func (e *Engine) StatusReport() Status {
	s := e.Section()
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Section: s, Last: e.result, LANs: e.lans}
	if d := e.desired; d != nil {
		var parts []string
		kinds := map[string]int{}
		for _, c := range d.Classes {
			kinds[c.Kind]++
		}
		for _, k := range sortedKeys(kinds) {
			parts = append(parts, fmt.Sprintf("%d %s", kinds[k], k))
		}
		n := 0
		for _, fs := range d.Filters {
			n += len(fs)
		}
		sort.Strings(parts)
		st.Summary = fmt.Sprintf("active=%v classes: %s; %d filters on %d devices", d.Active, strings.Join(parts, ", "), n, len(d.Filters))
	}
	return st
}
