package qos

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Paths on the router.
const (
	ConfigPath   = "/etc/config/perch-qos"
	SQMPath      = "/etc/config/sqm"
	FirewallPath = "/etc/config/firewall"
	SystemPath   = "/etc/config/system"
	TZPath       = "/tmp/TZ"
	// FlashDevicesPath is the on-flash cache of the last qos.devices.set.
	FlashDevicesPath = "/etc/perch-qos/devices.json"
	// RuntimeDir holds the state that lives as long as the kernel objects.
	RuntimeDir     = "/tmp/perch-qos"
	statePath      = RuntimeDir + "/state.json"
	runtimeDevices = RuntimeDir + "/devices.json"
	lockPath       = RuntimeDir + "/lock"
	// StoppedMarker is written by `perch-collector qos stop`: shaping stays
	// off until `qos apply` (or a reboot).
	StoppedMarker = RuntimeDir + "/stopped"
	lastBatchPath = RuntimeDir + "/last.batch"
	fullBatchPath = RuntimeDir + "/full.batch"
	resultPath    = RuntimeDir + "/last-apply.json"
)

// Engine timings.
const (
	// FlashInterval is the least time between two writes of the device
	// cache to flash (plan 3 WP-E: written on change, ≥ 60 s apart).
	FlashInterval = 60 * time.Second
	// QuotaFlashInterval is how often changed quota counters go to flash.
	QuotaFlashInterval = 15 * time.Minute
	neighborInterval   = 2 * time.Second
	interfaceInterval  = 10 * time.Second
	verifyInterval     = 60 * time.Second
	statsInterval      = 5 * time.Second
	tcTimeout          = 20 * time.Second
)

// Event is a qos.event notification (plan 3 section 6).
type Event struct {
	Type   string `json:"type"`
	At     string `json:"at"`
	MAC    string `json:"mac,omitempty"`
	Detail any    `json:"detail,omitempty"`
}

// Event types.
const (
	EventQuotaExhausted = "quota_exhausted"
	EventPoolExhausted  = "pool_exhausted"
	EventApplyFailed    = "apply_failed"
	EventLocalPause     = "local_pause"
	EventLocalResume    = "local_resume"
	EventClockUnsynced  = "schedule_clock_unsynced"
	EventSQMPaused      = "sqm_paused"
	EventSQMResumed     = "sqm_resumed"
	EventCapHit         = "cap_hit"
)

const maxQueuedEvents = 128

// ApplyResult is what a reconcile did.
type ApplyResult struct {
	At       time.Time `json:"at"`
	Reason   string    `json:"reason"`
	Active   bool      `json:"active"`
	Commands int       `json:"commands"`
	Errors   []string  `json:"errors,omitempty"`
	// Fingerprint of the plan the kernel should now match.
	Fingerprint string `json:"fingerprint"`
	Unchanged   bool   `json:"unchanged,omitempty"`
}

// Engine runs the shaper: it plans from perch-qos, the device set, the
// LANs and the neighbour table, and brings the kernel there.
type Engine struct {
	sys System
	// daemon: the long-running agent (writes device caches, counts quotas,
	// emits events). The CLI's engine only reconciles and reads.
	daemon bool

	mu       sync.Mutex
	devices  *Devices
	entries  []Entry
	rejected []Rejection

	cfg      *Config
	cfgStamp string
	sqm      []SQMQueue
	sqmStamp string
	wanNets  map[string]bool
	fwStamp  string
	zone     *Zone
	zoneKey  string
	lans     []LAN
	lansOK   bool
	lansAt   time.Time
	neigh    []Neighbor
	neighAt  time.Time

	desired    *Desired
	kernel     *Kernel
	kernelAt   time.Time
	result     ApplyResult
	inputsFP   string
	verifiedAt time.Time
	epoch      string

	flashDirty   bool
	flashAt      time.Time
	quotaDirty   bool
	quotaFlashAt time.Time

	events   []Event
	notify   chan struct{}
	kick     chan struct{}
	filterBy map[string]uint64 // last filter byte counters (quota deltas)
	// quotaPrimed: the filter counters were read once since the start.
	quotaPrimed bool
	capRuns     map[string]int
	capSent     map[string]time.Time
	prevRate    map[string]classSample
	lastPaus    string
	sqmSeen     map[string]bool
	errsSent    string
	poolSent    bool
	clockMsg    bool
}

type classSample struct {
	bytes uint64
	at    time.Time
}

// NewEngine prepares an engine; daemon selects the agent's behaviour.
func NewEngine(sys System, daemon bool) *Engine {
	e := &Engine{sys: sys, daemon: daemon, notify: make(chan struct{}, 1), kick: make(chan struct{}, 1),
		filterBy: map[string]uint64{}, capRuns: map[string]int{}, capSent: map[string]time.Time{},
		prevRate: map[string]classSample{}, sqmSeen: map[string]bool{}}
	e.devices = &Devices{Quotas: map[string]*QuotaState{}}
	return e
}

func newEpoch() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LoadDevices restores the last device set: the runtime copy (same boot:
// quotas keep being enforced), else the flash cache (after a reboot:
// entries return, quotas fail open until the controller sends a set).
func (e *Engine) LoadDevices() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if data, err := e.sys.ReadFile(runtimeDevices); err == nil {
		if d, err := DecodeDevices(data); err == nil {
			e.setDevicesLocked(d)
			return
		}
	}
	if data, err := e.sys.ReadFile(FlashDevicesPath); err == nil {
		if d, err := DecodeDevices(data); err == nil {
			d.FromFlash = true
			e.setDevicesLocked(d)
			log.Printf("qos: %d device entries restored from %s (revision %d); quotas fail open until the controller sends its set", len(d.Entries), FlashDevicesPath, d.Revision)
		}
	}
}

func (e *Engine) setDevicesLocked(d *Devices) {
	if d.Quotas == nil {
		d.Quotas = map[string]*QuotaState{}
	}
	e.devices = d
	min := int64(defaultMinDeviceKbit)
	if e.cfg != nil {
		min = e.cfg.MinDeviceKbit
	}
	e.entries, e.rejected = ValidateDevices(d.Entries, min, e.sys.LocalMACs())
}

// ErrNotActive is qos.devices.set's refusal while shaping is not set up
// on this router (-32010 qos_not_active).
var ErrNotActive = errors.New("qos_not_active")

// SetDevices takes a qos.devices.set: validates, stores (runtime copy now,
// flash at most every FlashInterval), re-seeds quotas the controller
// changed, and triggers a reconcile.
func (e *Engine) SetDevices(p DevicesSetParams) (DevicesSetResult, error) {
	if len(p.Devices) > MaxDeviceEntries {
		return DevicesSetResult{}, fmt.Errorf("at most %d devices", MaxDeviceEntries)
	}
	e.mu.Lock()
	e.refreshConfigLocked()
	if e.cfg == nil || !e.cfg.Present {
		e.mu.Unlock()
		return DevicesSetResult{}, ErrNotActive
	}
	entries, rejected := ValidateDevices(p.Devices, e.cfg.MinDeviceKbit, e.sys.LocalMACs())
	next := &Devices{Revision: p.Revision, SetAt: e.sys.Now().UTC(), Quotas: map[string]*QuotaState{}}
	for _, en := range entries {
		next.Entries = append(next.Entries, en.DeviceEntry())
		if en.Quota == nil {
			continue
		}
		old := e.devices.Quotas[en.MAC]
		if old != nil && old.Seed == en.Quota.UsedBytes {
			q := *old // the controller's value is the one it sent before: ours is newer
			next.Quotas[en.MAC] = &q
		} else {
			next.Quotas[en.MAC] = &QuotaState{Seed: en.Quota.UsedBytes, Used: en.Quota.UsedBytes}
		}
		if q := next.Quotas[en.MAC]; q.Used < en.Quota.LimitBytes {
			q.ExhaustedAt = time.Time{}
		}
	}
	e.devices, e.entries, e.rejected = next, entries, rejected
	e.flashDirty = true
	e.checkQuotasLocked()
	data, _ := json.Marshal(next)
	werr := e.sys.WriteFile(runtimeDevices, data, 0o600)
	e.mu.Unlock()
	if werr != nil {
		log.Printf("qos: keeping the device set: %v", werr)
	}
	e.Kick()
	return DevicesSetResult{Revision: p.Revision, Accepted: len(entries), Rejected: rejected}, nil
}

// Kick asks the daemon loop for a reconcile now.
func (e *Engine) Kick() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Notify is signalled when events are queued.
func (e *Engine) Notify() <-chan struct{} { return e.notify }

// DrainEvents returns and forgets the queued events.
func (e *Engine) DrainEvents() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.events
	e.events = nil
	return out
}

func (e *Engine) emitLocked(typ, mac string, detail any) {
	if !e.daemon {
		return
	}
	ev := Event{Type: typ, At: e.sys.Now().UTC().Format(time.RFC3339), MAC: mac, Detail: detail}
	if len(e.events) >= maxQueuedEvents {
		e.events = e.events[1:]
	}
	e.events = append(e.events, ev)
	log.Printf("qos: event %s %s", typ, mac)
	select {
	case e.notify <- struct{}{}:
	default:
	}
}

// stamp identifies a file's content by size and mtime ("-" = missing).
func (e *Engine) stamp(p string) string {
	st, err := e.sys.Stat(p)
	if err != nil {
		return "-"
	}
	return strconv.FormatInt(st.Size(), 10) + "@" + strconv.FormatInt(st.ModTime().UnixNano(), 10)
}

// refreshConfigLocked rereads the files that changed.
func (e *Engine) refreshConfigLocked() {
	if s := e.stamp(ConfigPath); s != e.cfgStamp || e.cfg == nil {
		e.cfgStamp = s
		data, err := e.sys.ReadFile(ConfigPath)
		if err != nil {
			c := DefaultConfig()
			c.Present = false
			e.cfg = c
		} else {
			prev := e.cfg
			e.cfg = ParseConfig(data)
			if !e.cfg.Valid() && (prev == nil || fmt.Sprint(prev.Errors) != fmt.Sprint(e.cfg.Errors)) {
				log.Printf("qos: %s is not usable, keeping the kernel as it is: %v", ConfigPath, e.cfg.Errors)
			}
		}
		// The floor may have changed.
		e.entries, e.rejected = ValidateDevices(e.devices.Entries, e.cfg.MinDeviceKbit, e.sys.LocalMACs())
	}
	if s := e.stamp(SQMPath); s != e.sqmStamp {
		e.sqmStamp = s
		data, _ := e.sys.ReadFile(SQMPath)
		e.sqm = ParseSQM(data)
	}
	if s := e.stamp(FirewallPath); s != e.fwStamp {
		e.fwStamp = s
		data, _ := e.sys.ReadFile(FirewallPath)
		e.wanNets = WANNetworks(data)
		e.lansAt = time.Time{}
	}
	tz, _ := e.sys.ReadFile(TZPath)
	if key := strings.TrimSpace(string(tz)); key != e.zoneKey || e.zone == nil {
		e.zoneKey = key
		z, err := ParseTZ(key)
		if err != nil {
			log.Printf("qos: %v; schedules run on UTC", err)
			z = UTCZone
		}
		e.zone = z
	}
}

func (e *Engine) refreshLANsLocked(force bool) {
	now := e.sys.Now()
	if !force && e.lansOK && now.Sub(e.lansAt) < interfaceInterval {
		return
	}
	e.lansAt = now
	dump, err := e.sys.Interfaces()
	if err != nil {
		return
	}
	if lans, ok := ParseLANs(dump, e.wanNets); ok {
		markSQMConflicts(lans, e.sqm)
		e.lans, e.lansOK = lans, true
	}
}

func (e *Engine) refreshNeighborsLocked(force bool) {
	now := e.sys.Now()
	if !force && !e.neighAt.IsZero() && now.Sub(e.neighAt) < neighborInterval {
		return
	}
	e.neighAt = now
	if n, err := e.sys.Neighbors(); err == nil {
		e.neigh = n
	}
}

// stopped reports whether `qos stop` holds shaping off.
func (e *Engine) stopped() bool {
	_, err := e.sys.Stat(StoppedMarker)
	return err == nil
}

func (e *Engine) exhaustedLocked() map[string]bool {
	out := map[string]bool{}
	if e.devices.FromFlash {
		return out // fail open until the controller re-seeds
	}
	for mac, q := range e.devices.Quotas {
		if !q.ExhaustedAt.IsZero() {
			out[mac] = true
		}
	}
	return out
}

// inputsFingerprintLocked summarises everything a plan depends on, so the
// daemon's 2 s tick replans only when something moved.
func (e *Engine) inputsFingerprintLocked(now time.Time, synced bool) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%v|%v\n", e.cfgStamp, e.sqmStamp, e.fwStamp, e.zoneKey, e.stopped(), synced)
	fmt.Fprintf(h, "dev %d %s %d\n", e.devices.Revision, e.devices.SetAt, len(e.entries))
	live := 0
	for _, en := range e.entries {
		if en.Expires.IsZero() || now.Before(en.Expires) {
			live++
		}
	}
	fmt.Fprintf(h, "live %d\n", live)
	for _, l := range e.lans {
		fmt.Fprintf(h, "lan %s %s %v %v %s\n", l.Network, l.Device, l.Prefixes, l.Addrs, l.Conflict)
	}
	for _, m := range sortedKeys(e.exhaustedLocked()) {
		fmt.Fprintf(h, "x %s\n", m)
	}
	if e.cfg != nil {
		for _, s := range ScheduleStates(e.cfg, now, e.zone, synced) {
			fmt.Fprintf(h, "s %s %v\n", s.Name, s.Active)
		}
		// Neighbours on networks with per-device caps.
		dynDevs := map[string]bool{}
		for _, n := range e.cfg.Networks {
			if n.Each != nil || len(n.Schedules) > 0 {
				for _, l := range e.lans {
					if l.Network == n.Name {
						dynDevs[l.Device] = true
					}
				}
			}
		}
		var macs []string
		for _, n := range e.neigh {
			if dynDevs[n.Device] {
				macs = append(macs, n.MAC+"@"+n.Device)
			}
		}
		sort.Strings(macs)
		fmt.Fprintf(h, "n %s\n", strings.Join(macs, ","))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// readKernel reads the ifbs and devs (with statistics; filters when
// withFilters).
func (e *Engine) readKernel(devs []string, extra []string, withFilters bool) (*Kernel, error) {
	cmds := readCommands(devs, withFilters)
	for _, d := range extra {
		cmds = append(cmds, "qdisc show dev "+d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), tcTimeout)
	defer cancel()
	stdout, stderr, _ := e.sys.Tc(ctx, cmds, true, true)
	answers, err := parseBatchOutput(cmds, stdout, stderr)
	if err != nil {
		return nil, err
	}
	return parseKernel(cmds, answers)
}

func (e *Engine) loadState() *State {
	data, err := e.sys.ReadFile(statePath)
	if err == nil {
		if st, err := DecodeState(data); err == nil {
			return st
		}
	}
	return NewState(newEpoch())
}

func (e *Engine) saveState(st *State) {
	data, _ := json.Marshal(st)
	if err := e.sys.WriteFile(statePath, data, 0o600); err != nil {
		log.Printf("qos: state: %v", err)
	}
}

// Reconcile brings the kernel to the plan. force skips the "nothing
// changed" shortcut (the CLI, hotplug, the periodic verify).
func (e *Engine) Reconcile(reason string, force bool) ApplyResult {
	unlock, err := e.sys.Lock(lockPath)
	if err != nil {
		return ApplyResult{At: e.sys.Now(), Reason: reason, Errors: []string{"lock: " + err.Error()}}
	}
	defer unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reconcileLocked(reason, force)
}

func (e *Engine) reconcileLocked(reason string, force bool) ApplyResult {
	now := e.sys.Now()
	e.refreshConfigLocked()
	e.refreshLANsLocked(force)
	e.refreshNeighborsLocked(force)
	synced := e.sys.ClockSynced()
	fp := e.inputsFingerprintLocked(now, synced)
	if !force && fp == e.inputsFP && now.Sub(e.verifiedAt) < verifyInterval && e.desired != nil {
		return ApplyResult{At: now, Reason: reason, Active: e.desired.Active, Fingerprint: e.desired.Fingerprint, Unchanged: true}
	}
	st := e.loadState()
	if e.epoch != "" && e.epoch != st.Epoch && e.daemon {
		st.Epoch = e.epoch
	}

	devs := map[string]bool{}
	for _, l := range e.lans {
		devs[l.Device] = true
	}
	for _, d := range st.Devices {
		devs[d] = true
	}
	devList := sortedKeys(devs)
	k, err := e.readKernel(devList, nil, true)
	if err != nil {
		res := ApplyResult{At: now, Reason: reason, Errors: []string{"reading tc: " + err.Error()}}
		e.result = res
		return res
	}
	busy := map[uint16]bool{}
	classBytes := map[uint16]uint64{}
	for _, ifb := range k.Ifb {
		if ifb == nil {
			continue
		}
		for m, c := range ifb.Classes {
			busy[m] = true
			classBytes[m] += c.Stats.Bytes
		}
	}
	cfg := e.cfg
	if e.stopped() {
		c := *cfg
		c.Enabled = false
		cfg = &c
	}
	in := Inputs{Config: cfg, Entries: e.entries, LANs: e.lans, Neighbors: e.neigh, Now: now, Zone: e.zone,
		ClockSynced: synced, Exhausted: e.exhaustedLocked(), Busy: busy, ClassBytes: classBytes}
	d := Plan(in, st)
	if cfg.Present && !cfg.Valid() && e.desired != nil {
		// Keep what the kernel has: a broken file never tears shaping down.
		d = e.desired
	} else if cfg.Present && !cfg.Valid() {
		res := ApplyResult{At: now, Reason: reason, Errors: issueStrings(cfg.Errors)}
		e.result = res
		e.inputsFP = fp
		return res
	}
	b := Diff(d, k, st.Devices)
	res := ApplyResult{At: now, Reason: reason, Active: d.Active, Fingerprint: d.Fingerprint, Commands: len(b.Lines)}
	if b.CreateIfbs {
		for _, dir := range dirs {
			if err := e.sys.EnsureIfb(dir.Ifb()); err != nil {
				res.Errors = append(res.Errors, err.Error())
			}
		}
		if k.Ifb[Down] == nil && k.Ifb[Up] == nil {
			st.Epoch = newEpoch()
		}
	}
	if len(b.Lines) > 0 && len(res.Errors) == 0 {
		_ = e.sys.WriteFile(lastBatchPath, []byte(b.Text()), 0o644)
		ctx, cancel := context.WithTimeout(context.Background(), tcTimeout)
		_, stderr, err := e.sys.Tc(ctx, b.Lines, false, false)
		cancel()
		if msgs := tcErrors(b.Lines, stderr); len(msgs) > 0 {
			res.Errors = append(res.Errors, msgs...)
		} else if err != nil {
			res.Errors = append(res.Errors, "tc: "+err.Error())
		}
	}
	if b.DeleteIfbs {
		for _, dir := range dirs {
			if err := e.sys.DeleteLink(dir.Ifb()); err != nil {
				res.Errors = append(res.Errors, err.Error())
			}
		}
	}
	if d.Active {
		_ = e.sys.WriteFile(fullBatchPath, []byte(Render(d).Text()), 0o644)
	}
	st.Devices = sortedKeys(d.Filters)
	if len(res.Errors) == 0 {
		st.Applied, st.AppliedAt = d.Fingerprint, now.UTC()
		e.inputsFP = fp
		e.verifiedAt = now
	} else {
		st.Applied = ""
		e.inputsFP = "" // retry on the next tick
	}
	e.epoch = st.Epoch
	e.saveState(st)
	e.desired = d
	e.result = res
	data, _ := json.MarshalIndent(res, "", "  ")
	_ = e.sys.WriteFile(resultPath, data, 0o644)
	if res.Commands > 0 && e.daemon {
		log.Printf("qos: applied %d tc commands (%s)", res.Commands, reason)
	}
	e.afterReconcileLocked(d, res, synced)
	return res
}

func issueStrings(list []Issue) []string {
	var out []string
	for _, i := range list {
		out = append(out, i.String())
	}
	return out
}

// tcErrors pairs `tc -force -batch` failures with their commands.
func tcErrors(lines []string, stderr []byte) []string {
	var out []string
	var pending []string
	for _, l := range strings.Split(string(stderr), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if m := failedLine.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			cmd := ""
			if n >= 1 && n <= len(lines) {
				cmd = lines[n-1]
			}
			out = append(out, fmt.Sprintf("%s: %s", cmd, strings.Join(pending, "; ")))
			pending = nil
			continue
		}
		pending = append(pending, l)
	}
	if len(out) > 20 {
		out = append(out[:20], fmt.Sprintf("… %d more", len(out)-20))
	}
	return out
}

// afterReconcileLocked emits the events a reconcile can cause.
func (e *Engine) afterReconcileLocked(d *Desired, res ApplyResult, synced bool) {
	if !e.daemon {
		return
	}
	errs := strings.Join(res.Errors, "\n")
	if errs != "" && errs != e.errsSent {
		e.emitLocked(EventApplyFailed, "", map[string]any{"errors": res.Errors})
	}
	e.errsSent = errs
	pool := false
	for _, i := range d.Issues {
		if i.Code == "pool_exhausted" {
			pool = true
			if !e.poolSent {
				e.emitLocked(EventPoolExhausted, "", map[string]any{"detail": i.Detail})
			}
		}
	}
	e.poolSent = pool
	if e.cfg != nil && len(e.cfg.Schedules) > 0 && !synced {
		if !e.clockMsg {
			e.emitLocked(EventClockUnsynced, "", nil)
		}
		e.clockMsg = true
	} else {
		e.clockMsg = false
	}
	paused := e.pausedByLocked()
	if paused != e.lastPaus {
		switch {
		case paused != "" && e.lastPaus == "":
			e.emitLocked(EventLocalPause, "", map[string]any{"by": paused})
		case paused == "" && e.lastPaus != "":
			e.emitLocked(EventLocalResume, "", map[string]any{"by": e.lastPaus})
		}
		e.lastPaus = paused
	}
	for _, q := range e.sqm {
		on, seen := e.sqmSeen[q.Section]
		if seen && on && !q.Enabled {
			e.emitLocked(EventSQMPaused, "", map[string]any{"section": q.Section, "device": q.Device})
		}
		if seen && !on && q.Enabled {
			e.emitLocked(EventSQMResumed, "", map[string]any{"section": q.Section, "device": q.Device})
		}
		e.sqmSeen[q.Section] = q.Enabled
	}
}

// pausedByLocked is "local" (qos stop), "config" (globals.enabled '0') or "".
func (e *Engine) pausedByLocked() string {
	switch {
	case e.stopped():
		return "local"
	case e.cfg != nil && e.cfg.Present && !e.cfg.Enabled:
		return "config"
	}
	return ""
}

// Stop removes every Perch tc object and holds shaping off until Start
// (`perch-collector qos stop`; the package's prerm).
func (e *Engine) Stop() ApplyResult {
	if err := e.sys.WriteFile(StoppedMarker, []byte(e.sys.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return ApplyResult{At: e.sys.Now(), Reason: "stop", Errors: []string{err.Error()}}
	}
	return e.Reconcile("stop", true)
}

// Start lifts a Stop and applies (`perch-collector qos apply`).
func (e *Engine) Start(reason string) ApplyResult {
	_ = e.sys.Remove(StoppedMarker)
	return e.Reconcile(reason, true)
}

// Run is the daemon loop: a reconcile when anything changed (2 s tick),
// a full verify every minute, statistics every 5 s for quotas, and the
// device cache written to flash when due. It returns when ctx ends.
func (e *Engine) Run(ctx context.Context) {
	e.LoadDevices()
	e.Reconcile("start", true)
	tick := time.NewTicker(neighborInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			e.flush(true)
			return
		case <-e.kick:
			e.Reconcile("devices", false)
		case <-tick.C:
			e.Reconcile("tick", false)
			e.mu.Lock()
			stale := e.sys.Now().Sub(e.kernelAt) >= statsInterval
			e.mu.Unlock()
			if stale {
				e.Section()
			}
			e.flush(false)
		}
	}
}

// flush writes the device cache to flash when it is due (always on exit).
func (e *Engine) flush(final bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.sys.Now()
	due := e.flashDirty && (final || now.Sub(e.flashAt) >= FlashInterval)
	if !due && e.quotaDirty && (final || now.Sub(e.quotaFlashAt) >= QuotaFlashInterval) {
		due = true
	}
	if !due {
		return
	}
	data, _ := json.Marshal(e.devices)
	if err := e.sys.WriteFile(FlashDevicesPath, data, 0o600); err != nil {
		log.Printf("qos: device cache: %v", err)
		return
	}
	e.flashDirty, e.quotaDirty = false, false
	e.flashAt, e.quotaFlashAt = now, now
}

// Desired returns the last plan (nil before the first reconcile).
func (e *Engine) Desired() *Desired {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.desired
}

// Result returns the last reconcile's result.
func (e *Engine) Result() ApplyResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.result
}

// Configured reports whether perch-qos exists on this router.
func (e *Engine) Configured() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshConfigLocked()
	return e.cfg != nil && e.cfg.Present
}

// fileExists is a helper for the probe.
func (e *Engine) fileExists(p string) bool {
	_, err := e.sys.Stat(p)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}
