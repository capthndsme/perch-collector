package netcap

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// Engine is a running capture as the reconciler sees it (capture.Engine).
type Engine interface {
	Run()
	Stop()
}

// Opener starts nothing: it opens a capture for t, the n-th engine of the
// current plan (n counts the engines that will run with it, for sharing a
// flow budget). The reconciler runs Engine.Run in its own goroutine.
type Opener func(t Target, n int) (Engine, error)

// Reconciler keeps one capture engine per planned device. Engines of
// devices that stay are never touched, so their counters and flow tables
// carry on; the aggregator is shared and never reset.
type Reconciler struct {
	Discover  func() Discovery
	Selection Selection
	Sys       SysNet
	Open      Opener
	// Apply hands every new plan to the aggregator (gateway MACs, local
	// prefixes) before engines start; nil = nothing.
	Apply func(Plan)
	// Logf logs; nil = log.Printf.
	Logf func(format string, args ...any)

	mu      sync.Mutex
	running map[string]*running // by device
	plan    Plan
	planned bool
	// logged remembers the last message per network so a skip or an open
	// failure repeated every rescan is logged once.
	logged map[string]string
	closed bool
}

type running struct {
	target Target
	engine Engine
}

func (r *Reconciler) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// once logs msg for key unless it was the last message logged for it.
func (r *Reconciler) once(key, msg string) {
	if r.logged == nil {
		r.logged = map[string]string{}
	}
	if r.logged[key] == msg {
		return
	}
	r.logged[key] = msg
	r.logf("%s", msg)
}

// Reconcile looks at the router once and starts and stops engines to match.
// It returns the devices started and stopped. When netifd does not answer,
// running engines are left alone (a busy netifd must not stop the capture).
func (r *Reconciler) Reconcile() (started, stopped []string) {
	d := r.Discover()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil
	}
	if r.running == nil {
		r.running = map[string]*running{}
	}
	if !d.OK {
		r.once("netifd", "capture: netifd did not answer; keeping the current captures ("+r.devicesLocked()+")")
		return nil, nil
	}
	delete(r.logged, "netifd")
	p := MakePlan(d, r.Selection, r.Sys)
	for _, s := range p.Skipped {
		dev := ""
		if s.Device != "" {
			dev = " (" + s.Device + ")"
		}
		r.once("skip:"+s.Network, "capture: not capturing "+s.Network+dev+": "+s.Reason)
	}
	want := map[string]Target{}
	for _, t := range p.Targets {
		want[t.Device] = t
		delete(r.logged, "skip:"+t.Network)
	}
	// Stop what went away or changed network, first: a device renamed
	// between two networks must not run twice.
	for dev, run := range r.running {
		t, ok := want[dev]
		if ok && t.Network == run.target.Network {
			run.target = t
			continue
		}
		run.engine.Stop()
		delete(r.running, dev)
		stopped = append(stopped, dev)
		r.logf("capture: stopped %s (network %s)", dev, run.target.Network)
	}
	r.plan, r.planned = p, true
	if r.Apply != nil {
		r.Apply(p)
	}
	for _, t := range p.Targets {
		if _, ok := r.running[t.Device]; ok {
			continue
		}
		e, err := r.Open(t, len(p.Targets))
		if err != nil {
			r.once("open:"+t.Device, "capture: cannot capture "+t.Network+" on "+t.Device+": "+err.Error()+" (retrying every rescan)")
			continue
		}
		delete(r.logged, "open:"+t.Device)
		r.running[t.Device] = &running{target: t, engine: e}
		go e.Run()
		started = append(started, t.Device)
		r.logf("capture: capturing %s on %s", strings.Join(t.Networks, "+"), t.Device)
	}
	sort.Strings(started)
	sort.Strings(stopped)
	return started, stopped
}

// Run reconciles now, then every interval and whenever kick fires, until
// ctx ends; then it stops every engine.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration, kick <-chan struct{}) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	r.Reconcile()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.Close()
			return
		case <-t.C:
		case <-kick:
		}
		r.Reconcile()
	}
}

// Close stops every engine; later Reconcile calls do nothing.
func (r *Reconciler) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for dev, run := range r.running {
		run.engine.Stop()
		delete(r.running, dev)
	}
}

// Captured maps each captured device to its network.
func (r *Reconciler) Captured() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.running))
	for dev, run := range r.running {
		out[dev] = run.target.Network
	}
	return out
}

// Plan is the last plan (ok false before the first one).
func (r *Reconciler) Plan() (Plan, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.plan, r.planned
}

// Devices renders the captured devices for a log line or the hello's
// capture interface: "br-lan,br-guest", sorted by network.
func (r *Reconciler) Devices() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.devicesLocked()
}

func (r *Reconciler) devicesLocked() string {
	type pair struct{ network, dev string }
	var list []pair
	for dev, run := range r.running {
		list = append(list, pair{run.target.Network, dev})
	}
	sort.Slice(list, func(a, b int) bool { return list[a].network < list[b].network })
	names := make([]string, len(list))
	for i, p := range list {
		names[i] = p.dev
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// FitInterfaceList shortens a comma-separated device list to at most max
// bytes, ending in "+N" for the N devices left out (the controller keeps 64
// characters of a collector's capture interface).
func FitInterfaceList(list string, max int) string {
	if len(list) <= max {
		return list
	}
	parts := strings.Split(list, ",")
	for keep := len(parts) - 1; keep >= 1; keep-- {
		s := strings.Join(parts[:keep], ",") + ",+" + itoa(len(parts)-keep)
		if len(s) <= max {
			return s
		}
	}
	if len(parts[0]) > max {
		return parts[0][:max]
	}
	return parts[0]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
