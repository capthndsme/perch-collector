package gwconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"

	"github.com/capthndsme/perch-collector/internal/netcap"
	"github.com/capthndsme/perch-collector/internal/observe"
)

// Apply checks (gateway-sync protocol 1): a job may carry health checks
// that the router runs itself after the commit. The confirm is refused
// until every check passed (or was skipped because it already failed before
// the job), and when a required one cannot pass within its budget the agent
// rolls back at once (reason checks_failed) instead of waiting for the
// deadline. This is the WAN safety net: a controller on the LAN proves
// nothing about the internet by reconnecting.
//
//	validate … simulate (unchanged)
//	baseline   every item once, before anything is staged: a failure is
//	           `skipped` (not the job's fault) unless mustPass
//	commit, reply pending_confirm {checks: {state: pending, baseline}}
//	Settle, reconnect (unchanged); the budget starts
//	rounds     every item not passed or skipped, in parallel, every 3 s
//	  all passed or skipped        -> passed (confirm allowed)
//	  budget over, one not passed  -> failed, rollback now (checks_failed)
//	confirm    refused (checks_pending / checks_failed) unless passed, or
//	           overrideChecks (state overridden)
//
// A job without checks that changes an uplink interface (a WAN proto, or one
// holding a default route now) gets the agent's own net, one default_route
// check: an old or buggy controller cannot take that away, only an explicit
// `"checks":{"v":1,"items":[]}`.
//
// State is kept in the pending record (checks, checkState) on every item
// that passes and on every change of the set's state, so a restarted daemon
// re-runs what has not passed with what is left of the budget; a restart
// never counts as a pass.

func init() { builtFeatures = append(builtFeatures, FeatureChecksV1) }

// Timing of the checks.
const (
	// checkRetry is the pause between two rounds.
	checkRetry = 3 * time.Second
	// checkNoteEvery bounds gateway.config.checks while running.
	checkNoteEvery = 5 * time.Second
	// checkBudgetGuard: the budget ends at least this long before the
	// confirm deadline, so a failure is a checks_failed rollback, never a
	// confirm_timeout one.
	checkBudgetGuard = 2 * time.Second
	// checkProbeMax bounds one probe (ping waits 2 s, a TCP connect 3 s).
	checkProbeMax = 8 * time.Second
	// checkDetailMax bounds an item's detail, in bytes.
	checkDetailMax = 200
)

// The agent's own net (protocol 1.6).
const (
	AgentRouteCheckID  = "agent:route4"
	agentChecksSeconds = 90
)

// Refusal codes of confirm while checks gate it.
const (
	CodeChecksPending = "checks_pending"
	CodeChecksFailed  = "checks_failed"
)

// checkStateRecord is the checks' state, in the pending record.
type checkStateRecord struct {
	State string `json:"state"`
	// StartedAt: when the budget started (nil before).
	StartedAt *time.Time `json:"startedAt,omitempty"`
	// TimeoutSeconds is the granted budget.
	TimeoutSeconds int               `json:"timeoutSeconds"`
	AgentAdded     bool              `json:"agentAdded,omitempty"`
	AllSkipped     bool              `json:"allSkipped,omitempty"`
	Items          []CheckItemResult `json:"items"`
	Baseline       []CheckItemResult `json:"baseline"`
}

func (s *checkStateRecord) clone() *checkStateRecord {
	if s == nil {
		return nil
	}
	c := *s
	c.Items = append([]CheckItemResult(nil), s.Items...)
	c.Baseline = append([]CheckItemResult(nil), s.Baseline...)
	if s.StartedAt != nil {
		t := *s.StartedAt
		c.StartedAt = &t
	}
	return &c
}

func (s *checkStateRecord) view() *ChecksView {
	if s == nil {
		return nil
	}
	v := &ChecksView{State: s.State, TimeoutSeconds: s.TimeoutSeconds, AllSkipped: s.AllSkipped,
		Items: append([]CheckItemResult{}, s.Items...)}
	if s.StartedAt != nil {
		v.StartedAt = s.StartedAt.UTC().Format(time.RFC3339)
	}
	return v
}

// terminal: the set will not change any more.
func terminalChecks(state string) bool {
	return state == CheckPassed || state == CheckFailed || state == CheckOverridden
}

// checkRun is one apply's running checks.
type checkRun struct {
	applyID   string
	items     []CheckItem
	st        *checkStateRecord
	rec       *pendingRecord
	budgetEnd time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	// roundStop and budgetStop stop the pending timers.
	roundStop  func() bool
	budgetStop func() bool
	stopped    bool
	lastNote   time.Time
	noteDue    bool
}

type checksHolder struct {
	mu  sync.Mutex
	run *checkRun
}

func strp(s string) *string { return &s }

func clip(s string) string {
	if len(s) <= checkDetailMax {
		return s
	}
	cut := checkDetailMax - len("…")
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// effectiveChecks are the checks an apply runs: the controller's, none when
// it said so explicitly, else the agent's own net when the job changes an
// uplink (agentAdded).
func (p *Plane) effectiveChecks(ctx context.Context, a *ApplyParams, sim *simulation, current map[string]*uci.Config) (c *Checks, agentAdded bool) {
	if a.Checks != nil {
		if len(a.Checks.Items) == 0 {
			return nil, false
		}
		cp := *a.Checks
		cp.Items = append([]CheckItem(nil), a.Checks.Items...)
		return &cp, false
	}
	if hit, where := p.touchesUplink(ctx, sim, current); hit {
		log.Printf("config plane: apply %s changes the uplink %s without checks: adding the agent's default-route check", a.ApplyID, where)
		return &Checks{V: ChecksVersion, TimeoutSeconds: agentChecksSeconds,
			Items: []CheckItem{{ID: AgentRouteCheckID, Kind: CheckDefaultRoute, Family: 4}}}, true
	}
	return nil, false
}

// touchesUplink reports whether a job changes, before or after it, a network
// interface with a WAN proto or one holding a default route now, or the
// device section such an interface uses.
func (p *Plane) touchesUplink(ctx context.Context, sim *simulation, current map[string]*uci.Config) (bool, string) {
	touched := sim.touched["network"]
	if len(touched) == 0 {
		return false, ""
	}
	before, after := current["network"], sim.desired["network"]
	section := func(c *uci.Config, name string) *uci.Section {
		if c == nil {
			return nil
		}
		return c.Section(name)
	}
	routed := map[string]bool{}
	if raw, err := p.ubusCall(ctx, "network.interface", "dump"); err == nil {
		if list, ok := observe.ParseInterfaceDump(raw); ok {
			for _, i := range list {
				if i.DefaultRoute {
					routed[i.Network] = true
				}
			}
		}
	}
	uplink := func(s *uci.Section) bool {
		if s == nil || s.Type != "interface" {
			return false
		}
		proto, _ := s.Get("proto")
		return routed[s.Name] || netcap.IsWANProto(proto.Str())
	}
	// The devices uplinks use, before and after.
	upDev := map[string]bool{}
	for _, c := range []*uci.Config{before, after} {
		if c == nil {
			continue
		}
		for _, s := range c.Sections {
			if uplink(s) {
				if d, _ := s.Get("device"); d.Str() != "" {
					upDev[d.Str()] = true
				}
			}
		}
	}
	names := make([]string, 0, len(touched))
	for n := range touched {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b, a := section(before, n), section(after, n)
		if b != nil && a != nil && b.Type == a.Type && bytes.Equal(uci.Canonical(b, nil), uci.Canonical(a, nil)) {
			continue
		}
		for _, s := range []*uci.Section{b, a} {
			if uplink(s) {
				return true, "network." + n
			}
			if s != nil && s.Type == "device" {
				if d, _ := s.Get("name"); upDev[d.Str()] {
					return true, "network." + n
				}
			}
		}
	}
	return false, ""
}

// runBaseline runs every item once before anything is staged: the baseline
// list, and the initial state (a failed item skipped unless mustPass).
func (p *Plane) runBaseline(ctx context.Context, c *Checks, secs int, agentAdded bool) *checkStateRecord {
	budget := c.TimeoutSeconds
	if max := secs - ChecksMargin; budget > max {
		budget = max
	}
	if budget < MinChecksSeconds {
		budget = MinChecksSeconds
	}
	st := &checkStateRecord{State: CheckPending, TimeoutSeconds: budget, AgentAdded: agentAdded}
	results := p.probeAll(ctx, c.Items, time.Time{})
	at := strp(p.clock.Now().UTC().Format(time.RFC3339))
	for i, it := range c.Items {
		r := results[i]
		b := CheckItemResult{ID: it.ID, Detail: strp(r.detail), At: at}
		item := CheckItemResult{ID: it.ID, State: CheckPending}
		switch {
		case r.ok:
			b.State = CheckPassed
		case it.MustPass:
			b.State = CheckFailed
		default:
			b.State = CheckSkipped
			item = CheckItemResult{ID: it.ID, State: CheckSkipped, Detail: strp(clip("failed before the job: " + r.detail)), At: at}
		}
		st.Baseline = append(st.Baseline, b)
		st.Items = append(st.Items, item)
	}
	st.AllSkipped = allSkipped(c.Items, st.Items)
	return st
}

// allSkipped: every item that is not mustPass was skipped (and there is at
// least one).
func allSkipped(items []CheckItem, st []CheckItemResult) bool {
	n := 0
	for i, it := range items {
		if it.MustPass {
			continue
		}
		n++
		if st[i].State != CheckSkipped {
			return false
		}
	}
	return n > 0
}

// startChecks starts (or, after a restart, resumes) the checks of a pending
// apply. The budget runs from now, or for a resumed run from its first
// start; it always ends before the deadline.
func (p *Plane) startChecks(rec *pendingRecord) {
	if rec.Checks == nil || len(rec.Checks.Items) == 0 || rec.CheckState == nil {
		return
	}
	st := rec.CheckState.clone()
	if terminalChecks(st.State) {
		return
	}
	now := p.clock.Now()
	if st.StartedAt == nil {
		t := now
		st.StartedAt = &t
	}
	budgetEnd := st.StartedAt.Add(time.Duration(st.TimeoutSeconds) * time.Second)
	if limit := rec.Deadline.Add(-checkBudgetGuard); budgetEnd.After(limit) {
		budgetEnd = limit
	}
	// Whatever was running when the daemon stopped runs again: only passed
	// and skipped items are kept.
	for i := range st.Items {
		if s := st.Items[i].State; s != CheckPassed && s != CheckSkipped {
			st.Items[i].State = CheckPending
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &checkRun{applyID: rec.ApplyID, items: rec.Checks.Items, st: st, rec: rec, budgetEnd: budgetEnd, ctx: ctx, cancel: cancel}
	p.chk.mu.Lock()
	if old := p.chk.run; old != nil {
		p.stopRunLocked(old)
	}
	p.chk.run = run
	done := p.evaluateLocked(run)
	if !done {
		st.State = CheckRunning
	}
	p.persistLocked(run)
	over := !done && !budgetEnd.After(now)
	if !done && !over {
		run.budgetStop = p.clock.AfterFunc(budgetEnd.Sub(now), func() { p.checksBudgetOver(run) })
		run.roundStop = p.clock.AfterFunc(0, func() { p.checkRound(run) })
	}
	note := p.noteLocked(run, true)
	p.chk.mu.Unlock()
	log.Printf("config plane: apply %s: checks %s (%d items, budget until %s)", rec.ApplyID, st.State, len(run.items), budgetEnd.UTC().Format(time.RFC3339))
	p.sendNote(note)
	if over {
		// Resumed after the budget ran out: no round may pass it now.
		p.checksBudgetOver(run)
	}
}

// evaluateLocked marks the set passed when every item passed or was
// skipped, and reports whether it is done.
func (p *Plane) evaluateLocked(run *checkRun) bool {
	for _, it := range run.st.Items {
		if it.State != CheckPassed && it.State != CheckSkipped {
			return false
		}
	}
	run.st.State = CheckPassed
	run.st.AllSkipped = allSkipped(run.items, run.st.Items)
	p.stopRunLocked(run)
	return true
}

// checkRound runs every item that has not passed once, in parallel.
func (p *Plane) checkRound(run *checkRun) {
	p.chk.mu.Lock()
	if run.stopped || p.chk.run != run {
		p.chk.mu.Unlock()
		return
	}
	var idx []int
	var items []CheckItem
	for i, it := range run.st.Items {
		if it.State == CheckPassed || it.State == CheckSkipped {
			continue
		}
		if it.State == CheckPending {
			run.st.Items[i].State = CheckRunning
			run.noteDue = true
		}
		idx = append(idx, i)
		items = append(items, run.items[i])
	}
	started := *run.st.StartedAt
	ctx := run.ctx
	p.chk.mu.Unlock()

	results := p.probeAll(ctx, items, started)

	p.chk.mu.Lock()
	if run.stopped || p.chk.run != run {
		p.chk.mu.Unlock()
		return
	}
	at := strp(p.clock.Now().UTC().Format(time.RFC3339))
	passedOne := false
	for k, i := range idx {
		r := results[k]
		cur := &run.st.Items[i]
		if r.ok {
			*cur = CheckItemResult{ID: cur.ID, State: CheckPassed, Detail: strp(r.detail), At: at}
			passedOne, run.noteDue = true, true
			continue
		}
		if cur.Detail == nil || *cur.Detail != r.detail {
			run.noteDue = true
		}
		cur.Detail, cur.At = strp(r.detail), at
	}
	done := p.evaluateLocked(run)
	if passedOne || done {
		p.persistLocked(run)
	}
	if !done {
		run.roundStop = p.clock.AfterFunc(checkRetry, func() { p.checkRound(run) })
	}
	note := p.noteLocked(run, done)
	p.chk.mu.Unlock()
	if done {
		log.Printf("config plane: apply %s: checks passed%s", run.applyID, map[bool]string{true: " (every optional check was skipped)", false: ""}[run.st.AllSkipped])
	}
	p.sendNote(note)
}

// checksBudgetOver ends a run whose budget is over: an item that has not
// passed has failed, and the apply is rolled back now.
func (p *Plane) checksBudgetOver(run *checkRun) {
	p.chk.mu.Lock()
	if run.stopped || p.chk.run != run || terminalChecks(run.st.State) {
		p.chk.mu.Unlock()
		return
	}
	at := strp(p.clock.Now().UTC().Format(time.RFC3339))
	var failed []string
	for i := range run.st.Items {
		it := &run.st.Items[i]
		if it.State == CheckPassed || it.State == CheckSkipped {
			continue
		}
		d := "no result within the budget"
		if it.Detail != nil && *it.Detail != "" {
			d = *it.Detail
		}
		*it = CheckItemResult{ID: it.ID, State: CheckFailed, Detail: strp(d), At: at}
		failed = append(failed, it.ID+": "+d)
	}
	run.st.State = CheckFailed
	p.persistLocked(run)
	p.stopRunLocked(run)
	note := p.noteLocked(run, true)
	p.chk.mu.Unlock()
	detail := strings.Join(failed, "; ")
	if len(detail) > 2*checkDetailMax {
		detail = detail[:2*checkDetailMax] + "…"
	}
	log.Printf("config plane: apply %s: checks failed (%s); rolling back before the deadline", run.applyID, detail)
	p.sendNote(note)
	p.rollbackPendingDetail(run.applyID, ReasonChecksFailed, detail)
}

// stopRunLocked stops a run's timers and probes. Caller holds p.chk.mu.
func (p *Plane) stopRunLocked(run *checkRun) {
	run.stopped = true
	if run.roundStop != nil {
		run.roundStop()
	}
	if run.budgetStop != nil {
		run.budgetStop()
	}
	run.cancel()
}

// stopChecks ends the checks of an apply that is being confirmed or rolled
// back, and returns their state as it stands (nil without checks).
func (p *Plane) stopChecks(id string, rec *pendingRecord) *ChecksView {
	p.chk.mu.Lock()
	defer p.chk.mu.Unlock()
	if run := p.chk.run; run != nil && run.applyID == id {
		p.stopRunLocked(run)
		p.chk.run = nil
		return run.st.view()
	}
	if rec != nil && rec.CheckState != nil {
		return rec.CheckState.view()
	}
	return nil
}

// checksStateLocked is an apply's checks state: from the run, else from the
// record; "" without checks. Caller holds p.chk.mu.
func (p *Plane) checksStateLocked(rec *pendingRecord) *checkStateRecord {
	if rec == nil || rec.Checks == nil || len(rec.Checks.Items) == 0 {
		return nil
	}
	if run := p.chk.run; run != nil && run.applyID == rec.ApplyID {
		return run.st
	}
	return rec.CheckState
}

// checksGate decides a confirm of rec: nil when it may go on. With override
// the checks end as overridden. Caller holds p.ap.mu (lock order ap, chk).
func (p *Plane) checksGate(rec *pendingRecord, override bool) error {
	p.chk.mu.Lock()
	st := p.checksStateLocked(rec)
	if st == nil || st.State == CheckPassed || st.State == CheckOverridden {
		p.chk.mu.Unlock()
		return nil
	}
	if override {
		if run := p.chk.run; run != nil && run.applyID == rec.ApplyID {
			p.stopRunLocked(run)
		}
		st.State = CheckOverridden
		p.chk.mu.Unlock()
		log.Printf("config plane: apply %s: confirmed with its checks overridden", rec.ApplyID)
		return nil
	}
	view := st.view()
	p.chk.mu.Unlock()
	code := CodeChecksPending
	if st.State == CheckFailed {
		code = CodeChecksFailed
	}
	e := perr(code, "the apply's checks have not passed (%s); confirm with overrideChecks to keep it anyway", view.State)
	e.Data = map[string]any{"checks": view}
	return e
}

// checksView is the pending apply's checks for the hello (nil without).
func (p *Plane) checksViewOf(rec *pendingRecord) *ChecksView {
	p.chk.mu.Lock()
	defer p.chk.mu.Unlock()
	return p.checksStateLocked(rec).view()
}

// checksReply is the apply reply's checks.
func (p *Plane) checksReply(rec *pendingRecord) *ChecksReply {
	p.chk.mu.Lock()
	defer p.chk.mu.Unlock()
	st := p.checksStateLocked(rec)
	if st == nil {
		return nil
	}
	return &ChecksReply{State: st.State, TimeoutSeconds: st.TimeoutSeconds, AgentAdded: st.AgentAdded,
		Baseline: append([]CheckItemResult{}, st.Baseline...)}
}

// persistLocked writes the run's state into the pending record. Never after
// the run stopped: the record may be gone by then (confirmed or restored).
func (p *Plane) persistLocked(run *checkRun) {
	if run.stopped && run.st.State != CheckFailed && run.st.State != CheckPassed {
		return
	}
	if p.chk.run != run {
		return
	}
	cp := *run.rec
	cp.CheckState = run.st.clone()
	if err := p.store().writePending(&cp); err != nil {
		log.Printf("config plane: apply %s: recording the checks: %v", run.applyID, err)
	}
}

// noteLocked builds gateway.config.checks when one is due: always when
// force (a change of the set's state), else at most every checkNoteEvery.
func (p *Plane) noteLocked(run *checkRun, force bool) *ChecksNote {
	now := p.clock.Now()
	if !force && (!run.noteDue || now.Sub(run.lastNote) < checkNoteEvery) {
		return nil
	}
	run.lastNote, run.noteDue = now, false
	n := &ChecksNote{ApplyID: run.applyID, State: run.st.State, AllSkipped: run.st.AllSkipped,
		Items: append([]CheckItemResult{}, run.st.Items...)}
	if run.st.StartedAt != nil {
		n.StartedAt = run.st.StartedAt.UTC().Format(time.RFC3339)
		n.ElapsedSeconds = float64(now.Sub(*run.st.StartedAt).Milliseconds()) / 1000
	}
	return n
}

func (p *Plane) sendNote(n *ChecksNote) {
	if n == nil {
		return
	}
	if h := p.hooksNow(); h.Checks != nil {
		h.Checks(*n)
	}
}

// probeResult is one probe's outcome.
type probeResult struct {
	ok     bool
	detail string
}

// probeAll runs items in parallel. since is when the budget started (zero
// for the baseline): interface_up reports how long it took.
func (p *Plane) probeAll(ctx context.Context, items []CheckItem, since time.Time) []probeResult {
	out := make([]probeResult, len(items))
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Add(1)
		go func(i int, it CheckItem) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, checkProbeMax)
			defer cancel()
			ok, detail := p.probe(pctx, it, since)
			out[i] = probeResult{ok: ok, detail: clip(detail)}
		}(i, it)
	}
	wg.Wait()
	return out
}

func (p *Plane) probe(ctx context.Context, it CheckItem, since time.Time) (bool, string) {
	switch it.Kind {
	case CheckInterfaceUp:
		return p.probeInterfaceUp(ctx, it, since)
	case CheckDefaultRoute:
		return p.probeDefaultRoute(ctx, it)
	case CheckReach:
		return p.probeReach(ctx, it)
	case CheckResolve:
		return p.probeResolve(ctx, it)
	case CheckWGHandshake:
		return p.probeWGHandshake(ctx, it)
	}
	return false, "unknown kind " + it.Kind
}

// ifaceStatus is `ubus call network.interface.<net> status`.
type ifaceStatus struct {
	Up       bool   `json:"up"`
	L3Device string `json:"l3_device"`
	Device   string `json:"device"`
	IPv4     []struct {
		Address string `json:"address"`
		Mask    int    `json:"mask"`
	} `json:"ipv4-address"`
	IPv6 []struct {
		Address string `json:"address"`
		Mask    int    `json:"mask"`
	} `json:"ipv6-address"`
	IPv6Prefix []struct {
		Address string `json:"address"`
		Mask    int    `json:"mask"`
	} `json:"ipv6-prefix"`
	Route []struct {
		Target  string `json:"target"`
		Mask    int    `json:"mask"`
		Nexthop string `json:"nexthop"`
	} `json:"route"`
	Errors []struct {
		Code string `json:"code"`
	} `json:"errors"`
}

func (p *Plane) ubusCall(ctx context.Context, object, method string) ([]byte, error) {
	ctx, cancel := p.callCtx(ctx)
	defer cancel()
	return p.ubus.CallRaw(ctx, object, method, nil)
}

func (p *Plane) status(ctx context.Context, network string) (*ifaceStatus, error) {
	raw, err := p.ubusCall(ctx, "network.interface."+network, "status")
	if err != nil {
		return nil, err
	}
	var st ifaceStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// l3 is the interface's L3 device ("" when it has none).
func (st *ifaceStatus) l3() string {
	if st.L3Device != "" {
		return st.L3Device
	}
	return st.Device
}

// gateway is the interface's default route next hop for a family.
func (st *ifaceStatus) gateway(family int) string {
	for _, r := range st.Route {
		if r.Mask != 0 {
			continue
		}
		if (family == 4 && r.Target == "0.0.0.0") || (family == 6 && r.Target == "::") {
			if ip := net.ParseIP(r.Nexthop); ip != nil && !ip.IsUnspecified() {
				return ip.String()
			}
		}
	}
	return ""
}

func famName(f int) string {
	if f == 6 {
		return "IPv6"
	}
	return "IPv4"
}

func (p *Plane) probeInterfaceUp(ctx context.Context, it CheckItem, since time.Time) (bool, string) {
	st, err := p.status(ctx, it.Network)
	if err != nil {
		return false, it.Network + ": no such interface"
	}
	if !st.Up {
		d := it.Network + " is down"
		if len(st.Errors) > 0 && st.Errors[0].Code != "" {
			d += " (" + st.Errors[0].Code + ")"
		}
		return false, d
	}
	addr := ""
	if it.family() == 4 && len(st.IPv4) > 0 {
		addr = st.IPv4[0].Address + "/" + strconv.Itoa(st.IPv4[0].Mask)
	}
	if it.family() == 6 {
		if len(st.IPv6) > 0 {
			addr = st.IPv6[0].Address + "/" + strconv.Itoa(st.IPv6[0].Mask)
		} else if len(st.IPv6Prefix) > 0 {
			addr = "prefix " + st.IPv6Prefix[0].Address + "/" + strconv.Itoa(st.IPv6Prefix[0].Mask)
		}
	}
	if addr == "" {
		return false, fmt.Sprintf("%s is up without an %s address", it.Network, famName(it.family()))
	}
	if since.IsZero() {
		return true, "up, " + addr
	}
	return true, fmt.Sprintf("up after %.1f s, %s", p.clock.Now().Sub(since).Seconds(), addr)
}

func (p *Plane) probeDefaultRoute(ctx context.Context, it CheckItem) (bool, string) {
	dev := ""
	if it.Network != "" {
		st, err := p.status(ctx, it.Network)
		if err != nil || st.l3() == "" {
			return false, "no " + famName(it.family()) + " default route: " + it.Network + " has no device"
		}
		dev = st.l3()
	}
	args := []string{"route", "show", "default"}
	if it.family() == 6 {
		args = append([]string{"-6"}, args...)
	}
	stdout, _, code, err := p.run(ctx, "ip", args...)
	if err != nil || code != 0 {
		return false, "ip route: failed"
	}
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "default") {
			continue
		}
		if dev != "" && routeDevice(line) != dev {
			continue
		}
		return true, line
	}
	if dev != "" {
		return false, fmt.Sprintf("no %s default route through %s", famName(it.family()), dev)
	}
	return false, "no " + famName(it.family()) + " default route"
}

// reachTarget is one address to reach; dev, for a link-local next hop,
// is the device it lives on.
type reachTarget struct {
	ip  string
	dev string
}

func (p *Plane) probeReach(ctx context.Context, it CheckItem) (bool, string) {
	var targets []reachTarget
	var unresolved []string
	for _, t := range it.Targets {
		if n, ok := strings.CutPrefix(t, GatewayTargetPrefix); ok {
			st, err := p.status(ctx, n)
			if err == nil {
				if gw := st.gateway(it.family()); gw != "" {
					rt := reachTarget{ip: gw}
					if ip := net.ParseIP(gw); ip != nil && ip.IsLinkLocalUnicast() {
						rt.dev = st.l3()
					}
					targets = append(targets, rt)
					continue
				}
			}
			unresolved = append(unresolved, t)
			continue
		}
		targets = append(targets, reachTarget{ip: t})
	}
	if len(targets) == 0 {
		return false, "no target (" + strings.Join(unresolved, ", ") + " unknown)"
	}
	dev := ""
	if it.Via != "" {
		st, err := p.status(ctx, it.Via)
		if err != nil || st.l3() == "" {
			return false, "via " + it.Via + ": no device"
		}
		dev = st.l3()
	}
	type answer struct {
		ok     bool
		detail string
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan answer, 2*len(targets))
	n := 0
	for _, t := range targets {
		t := t
		tdev := dev
		if tdev == "" {
			tdev = t.dev
		}
		n++
		go func() {
			args := []string{"-c", "1", "-W", "2"}
			if tdev != "" {
				args = append(args, "-I", tdev)
			}
			_, _, code, err := p.run(ctx, "ping", append(args, t.ip)...)
			if err == nil && code == 0 {
				ch <- answer{true, t.ip + " answered (icmp)"}
				return
			}
			ch <- answer{false, ""}
		}()
		if it.TCPPort > 0 {
			n++
			go func() {
				dctx, dcancel := context.WithTimeout(ctx, 3*time.Second)
				defer dcancel()
				host := t.ip
				if t.dev != "" {
					host += "%" + t.dev
				}
				addr := net.JoinHostPort(host, strconv.Itoa(it.TCPPort))
				if err := p.dialCheck(dctx, addr, dev); err != nil {
					ch <- answer{false, tcpFailure(err)}
					return
				}
				ch <- answer{true, addr + " connected (tcp)"}
			}()
		}
	}
	tcp := ""
	for i := 0; i < n; i++ {
		a := <-ch
		if a.ok {
			return true, a.detail
		}
		if a.detail != "" && tcp == "" {
			tcp = a.detail
		}
	}
	d := fmt.Sprintf("no answer from %d target", len(targets))
	if len(targets) != 1 {
		d += "s"
	}
	if it.TCPPort > 0 && tcp != "" {
		d += fmt.Sprintf("; tcp %d %s", it.TCPPort, tcp)
	}
	if len(unresolved) > 0 {
		d += "; " + strings.Join(unresolved, ", ") + " unknown"
	}
	return false, d
}

func tcpFailure(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "timed out"
	case strings.Contains(s, "unreachable"):
		return "unreachable"
	}
	return "failed"
}

func (p *Plane) dialCheck(ctx context.Context, addr, dev string) error {
	if p.o.CheckDial != nil {
		return p.o.CheckDial(ctx, "tcp", addr, dev)
	}
	d := net.Dialer{}
	if dev != "" {
		d.Control = bindToDevice(dev)
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

func (p *Plane) probeResolve(ctx context.Context, it CheckItem) (bool, string) {
	network := "ip4"
	if it.family() == 6 {
		network = "ip6"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var ips []net.IP
	var err error
	if p.o.CheckResolve != nil {
		ips, err = p.o.CheckResolve(ctx, network, it.Name)
	} else {
		ips, err = (&net.Resolver{PreferGo: true}).LookupIP(ctx, network, it.Name)
	}
	if err != nil || len(ips) == 0 {
		why := "no address"
		if err != nil {
			why = err.Error()
			if de, ok := err.(*net.DNSError); ok {
				why = de.Err
			}
		}
		return false, it.Name + ": " + why
	}
	return true, it.Name + " → " + ips[0].String()
}

func (p *Plane) probeWGHandshake(ctx context.Context, it CheckItem) (bool, string) {
	dev := it.Network
	if st, err := p.status(ctx, it.Network); err == nil && st.l3() != "" {
		dev = st.l3()
	}
	// latest-handshakes prints public keys and times only; `wg show … dump`
	// would print the private key and is never run.
	stdout, _, code, err := p.run(ctx, "wg", "show", dev, "latest-handshakes")
	if err != nil || code != 0 {
		return false, dev + ": no WireGuard interface"
	}
	now := p.clock.Now().Unix()
	within := int64(it.WithinSeconds)
	best := int64(-1)
	found := false
	for _, line := range strings.Split(string(stdout), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if it.PublicKey != "" && f[0] != it.PublicKey {
			continue
		}
		found = true
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || ts <= 0 {
			continue
		}
		age := now - ts
		if age < 0 {
			age = 0 // clocks a few seconds apart
		}
		if age <= within && (best < 0 || age < best) {
			best = age
		}
	}
	switch {
	case best >= 0:
		return true, fmt.Sprintf("handshake %d s ago", best)
	case it.PublicKey != "" && !found:
		return false, "peer not configured on " + dev
	case !found:
		return false, dev + " has no peers"
	}
	return false, fmt.Sprintf("no handshake within %d s", within)
}
