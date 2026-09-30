package gwconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// The apply engine (plan 1 section 3.4): validate, snapshot to flash,
// stage in a private area, commit in apply order, then drop the session
// and dial a fresh one; the controller confirms on the new session, or the
// agent restores the snapshot at the deadline on its own. One apply (or
// package job) at a time.

// Clock is the engine's time source; tests use a fake one.
type Clock interface {
	Now() time.Time
	// AfterFunc runs f after d; the returned func stops it.
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}

// Hooks connect the engine to the session loop (internal/controller).
type Hooks struct {
	// Reconnect closes the current session and dials a fresh one at once
	// (plan 1 section 3.4 step 5).
	Reconnect func(reason string)
	// Result sends gateway.config.result on the current session; false when
	// there is none (the outcome then waits in the hello's results).
	Result func(Result) bool
	// PairState sends gateway.pair.state on the current session; false
	// when there is none (the next hello's signing block tells).
	PairState func(PairStateNote) bool
	// Checks sends gateway.config.checks on the current session; false
	// when there is none (the hello's apply.checks tells).
	Checks func(ChecksNote) bool
}

// SessionRef identifies the session a request came in on.
type SessionRef struct {
	// Gen is the session's number in this process, counting from 1; 0 =
	// unknown or ended.
	Gen uint64
	// Challenge is the session's signing challenge (sign.go).
	Challenge string
}

// applier is the engine's state.
type applier struct {
	mu      sync.Mutex
	state   string
	pending *pendingRecord
	// applyGen is the session the pending apply was made on; a confirm must
	// come on a later one. anyGen: the apply was made by an earlier process
	// (daemon restart), so every session of this one is new.
	applyGen uint64
	anyGen   bool
	stop     func() bool
	// lastConfirmed makes a repeated confirm idempotent.
	lastConfirmed       string
	lastConfirmedHashes map[string]string
	// redialUntil: after an apply or a rollback the session loop redials
	// fast until then (RedialFast).
	redialUntil time.Time
}

func (p *Plane) store() store { return store{root: p.o.Root} }

// SetHooks connects the engine to the session loop.
func (p *Plane) SetHooks(h Hooks) {
	p.ap.mu.Lock()
	p.hooks = h
	p.ap.mu.Unlock()
}

func (p *Plane) hooksNow() Hooks {
	p.ap.mu.Lock()
	defer p.ap.mu.Unlock()
	return p.hooks
}

// ApplyState is the current apply for the hello and capabilities.
func (p *Plane) ApplyState() ApplyState {
	p.ap.mu.Lock()
	defer p.ap.mu.Unlock()
	st := ApplyState{State: StateIdle}
	if p.ap.pending != nil && (p.ap.state == StatePendingConfirm || p.ap.state == StateRollingBack) {
		st = ApplyState{State: p.ap.state, ApplyID: p.ap.pending.ApplyID, Kind: p.ap.pending.Kind,
			Deadline: p.ap.pending.Deadline.UTC().Format(time.RFC3339), Protected: p.ap.pending.Protected,
			Checks: p.checksViewOf(p.ap.pending)}
	} else if p.ap.state == StateApplying {
		st.State = StateApplying
	}
	return st
}

// Results are the outcomes the controller has not acknowledged.
func (p *Plane) Results() []Result { return p.store().readResults() }

// RedialFast: the session loop should retry every couple of seconds (an
// apply waits for its confirm on a fresh connection, or a rollback just
// happened).
func (p *Plane) RedialFast() bool {
	p.ap.mu.Lock()
	defer p.ap.mu.Unlock()
	return p.ap.state == StatePendingConfirm || p.clock.Now().Before(p.ap.redialUntil)
}

// replyGrace is the least time between an apply's reply and the session
// being dropped.
const replyGrace = 500 * time.Millisecond

// redialAfterRollback: how long the loop keeps redialing fast after a
// rollback, so the controller hears about it soon.
const redialAfterRollback = 2 * time.Minute

// Start resumes after a daemon start: a pending apply whose marker is gone
// was interrupted by a reboot and is rolled back ("reboot"); one whose
// deadline passed is rolled back ("confirm_timeout"); otherwise its timer
// is armed again and any session of this process may confirm it.
func (p *Plane) Start() {
	st := p.store()
	rec, err := st.readPending()
	if err != nil {
		log.Printf("config plane: %v; leaving it for the boot guard", err)
		return
	}
	if rec == nil {
		st.cleanStale("")
		return
	}
	st.cleanStale(rec.ApplyID)
	now := p.clock.Now()
	p.ap.mu.Lock()
	p.ap.pending, p.ap.state, p.ap.anyGen = rec, StatePendingConfirm, true
	p.ap.mu.Unlock()
	switch {
	case !st.hasMarker(rec.ApplyID):
		log.Printf("config plane: apply %s was pending when the router rebooted; restoring", rec.ApplyID)
		p.rollbackPending(rec.ApplyID, ReasonReboot, true)
	case !rec.Committed:
		// The daemon stopped between the snapshot and the end of the commit:
		// nobody knows how much of it landed, so nothing may be confirmed.
		log.Printf("config plane: apply %s was interrupted while committing; restoring", rec.ApplyID)
		p.rollbackPending(rec.ApplyID, ReasonCommitFailed, true)
	case !now.Before(rec.Deadline):
		log.Printf("config plane: apply %s passed its deadline while the daemon was down; restoring", rec.ApplyID)
		p.rollbackPending(rec.ApplyID, ReasonConfirmTimeout, true)
	case rec.CheckState != nil && rec.CheckState.State == CheckFailed:
		// The checks had failed and the daemon stopped before the restore.
		log.Printf("config plane: apply %s had failed its checks; restoring", rec.ApplyID)
		p.rollbackPendingDetail(rec.ApplyID, ReasonChecksFailed, "the checks had failed when the daemon stopped")
	default:
		log.Printf("config plane: apply %s still waits for its confirm (deadline %s)", rec.ApplyID, rec.Deadline.UTC().Format(time.RFC3339))
		p.armTimer(rec)
		// Checks that had not passed run again with what is left of their
		// budget (a restart never counts as a pass).
		p.startChecks(rec)
	}
}

func (p *Plane) armTimer(rec *pendingRecord) {
	d := rec.Deadline.Sub(p.clock.Now())
	if d < 0 {
		d = 0
	}
	id := rec.ApplyID
	stop := p.clock.AfterFunc(d, func() { p.rollbackPending(id, ReasonConfirmTimeout, true) })
	p.ap.mu.Lock()
	p.ap.stop = stop
	p.ap.mu.Unlock()
}

// reserve takes the one apply slot. For an id that is already pending it
// returns that apply (a retried request whose reply was lost).
func (p *Plane) reserve(id string) (*pendingRecord, error) {
	p.ap.mu.Lock()
	defer p.ap.mu.Unlock()
	if p.ap.state != "" && p.ap.state != StateIdle {
		if p.ap.pending != nil && p.ap.pending.ApplyID == id && p.ap.state == StatePendingConfirm {
			return p.ap.pending, nil
		}
		e := perr(CodeBusy, "another apply is in progress")
		e.Data = map[string]any{"reason": "apply_pending"}
		if p.ap.pending != nil {
			e.Data["applyId"] = p.ap.pending.ApplyID
		}
		return nil, e
	}
	p.ap.state = StateApplying
	return nil, nil
}

func (p *Plane) release() {
	p.ap.mu.Lock()
	if p.ap.state == StateApplying {
		p.ap.state = StateIdle
	}
	p.ap.mu.Unlock()
}

func busyLuci() error {
	e := perr(CodeBusy, "a LuCI apply is waiting for its confirm on the router; try again when it is confirmed or rolled back")
	e.Data = map[string]any{"reason": "luci_pending"}
	return e
}

// confirmSeconds clamps a requested window.
func (p *Plane) confirmSeconds(req *float64, protected bool) int {
	s := DefaultConfirmSeconds
	if req != nil && *req > 0 {
		s = int(*req)
	}
	if protected && s < ProtectedConfirmSeconds {
		s = ProtectedConfirmSeconds
	}
	max := p.o.ConfirmMax
	if max <= 0 {
		max = 600
	}
	if s > max {
		s = max
	}
	if s < MinConfirmSeconds {
		s = MinConfirmSeconds
	}
	return s
}

func (p *Plane) pendingResult(rec *pendingRecord) *ApplyResult {
	return &ApplyResult{State: StatePendingConfirm, ApplyID: rec.ApplyID, Deadline: rec.Deadline.UTC().Format(time.RFC3339),
		ConfirmTimeoutSeconds: rec.ConfirmSeconds, Protected: rec.Protected, Hashes: rec.HashesAfter,
		Checks: p.checksReply(rec), Generated: rec.Generated}
}

// Apply runs gateway.config.apply. secure: the transport is verified TLS,
// the only one that may carry secret values.
func (p *Plane) Apply(ctx context.Context, a *ApplyParams, sess SessionRef, secure bool) (*ApplyResult, error) {
	if !ValidApplyID(a.ApplyID) {
		return nil, perr(CodeBadParams, "invalid applyId %q", a.ApplyID)
	}
	switch a.Kind {
	case "":
		a.Kind = KindApply
	case KindApply, KindRevert, KindAdopt:
	default:
		return nil, perr(CodeBadParams, "unknown kind %q", a.Kind)
	}
	if err := validateChecks(a.Checks); err != nil {
		return nil, err
	}
	if err := checkUnsupported(a); err != nil {
		return nil, err
	}
	if p.Mode() != ModeManaged {
		return nil, &AccessError{Code: ErrNotManaged, Message: "the controller has not put this gateway in managed mode (agent.configure)"}
	}
	if rec, err := p.reserve(a.ApplyID); err != nil {
		return nil, err
	} else if rec != nil {
		return p.pendingResult(rec), nil
	}
	res, err := p.apply(ctx, a, sess, secure)
	if err != nil {
		p.release()
	}
	return res, err
}

func (p *Plane) apply(ctx context.Context, a *ApplyParams, sess SessionRef, secure bool) (*ApplyResult, error) {
	st := p.store()
	if uci.PendingState(p.o.Root).LuciPending {
		return nil, busyLuci()
	}
	// Every config an op or a ledger entry names, plus network and firewall
	// for the management-path check.
	names := map[string]bool{"network": true, "firewall": true}
	opConfigs := map[string]bool{}
	for _, op := range a.Ops {
		names[op.Config] = true
		opConfigs[op.Config] = true
	}
	for _, e := range a.Ledger.Set {
		names[e.Config] = true
	}
	current := map[string]*uci.Config{}
	hashes := map[string]string{}
	for n := range names {
		if !uci.ValidConfigName(n) {
			return nil, perr(CodeBadParams, "invalid config name %q", n)
		}
		l, err := p.files.Load(n)
		switch {
		case errors.Is(err, uci.ErrNoConfig):
			current[n], hashes[n] = nil, ""
		case err != nil:
			return nil, perr(CodeApplyFailed, "reading %s: %v", n, err)
		default:
			current[n], hashes[n] = l.Config, l.Hash
		}
	}
	// base: the hashes the controller planned against.
	var stale []string
	for c := range opConfigs {
		b, ok := a.Base[c]
		if !ok {
			return nil, perr(CodeBadParams, "base has no hash for %s", c)
		}
		if b != hashes[c] {
			stale = append(stale, c)
		}
	}
	if b, ok := a.Base[LedgerConfig]; ok && b != st.currentHash(LedgerConfig) {
		stale = append(stale, LedgerConfig)
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		e := perr(CodeStaleBase, "the router's config changed since the controller read it: %v", stale)
		e.Data = map[string]any{"configs": stale, "hashes": p.Hashes()}
		return nil, e
	}
	ledgerNow, err := p.readLedger()
	if err != nil {
		return nil, perr(CodeApplyFailed, "reading the ledger: %v", err)
	}
	// A dry run stages a placeholder for a generated value: no key is made
	// for a job that is not kept.
	gen := p.genValue
	if a.DryRun {
		gen = placeholderValue
	}
	sim, err := simulate(simInput{current: current, ledger: ledgerNow, params: a, writable: p.writable, generate: gen})
	if err != nil {
		return nil, err
	}
	if err := validateApply(sim.configs, func(name string) *uci.Config {
		if c, ok := sim.desired[name]; ok {
			return c
		}
		if c, ok := current[name]; ok {
			return c
		}
		if l, err := p.files.Load(name); err == nil {
			return l.Config
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if sim.usesSecrets && !secure {
		return nil, &AccessError{Code: ErrInsecure, Message: "secret values are only accepted over verified TLS"}
	}
	for _, c := range sim.configs {
		if c != "network" {
			continue
		}
		if lines := foreignStaged(p.o.Root, c); len(lines) > 0 {
			e := perr("foreign_staged", "%s has uncommitted changes staged on the router (uci set without commit); a reload would make them live", c)
			e.Data = map[string]any{"config": c, "changes": lines}
			return nil, e
		}
	}
	functional := false
	for _, c := range sim.configs {
		if sim.changed(current, c) {
			functional = true
		}
	}
	now := p.clock.Now()

	if a.DryRun {
		changes := []ChangeEntry{}
		if len(sim.configs) > 0 {
			stager, err := p.backend.Stager(ctx, sim.configs, a.ApplyID)
			if err != nil {
				return nil, perr(CodeApplyFailed, "%v", err)
			}
			err = stage(ctx, stager, sim)
			if err == nil {
				changes, err = changesOf(ctx, stager, sim)
			}
			_ = stager.Close(ctx)
			if err != nil {
				return nil, stageError(err)
			}
		}
		p.release()
		return &ApplyResult{State: StateDryRun, ApplyID: a.ApplyID, Changes: changes}, nil
	}

	if !functional {
		if !sim.ledgerChanged {
			p.release()
			return &ApplyResult{State: StateNoop, ApplyID: a.ApplyID, Hashes: p.Hashes()}, nil
		}
		// Adopt-only (README 7.6: named sections, no content change): the
		// ledger is the agent's own file, nothing is reloaded, no window.
		if err := p.writeLedger(sim.ledger, a.ApplyID); err != nil {
			return nil, perr(CodeApplyFailed, "writing the ledger: %v", err)
		}
		p.release()
		log.Printf("config plane: apply %s: ledger updated (%d entries), nothing else changed", a.ApplyID, len(sim.ledger))
		return &ApplyResult{State: StateApplied, ApplyID: a.ApplyID, Hashes: p.Hashes()}, nil
	}

	mgmt := p.ManagementPath(ctx)
	protected := a.Protected
	if hit, where := touchesProtected(sim, current, mgmt); hit {
		if !protected {
			log.Printf("config plane: apply %s touches the management path (%s): longer confirm window", a.ApplyID, where)
		}
		protected = true
	}
	secs := p.confirmSeconds(a.ConfirmTimeoutSeconds, protected)
	snap := append([]string(nil), sim.configs...)
	if sim.ledgerChanged {
		snap = append(snap, LedgerConfig)
	}
	rec := &pendingRecord{ApplyID: a.ApplyID, Kind: a.Kind, CreatedAt: now, Deadline: now.Add(time.Duration(secs) * time.Second),
		ConfirmSeconds: secs, Protected: protected, Configs: snap, Generated: sim.generated}
	// Checks: the controller's or the agent's own net, with their baseline
	// taken now, before anything is staged (checks.go).
	if c, agentAdded := p.effectiveChecks(ctx, a, sim, current); c != nil {
		rec.Checks = c
		rec.CheckState = p.runBaseline(ctx, c, secs, agentAdded)
		// The window runs from the commit, not from before the baseline.
		now = p.clock.Now()
		rec.CreatedAt, rec.Deadline = now, now.Add(time.Duration(secs)*time.Second)
	}
	if err := p.prepare(rec); err != nil {
		return nil, err
	}

	// Stage and commit.
	stager, err := p.backend.Stager(ctx, sim.configs, a.ApplyID)
	if err != nil {
		st.finish(a.ApplyID)
		return nil, perr(CodeApplyFailed, "%v", err)
	}
	if err := stage(ctx, stager, sim); err != nil {
		_ = stager.Close(ctx)
		st.finish(a.ApplyID)
		return nil, stageError(err)
	}
	for i, c := range sim.configs {
		if err := stager.Commit(ctx, c); err != nil {
			_ = stager.Close(ctx)
			if i == 0 {
				st.finish(a.ApplyID)
				if errors.Is(err, ubus.ErrPermissionDenied) {
					return nil, busyLuci()
				}
				return nil, perr(CodeApplyFailed, "committing %s: %v", c, err)
			}
			return nil, p.failCommitted(rec, fmt.Sprintf("committing %s: %v", c, err))
		}
	}
	_ = stager.Close(ctx)
	if sim.ledgerChanged {
		if err := p.writeLedger(sim.ledger, a.ApplyID); err != nil {
			return nil, p.failCommitted(rec, "writing the ledger: "+err.Error())
		}
	}
	for _, c := range sim.configs {
		l, err := p.files.Load(c)
		if err != nil {
			return nil, p.failCommitted(rec, fmt.Sprintf("reading %s back: %v", c, err))
		}
		if err := verifyCommitted(sim, c, l.Config); err != nil {
			return nil, p.failCommitted(rec, err.Error())
		}
	}
	if !p.backend.CommitReloads() {
		if err := p.backend.Reload(ctx, sim.configs); err != nil {
			return nil, p.failCommittedReason(rec, ReasonReloadFailed, "reload: "+err.Error())
		}
	}
	if err := p.committed(rec, sess); err != nil {
		return nil, p.failCommitted(rec, err.Error())
	}
	log.Printf("config plane: apply %s committed %v; confirm by %s (%ds%s)", a.ApplyID, rec.Configs,
		rec.Deadline.UTC().Format(time.RFC3339), secs, map[bool]string{true: ", management path", false: ""}[protected])
	go p.afterCommit(a.ApplyID)
	return p.pendingResult(rec), nil
}

// prepare snapshots the configs to flash and writes the pending record and
// the tmpfs marker: from here on a crash or a reboot restores.
func (p *Plane) prepare(rec *pendingRecord) error {
	st := p.store()
	before, err := st.snapshot(rec.ApplyID, "before", rec.Configs)
	if err != nil {
		st.finish(rec.ApplyID)
		return perr(CodeApplyFailed, "snapshot: %v", err)
	}
	rec.HashesBefore = before
	if err := st.setMarker(rec.ApplyID); err != nil {
		st.finish(rec.ApplyID)
		return perr(CodeApplyFailed, "marker: %v", err)
	}
	if err := st.writePending(rec); err != nil {
		st.finish(rec.ApplyID)
		return perr(CodeApplyFailed, "pending record: %v", err)
	}
	return nil
}

// committed records the after state, suppresses the echo, and arms the
// deadline.
func (p *Plane) committed(rec *pendingRecord, sess SessionRef) error {
	st := p.store()
	after, err := st.snapshot(rec.ApplyID, "after", rec.Configs)
	if err != nil {
		return fmt.Errorf("snapshot after commit: %v", err)
	}
	rec.HashesAfter, rec.Committed = after, true
	if err := st.writePending(rec); err != nil {
		return fmt.Errorf("pending record: %v", err)
	}
	for c, h := range after {
		if h != rec.HashesBefore[c] {
			p.RecordOwn(c, h, rec.ApplyID)
		}
	}
	p.ap.mu.Lock()
	p.ap.pending, p.ap.state, p.ap.applyGen, p.ap.anyGen = rec, StatePendingConfirm, sess.Gen, false
	p.ap.mu.Unlock()
	p.armTimer(rec)
	return nil
}

// afterCommit waits for the reload to settle, then drops the session so a
// fresh one proves DNS, routing, the firewall and TLS.
func (p *Plane) afterCommit(id string) {
	// The reply goes out when the handler returns; give it a moment on the
	// wire before anything can close the session.
	time.Sleep(replyGrace)
	ctx, cancel := context.WithTimeout(context.Background(), SettleMax+5*time.Second)
	_ = p.backend.Settle(ctx)
	cancel()
	p.ap.mu.Lock()
	rec := p.ap.pending
	still := rec != nil && rec.ApplyID == id && p.ap.state == StatePendingConfirm
	p.ap.mu.Unlock()
	if !still {
		return
	}
	// The checks' budget starts once the reload settled.
	p.startChecks(rec)
	if h := p.hooksNow(); h.Reconnect != nil {
		h.Reconnect("reconnecting after apply " + id)
	}
}

func (p *Plane) failCommitted(rec *pendingRecord, detail string) error {
	return p.failCommittedReason(rec, ReasonCommitFailed, detail)
}

// failCommittedReason rolls back an apply that failed after something was
// committed, and returns the error for the reply.
func (p *Plane) failCommittedReason(rec *pendingRecord, reason, detail string) error {
	log.Printf("config plane: apply %s failed after committing: %s; restoring", rec.ApplyID, detail)
	p.ap.mu.Lock()
	p.ap.pending, p.ap.state = rec, StateRollingBack
	p.ap.mu.Unlock()
	res := p.rollback(rec, reason, true, detail)
	e := perr(CodeApplyFailed, "%s (rolled back)", detail)
	e.Data = map[string]any{"rolledBack": true, "result": res}
	return e
}

// stage runs a simulation's steps on a stager, in apply order.
func stage(ctx context.Context, st uci.Stager, sim *simulation) error {
	for _, c := range sim.configs {
		for _, s := range sim.steps[c] {
			var err error
			switch s.kind {
			case stepAdd:
				_, err = st.Add(ctx, c, s.typ, s.name, s.options)
			case stepSet:
				err = st.Set(ctx, c, s.section, s.options)
			case stepDeleteOptions:
				err = st.DeleteOptions(ctx, c, s.section, s.names...)
			case stepDeleteSection:
				err = st.DeleteSection(ctx, c, s.section)
			case stepRename:
				err = st.Rename(ctx, c, s.section, s.name)
			case stepOrder:
				err = st.Order(ctx, c, s.names)
			}
			if err != nil {
				return fmt.Errorf("staging %s: %w", c, err)
			}
		}
	}
	return nil
}

func stageError(err error) error {
	if errors.Is(err, uci.ErrForeignChanges) {
		e := perr(CodeBusy, "%v", err)
		e.Data = map[string]any{"reason": "uncommitted"}
		return e
	}
	if errors.Is(err, ubus.ErrPermissionDenied) {
		return busyLuci()
	}
	return perr(CodeApplyFailed, "%v", err)
}

// Confirm runs gateway.config.confirm: on a session newer than the
// apply's, the snapshot is dropped and the change stays.
func (p *Plane) Confirm(id string, sess SessionRef) (map[string]any, error) {
	return p.ConfirmWith(id, false, sess)
}

// ConfirmWith is Confirm with overrideChecks.
func (p *Plane) ConfirmWith(id string, overrideChecks bool, sess SessionRef) (map[string]any, error) {
	p.ap.mu.Lock()
	if id != "" && id == p.ap.lastConfirmed {
		h := p.ap.lastConfirmedHashes
		p.ap.mu.Unlock()
		return map[string]any{"state": StateConfirmed, "applyId": id, "hashes": h}, nil
	}
	rec := p.ap.pending
	if rec == nil || rec.ApplyID != id {
		p.ap.mu.Unlock()
		if r := p.store().findResult(id); r != nil {
			e := perr(CodeDeadlinePassed, "apply %s was %s (%s)", id, r.Outcome, r.Reason)
			e.Data = map[string]any{"result": r}
			return nil, e
		}
		return nil, perr(CodeUnknownApply, "no pending apply %q", id)
	}
	if p.ap.state != StatePendingConfirm {
		p.ap.mu.Unlock()
		return nil, perr(CodeDeadlinePassed, "apply %s is being rolled back", id)
	}
	if !p.ap.anyGen && sess.Gen <= p.ap.applyGen {
		p.ap.mu.Unlock()
		return nil, perr(CodeNotReconnected, "confirm apply %s on the fresh session the agent opens after it, not on the one it was sent on", id)
	}
	if !p.clock.Now().Before(rec.Deadline) {
		p.ap.mu.Unlock()
		return nil, perr(CodeDeadlinePassed, "the confirm window of apply %s has closed", id)
	}
	if err := p.checksGate(rec, overrideChecks); err != nil {
		p.ap.mu.Unlock()
		return nil, err
	}
	if p.ap.stop != nil {
		p.ap.stop()
	}
	p.ap.pending, p.ap.state, p.ap.stop = nil, StateIdle, nil
	p.ap.mu.Unlock()
	p.stopChecks(id, nil)
	p.store().finish(id)
	hashes := p.Hashes()
	p.ap.mu.Lock()
	p.ap.lastConfirmed, p.ap.lastConfirmedHashes = id, hashes
	p.ap.mu.Unlock()
	log.Printf("config plane: apply %s confirmed", id)
	return map[string]any{"state": StateConfirmed, "applyId": id, "hashes": hashes}, nil
}

// RollbackNow runs gateway.config.rollback: the admin reverts a pending
// apply. The restore runs after the reply.
func (p *Plane) RollbackNow(id string) (map[string]any, error) {
	p.ap.mu.Lock()
	rec := p.ap.pending
	if rec == nil || rec.ApplyID != id || p.ap.state != StatePendingConfirm {
		state := p.ap.state
		p.ap.mu.Unlock()
		if rec != nil && rec.ApplyID == id && state == StateRollingBack {
			return map[string]any{"state": StateRollingBack, "applyId": id}, nil
		}
		if r := p.store().findResult(id); r != nil {
			return map[string]any{"state": r.Outcome, "applyId": id}, nil
		}
		return nil, perr(CodeUnknownApply, "no pending apply %q", id)
	}
	p.ap.mu.Unlock()
	go p.rollbackPending(id, ReasonAdmin, true)
	return map[string]any{"state": StateRollingBack, "applyId": id}, nil
}

// Ack runs gateway.config.ack.
func (p *Plane) Ack(ids []string) (map[string]any, error) {
	n, err := p.store().ack(ids)
	if err != nil {
		return nil, perr(CodeApplyFailed, "%v", err)
	}
	return map[string]any{"acked": n}, nil
}

// rollbackPending rolls back the pending apply id, if it still is.
func (p *Plane) rollbackPending(id, reason string, reload bool) {
	p.rollbackPendingWith(id, reason, reload, "")
}

// rollbackPendingDetail rolls back the pending apply id now, with a detail
// for the result (the checks' failure).
func (p *Plane) rollbackPendingDetail(id, reason, detail string) {
	p.rollbackPendingWith(id, reason, true, detail)
}

func (p *Plane) rollbackPendingWith(id, reason string, reload bool, detail string) {
	p.ap.mu.Lock()
	rec := p.ap.pending
	if rec == nil || rec.ApplyID != id || p.ap.state != StatePendingConfirm {
		// Confirmed, or someone else is on it (admin rollback vs deadline).
		p.ap.mu.Unlock()
		return
	}
	p.ap.state = StateRollingBack
	if p.ap.stop != nil {
		p.ap.stop()
		p.ap.stop = nil
	}
	p.ap.mu.Unlock()
	p.rollback(rec, reason, reload, detail)
}

// rollback restores an apply's snapshot, records the outcome and tells the
// controller. reload: have procd reload the restored configs' services
// (not at boot, where they start after the guard).
func (p *Plane) rollback(rec *pendingRecord, reason string, reload bool, detail string) Result {
	// The checks end first: nothing may record them once the files are back.
	checks := p.stopChecks(rec.ApplyID, rec)
	res := restore(p.store(), rec, reason, detail, p.redact, p.o.Root, p.pkgRunner(), p.clock.Now())
	if checks != nil {
		res.Result.Checks = checks
	}
	if rec.Packages != nil {
		p.refreshSiblings()
	}
	if reload && len(res.restored) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		var cfgs []string
		for _, c := range res.restored {
			if c != LedgerConfig {
				cfgs = append(cfgs, c)
			}
		}
		if err := p.backend.Reload(ctx, cfgs); err != nil {
			log.Printf("config plane: rollback of %s: reload: %v", rec.ApplyID, err)
			if res.Result.Detail == "" {
				res.Result.Detail = "reload: " + err.Error()
			}
		}
		cancel()
	}
	for _, c := range res.restored {
		p.RecordOwn(c, p.store().currentHash(c), rec.ApplyID)
	}
	res.Result.Hashes = p.Hashes()
	st := p.store()
	if err := st.addResult(res.Result); err != nil {
		log.Printf("config plane: recording the rollback of %s: %v", rec.ApplyID, err)
	}
	if res.failed {
		st.keepFailed(rec.ApplyID)
	} else {
		st.finish(rec.ApplyID)
	}
	p.ap.mu.Lock()
	if p.ap.pending != nil && p.ap.pending.ApplyID == rec.ApplyID {
		p.ap.pending = nil
	}
	p.ap.state, p.ap.stop = StateIdle, nil
	p.ap.redialUntil = p.clock.Now().Add(redialAfterRollback)
	p.ap.mu.Unlock()
	log.Printf("config plane: apply %s %s (%s); restored %v", rec.ApplyID, res.Result.Outcome, reason, res.restored)
	if h := p.hooksNow(); h.Result != nil {
		h.Result(res.Result)
	}
	p.wake()
	return res.Result
}

type restoreOutcome struct {
	Result   Result
	restored []string
	failed   bool
}

// restore is the rollback's file work, shared with the boot guard: note
// router edits made during the window (discarded), remove what a package
// job installed, and put the snapshotted files back.
func restore(st store, rec *pendingRecord, reason, detail string, redact uci.Redactor, root string, run ubus.Runner, now time.Time) restoreOutcome {
	out := restoreOutcome{Result: Result{ApplyID: rec.ApplyID, Kind: rec.Kind, Outcome: OutcomeRolledBack, Reason: reason,
		At: now.UTC().Format(time.RFC3339), Detail: detail, Checks: rec.CheckState.view()}}
	if rec.Committed {
		out.Result.Discarded = discarded(st, rec, redact)
	}
	var problems []string
	if rec.Packages != nil {
		removed, err := removePackages(context.Background(), run, root, rec.Packages)
		out.Result.Packages = removed
		if err != nil {
			problems = append(problems, err.Error())
		}
	}
	for _, c := range rec.Configs {
		before, ok := rec.HashesBefore[c]
		if !ok {
			continue
		}
		if st.currentHash(c) == before {
			continue
		}
		if err := st.restore(rec.ApplyID, c, before); err != nil {
			problems = append(problems, fmt.Sprintf("restoring %s: %v", c, err))
			continue
		}
		out.restored = append(out.restored, c)
	}
	if len(problems) > 0 {
		out.failed = true
		out.Result.Outcome = OutcomeFailed
		d := problems[0]
		if len(problems) > 1 {
			d = fmt.Sprintf("%s (+%d more)", d, len(problems)-1)
		}
		if out.Result.Detail != "" {
			d = out.Result.Detail + "; " + d
		}
		out.Result.Detail = d
	}
	return out
}

// discarded lists router edits made during the confirm window: sections
// that differ between what the apply committed and the files now.
func discarded(st store, rec *pendingRecord, redact uci.Redactor) map[string][]DiscardedSection {
	out := map[string][]DiscardedSection{}
	for _, c := range rec.Configs {
		if c == LedgerConfig || rec.HashesAfter == nil || st.currentHash(c) == rec.HashesAfter[c] {
			continue
		}
		afterData, err := st.snapshotData(rec.ApplyID, "after", c)
		if err != nil {
			continue
		}
		after := &uci.Config{Name: c}
		if afterData != nil {
			if parsed, err := uci.Parse(c, afterData); err == nil {
				after = parsed
			}
		}
		now := &uci.Config{Name: c}
		if data, err := os.ReadFile(st.configPath(c)); err == nil {
			if parsed, err := uci.Parse(c, data); err == nil {
				now = parsed
			}
		}
		var list []DiscardedSection
		for _, s := range now.Sections {
			a := after.Section(s.Name)
			change := ""
			switch {
			case a == nil:
				change = "added"
			case !bytes.Equal(uci.Canonical(a, nil), uci.Canonical(s, nil)):
				change = "changed"
			}
			if change == "" {
				continue
			}
			r := redact.Section(c, s)
			list = append(list, DiscardedSection{Change: change, Section: Section{Name: s.Name, Type: s.Type, Anonymous: s.Anonymous,
				Index: s.Index, Options: r.Section.Values(), Secrets: r.Secrets, Hash: r.Hash()}})
		}
		for _, s := range after.Sections {
			if now.Section(s.Name) == nil {
				list = append(list, DiscardedSection{Change: "removed", Section: Section{Name: s.Name, Type: s.Type, Anonymous: s.Anonymous,
					Index: s.Index, Options: map[string]uci.Value{}}})
			}
		}
		if len(list) > 0 {
			out[c] = list
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Guard is the boot guard (`perch-collector config-guard`, init script
// perch-collector-guard at START=15, before network): a pending apply whose
// tmpfs marker is gone was interrupted by a reboot, so its snapshot is
// restored before any service reads the configs. Nothing is reloaded. It
// returns the outcome, nil when there was nothing to do.
func Guard(root string, run ubus.Runner, now time.Time, redact uci.Redactor) (*Result, error) {
	st := store{root: root}
	rec, err := st.readPending()
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	if st.hasMarker(rec.ApplyID) {
		// The system did not reboot: the daemon owns this apply.
		return nil, nil
	}
	if run == nil {
		run = ubus.ExecRunner
	}
	res := restore(st, rec, ReasonReboot, "", redact, root, run, now)
	hashes := map[string]string{}
	for _, c := range rec.Configs {
		if h := st.currentHash(c); h != "" {
			hashes[c] = h
		}
	}
	res.Result.Hashes = hashes
	if err := st.addResult(res.Result); err != nil {
		return &res.Result, err
	}
	if res.failed {
		st.keepFailed(rec.ApplyID)
	} else {
		st.finish(rec.ApplyID)
	}
	return &res.Result, nil
}
