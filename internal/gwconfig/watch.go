package gwconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Controller modes (agent.configure gatewayConfig.mode).
const (
	ModeOff     = "off"
	ModeObserve = "observe"
	ModeManaged = "managed"
)

// Watch timing defaults and bounds, in seconds (plan 1 section 11; the
// controller sends its settings, the agent clamps again).
const (
	DefaultWatchSeconds    = 30
	MinWatchSeconds        = 10
	MaxWatchSeconds        = 600
	DefaultDebounceSeconds = 5
	MinDebounceSeconds     = 1
	MaxDebounceSeconds     = 60
	// LuciHold is how long a change is held back while a LuCI apply waits
	// for its confirm: one that rolls back is never reported.
	LuciHold = 5 * time.Minute
)

// Origins of a change.
const (
	OriginRouter = "router"
	OriginPerch  = "perch"
)

// Author kinds, best effort ("likely" in the dashboard).
const (
	AuthorLuci    = "luci"
	AuthorCLI     = "cli"
	AuthorPerch   = "perch"
	AuthorUnknown = "unknown"
)

// Author says who likely made a change and how it was seen: "trigger"
// (procd's reload trigger, i.e. a LuCI/rpcd commit or reload_config) or
// "poll" (a file change noticed by polling: a CLI `uci commit` without a
// reload, an editor, scp).
type Author struct {
	Kind string `json:"kind"`
	User string `json:"user,omitempty"`
	Via  string `json:"via,omitempty"`
}

// Changed is the gateway.config.changed notification (plan 1 section 4).
type Changed struct {
	// Hashes are every readable config's current hash (absent = no file).
	Hashes  map[string]string `json:"hashes"`
	Changed []string          `json:"changed"`
	Origin  string            `json:"origin"`
	ApplyID string            `json:"applyId,omitempty"`
	Author  Author            `json:"author"`
	At      string            `json:"at"`
	// Uncommitted are readable configs with staged, uncommitted changes.
	Uncommitted []string `json:"uncommitted"`
}

// Configure is agent.configure's gatewayConfig block.
type Configure struct {
	Mode            string   `json:"mode"`
	Authoritative   bool     `json:"authoritative"`
	WatchSeconds    *float64 `json:"watchSeconds"`
	DebounceSeconds *float64 `json:"debounceSeconds"`
}

type fileState struct {
	stamp string
	hash  string // "" = no file
}

type ownEcho struct {
	hash    string
	applyID string
}

type watchState struct {
	mode     string
	watch    time.Duration
	debounce time.Duration
	// known is what the last scan saw; reported what the controller was last
	// told (the hello's hashes, then each notification).
	known    map[string]fileState
	reported map[string]string
	based    bool
	// dirty: configs whose hash differs from reported, since when.
	dirty      map[string]time.Time
	lastChange time.Time
	// triggered: procd's reload trigger fired since the last report.
	triggered bool
	force     bool
	own       map[string]ownEcho
	lastPoll  time.Time
	// gen counts rebases: a report built before a hello is not recorded
	// against the new baseline.
	gen uint64
}

func (w *watchState) init() {
	w.mode = ModeOff
	w.watch = DefaultWatchSeconds * time.Second
	w.debounce = DefaultDebounceSeconds * time.Second
	w.known = map[string]fileState{}
	w.reported = map[string]string{}
	w.dirty = map[string]time.Time{}
	w.own = map[string]ownEcho{}
}

// rebase makes hashes the baseline: what the controller knows now.
func (w *watchState) rebase(hashes map[string]string) {
	w.reported = map[string]string{}
	for k, v := range hashes {
		w.reported[k] = v
	}
	w.based = true
	w.gen++
	w.dirty = map[string]time.Time{}
	w.triggered = false
}

func clampSeconds(v *float64, def, lo, hi int) time.Duration {
	s := def
	if v != nil {
		s = int(*v)
		if s < lo {
			s = lo
		}
		if s > hi {
			s = hi
		}
	}
	return time.Duration(s) * time.Second
}

// Configure applies the controller's settings; mode off stops watching.
// Unknown modes read as off.
func (p *Plane) Configure(c Configure) {
	p.mu.Lock()
	switch c.Mode {
	case ModeObserve, ModeManaged:
		p.w.mode = c.Mode
	default:
		p.w.mode = ModeOff
	}
	p.w.watch = clampSeconds(c.WatchSeconds, DefaultWatchSeconds, MinWatchSeconds, MaxWatchSeconds)
	p.w.debounce = clampSeconds(c.DebounceSeconds, DefaultDebounceSeconds, MinDebounceSeconds, MaxDebounceSeconds)
	p.mu.Unlock()
	p.wake()
}

// Mode is the controller's current mode for this gateway.
func (p *Plane) Mode() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.w.mode
}

// Trigger is procd's reload trigger (SIGHUP from the init script's
// reload_service): re-hash now, and attribute what changed to the trigger.
func (p *Plane) Trigger() {
	p.mu.Lock()
	p.w.triggered, p.w.force = true, true
	p.mu.Unlock()
	p.wake()
}

// RecordOwn is the echo-suppression hook for the plane's own writes: after
// committing or rolling back a config, record its new hash, and a later
// change to exactly that hash is reported once as origin "perch" with the
// apply id, never as a router edit.
func (p *Plane) RecordOwn(config, hash, applyID string) {
	p.mu.Lock()
	p.w.own[config] = ownEcho{hash: hash, applyID: applyID}
	p.mu.Unlock()
}

func (p *Plane) wake() {
	select {
	case p.poke <- struct{}{}:
	default:
	}
}

// Notifier sends one notification; false when it could not be sent (no
// session), and the change stays pending.
type Notifier func(Changed) bool

// Run watches until ctx ends, reporting through notify. It polls every
// watch interval while the controller's mode is not off, and re-hashes at
// once on Trigger.
func (p *Plane) Run(ctx context.Context, notify Notifier) {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		wait := p.Step(notify)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-p.poke:
		}
	}
}

// Step does one round of change detection: scan if the poll is due or a
// trigger forced it, and report what has been quiet for the debounce time.
// It returns how long to wait before the next round.
func (p *Plane) Step(notify Notifier) time.Duration {
	now := p.o.Now()
	p.mu.Lock()
	mode, force := p.w.mode, p.w.force
	if mode == ModeOff || p.Access() == AccessNone {
		p.w.force = false
		p.mu.Unlock()
		return time.Minute
	}
	if !p.w.based {
		// No hello yet: the current state is the baseline.
		p.mu.Unlock()
		base := p.Hashes()
		p.mu.Lock()
		if !p.w.based {
			p.w.rebase(base)
		}
	}
	due := force || now.Sub(p.w.lastPoll) >= p.w.watch
	p.mu.Unlock()

	if due {
		p.scan(now, force)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	next := p.w.watch - now.Sub(p.w.lastPoll)
	if len(p.w.dirty) == 0 {
		// A trigger that changed nothing readable (another config, a
		// reload) must not colour the next edit.
		p.w.triggered = false
		return positive(next)
	}
	quiet := now.Sub(p.w.lastChange)
	if quiet < p.w.debounce {
		return positive(minDur(next, p.w.debounce-quiet))
	}
	pending := uci.PendingState(p.o.Root)
	if pending.LuciPending && now.Sub(p.w.oldestDirty()) < LuciHold {
		// Hold, and look again soon: the apply resolves within its timeout.
		return positive(minDur(next, 2*time.Second))
	}
	notes, gen, triggered := p.notesLocked(now, pending)
	p.mu.Unlock()
	// Outside the lock: the author is one ubus call, and a hello must not
	// wait for it.
	if triggered {
		author := p.author()
		for i := range notes {
			if notes[i].Origin == OriginRouter {
				notes[i].Author = author
			}
		}
	}
	var sent []Changed
	for _, n := range notes {
		if notify == nil || !notify(n) {
			break // no session: stays dirty; the next hello rebases anyway
		}
		sent = append(sent, n)
	}
	p.mu.Lock()
	if gen == p.w.gen {
		for _, n := range sent {
			for _, c := range n.Changed {
				p.w.reported[c] = n.Hashes[c]
				delete(p.w.dirty, c)
				if n.Origin == OriginPerch {
					delete(p.w.own, c)
				}
			}
		}
		if len(sent) == len(notes) {
			p.w.triggered = false
		}
	}
	return positive(p.w.watch - now.Sub(p.w.lastPoll))
}

func positive(d time.Duration) time.Duration {
	if d < 100*time.Millisecond {
		return 100 * time.Millisecond
	}
	return d
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (w *watchState) oldestDirty() time.Time {
	var t time.Time
	for _, at := range w.dirty {
		if t.IsZero() || at.Before(t) {
			t = at
		}
	}
	return t
}

// scan stats every readable config and re-hashes the ones whose stamp
// moved (all of them when forced).
func (p *Plane) scan(now time.Time, force bool) {
	type seen struct {
		name string
		st   fileState
	}
	var results []seen
	p.mu.Lock()
	known := make(map[string]fileState, len(p.w.known))
	for k, v := range p.w.known {
		known[k] = v
	}
	p.w.force = false
	p.w.lastPoll = now
	p.mu.Unlock()
	for _, c := range p.Readable() {
		st := p.files.Stamp(c)
		prev, ok := known[c]
		if ok && !force && prev.stamp == st {
			continue
		}
		h := ""
		if st != "-" {
			var err error
			if h, err = p.files.Hash(c); err != nil {
				if !errors.Is(err, uci.ErrNoConfig) {
					continue // unreadable for now: try again next round
				}
				h = ""
			}
		}
		results = append(results, seen{c, fileState{stamp: st, hash: h}})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range results {
		prev, hadPrev := p.w.known[r.name]
		p.w.known[r.name] = r.st
		if r.st.hash == p.w.reported[r.name] {
			// Back where the controller last saw it (a reverted edit).
			delete(p.w.dirty, r.name)
			continue
		}
		if _, ok := p.w.dirty[r.name]; !ok {
			p.w.dirty[r.name] = now
			p.w.lastChange = now
		} else if hadPrev && prev.hash != r.st.hash {
			p.w.lastChange = now // changed again: debounce restarts
		}
	}
}

// notesLocked builds the notifications for what is dirty: own echoes
// (origin perch, one per apply id) and router edits, separately. It
// returns the baseline generation they were built against and whether the
// router edits need an author from the session list. Called with p.mu held.
func (p *Plane) notesLocked(now time.Time, pending uci.Pending) ([]Changed, uint64, bool) {
	hashes := map[string]string{}
	for _, c := range p.Readable() {
		if st, ok := p.w.known[c]; ok {
			if st.hash != "" {
				hashes[c] = st.hash
			}
		} else if h, ok := p.w.reported[c]; ok && h != "" {
			hashes[c] = h
		}
	}
	var router []string
	perch := map[string][]string{}
	for c := range p.w.dirty {
		if own, ok := p.w.own[c]; ok && own.hash == hashes[c] {
			perch[own.applyID] = append(perch[own.applyID], c)
			continue
		}
		router = append(router, c)
	}
	uncommitted := p.filterReadable(pending.Uncommitted)
	at := now.UTC().Format("2006-01-02T15:04:05Z")
	var notes []Changed
	ids := make([]string, 0, len(perch))
	for id := range perch {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		sort.Strings(perch[id])
		notes = append(notes, Changed{Hashes: hashes, Changed: perch[id], Origin: OriginPerch, ApplyID: id,
			Author: Author{Kind: AuthorPerch}, At: at, Uncommitted: uncommitted})
	}
	triggered := false
	if len(router) > 0 {
		sort.Strings(router)
		author := Author{Kind: AuthorCLI, Via: "poll"}
		triggered = p.w.triggered
		notes = append(notes, Changed{Hashes: hashes, Changed: router, Origin: OriginRouter,
			Author: author, At: at, Uncommitted: uncommitted})
	}
	return notes, p.w.gen, triggered
}

// author guesses who made a router edit that procd's trigger saw: the one
// logged-in LuCI user, else unknown.
func (p *Plane) author() Author {
	ctx, cancel := p.callCtx(context.Background())
	defer cancel()
	users, err := p.luciUsers(ctx)
	if err == nil && len(users) == 1 {
		return Author{Kind: AuthorLuci, User: users[0], Via: "trigger"}
	}
	return Author{Kind: AuthorUnknown, Via: "trigger"}
}

// luciUsers lists the user names of the logged-in rpcd sessions (`ubus call
// session list` answers with one JSON object per session).
func (p *Plane) luciUsers(ctx context.Context) ([]string, error) {
	raw, err := p.ubus.CallRaw(ctx, "session", "list", nil)
	if err != nil {
		return nil, err
	}
	return sessionUsers(raw)
}

func sessionUsers(raw []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var users []string
	for {
		var s struct {
			Data struct {
				Username string `json:"username"`
			} `json:"data"`
		}
		if err := dec.Decode(&s); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if s.Data.Username != "" {
			users = append(users, s.Data.Username)
		}
	}
	return users, nil
}
