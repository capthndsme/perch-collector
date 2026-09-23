package portal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Paid Hotspot checkouts and click-through on the router (docs/gateway/
// portal.md §14 in the controller repository).
//
// The router runs every checkout itself, always, so paid access keeps
// working through a controller outage: a guest claims a coin terminal on
// the portal page, the terminal reports coins as they drop (signed with its
// token, §14.6), the page shows the running total, and "done" or the idle
// timeout finalises it at the price locked when the checkout opened. A
// finalised checkout becomes a local grant (group c:<checkoutRef>) plus a
// local voucher whose code, the guest's reference code, is an HMAC of the
// signed record: the controller derives the same code from the journaled
// checkout_finalized event and mints it as a real voucher, then maps the
// grant to v:<voucherId>. Click-through grants are local too
// (t:<localRef> → g:<grantId>).

// Checkout states.
const (
	CheckoutOpen      = "open"
	CheckoutFinalized = "finalized"
	CheckoutCancelled = "cancelled"
	CheckoutExpired   = "expired"
)

// Hotspot timings and bounds.
const (
	terminalHeartbeatSeconds = 5
	terminalOnlineMs         = 4 * terminalHeartbeatSeconds * 1000
	terminalReceiptMs        = 120 * 1000
	guestRecentCheckoutMs    = 10 * 60 * 1000
	receiptMs                = 24 * 3600 * 1000
	checkoutRetentionMs      = 24 * 3600 * 1000
	maxStoredCheckouts       = 2000
	terminalNonceMemory      = 32
	terminalUnclaimedMemory  = 256
	clickUseRetentionMs      = 30 * 24 * 3600 * 1000
	terminalsReportInterval  = 30 * time.Second
	localVoucherGraceMs      = 24 * 3600 * 1000
)

// TerminalStatus is what a terminal says about itself in its heartbeat.
type TerminalStatus struct {
	Acceptor string `json:"acceptor,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	Error    string `json:"error,omitempty"`
}

// terminalState is a terminal's runtime state (persisted).
type terminalState struct {
	TerminalID int64           `json:"terminalId"`
	Session    string          `json:"session,omitempty"`
	LastSeq    int64           `json:"lastSeq"`
	Nonces     []string        `json:"nonces,omitempty"`
	LastSeenAt int64           `json:"lastSeenAt,omitempty"`
	Status     *TerminalStatus `json:"status,omitempty"`
	// Unclaimed are the eventIds already journaled as checkout_unclaimed.
	Unclaimed []string `json:"unclaimed,omitempty"`
}

// CheckoutResult is what a finalised checkout bought.
type CheckoutResult struct {
	ReferenceCode   string `json:"referenceCode"`
	LocalRef        string `json:"localRef"`
	DurationSeconds int64  `json:"durationSeconds"`
	QuotaBytes      *int64 `json:"quotaBytes"`
	DownKbps        *int64 `json:"downKbps"`
	UpKbps          *int64 `json:"upKbps"`
	UnusedAmount    int64  `json:"unusedAmount"`
	Placement       string `json:"placement"`
	Seq             int64  `json:"seq"`
}

// Checkout is one guest's payment at one terminal.
type Checkout struct {
	Ref            string          `json:"ref"`
	PortalID       int64           `json:"portalId"`
	TerminalID     int64           `json:"terminalId"`
	TerminalName   string          `json:"terminalName"`
	MAC            string          `json:"mac"`
	IP             string          `json:"ip,omitempty"`
	Hostname       *string         `json:"hostname,omitempty"`
	OpenedAt       int64           `json:"openedAt"`
	LastActivityAt int64           `json:"lastActivityAt"`
	IdleTimeoutMs  int64           `json:"idleTimeoutMs"`
	Price          PriceTable      `json:"price"`
	Amount         int64           `json:"amount"`
	Coins          []Coin          `json:"coins"`
	State          string          `json:"state"`
	ClosedAt       int64           `json:"closedAt,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	Result         *CheckoutResult `json:"result,omitempty"`
}

func (ck *Checkout) idleDeadline() int64 { return ck.LastActivityAt + ck.IdleTimeoutMs }

// LocalVoucher is a reference code the router minted and the controller
// has not acknowledged yet (it is dropped once it has).
type LocalVoucher struct {
	CheckoutRef string `json:"checkoutRef"`
	Verifier    string `json:"verifier"`
	PortalID    int64  `json:"portalId"`
	GroupKey    string `json:"groupKey"`
	// Seq is the journal seq of its checkout_finalized event.
	Seq       int64  `json:"seq"`
	CreatedAt int64  `json:"createdAt"`
	EndedAt   *int64 `json:"endedAt,omitempty"`
}

type clickUse struct {
	ID       int64
	PortalID int64
	MAC      string
	At       int64
}

// hotspotState is the engine's Paid Hotspot and click-through state.
type hotspotState struct {
	terminals     map[int64]*terminalState
	checkouts     map[string]*Checkout
	localVouchers map[string]*LocalVoucher
	clickUses     []clickUse
	clickNextID   int64

	openLimit, termLimit, termFail *Window

	lastTerminalsReport time.Time
	termOnline          map[int64]bool
}

func newHotspotState() hotspotState {
	return hotspotState{
		terminals: map[int64]*terminalState{}, checkouts: map[string]*Checkout{},
		localVouchers: map[string]*LocalVoucher{}, termOnline: map[int64]bool{},
		openLimit: NewWindow(10, time.Minute), termLimit: NewWindow(120, time.Minute),
		termFail: NewWindow(20, 15*time.Minute),
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isLocalGroupKey(k string) bool { return strings.HasPrefix(k, "c:") || strings.HasPrefix(k, "t:") }

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func (e *Engine) loadHotspotLocked() error {
	terms, err := loadJSONRows[terminalState](e.store, `SELECT data FROM terminals`)
	if err != nil {
		return err
	}
	for i := range terms {
		t := terms[i]
		e.terminals[t.TerminalID] = &t
	}
	cks, err := loadJSONRows[Checkout](e.store, `SELECT data FROM checkouts`)
	if err != nil {
		return err
	}
	for i := range cks {
		ck := cks[i]
		e.checkouts[ck.Ref] = &ck
	}
	lvs, err := loadJSONRows[LocalVoucher](e.store, `SELECT data FROM local_vouchers`)
	if err != nil {
		return err
	}
	for i := range lvs {
		lv := lvs[i]
		e.localVouchers[lv.CheckoutRef] = &lv
	}
	rows, err := e.store.Query(`SELECT id, portal_id, mac, at FROM clickthrough_uses ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var u clickUse
		if err := rows.Scan(&u.ID, &u.PortalID, &u.MAC, &u.At); err != nil {
			return err
		}
		e.clickUses = append(e.clickUses, u)
		if u.ID > e.clickNextID {
			e.clickNextID = u.ID
		}
	}
	return rows.Err()
}

func (e *Engine) saveTerminalState(t *terminalState, class int) {
	b, _ := json.Marshal(t)
	if err := e.store.Exec(class, `INSERT OR REPLACE INTO terminals (terminal_id, data) VALUES (?, ?)`, t.TerminalID, string(b)); err != nil {
		e.log.Error("portal: saving a terminal", "err", err)
	}
}

func (e *Engine) saveCheckout(ck *Checkout) {
	b, _ := json.Marshal(ck)
	if err := e.store.Exec(ClassGrant, `INSERT OR REPLACE INTO checkouts (ref, data) VALUES (?, ?)`, ck.Ref, string(b)); err != nil {
		e.log.Error("portal: saving a checkout", "err", err)
	}
}

func (e *Engine) saveLocalVoucher(lv *LocalVoucher) {
	b, _ := json.Marshal(lv)
	if err := e.store.Exec(ClassGrant, `INSERT OR REPLACE INTO local_vouchers (ref, data) VALUES (?, ?)`, lv.CheckoutRef, string(b)); err != nil {
		e.log.Error("portal: saving a local voucher", "err", err)
	}
}

func (e *Engine) dropLocalVoucherLocked(ref string) {
	delete(e.localVouchers, ref)
	_ = e.store.Exec(ClassGrant, `DELETE FROM local_vouchers WHERE ref = ?`, ref)
}

// ---------------------------------------------------------------------------
// Terminals
// ---------------------------------------------------------------------------

// terminalRef is a configured terminal with its portal.
type terminalRef struct {
	portal *portalRuntime
	cfg    *TerminalConfig
}

// terminalLocked finds a configured terminal on a portal offering payment.
func (e *Engine) terminalLocked(id int64) (terminalRef, bool) {
	for _, pid := range e.portalIDs() {
		p := e.portals[pid]
		if !p.cfg.Methods.Payment || p.cfg.Payment == nil {
			continue
		}
		for i := range p.cfg.Payment.Terminals {
			if p.cfg.Payment.Terminals[i].TerminalID == id {
				return terminalRef{portal: p, cfg: &p.cfg.Payment.Terminals[i]}, true
			}
		}
	}
	return terminalRef{}, false
}

func (e *Engine) terminalStateLocked(id int64) *terminalState {
	t := e.terminals[id]
	if t == nil {
		t = &terminalState{TerminalID: id}
		e.terminals[id] = t
	}
	return t
}

func (e *Engine) terminalOnlineLocked(id int64, now int64) bool {
	t := e.terminals[id]
	return t != nil && t.LastSeenAt > 0 && now-t.LastSeenAt < terminalOnlineMs
}

func (e *Engine) openCheckoutOfTerminalLocked(id int64) *Checkout {
	for _, ck := range e.checkouts {
		if ck.State == CheckoutOpen && ck.TerminalID == id {
			return ck
		}
	}
	return nil
}

func (e *Engine) openCheckoutOfMACLocked(portalID int64, mac string) *Checkout {
	for _, ck := range e.checkouts {
		if ck.State == CheckoutOpen && ck.PortalID == portalID && ck.MAC == mac {
			return ck
		}
	}
	return nil
}

// latestClosedLocked is the newest closed checkout matching f.
func (e *Engine) latestClosedLocked(f func(*Checkout) bool) *Checkout {
	var best *Checkout
	for _, ck := range e.checkouts {
		if ck.State == CheckoutOpen || !f(ck) {
			continue
		}
		if best == nil || ck.ClosedAt > best.ClosedAt || (ck.ClosedAt == best.ClosedAt && ck.Ref > best.Ref) {
			best = ck
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Checkout lifecycle
// ---------------------------------------------------------------------------

// sweepCheckoutsLocked closes checkouts whose idle timeout passed.
func (e *Engine) sweepCheckoutsLocked(now int64, ops *ElementOps) {
	refs := make([]string, 0)
	for ref, ck := range e.checkouts {
		if ck.State == CheckoutOpen && now >= ck.idleDeadline() {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	for _, ref := range refs {
		e.closeCheckoutLocked(e.checkouts[ref], ReasonTimeout, CheckoutExpired, now, ops)
	}
}

// closeCheckoutLocked ends an open checkout without a guest's decision (idle
// timeout, terminal or method gone): a purchasable amount is finalised, an
// amount below the smallest rate is recorded as unclaimed money, nothing
// paid closes as emptyState.
func (e *Engine) closeCheckoutLocked(ck *Checkout, reason, emptyState string, now int64, ops *ElementOps) {
	if ck.Amount > 0 {
		if err := e.finalizeLocked(ck, reason, now, ops); err == nil {
			return
		} else {
			e.log.Warn("portal: checkout could not be finalised", "checkout", ck.Ref, "err", err)
		}
		e.journalUnclaimedLocked(ck.PortalID, ck.TerminalID, "", ck.Amount, ck.Price.Currency, ck.Ref, "below_minimum", now)
		emptyState = CheckoutExpired
	}
	ck.State = emptyState
	ck.ClosedAt = now
	ck.Reason = reason
	e.saveCheckout(ck)
	e.sendTerminalsLocked(true)
}

type hotspotError string

func (h hotspotError) Error() string { return string(h) }

const (
	errBelowMinimum hotspotError = "below_minimum"
	errNotReady     hotspotError = "not_ready"
)

// placementLocked places an entitlement of group key against the device's
// current live entitlement from another group (as offlineRedeemLocked).
func (e *Engine) placementLocked(portalID int64, mac, key string, cand Limits) (string, *Grant) {
	var devLive []*Grant
	for _, g := range e.grants {
		if g.Live() && g.PortalID == portalID && g.MAC == mac && g.GroupKey != key {
			devLive = append(devLive, g)
		}
	}
	if len(devLive) == 0 {
		return "current", nil
	}
	current := e.firstInOrder(devLive)
	return PlaceBehindCurrent(e.entitlementOf(current).Limits, cand), current
}

// finalizeLocked turns a paid checkout into the guest's access (§14.5).
func (e *Engine) finalizeLocked(ck *Checkout, reason string, now int64, ops *ElementOps) error {
	if e.keys == nil {
		return errNotReady
	}
	res := PriceEntitlement(ck.Price, ck.Amount)
	if res.DurationSeconds == 0 {
		return errBelowMinimum
	}
	localRef := fmt.Sprintf("k%d-%s", e.lastSeq+1, randHex(4))
	rec := CheckoutRecord{CheckoutRef: ck.Ref, PortalID: ck.PortalID, TerminalID: ck.TerminalID, MAC: ck.MAC,
		Amount: ck.Amount, Currency: ck.Price.Currency, PriceTableID: ck.Price.PriceTableID, PriceRevision: ck.Price.Revision,
		DurationMode: res.DurationMode, DurationSeconds: res.DurationSeconds, QuotaBytes: res.QuotaBytes,
		DownKbps: res.DownKbps, UpKbps: res.UpKbps, OpenedAt: ck.OpenedAt, FinalizedAt: now, Reason: reason,
		LocalRef: localRef, UnusedAmount: res.UnusedAmount, CoinCount: int64(len(ck.Coins))}
	sig, err := e.keys.SignCheckout(rec)
	if err != nil {
		return err
	}
	code, err := e.keys.CheckoutReferenceCode(rec)
	if err != nil {
		return err
	}
	key := "c:" + ck.Ref
	dur := res.DurationSeconds
	cand := Limits{DurationMode: res.DurationMode, DurationSeconds: &dur, QuotaBytes: res.QuotaBytes, MaxDevices: 1}
	placement, current := e.placementLocked(ck.PortalID, ck.MAC, key, cand)
	runsNow := placement != "queue"

	wg := WireGroup{GroupKey: key, DurationMode: res.DurationMode, DurationSeconds: &dur, QuotaBytes: copyInt(res.QuotaBytes),
		DownKbps: copyInt(res.DownKbps), UpKbps: copyInt(res.UpKbps), MaxDevices: 1}
	var startsAt, expiresAt *int64
	if runsNow && res.DurationMode == ModeWallClock {
		s, x := now, now+dur*1000
		startsAt, expiresAt = &s, &x
		xx := x
		wg.ExpiresAt = &xx
	}
	grp := &Group{WireGroup: wg, Local: true, AckedSeq: e.lastSeq}
	e.groups[key] = grp
	e.saveGroup(grp)

	e.nextLID++
	lr := localRef
	g := &Grant{LID: e.nextLID, LocalRef: &lr, PortalID: ck.PortalID, GroupKey: key, MAC: ck.MAC,
		State: StatePending, CreatedAt: now, Hostname: ck.Hostname}
	if ck.IP != "" {
		ip := ck.IP
		g.IP = &ip
		g.IPs = []string{ip}
	}
	if !runsNow {
		g.State = StateQueued
	}
	pid, tid := ck.PortalID, ck.TerminalID
	amount, ptid, prev := ck.Amount, ck.Price.PriceTableID, ck.Price.Revision
	opened, fin, unused, coins, epoch := ck.OpenedAt, now, res.UnusedAmount, int64(len(ck.Coins)), e.keys.Epoch
	lr2 := localRef
	ev := Event{Type: EvCheckoutFinalized, PortalID: &pid, MAC: ck.MAC, LocalRef: &lr2, IP: g.IP, Hostname: ck.Hostname,
		CheckoutRef: ck.Ref, TerminalID: &tid, Amount: &amount, Currency: ck.Price.Currency, PriceTableID: &ptid,
		PriceRevision: &prev, DurationMode: res.DurationMode, DurationSeconds: &dur, QuotaBytes: copyInt(res.QuotaBytes),
		DownKbps: copyInt(res.DownKbps), UpKbps: copyInt(res.UpKbps), OpenedAt: &opened, FinalizedAt: &fin,
		Reason: reason, UnusedAmount: &unused, CoinCount: &coins, Coins: append([]Coin{}, ck.Coins...),
		KeyEpoch: &epoch, Sig: sig, Placement: placement, StartsAt: startsAt, ExpiresAt: expiresAt}
	if placement == "swap" && current != nil {
		ev.DemotedGrantID, ev.DemotedLocalRef = current.GrantID, current.LocalRef
	}
	seq := e.journalLocked(ev, now)
	g.CreatedSeq = seq
	e.grants[g.LID] = g
	e.saveGrant(g, ClassGrant)
	if placement == "swap" && current != nil {
		current.State = StateQueued
		e.saveGrant(current, ClassGrant)
	}
	if runsNow {
		e.authorizeMACLocked(ck.PortalID, ck.MAC, ops)
		e.startGroupClockLocked(g, now)
	}
	lv := &LocalVoucher{CheckoutRef: ck.Ref, Verifier: e.keys.Verifier(code), PortalID: ck.PortalID, GroupKey: key,
		Seq: seq, CreatedAt: now}
	e.localVouchers[ck.Ref] = lv
	e.saveLocalVoucher(lv)

	ck.State, ck.ClosedAt, ck.Reason = CheckoutFinalized, now, reason
	ck.Result = &CheckoutResult{ReferenceCode: code, LocalRef: localRef, DurationSeconds: dur, QuotaBytes: copyInt(res.QuotaBytes),
		DownKbps: copyInt(res.DownKbps), UpKbps: copyInt(res.UpKbps), UnusedAmount: res.UnusedAmount, Placement: placement, Seq: seq}
	e.saveCheckout(ck)
	e.sendTerminalsLocked(true)
	e.log.Info("portal: checkout finalised", "portal", ck.PortalID, "terminal", ck.TerminalID, "mac", ck.MAC,
		"amount", ck.Amount, "seconds", dur, "placement", placement, "reason", reason)
	return nil
}

// journalUnclaimedLocked records money a terminal took that bought nothing.
func (e *Engine) journalUnclaimedLocked(portalID, terminalID int64, eventID string, amount int64, currency, ref, reason string, now int64) {
	pid, tid, amt := portalID, terminalID, amount
	id := eventID
	ev := Event{Type: EvCheckoutUnclaimed, PortalID: &pid, TerminalID: &tid, EventID: &id, Amount: &amt,
		Currency: currency, CheckoutRef: ref, Reason: reason}
	if t, ok := e.terminalLocked(terminalID); ok && t.cfg.MAC != nil {
		ev.MAC = NormalizeMAC(*t.cfg.MAC)
	}
	e.journalLocked(ev, now)
	e.log.Warn("portal: payment not credited", "terminal", terminalID, "amount", amount, "reason", reason, "checkout", ref)
}

// hotspotConfiguredLocked applies a new portal.configure to open checkouts:
// a checkout whose terminal or method went away closes.
func (e *Engine) hotspotConfiguredLocked() {
	now := e.clock.Now()
	ops := &ElementOps{}
	refs := make([]string, 0)
	for ref, ck := range e.checkouts {
		if ck.State != CheckoutOpen {
			continue
		}
		t, ok := e.terminalLocked(ck.TerminalID)
		if !ok || !t.cfg.Enabled || t.portal.cfg.PortalID != ck.PortalID {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	for _, ref := range refs {
		e.closeCheckoutLocked(e.checkouts[ref], ReasonTimeout, CheckoutCancelled, now, ops)
	}
	e.applyOpsLocked(ops)
	e.sendTerminalsLocked(true)
}

// ---------------------------------------------------------------------------
// Guest actions
// ---------------------------------------------------------------------------

func (e *Engine) paymentPortalLocked(portalID int64) *portalRuntime {
	p := e.portals[portalID]
	if p == nil || !p.cfg.Enabled || !p.cfg.Methods.Payment || p.cfg.Payment == nil {
		return nil
	}
	return p
}

// OpenCheckout claims a terminal for the guest.
func (e *Engine) OpenCheckout(c Client, terminalID int64) Outcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.paymentPortalLocked(c.PortalID)
	if p == nil {
		return fail("bad_request")
	}
	if e.keys == nil {
		return fail("not_ready")
	}
	if ok, retry := e.openLimit.Allow(c.MAC, e.tickNow()); !ok {
		return Outcome{Code: "rate_limited", Status: ErrorStatus("rate_limited"), RetryAfter: retry}
	}
	now := e.clock.Now()
	ops := &ElementOps{}
	e.sweepCheckoutsLocked(now, ops)
	e.applyOpsLocked(ops)
	var tc *TerminalConfig
	for i := range p.cfg.Payment.Terminals {
		if p.cfg.Payment.Terminals[i].TerminalID == terminalID {
			tc = &p.cfg.Payment.Terminals[i]
		}
	}
	if tc == nil || !tc.Enabled {
		return fail("terminal_unknown")
	}
	table := p.cfg.Payment.tableFor(tc)
	if table == nil {
		return fail("not_ready")
	}
	if cur := e.openCheckoutOfTerminalLocked(terminalID); cur != nil {
		if cur.MAC == c.MAC && cur.PortalID == c.PortalID {
			return Outcome{OK: true, Code: "checkout_started", Status: 200}
		}
		return fail("terminal_busy")
	}
	if !e.terminalOnlineLocked(terminalID, now) {
		return fail("terminal_offline")
	}
	if mine := e.openCheckoutOfMACLocked(c.PortalID, c.MAC); mine != nil {
		if mine.Amount > 0 {
			return fail("checkout_open")
		}
		mine.State, mine.ClosedAt, mine.Reason = CheckoutCancelled, now, "moved"
		e.saveCheckout(mine)
	}
	price := *table
	price.Entries = append([]PriceEntry(nil), table.Entries...)
	ck := &Checkout{Ref: "ck-" + randHex(8), PortalID: c.PortalID, TerminalID: terminalID, TerminalName: tc.Name,
		MAC: c.MAC, IP: c.IP, Hostname: c.Hostname, OpenedAt: now, LastActivityAt: now,
		IdleTimeoutMs: p.cfg.Payment.idleTimeoutMs(), Price: price, Coins: []Coin{}, State: CheckoutOpen}
	e.checkouts[ck.Ref] = ck
	e.saveCheckout(ck)
	e.pruneCheckoutsLocked(now)
	e.sendTerminalsLocked(true)
	e.log.Info("portal: checkout opened", "portal", c.PortalID, "terminal", terminalID, "mac", c.MAC, "checkout", ck.Ref)
	return Outcome{OK: true, Code: "checkout_started", Status: 200}
}

// doneLocked finalises a checkout on the guest's or the terminal's word.
func (e *Engine) doneLocked(ck *Checkout, reason string, now int64) Outcome {
	if ck.Amount == 0 {
		ck.State, ck.ClosedAt, ck.Reason = CheckoutCancelled, now, reason
		e.saveCheckout(ck)
		e.sendTerminalsLocked(true)
		return Outcome{OK: true, Code: "checkout_cancelled", Status: 200}
	}
	ops := &ElementOps{}
	err := e.finalizeLocked(ck, reason, now, ops)
	e.applyOpsLocked(ops)
	e.snapshotIfDue()
	switch err {
	case nil:
		return Outcome{OK: true, Code: "paid", Status: 200}
	case errBelowMinimum:
		return fail("below_minimum")
	}
	e.log.Warn("portal: checkout could not be finalised", "checkout", ck.Ref, "err", err)
	return fail("not_ready")
}

// CheckoutDone finalises the guest's open checkout (reason done).
func (e *Engine) CheckoutDone(c Client) Outcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.paymentPortalLocked(c.PortalID) == nil {
		return fail("bad_request")
	}
	now := e.clock.Now()
	ops := &ElementOps{}
	e.sweepCheckoutsLocked(now, ops)
	e.applyOpsLocked(ops)
	ck := e.openCheckoutOfMACLocked(c.PortalID, c.MAC)
	if ck == nil {
		return fail("no_checkout")
	}
	return e.doneLocked(ck, ReasonDone, now)
}

// CheckoutCancel gives the terminal back when nothing was paid.
func (e *Engine) CheckoutCancel(c Client) Outcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.paymentPortalLocked(c.PortalID) == nil {
		return fail("bad_request")
	}
	now := e.clock.Now()
	ops := &ElementOps{}
	e.sweepCheckoutsLocked(now, ops)
	e.applyOpsLocked(ops)
	ck := e.openCheckoutOfMACLocked(c.PortalID, c.MAC)
	if ck == nil {
		return fail("no_checkout")
	}
	if ck.Amount > 0 {
		return fail("checkout_paid")
	}
	ck.State, ck.ClosedAt, ck.Reason = CheckoutCancelled, now, "cancel"
	e.saveCheckout(ck)
	e.sendTerminalsLocked(true)
	return Outcome{OK: true, Code: "checkout_cancelled", Status: 200}
}

// ---------------------------------------------------------------------------
// Local vouchers (reference codes the controller does not know yet)
// ---------------------------------------------------------------------------

func (e *Engine) localVoucherByCodeLocked(code string) *LocalVoucher {
	if e.keys == nil || len(e.localVouchers) == 0 {
		return nil
	}
	v := e.keys.Verifier(code)
	for _, lv := range e.localVouchers {
		if SignatureMatches(lv.Verifier, v) {
			return lv
		}
	}
	return nil
}

// localRedeemLocked moves a local voucher's entitlement to the guest's
// device (decision 23: the device that held it leaves, reason moved).
func (e *Engine) localRedeemLocked(c Client, lv *LocalVoucher) Outcome {
	if lv.PortalID != c.PortalID {
		return fail("wrong_portal")
	}
	grp := e.groups[lv.GroupKey]
	if grp == nil {
		return fail("expired")
	}
	now := e.clock.Now()
	switch Exhaustion(grp.EffectiveLimits(), e.groupUsageLocked(lv.GroupKey), now) {
	case EndExpired:
		return fail("expired")
	case EndQuota:
		return fail("exhausted")
	}
	var holders []SlotHolder
	byRef := map[string]*Grant{}
	for _, g := range e.sortedGrants() {
		if g.GroupKey != lv.GroupKey {
			continue
		}
		if g.MAC == c.MAC && g.PortalID == c.PortalID {
			return fail("already_authorized")
		}
		ref := fmt.Sprint(g.LID)
		started := g.CreatedAt
		if g.StartedAt != nil {
			started = *g.StartedAt
		}
		holders = append(holders, SlotHolder{Ref: ref, MAC: g.MAC, StartedAt: started, Order: g.Order()})
		byRef[ref] = g
	}
	evict := EvictOldest(holders, 1)
	placement, current := e.placementLocked(c.PortalID, c.MAC, lv.GroupKey, grp.EffectiveLimits())
	runsNow := placement != "queue"
	var startsAt, expiresAt *int64
	if runsNow && grp.DurationMode == ModeWallClock && grp.ExpiresAt == nil && grp.ClockStartedAt == nil && grp.DurationSeconds != nil {
		s, x := now, now+*grp.DurationSeconds*1000
		startsAt, expiresAt = &s, &x
		xx := x
		grp.ExpiresAt = &xx
		e.saveGroup(grp)
	}
	ops := &ElementOps{}
	e.nextLID++
	ref := newLocalRef(e.lastSeq + 1)
	g := &Grant{LID: e.nextLID, LocalRef: &ref, PortalID: c.PortalID, GroupKey: lv.GroupKey, MAC: c.MAC,
		State: StatePending, CreatedAt: now, Hostname: c.Hostname}
	if c.IP != "" {
		ip := c.IP
		g.IP = &ip
		g.IPs = []string{ip}
	}
	if !runsNow {
		g.State = StateQueued
	}
	pid := c.PortalID
	zero := int64(0)
	ref2 := ref
	ev := Event{Type: EvOfflineRedeemed, PortalID: &pid, MAC: c.MAC, VoucherID: &zero, CheckoutRef: lv.CheckoutRef,
		LocalRef: &ref2, Placement: placement, StartsAt: startsAt, ExpiresAt: expiresAt, IP: g.IP, Hostname: c.Hostname}
	if placement == "swap" && current != nil {
		ev.DemotedGrantID, ev.DemotedLocalRef = current.GrantID, current.LocalRef
	}
	g.CreatedSeq = e.journalLocked(ev, now)
	e.grants[g.LID] = g
	e.saveGrant(g, ClassGrant)
	if placement == "swap" && current != nil {
		current.State = StateQueued
		e.saveGrant(current, ClassGrant)
	}
	for _, r := range evict {
		if old := byRef[r]; old != nil {
			if old.State == StateQueued {
				e.dropGrantLocked(old)
				continue
			}
			e.endGrantLocked(old, EndMoved, now, ops)
		}
	}
	if runsNow {
		e.authorizeMACLocked(c.PortalID, c.MAC, ops)
		e.startGroupClockLocked(g, now)
	}
	e.applyOpsLocked(ops)
	e.snapshotIfDue()
	e.log.Info("portal: reference code redeemed", "portal", c.PortalID, "mac", c.MAC, "checkout", lv.CheckoutRef, "placement", placement)
	return Outcome{OK: true, Code: "connected", Status: 200}
}

// renameLocalGroupLocked follows the controller mapping a local group
// (c:/t:) to its own key: ended usage moves along, and the local group goes
// once no grant uses it.
func (e *Engine) renameLocalGroupLocked(oldKey, newKey string) {
	for i := range e.ended {
		if e.ended[i].GroupKey == oldKey {
			e.ended[i].GroupKey = newKey
		}
	}
	_ = e.store.Exec(ClassGrant, `UPDATE ended_usage SET group_key = ? WHERE group_key = ?`, newKey, oldKey)
	for _, lv := range e.localVouchers {
		if lv.GroupKey == oldKey {
			lv.GroupKey = newKey
			e.saveLocalVoucher(lv)
		}
	}
	for _, g := range e.grants {
		if g.GroupKey == oldKey {
			return
		}
	}
	delete(e.groups, oldKey)
	e.deleteGroup(oldKey)
}

// dropAckedLocalVouchersLocked: the controller recorded the payments up to
// acked; its own voucher list carries them from now on (a voided one must
// not stay redeemable here).
func (e *Engine) dropAckedLocalVouchersLocked(acked int64) {
	for ref, lv := range e.localVouchers {
		if lv.Seq <= acked {
			e.dropLocalVoucherLocked(ref)
		}
	}
}

// dropListedLocalVouchersLocked drops local vouchers the held list has.
func (e *Engine) dropListedLocalVouchersLocked() {
	for ref, lv := range e.localVouchers {
		if _, ok := e.voucherByVerifier[lv.Verifier]; ok {
			e.dropLocalVoucherLocked(ref)
		}
	}
}

// ---------------------------------------------------------------------------
// Click-through (decision 32)
// ---------------------------------------------------------------------------

// clickRetryLocked is how long until the device may use click-through again
// (0 = now).
func (e *Engine) clickRetryLocked(portalID int64, mac string, cfg ClickThroughConfig, now int64) int64 {
	window := int64(cfg.WindowHours) * 3600 * 1000
	var ats []int64
	for _, u := range e.clickUses {
		if u.PortalID == portalID && u.MAC == mac && u.At > now-window {
			ats = append(ats, u.At)
		}
	}
	if len(ats) < cfg.PerWindow {
		return 0
	}
	sort.Slice(ats, func(a, b int) bool { return ats[a] < ats[b] })
	wait := ats[len(ats)-cfg.PerWindow] + window - now
	if wait < 1 {
		wait = 1
	}
	return wait
}

// ClickThrough gives the guest free, limited access after accepting the terms.
func (e *Engine) ClickThrough(c Client, accepted bool) Outcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.portals[c.PortalID]
	if p == nil || !p.cfg.Enabled || !p.cfg.Methods.ClickThrough || p.cfg.ClickThrough == nil {
		return fail("bad_request")
	}
	if !accepted {
		return fail("terms_required")
	}
	for _, g := range e.grants {
		if g.Live() && g.PortalID == c.PortalID && g.MAC == c.MAC {
			return fail("already_authorized")
		}
	}
	cfg := p.cfg.ClickThrough.normalized()
	now := e.clock.Now()
	if wait := e.clickRetryLocked(c.PortalID, c.MAC, cfg, now); wait > 0 {
		return Outcome{Code: "clickthrough_used", Status: ErrorStatus("clickthrough_used"), RetryAfter: time.Duration(wait) * time.Millisecond}
	}
	localRef := fmt.Sprintf("t%d-%s", e.lastSeq+1, randHex(4))
	key := "t:" + localRef
	dur := cfg.Minutes * 60
	exp := now + dur*1000
	wg := WireGroup{GroupKey: key, DurationMode: ModeWallClock, ExpiresAt: &exp, DurationSeconds: &dur,
		QuotaBytes: copyInt(cfg.QuotaBytes), DownKbps: copyInt(cfg.DownKbps), UpKbps: copyInt(cfg.UpKbps), MaxDevices: 1}
	grp := &Group{WireGroup: wg, Local: true, AckedSeq: e.lastSeq}
	e.groups[key] = grp
	e.saveGroup(grp)
	e.nextLID++
	lr := localRef
	g := &Grant{LID: e.nextLID, LocalRef: &lr, PortalID: c.PortalID, GroupKey: key, MAC: c.MAC,
		State: StatePending, CreatedAt: now, Hostname: c.Hostname}
	if c.IP != "" {
		ip := c.IP
		g.IP = &ip
		g.IPs = []string{ip}
	}
	pid := c.PortalID
	lr2 := localRef
	s, x, d := now, exp, dur
	ev := Event{Type: EvClickThroughGranted, PortalID: &pid, MAC: c.MAC, LocalRef: &lr2, IP: g.IP, Hostname: c.Hostname,
		StartsAt: &s, ExpiresAt: &x, DurationSeconds: &d, QuotaBytes: copyInt(cfg.QuotaBytes),
		DownKbps: copyInt(cfg.DownKbps), UpKbps: copyInt(cfg.UpKbps)}
	g.CreatedSeq = e.journalLocked(ev, now)
	e.grants[g.LID] = g
	e.saveGrant(g, ClassGrant)
	e.clickNextID++
	u := clickUse{ID: e.clickNextID, PortalID: c.PortalID, MAC: c.MAC, At: now}
	e.clickUses = append(e.clickUses, u)
	_ = e.store.Exec(ClassGrant, `INSERT INTO clickthrough_uses (id, portal_id, mac, at) VALUES (?, ?, ?, ?)`, u.ID, u.PortalID, u.MAC, u.At)
	ops := &ElementOps{}
	e.authorizeMACLocked(c.PortalID, c.MAC, ops)
	e.applyOpsLocked(ops)
	e.snapshotIfDue()
	e.log.Info("portal: click-through granted", "portal", c.PortalID, "mac", c.MAC, "minutes", cfg.Minutes)
	return Outcome{OK: true, Code: "connected", Status: 200}
}

// ---------------------------------------------------------------------------
// Tick: sweeps, pruning, the terminals report
// ---------------------------------------------------------------------------

func (e *Engine) hotspotTickLocked(now int64, ops *ElementOps) {
	e.sweepCheckoutsLocked(now, ops)
	e.pruneCheckoutsLocked(now)
	// Local vouchers: forgotten 24 h after their entitlement ended.
	for ref, lv := range e.localVouchers {
		over := true
		if grp := e.groups[lv.GroupKey]; grp != nil {
			if Exhaustion(grp.EffectiveLimits(), e.groupUsageLocked(lv.GroupKey), now) == "" {
				over = false
			}
		}
		if !over {
			if lv.EndedAt != nil {
				lv.EndedAt = nil
				e.saveLocalVoucher(lv)
			}
			continue
		}
		if lv.EndedAt == nil {
			t := now
			lv.EndedAt = &t
			e.saveLocalVoucher(lv)
		} else if now-*lv.EndedAt > localVoucherGraceMs {
			e.dropLocalVoucherLocked(ref)
		}
	}
	// Click-through uses older than the longest window.
	cut := 0
	for cut < len(e.clickUses) && e.clickUses[cut].At < now-clickUseRetentionMs {
		cut++
	}
	if cut > 0 {
		last := e.clickUses[cut-1].ID
		e.clickUses = append([]clickUse(nil), e.clickUses[cut:]...)
		_ = e.store.Exec(ClassGrant, `DELETE FROM clickthrough_uses WHERE id <= ?`, last)
	}
	// Terminals that went quiet.
	changed := false
	for id := range e.termOnline {
		if e.termOnline[id] && !e.terminalOnlineLocked(id, now) {
			changed = true
		}
	}
	e.sendTerminalsLocked(changed)
}

// pruneCheckoutsLocked forgets closed checkouts after 24 h, and the oldest
// closed ones beyond maxStoredCheckouts.
func (e *Engine) pruneCheckoutsLocked(now int64) {
	var closed []*Checkout
	for ref, ck := range e.checkouts {
		if ck.State == CheckoutOpen {
			continue
		}
		if now-ck.ClosedAt > checkoutRetentionMs {
			delete(e.checkouts, ref)
			_ = e.store.Exec(ClassGrant, `DELETE FROM checkouts WHERE ref = ?`, ref)
			continue
		}
		closed = append(closed, ck)
	}
	if extra := len(e.checkouts) - maxStoredCheckouts; extra > 0 {
		sort.Slice(closed, func(a, b int) bool { return closed[a].ClosedAt < closed[b].ClosedAt })
		for i := 0; i < extra && i < len(closed); i++ {
			delete(e.checkouts, closed[i].Ref)
			_ = e.store.Exec(ClassGrant, `DELETE FROM checkouts WHERE ref = ?`, closed[i].Ref)
		}
	}
}

// TerminalReport is one terminal in portal.terminals.
type TerminalReport struct {
	TerminalID int64                   `json:"terminalId"`
	PortalID   int64                   `json:"portalId"`
	Online     bool                    `json:"online"`
	LastSeenAt *int64                  `json:"lastSeenAt"`
	Status     *TerminalStatus         `json:"status"`
	Checkout   *TerminalReportCheckout `json:"checkout"`
}

// TerminalReportCheckout is a terminal's open checkout in portal.terminals.
type TerminalReportCheckout struct {
	CheckoutRef string `json:"checkoutRef"`
	State       string `json:"state"`
	Amount      int64  `json:"amount"`
	OpenedAt    int64  `json:"openedAt"`
}

// TerminalsParams are portal.terminals' params (notification).
type TerminalsParams struct {
	CollectedAt int64            `json:"collectedAt"`
	Terminals   []TerminalReport `json:"terminals"`
}

// terminalsReportLocked is every configured terminal's state.
func (e *Engine) terminalsReportLocked(now int64) TerminalsParams {
	p := TerminalsParams{CollectedAt: now, Terminals: []TerminalReport{}}
	for _, pid := range e.portalIDs() {
		pr := e.portals[pid]
		if !pr.cfg.Methods.Payment || pr.cfg.Payment == nil {
			continue
		}
		for _, t := range pr.cfg.Payment.Terminals {
			r := TerminalReport{TerminalID: t.TerminalID, PortalID: pid, Online: e.terminalOnlineLocked(t.TerminalID, now)}
			if st := e.terminals[t.TerminalID]; st != nil {
				if st.LastSeenAt > 0 {
					v := st.LastSeenAt
					r.LastSeenAt = &v
				}
				if st.Status != nil {
					s := *st.Status
					r.Status = &s
				}
			}
			if ck := e.openCheckoutOfTerminalLocked(t.TerminalID); ck != nil {
				r.Checkout = &TerminalReportCheckout{CheckoutRef: ck.Ref, State: ck.State, Amount: ck.Amount, OpenedAt: ck.OpenedAt}
			}
			p.Terminals = append(p.Terminals, r)
		}
	}
	sort.Slice(p.Terminals, func(a, b int) bool { return p.Terminals[a].TerminalID < p.Terminals[b].TerminalID })
	return p
}

// sendTerminalsLocked sends portal.terminals now (force) or when the last
// report is older than terminalsReportInterval; only with a session and
// terminals configured.
func (e *Engine) sendTerminalsLocked(force bool) {
	now := e.clock.Now()
	report := e.terminalsReportLocked(now)
	for id := range e.termOnline {
		delete(e.termOnline, id)
	}
	for _, t := range report.Terminals {
		e.termOnline[t.TerminalID] = t.Online
	}
	a := e.currentAgent()
	if a == nil || len(report.Terminals) == 0 {
		return
	}
	wall := e.tickNow()
	if !force && wall.Sub(e.lastTerminalsReport) < terminalsReportInterval {
		return
	}
	e.lastTerminalsReport = wall
	go func() { _ = a.Notify("portal.terminals", report) }()
}

// newSession is a terminal session id: 16 random bytes, base64url.
func newSession() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
