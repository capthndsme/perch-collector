package portal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/capthndsme/perch-agentkit/rpc"
)

// Client is a guest as the pages see it: identified by the TCP source
// address → MAC on the portal's device, never by anything it sends.
type Client struct {
	PortalID int64
	MAC      string
	IP       string
	Hostname *string
}

// Outcome is a guest action's result: a message code and its HTTP status.
type Outcome struct {
	OK         bool
	Code       string
	Status     int
	RetryAfter time.Duration
}

// ErrorStatus maps a guest error code to its HTTP status (plan 4 §8).
func ErrorStatus(code string) int {
	switch code {
	case "invalid_code", "invalid_credentials":
		return http.StatusUnauthorized
	case "origin_mismatch", "wrong_portal", "disabled":
		return http.StatusForbidden
	case "already_authorized", "device_limit":
		return http.StatusConflict
	case "expired", "exhausted", "revoked":
		return http.StatusGone
	case "rate_limited":
		return http.StatusTooManyRequests
	case "controller_unreachable":
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

func fail(code string) Outcome { return Outcome{Code: code, Status: ErrorStatus(code)} }

// redeemTimeout bounds the controller round trip of a guest action.
const redeemTimeout = 8 * time.Second

// limited checks the failure limiters (only failures count).
func (e *Engine) limited(c Client, wall time.Time) (bool, time.Duration) {
	var retry time.Duration
	blocked := false
	for _, w := range []struct {
		lim *Window
		key string
	}{{e.failMin, c.MAC}, {e.failHour, c.MAC}, {e.failPortal, fmt.Sprint(c.PortalID)}} {
		if b, r := w.lim.Blocked(w.key, wall); b {
			blocked = true
			if r > retry {
				retry = r
			}
		}
	}
	return blocked, retry
}

func (e *Engine) recordFailure(c Client, code string, wall time.Time) {
	if code != "invalid_code" && code != "invalid_credentials" {
		return
	}
	e.failMin.Hit(c.MAC, wall)
	e.failHour.Hit(c.MAC, wall)
	e.failPortal.Hit(fmt.Sprint(c.PortalID), wall)
}

// Redeem redeems a voucher code for a guest: online through the
// controller, or offline from the held list when the controller is away
// (decision 20).
func (e *Engine) Redeem(ctx context.Context, c Client, input string, replace bool) Outcome {
	wall := e.tickNow()
	if b, retry := e.limited(c, wall); b {
		return Outcome{Code: "rate_limited", Status: http.StatusTooManyRequests, RetryAfter: retry}
	}
	code := NormalizeCode(input)
	if code == "" {
		e.recordFailure(c, "invalid_code", wall)
		return fail("invalid_code")
	}
	if !e.methodAllowed(c.PortalID, true) {
		return fail("bad_request")
	}
	out, err := e.callController(ctx, "portal.redeem", RedeemParams{PortalID: c.PortalID, MAC: c.MAC, IP: c.IP, Hostname: c.Hostname, Code: code, Replace: replace})
	if err == nil {
		return out
	}
	if !errors.Is(err, ErrOffline) {
		var re *rpcCodeError
		if errors.As(err, &re) {
			e.recordFailure(c, re.code, wall)
			return fail(re.code)
		}
		return fail("controller_unreachable")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	o := e.offlineRedeemLocked(c, code)
	e.recordFailure(c, o.Code, wall)
	return o
}

// Login signs a guest in with portal-user credentials (controller only).
func (e *Engine) Login(ctx context.Context, c Client, username, password string, replace bool) Outcome {
	wall := e.tickNow()
	if b, retry := e.limited(c, wall); b {
		return Outcome{Code: "rate_limited", Status: http.StatusTooManyRequests, RetryAfter: retry}
	}
	if username == "" || password == "" || len(username) > 64 || len(password) > 128 {
		return fail("bad_request")
	}
	if !e.methodAllowed(c.PortalID, false) {
		return fail("bad_request")
	}
	out, err := e.callController(ctx, "portal.login", LoginParams{PortalID: c.PortalID, MAC: c.MAC, IP: c.IP, Hostname: c.Hostname, Username: username, Password: password, Replace: replace})
	if err == nil {
		return out
	}
	var re *rpcCodeError
	if errors.As(err, &re) {
		e.recordFailure(c, re.code, wall)
		return fail(re.code)
	}
	return fail("controller_unreachable")
}

func (e *Engine) methodAllowed(portalID int64, voucher bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.portals[portalID]
	if p == nil {
		return false
	}
	if voucher {
		return p.cfg.Methods.Voucher
	}
	return p.cfg.Methods.Password
}

type rpcCodeError struct{ code string }

func (r *rpcCodeError) Error() string { return r.code }

var guestCodes = map[string]bool{
	"invalid_code": true, "invalid_credentials": true, "expired": true, "exhausted": true, "revoked": true,
	"disabled": true, "device_limit": true, "already_authorized": true, "wrong_portal": true, "rate_limited": true,
	"controller_unreachable": true,
}

// callController runs portal.redeem / portal.login and applies the answer.
// ErrOffline: no session or no answer (the offline path may run).
func (e *Engine) callController(ctx context.Context, method string, params any) (Outcome, error) {
	a := e.currentAgent()
	if a == nil {
		return Outcome{}, ErrOffline
	}
	cctx, cancel := context.WithTimeout(ctx, redeemTimeout)
	defer cancel()
	var res RedeemResult
	err := a.Call(cctx, method, params, &res)
	if err != nil {
		var rerr *rpc.Error
		if errors.As(err, &rerr) {
			if m, ok := rerr.Data.(map[string]any); ok {
				if s, ok := m["error"].(string); ok && guestCodes[s] {
					return Outcome{}, &rpcCodeError{s}
				}
			}
			return Outcome{}, &rpcCodeError{"controller_unreachable"}
		}
		return Outcome{}, ErrOffline
	}
	if res.Queued || res.Grant == nil {
		return Outcome{OK: true, Code: "connected", Status: http.StatusOK}, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.applyRedeemResultLocked(res); err != nil {
		e.log.Warn("portal: controller answer refused", "method", method, "err", err)
		return Outcome{}, &rpcCodeError{"controller_unreachable"}
	}
	return Outcome{OK: true, Code: "connected", Status: http.StatusOK}, nil
}

// applyRedeemResultLocked verifies and applies a signed grant and group.
func (e *Engine) applyRedeemResultLocked(res RedeemResult) error {
	if e.keys == nil {
		return errors.New("no portal key")
	}
	if res.Group == nil {
		return errors.New("grant without its group")
	}
	want, err := e.keys.SignGroup(res.Group.WireGroup)
	if !verify(want, err, res.Group.Sig) {
		return errors.New("group signature does not verify")
	}
	want, err = e.keys.SignGrant(res.Grant.WireGrant)
	if !verify(want, err, res.Grant.Sig) {
		return errors.New("grant signature does not verify")
	}
	if res.Grant.GroupKey != res.Group.GroupKey {
		return errors.New("grant and group do not match")
	}
	if e.portals[res.Grant.PortalID] == nil {
		return errors.New("unknown portal")
	}
	now := e.clock.Now()
	if old := e.groups[res.Group.GroupKey]; old != nil {
		// The router's accounting of this group is unchanged by one more
		// device: keep its base (the next full set brings the new one).
		old.DurationMode, old.ExpiresAt, old.DurationSeconds = res.Group.DurationMode, res.Group.ExpiresAt, res.Group.DurationSeconds
		old.QuotaBytes, old.DownKbps, old.UpKbps = res.Group.QuotaBytes, res.Group.DownKbps, res.Group.UpKbps
		old.MaxDevices, old.Revision = res.Group.MaxDevices, res.Group.Revision
		e.saveGroup(old)
	} else {
		e.upsertGroupLocked(*res.Group, e.lastSeq)
	}
	ops := &ElementOps{}
	e.upsertGrantLocked(*res.Grant, now, ops)
	e.applyOpsLocked(ops)
	e.snapshotIfDue()
	return nil
}

// voucherOfLocked is the held offline voucher of a group key (v:<id>).
func (e *Engine) voucherOfLocked(key string) *Voucher {
	var id int64
	if _, err := fmt.Sscanf(key, "v:%d", &id); err != nil {
		return nil
	}
	return e.vouchers[id]
}

// startVoucherClockLocked starts an offline voucher's wall clock (and its
// group's deadline) when it first runs.
func (e *Engine) startVoucherClockLocked(v *Voucher, now int64) (startsAt, expiresAt *int64) {
	s, x := StartClock(v.Effective(), now)
	if s == nil {
		return nil, nil
	}
	v.LocalStartsAt, v.LocalExpiresAt = s, x
	e.saveVoucher(v)
	if grp := e.groups[v.GroupKey]; grp != nil && grp.ExpiresAt == nil {
		grp.ExpiresAt = x
		e.saveGroup(grp)
	}
	return s, x
}

func newLocalRef(seq int64) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("o%d-%s", seq, hex.EncodeToString(b[:]))
}

// offlineRedeemLocked is planVoucherRedemption on the router
// (docs/gateway/portal.md §4.7).
func (e *Engine) offlineRedeemLocked(c Client, code string) Outcome {
	if e.keys == nil || !*e.settings.OfflineRedemption {
		return fail("controller_unreachable")
	}
	id, ok := e.voucherByVerifier[e.keys.Verifier(code)]
	if !ok {
		if len(e.vouchers) == 0 {
			// Nothing to check against: the code may well be valid.
			return fail("controller_unreachable")
		}
		return fail("invalid_code")
	}
	v := e.vouchers[id]
	now := e.clock.Now()
	onPortal := false
	for _, p := range v.PortalIDs {
		onPortal = onPortal || p == c.PortalID
	}
	if !onPortal {
		return fail("wrong_portal")
	}
	eff := v.Effective()
	var usage Usage
	grp := e.groups[v.GroupKey]
	if grp != nil {
		usage = e.groupUsageLocked(v.GroupKey)
	} else {
		usage = Usage{TimeUsedSeconds: v.TimeUsedSeconds, BytesUsed: v.BytesUsed}
	}
	// The wire voucher has no first-use time: a clock, usage, a group held
	// here or a local redemption mark it used.
	used := v.FirstUsed || eff.ExpiresAt != nil || usage.TimeUsedSeconds > 0 || usage.BytesUsed > 0 || grp != nil
	switch VoucherStatus(eff, usage, used, now) {
	case "expired":
		return fail("expired")
	case "exhausted":
		return fail("exhausted")
	}
	var holders []SlotHolder
	byRef := map[string]*Grant{}
	for _, g := range e.sortedGrants() {
		if g.GroupKey != v.GroupKey {
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
	evict := EvictOldest(holders, VoucherLimits(eff).MaxDevices)

	// The device's current entitlement on this portal from another group.
	var current *Grant
	var devLive []*Grant
	for _, g := range e.grants {
		if g.Live() && g.PortalID == c.PortalID && g.MAC == c.MAC && g.GroupKey != v.GroupKey {
			devLive = append(devLive, g)
		}
	}
	if len(devLive) > 0 {
		current = e.firstInOrder(devLive)
	}
	placement := "current"
	if current != nil {
		curLimits := e.entitlementOf(current).Limits
		placement = PlaceBehindCurrent(curLimits, VoucherLimits(eff))
	}
	runsNow := placement != "queue"

	// Group: the held one, else one made from the voucher.
	if grp == nil {
		wg := WireGroup{GroupKey: v.GroupKey, DurationMode: v.DurationMode, ExpiresAt: eff.ExpiresAt,
			DurationSeconds: v.DurationSeconds, QuotaBytes: v.QuotaBytes, BaseTimeUsedSeconds: v.TimeUsedSeconds,
			BaseBytesUsed: v.BytesUsed, DownKbps: v.DownKbps, UpKbps: v.UpKbps, MaxDevices: VoucherLimits(eff).MaxDevices,
			Revision: v.Revision}
		grp = &Group{WireGroup: wg, Local: true, AckedSeq: e.lastSeq}
		e.groups[v.GroupKey] = grp
		e.saveGroup(grp)
	}
	var startsAt, expiresAt *int64
	if runsNow {
		startsAt, expiresAt = e.startVoucherClockLocked(v, now)
	}
	v.FirstUsed = true
	e.saveVoucher(v)

	ops := &ElementOps{}
	e.nextLID++
	ref := newLocalRef(e.lastSeq + 1)
	g := &Grant{LID: e.nextLID, LocalRef: &ref, PortalID: c.PortalID, GroupKey: v.GroupKey, MAC: c.MAC,
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
	vid := v.VoucherID
	ev := Event{Type: EvOfflineRedeemed, PortalID: &pid, MAC: c.MAC, VoucherID: &vid, LocalRef: &ref,
		Placement: placement, StartsAt: startsAt, ExpiresAt: expiresAt, IP: g.IP, Hostname: c.Hostname}
	if placement == "swap" && current != nil {
		ev.DemotedGrantID, ev.DemotedLocalRef = current.GrantID, current.LocalRef
	}
	g.CreatedSeq = e.journalLocked(ev, now)
	e.grants[g.LID] = g
	e.saveGrant(g, ClassGrant)
	if placement == "swap" && current != nil {
		// The data bucket waits in the queue; the MAC stays authorised
		// through the new grant, so the sets do not change.
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
	e.log.Info("portal: voucher redeemed offline", "portal", c.PortalID, "mac", c.MAC, "voucher", vid, "placement", placement)
	return Outcome{OK: true, Code: "connected", Status: http.StatusOK}
}

// Logout ends the guest's grants on this portal (reason logout).
func (e *Engine) Logout(ctx context.Context, c Client) Outcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock.Now()
	ops := &ElementOps{}
	ended := false
	for _, g := range e.sortedGrants() {
		if g.PortalID == c.PortalID && g.MAC == c.MAC && g.Live() {
			e.endGrantLocked(g, EndLogout, now, ops)
			ended = true
		}
	}
	e.applyOpsLocked(ops)
	e.snapshotIfDue()
	if !ended {
		return Outcome{OK: true, Code: "logged_out", Status: http.StatusOK}
	}
	return Outcome{OK: true, Code: "logged_out", Status: http.StatusOK}
}

// GuestStatus is what the pages show about a guest.
type GuestStatus struct {
	State            string // unauthenticated | pending_device | active | queued
	Grant            *Grant
	RemainingSeconds *int64
	RemainingBytes   *int64
	ExpiresAt        *int64
	Methods          Methods
	PortalName       string
	GatewayName      string
	PrivacyNotice    string
}

// StatusOf reads a guest's state.
func (e *Engine) StatusOf(c Client) GuestStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := GuestStatus{State: "unauthenticated"}
	if p := e.portals[c.PortalID]; p != nil {
		st.Methods, st.PortalName, st.GatewayName, st.PrivacyNotice = p.cfg.Methods, p.cfg.Name, p.cfg.GatewayName, p.cfg.PrivacyNotice
	}
	var live, queued []*Grant
	for _, g := range e.grants {
		if g.PortalID != c.PortalID || g.MAC != c.MAC {
			continue
		}
		if g.Live() {
			live = append(live, g)
		} else if g.State == StateQueued {
			queued = append(queued, g)
		}
	}
	var g *Grant
	switch {
	case len(live) > 0:
		g = e.firstInOrder(live)
	case len(queued) > 0:
		g = e.firstInOrder(queued)
	default:
		return st
	}
	cp := *g
	st.Grant = &cp
	st.State = g.State
	if grp := e.groups[g.GroupKey]; grp != nil {
		l := GrantLimits(grp.EffectiveLimits(), g.ExpiresAt)
		st.RemainingSeconds, st.RemainingBytes = Remaining(l, e.groupUsageLocked(g.GroupKey), e.clock.Now())
		st.ExpiresAt = l.ExpiresAt
	}
	return st
}
