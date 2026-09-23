package portal

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/capthndsme/perch-collector/internal/observe"
)

const (
	macG1 = "02:00:00:00:20:11"
	macG2 = "02:00:00:00:20:12"
)

var nonceCounter int

func nextNonce() string {
	nonceCounter++
	raw := make([]byte, 16)
	raw[0], raw[1] = byte(nonceCounter), byte(nonceCounter>>8)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// controllerSide signs what the controller would send.
type controllerSide struct {
	t    *testing.T
	keys *Keys
	now  int64
}

func newController(t *testing.T) *controllerSide {
	return &controllerSide{t: t, keys: vecKeys(t), now: 1790000000000}
}

func (c *controllerSide) configure(portals ...PortalConfig) Config {
	return Config{Revision: 1, GatewayID: 7, Keys: &ConfigureKeys{Epoch: 1, GatewayKey: vecGatewayKey},
		Settings: Settings{EnforceIntervalSeconds: 5}, Portals: portals}
}

func guestPortal(id int64) PortalConfig {
	return PortalConfig{PortalID: id, Name: "Guest", Network: "guest", Enabled: true, Methods: Methods{Voucher: true},
		TemplateSHA256: EmptySetSHA256, GatewayName: "Lab", WalledGarden: []string{"example.com", "203.0.113.0/24"}}
}

func (c *controllerSide) group(g WireGroup) SignedGroup {
	s, err := c.keys.SignGroup(g)
	if err != nil {
		c.t.Fatal(err)
	}
	return SignedGroup{WireGroup: g, Sig: s}
}

func (c *controllerSide) grant(g WireGrant) SignedGrant {
	s, err := c.keys.SignGrant(g)
	if err != nil {
		c.t.Fatal(err)
	}
	return SignedGrant{WireGrant: g, Sig: s}
}

func (c *controllerSide) authorize(full bool, acked int64, groups []SignedGroup, grants []SignedGrant, ext ...ExternalRef) AuthorizeParams {
	p := AuthorizeParams{Full: full, ServerNow: c.now, AckedEventSeq: acked, Nonce: nextNonce(), KeyEpoch: 1,
		Groups: groups, Grants: grants, RevertExternals: ext}
	var items []string
	for _, g := range groups {
		items = append(items, g.Sig)
	}
	for _, g := range grants {
		items = append(items, g.Sig)
	}
	sig, err := c.keys.SignEnvelope(Envelope{Kind: "authorize", Full: full, ServerNow: c.now, Nonce: p.Nonce,
		ItemSignatures: items, AckedEventSeq: acked, Externals: ext})
	if err != nil {
		c.t.Fatal(err)
	}
	p.Sig = sig
	return p
}

func (c *controllerSide) deauthorize(ids []int64, reason string) DeauthorizeParams {
	p := DeauthorizeParams{GrantIDs: ids, Reason: reason, ServerNow: c.now, Nonce: nextNonce(), KeyEpoch: 1}
	p.Sig, _ = c.keys.SignEnvelope(Envelope{Kind: "deauthorize", ServerNow: c.now, Nonce: p.Nonce, ItemSignatures: []string{}, GrantIDs: ids, Reason: &reason})
	return p
}

func (c *controllerSide) vouchers(list ...WireOfflineVoucher) VouchersParams {
	p := VouchersParams{Enabled: true, ServerNow: c.now, Nonce: nextNonce(), KeyEpoch: 1}
	var items []string
	for _, v := range list {
		s, err := c.keys.SignOfflineVoucher(v)
		if err != nil {
			c.t.Fatal(err)
		}
		p.Vouchers = append(p.Vouchers, SignedOfflineVoucher{WireOfflineVoucher: v, Sig: s})
		items = append(items, s)
	}
	p.Sig, _ = c.keys.SignEnvelope(Envelope{Kind: "vouchers", Full: true, ServerNow: c.now, Nonce: p.Nonce, ItemSignatures: items})
	return p
}

func dataGroup(key string, quota int64) WireGroup {
	return WireGroup{GroupKey: key, DurationMode: ModeWallClock, QuotaBytes: &quota, MaxDevices: 1, Revision: 1}
}

func timeGroup(key string, expiresAt int64) WireGroup {
	d := int64(3600)
	return WireGroup{GroupKey: key, DurationMode: ModeWallClock, ExpiresAt: &expiresAt, DurationSeconds: &d, MaxDevices: 1, Revision: 1}
}

func configured(t *testing.T, setup ...func(*fakeSystem)) (*Engine, *fakeSystem, *controllerSide, *testClock) {
	t.Helper()
	sys := newFakeSystem()
	for _, f := range setup {
		f(sys)
	}
	e, tc := newTestEngine(t, sys, filepath.Join(t.TempDir(), "state.db"))
	c := newController(t)
	res, err := e.Configure(context.Background(), c.configure(guestPortal(3)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Portals) != 1 || res.Portals[0].State != "active" || res.Portals[0].Device != "guest" {
		t.Fatalf("configure result %+v", res)
	}
	if res.KeyEpoch == nil || *res.KeyEpoch != 1 {
		t.Fatalf("key epoch %+v", res.KeyEpoch)
	}
	return e, sys, c, tc
}

func eventsOf(e *Engine, typ string) []Event {
	var out []Event
	for _, ev := range e.events {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

func TestConfigureRendersAndWritesDropIns(t *testing.T) {
	_, sys, _, _ := configured(t)
	if !sys.tables["inet perch_portal"] || !sys.tables["inet perch_portal_acct"] || !sys.tables["netdev perch_portal_fast"] {
		t.Fatal("tables not created")
	}
	if !strings.Contains(sys.files[Fw4IncludePath], `iifname { "guest" }`) {
		t.Fatalf("fw4 drop-in: %q", sys.files[Fw4IncludePath])
	}
	var reloaded, restarted bool
	for _, c := range sys.commands {
		reloaded = reloaded || c == "fw4 -q reload"
		restarted = restarted || c == "/etc/init.d/dnsmasq restart"
	}
	if !reloaded {
		t.Fatal("fw4 not reloaded after the drop-in changed")
	}
	_ = restarted // conf dirs under /tmp do not exist in the test
	if !sys.has("inet", "p3_wgnet4", "203.0.113.0/24") {
		t.Fatal("walled garden network missing")
	}
}

// TestAuthorizeTickCountAndQuota: a kernel without quota objects; the tick
// alone enforces the quota (and overshoots by what one tick moved).
func TestAuthorizeTickCountAndQuota(t *testing.T) {
	e, sys, c, _ := configured(t, func(s *fakeSystem) { s.noQuota = true })
	if e.enf.Quota {
		t.Fatal("quota probe passed on a kernel without quotas")
	}
	ctx := context.Background()
	gid := int64(42)
	res, err := e.Authorize(ctx, c.authorize(true, 0,
		[]SignedGroup{c.group(dataGroup("v:17", 1000))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "v:17", MAC: macG1, Revision: 1})}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 || res.Results[0].State != StatePending {
		t.Fatalf("results %+v", res.Results)
	}
	if !sys.has("inet", "p3_auth", macG1) || !sys.has("acct", "p3_up", macG1) {
		t.Fatal("MAC not authorised")
	}
	// The device shows up: active, journaled.
	sys.neighbors = []observe.Neighbor{{IP: "192.168.20.111", MAC: macG1, Device: "guest", Reachable: true}}
	e.Tick(ctx)
	if g := e.findGrantLocked(&gid, nil); g == nil || g.State != StateActive || g.IP == nil || *g.IP != "192.168.20.111" {
		t.Fatalf("grant %+v", g)
	}
	if len(eventsOf(e, EvGrantActive)) != 1 {
		t.Fatal("no grant_active")
	}
	sys.count("p3_up", macG1, 300)
	sys.count("p3_down", macG1, 400)
	e.Tick(ctx)
	g := e.findGrantLocked(&gid, nil)
	if g.BytesUp != 300 || g.BytesDown != 400 {
		t.Fatalf("counted %d/%d", g.BytesUp, g.BytesDown)
	}
	// Crossing the quota ends it: out of the sets, flows flushed, journaled.
	sys.count("p3_down", macG1, 400)
	e.Tick(ctx)
	if e.findGrantLocked(&gid, nil) != nil {
		t.Fatal("grant still held after its quota")
	}
	if sys.has("inet", "p3_auth", macG1) {
		t.Fatal("MAC still authorised")
	}
	if len(sys.flushed) != 1 || sys.flushed[0][0] != "192.168.20.111" {
		t.Fatalf("flush %v", sys.flushed)
	}
	ended := eventsOf(e, EvGrantEnded)
	if len(ended) != 1 || ended[0].Reason != EndQuota || *ended[0].BytesDown != 800 || *ended[0].BytesUp != 300 {
		t.Fatalf("ended %+v", ended)
	}
}

func TestExpiryEndsGrant(t *testing.T) {
	e, sys, c, tc := configured(t)
	ctx := context.Background()
	gid := int64(5)
	exp := c.now + 60_000
	_, err := e.Authorize(ctx, c.authorize(true, 0, []SignedGroup{c.group(timeGroup("g:5", exp))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "g:5", MAC: macG1, Revision: 1})}))
	if err != nil {
		t.Fatal(err)
	}
	e.Tick(ctx)
	if e.findGrantLocked(&gid, nil) == nil {
		t.Fatal("ended early")
	}
	tc.Add(61 * time.Second)
	e.Tick(ctx)
	if e.findGrantLocked(&gid, nil) != nil || sys.has("inet", "p3_auth", macG1) {
		t.Fatal("not ended at its deadline")
	}
	if ev := eventsOf(e, EvGrantEnded); len(ev) != 1 || ev[0].Reason != EndExpired {
		t.Fatalf("%+v", ev)
	}
}

func TestActiveTimeChargedOncePerGroupTick(t *testing.T) {
	e, sys, c, tc := configured(t)
	ctx := context.Background()
	d := int64(12)
	g := WireGroup{GroupKey: "v:9", DurationMode: ModeActiveTime, DurationSeconds: &d, MaxDevices: 2, Revision: 1}
	a, b := int64(1), int64(2)
	_, err := e.Authorize(ctx, c.authorize(true, 0, []SignedGroup{c.group(g)}, []SignedGrant{
		c.grant(WireGrant{GrantID: &a, PortalID: 3, GroupKey: "v:9", MAC: macG1, Revision: 1}),
		c.grant(WireGrant{GrantID: &b, PortalID: 3, GroupKey: "v:9", MAC: macG2, Revision: 1}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	e.Tick(ctx)
	for i := 0; i < 2; i++ {
		tc.Add(5 * time.Second)
		sys.count("p3_up", macG1, 10)
		sys.count("p3_up", macG2, 10)
		e.Tick(ctx)
	}
	ga, gb := e.findGrantLocked(&a, nil), e.findGrantLocked(&b, nil)
	if ga.ActiveSeconds() != 10 || gb.ActiveSeconds() != 0 {
		t.Fatalf("charged %d / %d", ga.ActiveSeconds(), gb.ActiveSeconds())
	}
	// Idle ticks cost nothing.
	tc.Add(5 * time.Second)
	e.Tick(ctx)
	if ga.ActiveSeconds() != 10 {
		t.Fatal("idle tick charged")
	}
	tc.Add(5 * time.Second)
	sys.count("p3_up", macG2, 10)
	e.Tick(ctx)
	if e.findGrantLocked(&a, nil) != nil || e.findGrantLocked(&b, nil) != nil {
		t.Fatal("12 s budget not ended at 15 s")
	}
}

func TestExternalAuthUndoneAndExternalDeauthRespected(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	gid := int64(8)
	_, _ = e.Authorize(ctx, c.authorize(true, 0, []SignedGroup{c.group(dataGroup("g:8", 1<<30))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "g:8", MAC: macG1, Revision: 1})}))
	sys.setElem("inet", "p3_auth", macG2, true) // nft add element by hand
	e.Tick(ctx)
	if sys.has("inet", "p3_auth", macG2) {
		t.Fatal("outside authorisation not undone")
	}
	if len(eventsOf(e, EvExternalAuth)) != 1 {
		t.Fatal("external_auth not journaled")
	}
	sys.setElem("inet", "p3_auth", macG1, false) // nft delete element by hand
	e.Tick(ctx)
	if e.findGrantLocked(&gid, nil) != nil {
		t.Fatal("grant survived a deauth outside Perch")
	}
	if ev := eventsOf(e, EvGrantEnded); len(ev) != 1 || ev[0].Reason != EndRouterDeauth {
		t.Fatalf("%+v", ev)
	}
}

func TestTablesGoneAreReapplied(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	gid := int64(8)
	_, _ = e.Authorize(ctx, c.authorize(true, 0, []SignedGroup{c.group(dataGroup("g:8", 1<<30))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "g:8", MAC: macG1, Revision: 1})}))
	_ = sys.Apply(RenderDeleteAll()) // nft flush ruleset, a reboot
	e.Tick(ctx)
	if !sys.has("inet", "p3_auth", macG1) {
		t.Fatal("grant not re-applied")
	}
	if e.findGrantLocked(&gid, nil) == nil || len(eventsOf(e, EvGrantEnded)) != 0 {
		t.Fatal("a lost table must not end grants")
	}
}

func TestEnvelopeChecks(t *testing.T) {
	e, _, c, _ := configured(t)
	ctx := context.Background()
	p := c.authorize(false, 0, nil, nil)
	if _, err := e.Authorize(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Authorize(ctx, p); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("replay accepted: %v", err)
	}
	bad := c.authorize(false, 0, nil, nil)
	bad.Sig = strings.Repeat("A", 43)
	if _, err := e.Authorize(ctx, bad); err == nil {
		t.Fatal("bad signature accepted")
	}
	wrong := c.authorize(false, 0, nil, nil)
	wrong.KeyEpoch = 2
	if _, err := e.Authorize(ctx, wrong); err == nil {
		t.Fatal("unknown epoch accepted")
	}
	c.now += 11 * 60 * 1000
	if _, err := e.Authorize(ctx, c.authorize(false, 0, nil, nil)); err != nil {
		t.Fatal(err)
	}
	c.now -= 11 * 60 * 1000
	if _, err := e.Authorize(ctx, c.authorize(false, 0, nil, nil)); err == nil {
		t.Fatal("stale envelope accepted")
	}
	// A tampered item is rejected on its own.
	c.now += 11 * 60 * 1000
	gid := int64(1)
	sg := c.grant(WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "g:1", MAC: macG1, Revision: 1})
	sg.MAC = macG2
	res, err := e.Authorize(ctx, c.authorize(false, 0, []SignedGroup{c.group(dataGroup("g:1", 10))}, []SignedGrant{sg}))
	if err != nil || res.Results[0].State != "rejected" || res.Results[0].Error != "bad_signature" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestFullSetRemovesAndKeepsNewOfflineGrants(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	a, b := int64(1), int64(2)
	_, _ = e.Authorize(ctx, c.authorize(true, 0, []SignedGroup{c.group(dataGroup("g:1", 1<<30)), c.group(dataGroup("g:2", 1<<30))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &a, PortalID: 3, GroupKey: "g:1", MAC: macG1, Revision: 1}),
			c.grant(WireGrant{GrantID: &b, PortalID: 3, GroupKey: "g:2", MAC: macG2, Revision: 1})}))
	res, err := e.Authorize(ctx, c.authorize(true, 0, []SignedGroup{c.group(dataGroup("g:1", 1<<30))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &a, PortalID: 3, GroupKey: "g:1", MAC: macG1, Revision: 1})}))
	if err != nil || len(res.Ended) != 1 || *res.Ended[0].GrantID != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if sys.has("inet", "p3_auth", macG2) || !sys.has("inet", "p3_auth", macG1) {
		t.Fatal("sets wrong after full set")
	}
	if ev := eventsOf(e, EvGrantEnded); len(ev) != 1 || ev[0].Reason != EndRemoved {
		t.Fatalf("%+v", ev)
	}
}

func TestDeauthorize(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	a := int64(1)
	_, _ = e.Authorize(ctx, c.authorize(true, 0, []SignedGroup{c.group(dataGroup("g:1", 1<<30))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &a, PortalID: 3, GroupKey: "g:1", MAC: macG1, Revision: 1})}))
	sys.neighbors = []observe.Neighbor{{IP: "192.168.20.111", MAC: macG1, Device: "guest"}}
	res, err := e.Deauthorize(ctx, c.deauthorize([]int64{1, 99}, "revoked"))
	if err != nil || len(res.Ended) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if sys.has("inet", "p3_auth", macG1) || len(sys.flushed) != 1 {
		t.Fatal("not cut")
	}
}

func offlineVoucher(t *testing.T, id int64, code string, quota *int64, dur *int64, max int64) WireOfflineVoucher {
	k := vecKeys(t)
	return WireOfflineVoucher{VoucherID: id, Verifier: k.Verifier(code), PortalIDs: []int64{3}, GroupKey: fmt.Sprintf("v:%d", id),
		DurationMode: ModeWallClock, StartMode: StartFirstUse, DurationSeconds: dur, QuotaBytes: quota, MaxDevices: max, Revision: 1}
}

func TestOfflineRedemptionAndSync(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	dur := int64(600)
	if res, err := e.Vouchers(ctx, c.vouchers(offlineVoucher(t, 17, vecCode, nil, &dur, 1))); err != nil || res.Stored != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	cl := Client{PortalID: 3, MAC: macG1, IP: "192.168.20.111"}
	// No session: offline. A wrong code first.
	if o := e.Redeem(ctx, cl, "AAAAA-AAAAA", false); o.Code != "invalid_code" || o.Status != 401 {
		t.Fatalf("%+v", o)
	}
	o := e.Redeem(ctx, cl, "k7q2m-9xh4d", false)
	if !o.OK {
		t.Fatalf("%+v", o)
	}
	if !sys.has("inet", "p3_auth", macG1) {
		t.Fatal("not authorised offline")
	}
	red := eventsOf(e, EvOfflineRedeemed)
	if len(red) != 1 || *red[0].VoucherID != 17 || red[0].Placement != "current" || red[0].ExpiresAt == nil || *red[0].ExpiresAt != c.now+600_000 {
		t.Fatalf("%+v", red)
	}
	// The same code on a second device moves the voucher (max 1 device).
	cl2 := Client{PortalID: 3, MAC: macG2, IP: "192.168.20.112"}
	if o := e.Redeem(ctx, cl2, vecCode, false); !o.OK {
		t.Fatalf("%+v", o)
	}
	if sys.has("inet", "p3_auth", macG1) || !sys.has("inet", "p3_auth", macG2) {
		t.Fatal("voucher did not move")
	}
	if ev := eventsOf(e, EvGrantEnded); len(ev) != 1 || ev[0].Reason != EndMoved {
		t.Fatalf("%+v", ev)
	}
	// portal.sync reports both redemptions and the held grant.
	rep, _ := e.Sync(ctx, SyncParams{AckedEventSeq: 0})
	if rep.LastEventSeq != int64(len(e.events)) || len(rep.Grants) != 1 || rep.Grants[0].LocalRef == nil || rep.Grants[0].GrantID != nil {
		t.Fatalf("%+v", rep)
	}
	ref := *rep.Grants[0].LocalRef
	// A full set from before the redemption keeps it; the answer maps its id.
	if _, err := e.Authorize(ctx, c.authorize(true, 0, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if !sys.has("inet", "p3_auth", macG2) {
		t.Fatal("offline grant dropped by an older full set")
	}
	gid := int64(77)
	exp := c.now + 600_000
	grp := WireGroup{GroupKey: "v:17", DurationMode: ModeWallClock, ExpiresAt: &exp, DurationSeconds: &dur, MaxDevices: 1, Revision: 2}
	_, err := e.Authorize(ctx, c.authorize(true, rep.LastEventSeq, []SignedGroup{c.group(grp)},
		[]SignedGrant{c.grant(WireGrant{GrantID: &gid, LocalRef: &ref, PortalID: 3, GroupKey: "v:17", MAC: macG2, Revision: 1})}))
	if err != nil {
		t.Fatal(err)
	}
	g := e.findGrantLocked(&gid, nil)
	if g == nil || g.LocalRef == nil || *g.LocalRef != ref {
		t.Fatalf("id not mapped: %+v", g)
	}
	// Sync after the ack returns nothing old.
	rep2, _ := e.Sync(ctx, SyncParams{AckedEventSeq: rep.LastEventSeq})
	if len(rep2.Events) != 0 {
		t.Fatalf("%+v", rep2.Events)
	}
}

func TestOnlineRedeemAppliesSignedAnswer(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	gid := int64(501)
	a := &fakeAgent{handler: func(method string, params any, result any) error {
		r := result.(*RedeemResult)
		grp := c.group(dataGroup("v:30", 1<<30))
		gr := c.grant(WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "v:30", MAC: macG1, Revision: 1})
		r.Group, r.Grant = &grp, &gr
		return nil
	}}
	e.SetAgent(a)
	o := e.Redeem(ctx, Client{PortalID: 3, MAC: macG1, IP: "192.168.20.111"}, "ABCDE-FGHJK", false)
	if !o.OK || !sys.has("inet", "p3_auth", macG1) {
		t.Fatalf("%+v", o)
	}
	// A controller that does not answer: offline, and nothing held → unreachable.
	a.down = true
	if o := e.Redeem(ctx, Client{PortalID: 3, MAC: macG2}, "ABCDE-FGHJK", false); o.Code != "controller_unreachable" || o.Status != 503 {
		t.Fatalf("%+v", o)
	}
}

func TestFailureLimits(t *testing.T) {
	e, _, c, _ := configured(t)
	ctx := context.Background()
	dur := int64(600)
	_, _ = e.Vouchers(ctx, c.vouchers(offlineVoucher(t, 17, vecCode, nil, &dur, 1)))
	cl := Client{PortalID: 3, MAC: macG1}
	for i := 0; i < 5; i++ {
		if o := e.Redeem(ctx, cl, "AAAAAAAAAA", false); o.Code != "invalid_code" {
			t.Fatalf("attempt %d: %+v", i, o)
		}
	}
	o := e.Redeem(ctx, cl, vecCode, false)
	if o.Code != "rate_limited" || o.Status != 429 || o.RetryAfter <= 0 {
		t.Fatalf("6th attempt %+v", o)
	}
	// Another device still redeems.
	if o := e.Redeem(ctx, Client{PortalID: 3, MAC: macG2}, vecCode, false); !o.OK {
		t.Fatalf("%+v", o)
	}
}

func TestRestartRestoresState(t *testing.T) {
	sys := newFakeSystem()
	path := filepath.Join(t.TempDir(), "state.db")
	e, _ := newTestEngine(t, sys, path)
	c := newController(t)
	ctx := context.Background()
	if _, err := e.Configure(ctx, c.configure(guestPortal(3))); err != nil {
		t.Fatal(err)
	}
	gid := int64(9)
	_, _ = e.Authorize(ctx, c.authorize(true, 0, []SignedGroup{c.group(dataGroup("g:9", 1<<30))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "g:9", MAC: macG1, Revision: 1})}))
	e.Shutdown()
	// Reboot: tables gone, a new process on the snapshot, no controller.
	sys2 := newFakeSystem()
	e2, _ := newTestEngine(t, sys2, path)
	e2.Start(ctx)
	if !sys2.has("inet", "p3_auth", macG1) {
		t.Fatal("grant not re-applied at start")
	}
	if e2.keys == nil || e2.keys.Epoch != 1 || e2.lastSeq != e.lastSeq {
		t.Fatal("keys or journal lost")
	}
	// The nonce memory survived: a replay is still refused.
	p := c.authorize(false, 0, nil, nil)
	if _, err := e2.Authorize(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.Authorize(ctx, p); err == nil {
		t.Fatal("replay after restart accepted")
	}
}

func TestSeveralPortals(t *testing.T) {
	sys := newFakeSystem()
	sys.devices["br-trunk.110"] = nil
	e, _ := newTestEngine(t, sys, filepath.Join(t.TempDir(), "s.db"))
	c := newController(t)
	v := guestPortal(4)
	v.Network = "vlan110"
	res, err := e.Configure(context.Background(), c.configure(guestPortal(3), v))
	if err != nil || len(res.Portals) != 2 || res.Portals[1].Device != "br-trunk.110" {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.Contains(sys.files[Fw4IncludePath], `"br-trunk.110", "guest"`) {
		t.Fatalf("%s", sys.files[Fw4IncludePath])
	}
	a, b := int64(1), int64(2)
	_, err = e.Authorize(context.Background(), c.authorize(true, 0, []SignedGroup{c.group(dataGroup("g:1", 1<<30)), c.group(dataGroup("g:2", 1<<30))},
		[]SignedGrant{c.grant(WireGrant{GrantID: &a, PortalID: 3, GroupKey: "g:1", MAC: macG1, Revision: 1}),
			c.grant(WireGrant{GrantID: &b, PortalID: 4, GroupKey: "g:2", MAC: macG2, Revision: 1})}))
	if err != nil {
		t.Fatal(err)
	}
	if !sys.has("inet", "p3_auth", macG1) || !sys.has("inet", "p4_auth", macG2) || sys.has("inet", "p3_auth", macG2) {
		t.Fatal("portal sets mixed up")
	}
}
