package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testToken  = "perch_pt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testToken2 = "perch_pt_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	macTerm    = "02:00:00:00:20:99"
)

// hotspotPortal is guestPortal(3) with payment (terminals 4 and 5, the
// vector table) and click-through.
func hotspotPortal() PortalConfig {
	pc := guestPortal(3)
	pc.Methods.Payment, pc.Methods.ClickThrough = true, true
	tab := vectorTable()
	id := tab.PriceTableID
	pc.Payment = &PaymentConfig{IdleTimeoutSeconds: 60, PriceTableID: &id, PriceTables: []PriceTable{tab},
		Terminals: []TerminalConfig{
			{TerminalID: 4, Name: "Lobby", Token: testToken, Enabled: true},
			{TerminalID: 5, Name: "Cafe", Token: testToken2, Enabled: true},
		}}
	pc.ClickThrough = &ClickThroughConfig{Minutes: 30, WindowHours: 24, PerWindow: 1, Terms: "Be nice."}
	return pc
}

func hotspotEngine(t *testing.T, mutate ...func(*PortalConfig)) (*Engine, *fakeSystem, *controllerSide, *testClock) {
	t.Helper()
	sys := newFakeSystem()
	e, tc := newTestEngine(t, sys, filepath.Join(t.TempDir(), "state.db"))
	c := newController(t)
	pc := hotspotPortal()
	for _, m := range mutate {
		m(&pc)
	}
	if _, err := e.Configure(context.Background(), c.configure(pc)); err != nil {
		t.Fatal(err)
	}
	return e, sys, c, tc
}

// fakeTerminal signs requests like a coin box.
type fakeTerminal struct {
	t       *testing.T
	e       *Engine
	id      int64
	token   string
	session string
	seq     int64
	portal  int64
	mac     string
	nonces  int
}

func newTerminal(t *testing.T, e *Engine, id int64, token string) *fakeTerminal {
	return &fakeTerminal{t: t, e: e, id: id, token: token, portal: 3, mac: macTerm}
}

func (f *fakeTerminal) raw(method, op string, body string, session string, seq int64) TerminalAnswer {
	path := TerminalPathPrefix + op
	sig := SignTerminalRequest(f.token, method, path, f.id, session, seq, []byte(body))
	return f.e.Terminal(PortalView{ID: f.portal}, Client{PortalID: f.portal, MAC: f.mac, IP: "192.168.20.99"},
		TerminalRequest{Method: method, Path: path, Terminal: fmt.Sprint(f.id), Session: session, Seq: fmt.Sprint(seq),
			Signature: sig, Body: []byte(body)})
}

func (f *fakeTerminal) open() {
	f.t.Helper()
	f.nonces++
	a := f.raw("POST", "session", fmt.Sprintf(`{"nonce":"nonce-%d-abcdefghijkl"}`, f.nonces), "", 0)
	if a.Status != 200 {
		f.t.Fatalf("session: %d %v", a.Status, a.Body)
	}
	f.session = a.Body.(map[string]any)["session"].(string)
	f.seq = 0
}

func (f *fakeTerminal) call(method, op, body string) TerminalAnswer {
	f.seq++
	return f.raw(method, op, body, f.session, f.seq)
}

func (f *fakeTerminal) coin(ref, event string, amount int64) TerminalAnswer {
	return f.call("POST", "coins", fmt.Sprintf(`{"checkoutRef":%q,"eventId":%q,"amount":%d}`, ref, event, amount))
}

func bodyJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func openCheckoutRef(t *testing.T, e *Engine, mac string) string {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	ck := e.openCheckoutOfMACLocked(3, mac)
	if ck == nil {
		t.Fatal("no open checkout")
	}
	return ck.Ref
}

var g1 = Client{PortalID: 3, MAC: macG1, IP: "192.168.20.111"}
var g2 = Client{PortalID: 3, MAC: macG2, IP: "192.168.20.112"}

func TestCheckoutFullFlow(t *testing.T) {
	e, sys, _, tc := hotspotEngine(t)
	term := newTerminal(t, e, 4, testToken)
	// Offline terminal: refused.
	if o := e.OpenCheckout(g1, 4); o.Code != "terminal_offline" || o.Status != 503 {
		t.Fatalf("%+v", o)
	}
	term.open()
	if o := e.OpenCheckout(g1, 4); !o.OK || o.Code != "checkout_started" {
		t.Fatalf("%+v", o)
	}
	// Idempotent for the same guest; busy for another.
	if o := e.OpenCheckout(g1, 4); !o.OK {
		t.Fatalf("%+v", o)
	}
	if o := e.OpenCheckout(g2, 4); o.Code != "terminal_busy" || o.Status != 409 {
		t.Fatalf("%+v", o)
	}
	ref := openCheckoutRef(t, e, macG1)
	// The terminal sees it, without the guest's MAC.
	hb := bodyJSON(t, term.call("POST", "heartbeat", `{"status":{"acceptor":"on","firmware":"fw-1"}}`).Body)
	ck := hb["checkout"].(map[string]any)
	if ck["checkoutRef"] != ref || ck["state"] != "open" || strings.Contains(fmt.Sprint(hb), macG1) {
		t.Fatalf("%v", hb)
	}
	for i, amt := range []int64{5, 1, 1} {
		a := term.coin(ref, fmt.Sprintf("b1-%d", i), amt)
		if a.Status != 200 || bodyJSON(t, a.Body)["accepted"] != true {
			t.Fatalf("coin %d: %d %v", i, a.Status, a.Body)
		}
	}
	// A retried coin (same eventId, new seq) counts once.
	if a := term.coin(ref, "b1-1", 1); bodyJSON(t, a.Body)["accepted"] != false {
		t.Fatalf("%v", a.Body)
	}
	h := e.GuestHotspot(g1)
	if h.Checkout.Amount != 7 || h.Checkout.AmountText != "PHP 7" || h.Checkout.PreviewText != "1 h 20 min · 5 Mbit/s down" {
		t.Fatalf("%+v", h.Checkout)
	}
	if o := e.CheckoutCancel(g1); o.Code != "checkout_paid" {
		t.Fatalf("%+v", o)
	}
	tc.Add(10 * time.Second)
	if o := e.CheckoutDone(g1); !o.OK || o.Code != "paid" {
		t.Fatalf("%+v", o)
	}
	if !sys.has("inet", "p3_auth", macG1) {
		t.Fatal("paying device not authorised")
	}
	evs := eventsOf(e, EvCheckoutFinalized)
	if len(evs) != 1 {
		t.Fatalf("%d finalized events", len(evs))
	}
	ev := evs[0]
	if ev.CheckoutRef != ref || *ev.Amount != 7 || *ev.DurationSeconds != 4800 || *ev.CoinCount != 3 || len(ev.Coins) != 3 ||
		ev.Reason != "done" || ev.Placement != "current" || ev.ExpiresAt == nil || *ev.ExpiresAt != *ev.FinalizedAt+4800*1000 {
		t.Fatalf("%+v", ev)
	}
	// The signature and the code match the record.
	rec := CheckoutRecord{CheckoutRef: ref, PortalID: 3, TerminalID: 4, MAC: macG1, Amount: 7, Currency: "PHP", PriceTableID: 2,
		PriceRevision: 3, DurationMode: ModeWallClock, DurationSeconds: 4800, DownKbps: i64(5000), UpKbps: i64(2000),
		OpenedAt: *ev.OpenedAt, FinalizedAt: *ev.FinalizedAt, Reason: "done", LocalRef: *ev.LocalRef, CoinCount: 3}
	k := vecKeys(t)
	if sig, _ := k.SignCheckout(rec); sig != ev.Sig {
		t.Fatal("signature")
	}
	code, _ := k.CheckoutReferenceCode(rec)
	h = e.GuestHotspot(g1)
	if h.Receipt == nil || h.Receipt.ReferenceCode != FormatCode(code) || h.Checkout.State != "finalized" {
		t.Fatalf("%+v", h)
	}
	// JSON: record fields present, nullable ones null.
	raw, _ := json.Marshal(ev)
	for _, want := range []string{`"quotaBytes":null`, `"unusedAmount":0`, `"keyEpoch":1`, `"terminalId":4`, `"coins":[`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("%s missing %s", raw, want)
		}
	}
	// The terminal sees the code for 120 s (a receipt printer), then nothing.
	tv := bodyJSON(t, term.call("GET", "checkout", "").Body)["checkout"].(map[string]any)
	if tv["referenceCode"] != FormatCode(code) || tv["state"] != "finalized" {
		t.Fatalf("%v", tv)
	}
	tc.Add(121 * time.Second)
	term.open() // quiet for long: the session lives on, but open a new one anyway
	if tv := bodyJSON(t, term.call("GET", "checkout", "").Body)["checkout"]; tv != nil {
		t.Fatalf("%v", tv)
	}
	// A late coin for the closed checkout: unclaimed, journaled once.
	for i := 0; i < 2; i++ {
		a := term.coin(ref, "late-1", 5)
		if a.Status != 409 || bodyJSON(t, a.Body)["error"] != "checkout_closed" || bodyJSON(t, a.Body)["recorded"] != true {
			t.Fatalf("%d %v", a.Status, a.Body)
		}
	}
	if u := eventsOf(e, EvCheckoutUnclaimed); len(u) != 1 || *u[0].Amount != 5 || u[0].Reason != "late" || *u[0].EventID != "late-1" {
		t.Fatalf("%+v", u)
	}
}

func TestCheckoutIdleAndBelowMinimum(t *testing.T) {
	e, sys, _, tc := hotspotEngine(t, func(pc *PortalConfig) {
		// Only the 5-peso rate: 1 peso buys nothing.
		pc.Payment.PriceTables[0].Entries = pc.Payment.PriceTables[0].Entries[1:2]
	})
	term := newTerminal(t, e, 4, testToken)
	term.open()
	// Claimed and walked away: the terminal is free again after 60 s.
	if o := e.OpenCheckout(g1, 4); !o.OK {
		t.Fatal(o)
	}
	tc.Add(61 * time.Second)
	term.call("POST", "heartbeat", "")
	if o := e.OpenCheckout(g2, 4); !o.OK {
		t.Fatalf("%+v", o)
	}
	ref := openCheckoutRef(t, e, macG2)
	term.coin(ref, "c1", 1)
	if o := e.CheckoutDone(g2); o.Code != "below_minimum" || o.Status != 409 {
		t.Fatalf("%+v", o)
	}
	// Each coin resets the idle timer.
	tc.Add(50 * time.Second)
	term.coin(ref, "c2", 1)
	tc.Add(50 * time.Second)
	e.Tick(context.Background())
	if e.GuestHotspot(g2).Checkout.State != "open" {
		t.Fatal("closed too early")
	}
	// Timeout with credit below the smallest rate: unclaimed, no access.
	tc.Add(11 * time.Second)
	e.Tick(context.Background())
	if st := e.GuestHotspot(g2).Checkout.State; st != "expired" {
		t.Fatal(st)
	}
	if u := eventsOf(e, EvCheckoutUnclaimed); len(u) != 1 || u[0].Reason != "below_minimum" || *u[0].Amount != 2 || u[0].CheckoutRef != ref {
		t.Fatalf("%+v", u)
	}
	if sys.has("inet", "p3_auth", macG2) {
		t.Fatal("authorised without a purchase")
	}
	// Timeout with enough credit finalises (reason timeout).
	term.call("POST", "heartbeat", "")
	if o := e.OpenCheckout(g2, 4); !o.OK {
		t.Fatalf("%+v", o)
	}
	ref = openCheckoutRef(t, e, macG2)
	term.coin(ref, "c3", 5)
	tc.Add(61 * time.Second)
	e.Tick(context.Background())
	if f := eventsOf(e, EvCheckoutFinalized); len(f) != 1 || f[0].Reason != "timeout" {
		t.Fatalf("%+v", f)
	}
	if !sys.has("inet", "p3_auth", macG2) {
		t.Fatal("not authorised after the timeout")
	}
}

func TestCheckoutRulesAndPriceLock(t *testing.T) {
	e, _, c, _ := hotspotEngine(t)
	t4, t5 := newTerminal(t, e, 4, testToken), newTerminal(t, e, 5, testToken2)
	t4.open()
	t5.open()
	e.OpenCheckout(g1, 4)
	// Moving an empty checkout to another terminal is fine.
	if o := e.OpenCheckout(g1, 5); !o.OK {
		t.Fatalf("%+v", o)
	}
	if o := e.OpenCheckout(g2, 4); !o.OK {
		t.Fatalf("free again: %+v", o)
	}
	ref := openCheckoutRef(t, e, macG1)
	t5.coin(ref, "x1", 5)
	if o := e.OpenCheckout(g1, 4); o.Code != "terminal_busy" {
		t.Fatalf("%+v", o)
	}
	e.CheckoutCancel(g2)
	if o := e.OpenCheckout(g1, 4); o.Code != "checkout_open" {
		t.Fatalf("%+v", o)
	}
	// The operator doubles the price mid-checkout: the open one keeps its price.
	pc := hotspotPortal()
	pc.Payment.PriceTables[0].Revision = 4
	pc.Payment.PriceTables[0].Entries = []PriceEntry{{Amount: 10, Minutes: 60}}
	if _, err := e.Configure(context.Background(), c.configure(pc)); err != nil {
		t.Fatal(err)
	}
	t5.coin(ref, "x2", 5)
	if o := e.CheckoutDone(g1); !o.OK {
		t.Fatalf("%+v", o)
	}
	ev := eventsOf(e, EvCheckoutFinalized)[0]
	if *ev.PriceRevision != 3 || *ev.DurationSeconds != 2*3600 {
		t.Fatalf("price not locked: rev %d %d s", *ev.PriceRevision, *ev.DurationSeconds)
	}
	// A disabled terminal ends its open checkout: paid ones finalise.
	t4.call("POST", "heartbeat", "")
	e.OpenCheckout(g2, 4)
	ref2 := openCheckoutRef(t, e, macG2)
	t4.coin(ref2, "y1", 10)
	pc.Payment.Terminals[0].Enabled = false
	if _, err := e.Configure(context.Background(), c.configure(pc)); err != nil {
		t.Fatal(err)
	}
	if f := eventsOf(e, EvCheckoutFinalized); len(f) != 2 || f[1].CheckoutRef != ref2 || *f[1].DurationSeconds != 3600 {
		t.Fatalf("%+v", f)
	}
	if o := e.OpenCheckout(g2, 4); o.Code != "terminal_unknown" {
		t.Fatalf("%+v", o)
	}
}

func TestTerminalAuth(t *testing.T) {
	e, _, c, _ := hotspotEngine(t)
	term := newTerminal(t, e, 4, testToken)
	// Wrong token, unknown terminal, wrong portal.
	bad := newTerminal(t, e, 4, testToken2)
	if a := bad.raw("POST", "session", `{"nonce":"abcdefghijklmnopq"}`, "", 0); a.Status != 401 || bodyJSON(t, a.Body)["error"] != "invalid_signature" {
		t.Fatalf("%d %v", a.Status, a.Body)
	}
	if a := newTerminal(t, e, 9, testToken).raw("POST", "session", `{"nonce":"abcdefghijklmnopq"}`, "", 0); a.Status != 401 {
		t.Fatalf("%d", a.Status)
	}
	wp := newTerminal(t, e, 4, testToken)
	wp.portal = 8
	if a := wp.raw("POST", "session", `{"nonce":"abcdefghijklmnopq"}`, "", 0); a.Status != 403 || bodyJSON(t, a.Body)["error"] != "wrong_portal" {
		t.Fatalf("%d %v", a.Status, a.Body)
	}
	term.open()
	// Replayed session request: nonce reused.
	if a := term.raw("POST", "session", `{"nonce":"nonce-1-abcdefghijkl"}`, "", 0); a.Status != 409 || bodyJSON(t, a.Body)["error"] != "nonce_reused" {
		t.Fatalf("%d %v", a.Status, a.Body)
	}
	// Replayed request: stale seq; tampered body: signature.
	if a := term.call("POST", "heartbeat", ""); a.Status != 200 {
		t.Fatalf("%d", a.Status)
	}
	if a := term.raw("POST", "heartbeat", "", term.session, term.seq); a.Status != 409 || bodyJSON(t, a.Body)["error"] != "stale_seq" {
		t.Fatalf("%d %v", a.Status, a.Body)
	}
	path := TerminalPathPrefix + "coins"
	sig := SignTerminalRequest(testToken, "POST", path, 4, term.session, 50, []byte(`{"amount":1}`))
	a := e.Terminal(PortalView{ID: 3}, Client{PortalID: 3, MAC: macTerm, IP: "192.168.20.99"}, TerminalRequest{Method: "POST", Path: path,
		Terminal: "4", Session: term.session, Seq: "50", Signature: sig, Body: []byte(`{"amount":100}`)})
	if a.Status != 401 {
		t.Fatalf("tampered: %d", a.Status)
	}
	// An old session is dead once a new one opens.
	old := term.session
	term.open()
	if a := term.raw("POST", "heartbeat", "", old, 99); a.Status != 401 || bodyJSON(t, a.Body)["error"] != "session_unknown" {
		t.Fatalf("%d %v", a.Status, a.Body)
	}
	// MAC pin.
	pc := hotspotPortal()
	pin := "02-00-00-00-20-98"
	pc.Payment.Terminals[0].MAC = &pin
	if _, err := e.Configure(context.Background(), c.configure(pc)); err != nil {
		t.Fatal(err)
	}
	if a := term.call("POST", "heartbeat", ""); a.Status != 403 || bodyJSON(t, a.Body)["error"] != "mac_mismatch" {
		t.Fatalf("%d %v", a.Status, a.Body)
	}
	term.mac = "02:00:00:00:20:98"
	if a := term.call("POST", "heartbeat", ""); a.Status != 200 {
		t.Fatalf("%d %v", a.Status, a.Body)
	}
	// Bad amount.
	if a := term.coin("ck-x", "e1", 0); a.Status != 422 {
		t.Fatalf("%d", a.Status)
	}
	// Twenty failures from one address: blocked before any lookup.
	for i := 0; i < 20; i++ {
		bad.raw("POST", "session", `{"nonce":"abcdefghijklmnopq"}`, "", 0)
	}
	if a := term.call("POST", "heartbeat", ""); a.Status != 429 {
		t.Fatalf("%d", a.Status)
	}
}

func TestReferenceCodeMovesToNewMAC(t *testing.T) {
	e, sys, c, tc := hotspotEngine(t)
	ctx := context.Background()
	term := newTerminal(t, e, 4, testToken)
	term.open()
	e.OpenCheckout(g1, 4)
	ref := openCheckoutRef(t, e, macG1)
	term.coin(ref, "a", 5)
	e.CheckoutDone(g1)
	code := e.GuestHotspot(g1).Receipt.ReferenceCode
	tc.Add(10 * time.Minute)
	// The guest's MAC rotates; the controller is online but does not know
	// the code yet: redeemed here.
	a := &fakeAgent{handler: func(method string, params, result any) error { return fmt.Errorf("unexpected %s", method) }}
	e.SetAgent(a)
	if o := e.Redeem(ctx, g2, strings.ToLower(code), false); !o.OK {
		t.Fatalf("%+v", o)
	}
	if len(a.calls) != 0 {
		t.Fatalf("controller asked: %v", a.calls)
	}
	if sys.has("inet", "p3_auth", macG1) || !sys.has("inet", "p3_auth", macG2) {
		t.Fatal("entitlement did not move")
	}
	ended := eventsOf(e, EvGrantEnded)
	if len(ended) != 1 || ended[0].Reason != EndMoved || ended[0].MAC != macG1 {
		t.Fatalf("%+v", ended)
	}
	red := eventsOf(e, EvOfflineRedeemed)
	if len(red) != 1 || *red[0].VoucherID != 0 || red[0].CheckoutRef != ref || red[0].StartsAt != nil {
		t.Fatalf("%+v", red)
	}
	raw, _ := json.Marshal(red[0])
	if !strings.Contains(string(raw), `"voucherId":0`) {
		t.Fatal(string(raw))
	}
	// The remaining time is the same deadline, not a fresh hour.
	st := e.StatusOf(g2)
	if st.RemainingSeconds == nil || *st.RemainingSeconds != 3000 {
		t.Fatalf("remaining %v", st.RemainingSeconds)
	}
	// The controller records the payment: the full set maps localRef → id
	// and c:<ref> → v:77; the local voucher goes.
	e.mu.Lock()
	var newGrant *Grant
	for _, g := range e.grants {
		newGrant = g
	}
	e.mu.Unlock()
	exp := *eventsOf(e, EvCheckoutFinalized)[0].ExpiresAt
	grp := timeGroup("v:77", exp)
	grp.DurationSeconds = i64(3600)
	gid := int64(501)
	res, err := e.Authorize(ctx, c.authorize(true, e.lastSeq, []SignedGroup{c.group(grp)},
		[]SignedGrant{c.grant(WireGrant{GrantID: &gid, LocalRef: newGrant.LocalRef, PortalID: 3, GroupKey: "v:77", MAC: macG2, Revision: 1})}))
	if err != nil || len(res.Results) != 1 || res.Results[0].State == "rejected" {
		t.Fatalf("%+v %v", res, err)
	}
	e.mu.Lock()
	_, hasOld := e.groups["c:"+ref]
	nLocal := len(e.localVouchers)
	for _, u := range e.ended {
		if u.GroupKey != "v:77" {
			t.Errorf("ended usage not renamed: %+v", u)
		}
	}
	e.mu.Unlock()
	if hasOld || nLocal != 0 {
		t.Fatalf("old group %v, local vouchers %d", hasOld, nLocal)
	}
	if !sys.has("inet", "p3_auth", macG2) {
		t.Fatal("lost access on the mapping")
	}
}

func TestLocalVoucherDroppedByList(t *testing.T) {
	e, _, c, _ := hotspotEngine(t)
	term := newTerminal(t, e, 4, testToken)
	term.open()
	e.OpenCheckout(g1, 4)
	ref := openCheckoutRef(t, e, macG1)
	term.coin(ref, "a", 1)
	e.CheckoutDone(g1)
	code := NormalizeCode(e.GuestHotspot(g1).Receipt.ReferenceCode)
	dur := int64(600)
	if _, err := e.Vouchers(context.Background(), c.vouchers(offlineVoucher(t, 88, code, nil, &dur, 1))); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.localVouchers) != 0 {
		t.Fatal("local voucher kept")
	}
}

func TestCheckoutQueuesBehindLiveTime(t *testing.T) {
	e, sys, _, _ := hotspotEngine(t)
	// The guest already has click-through time: the payment waits behind it.
	if o := e.ClickThrough(g1, true); !o.OK {
		t.Fatalf("%+v", o)
	}
	term := newTerminal(t, e, 4, testToken)
	term.open()
	e.OpenCheckout(g1, 4)
	ref := openCheckoutRef(t, e, macG1)
	term.coin(ref, "a", 5)
	if o := e.CheckoutDone(g1); !o.OK {
		t.Fatalf("%+v", o)
	}
	ev := eventsOf(e, EvCheckoutFinalized)[0]
	if ev.Placement != "queue" || ev.ExpiresAt != nil {
		t.Fatalf("%+v", ev)
	}
	if !sys.has("inet", "p3_auth", macG1) {
		t.Fatal("click-through lost")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	queued := 0
	for _, g := range e.grants {
		if g.State == StateQueued {
			queued++
		}
	}
	if queued != 1 {
		t.Fatalf("%d queued", queued)
	}
}

func TestClickThroughLimit(t *testing.T) {
	e, sys, _, tc := hotspotEngine(t)
	if o := e.ClickThrough(g1, false); o.Code != "terms_required" {
		t.Fatalf("%+v", o)
	}
	if o := e.ClickThrough(g1, true); !o.OK {
		t.Fatalf("%+v", o)
	}
	if !sys.has("inet", "p3_auth", macG1) {
		t.Fatal("not authorised")
	}
	ev := eventsOf(e, EvClickThroughGranted)
	if len(ev) != 1 || *ev[0].DurationSeconds != 1800 || *ev[0].ExpiresAt-*ev[0].StartsAt != 1800*1000 || !strings.HasPrefix(*ev[0].LocalRef, "t") {
		t.Fatalf("%+v", ev)
	}
	raw, _ := json.Marshal(ev[0])
	if !strings.Contains(string(raw), `"downKbps":null`) {
		t.Fatal(string(raw))
	}
	if o := e.ClickThrough(g1, true); o.Code != "already_authorized" {
		t.Fatalf("%+v", o)
	}
	tc.Add(31 * time.Minute)
	e.Tick(context.Background())
	if sys.has("inet", "p3_auth", macG1) {
		t.Fatal("still authorised after 30 min")
	}
	o := e.ClickThrough(g1, true)
	if o.Code != "clickthrough_used" || o.Status != 429 || o.RetryAfter < 23*time.Hour {
		t.Fatalf("%+v", o)
	}
	h := e.GuestHotspot(g1)
	if h.ClickThrough.Available || *h.ClickThrough.RetryAfterSeconds < 23*3600 {
		t.Fatalf("%+v", h.ClickThrough)
	}
	if s := HotspotSnippets(h)["clickthrough_form"]; !strings.HasPrefix(s, `<p class="perch-clickthrough-used">Free access used. It is available again in 23 h 29 min.</p>`) {
		t.Fatal(s)
	}
	tc.Add(24 * time.Hour)
	if o := e.ClickThrough(g1, true); !o.OK {
		t.Fatalf("%+v", o)
	}
}

func TestClickThroughRenamedToControllerGroup(t *testing.T) {
	e, sys, c, _ := hotspotEngine(t)
	e.ClickThrough(g1, true)
	ev := eventsOf(e, EvClickThroughGranted)[0]
	gid := int64(9)
	g := WireGroup{GroupKey: "g:9", DurationMode: ModeWallClock, ExpiresAt: ev.ExpiresAt, DurationSeconds: i64(1800), MaxDevices: 1, Revision: 1}
	// A delta (not a full set) maps it too.
	_, err := e.Authorize(context.Background(), c.authorize(false, e.lastSeq, []SignedGroup{c.group(g)},
		[]SignedGrant{c.grant(WireGrant{GrantID: &gid, LocalRef: ev.LocalRef, PortalID: 3, GroupKey: "g:9", MAC: macG1, Revision: 1})}))
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	_, old := e.groups["t:"+*ev.LocalRef]
	e.mu.Unlock()
	if old || !sys.has("inet", "p3_auth", macG1) {
		t.Fatalf("old group %v", old)
	}
}

func TestHotspotPersistsAcrossRestart(t *testing.T) {
	sys := newFakeSystem()
	path := filepath.Join(t.TempDir(), "state.db")
	e, _ := newTestEngine(t, sys, path)
	c := newController(t)
	if _, err := e.Configure(context.Background(), c.configure(hotspotPortal())); err != nil {
		t.Fatal(err)
	}
	term := newTerminal(t, e, 4, testToken)
	term.open()
	e.OpenCheckout(g1, 4)
	ref := openCheckoutRef(t, e, macG1)
	term.coin(ref, "a", 5)
	e.ClickThrough(g2, true)
	e.Shutdown()
	e2, _ := newTestEngine(t, sys, path)
	e2.Start(context.Background())
	e2.mu.Lock()
	ck := e2.checkouts[ref]
	sess := e2.terminals[4].Session
	uses := len(e2.clickUses)
	e2.mu.Unlock()
	if ck == nil || ck.Amount != 5 || sess != term.session || uses != 1 {
		t.Fatalf("%+v %q %d", ck, sess, uses)
	}
	term.e = e2
	if a := term.coin(ref, "b", 1); a.Status != 200 {
		t.Fatalf("%d %v", a.Status, a.Body)
	}
	if o := e2.CheckoutDone(g1); !o.OK {
		t.Fatalf("%+v", o)
	}
}

func TestTerminalsNotification(t *testing.T) {
	e, _, _, _ := hotspotEngine(t)
	a := &fakeAgent{}
	e.SetAgent(a)
	term := newTerminal(t, e, 4, testToken)
	term.open()
	e.mu.Lock()
	rep := e.terminalsReportLocked(e.clock.Now())
	e.mu.Unlock()
	if len(rep.Terminals) != 2 || !rep.Terminals[0].Online || rep.Terminals[1].Online {
		t.Fatalf("%+v", rep)
	}
	time.Sleep(20 * time.Millisecond)
	a.mu.Lock()
	defer a.mu.Unlock()
	found := false
	for _, n := range a.notes {
		found = found || n == "portal.terminals"
	}
	if !found {
		t.Fatalf("%v", a.notes)
	}
}

func TestHotspotSnippets(t *testing.T) {
	e, _, _, _ := hotspotEngine(t)
	term := newTerminal(t, e, 4, testToken)
	term.open()
	s := HotspotSnippets(e.GuestHotspot(g1))
	want := `<form class="perch-form perch-checkout-start" method="post" action="/portal/checkout" data-perch-checkout="picker">` +
		`<label for="perch-terminal">Pay at a coin terminal</label><select id="perch-terminal" name="terminalId">` +
		`<option value="5" disabled>Cafe (offline)</option><option value="4">Lobby</option></select><button type="submit">Start</button></form>` +
		`<ul class="perch-rates"><li>PHP 1: 10 min</li><li>PHP 5: 1 h · 5 Mbit/s down</li><li>PHP 20: 5 h · 10 Mbit/s down</li></ul>`
	if s["checkout_form"] != want {
		t.Fatalf("picker:\n%s", s["checkout_form"])
	}
	if s["clickthrough_form"] != `<form class="perch-form perch-clickthrough" method="post" action="/portal/clickthrough"><p class="perch-terms">Be nice.</p>`+
		`<label class="perch-accept"><input type="checkbox" name="accept" value="1" required> I accept the terms of use</label><button type="submit">Free access: 30 min</button></form>` {
		t.Fatal(s["clickthrough_form"])
	}
	e.OpenCheckout(g1, 4)
	ref := openCheckoutRef(t, e, macG1)
	s = HotspotSnippets(e.GuestHotspot(g1))
	if s["checkout_form"] != `<section class="perch-checkout" data-perch-checkout="open" data-ref="`+ref+`"><h2>Insert coins at Lobby</h2>`+
		`<p class="perch-total" data-perch-amount>PHP 0</p><p class="perch-preview" data-perch-preview>Insert coins</p>`+
		`<p class="perch-idle">Closes after <span data-perch-idle>60</span> s without a coin.</p><p class="perch-terminal-state" data-perch-terminal-state></p>`+
		`<form class="perch-form" method="post" action="/portal/checkout/done"><button type="submit">Done</button></form>`+
		`<form class="perch-form" method="post" action="/portal/checkout/cancel"><button type="submit" class="secondary">Cancel</button></form>`+
		`<p><a href="/">Refresh</a></p></section>` {
		t.Fatal(s["checkout_form"])
	}
	term.coin(ref, "a", 5)
	e.CheckoutDone(g1)
	h := e.GuestHotspot(g1)
	s = HotspotSnippets(h)
	if s["reference_code"] != h.Receipt.ReferenceCode || !strings.HasPrefix(s["receipt"], `<section class="perch-receipt"><h2>Your reference code</h2><p class="perch-code">`+h.Receipt.ReferenceCode+`</p>`) ||
		!strings.Contains(s["receipt"], `<p class="perch-receipt-detail">PHP 5 · 1 h · 5 Mbit/s down · 2026-09-21 14:13 UTC</p></section>`) {
		t.Fatal(s["receipt"])
	}
	if HotspotSnippets(nil)["checkout_form"] != "" {
		t.Fatal("nil view")
	}
}

func TestFASCheckoutAndTerminalRoutes(t *testing.T) {
	f := newFAS(t, func(pc *PortalConfig) {
		h := hotspotPortal()
		pc.Methods, pc.Payment, pc.ClickThrough = h.Methods, h.Payment, h.ClickThrough
	})
	// The login page carries the snippets and the script.
	_, body := f.do(t, "GET", "/", "", nil, nil)
	for _, want := range []string{`data-perch-checkout="picker"`, `action="/portal/clickthrough"`, `/checkout.js" defer`, `action="/portal/voucher"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s", want)
		}
	}
	res, _ := f.do(t, "GET", "/assets/"+EmptySetSHA256+"/checkout.js", "", nil, nil)
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/javascript") {
		t.Fatalf("%d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	// A terminal over HTTP (the test client is both here).
	path := TerminalPathPrefix + "session"
	b := `{"nonce":"abcdefghijklmnopqrstu"}`
	hdr := map[string]string{"X-Perch-Terminal": "4", "X-Perch-Session": "", "X-Perch-Seq": "0",
		"X-Perch-Signature": SignTerminalRequest(testToken, "POST", path, 4, "", 0, []byte(b)), "Content-Type": "application/json"}
	res, body = f.do(t, "POST", path, "", strings.NewReader(b), hdr)
	if res.StatusCode != 200 || !strings.Contains(body, `"session"`) {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	// Open a checkout with a form post: 303 back.
	res, _ = f.do(t, "POST", "/portal/checkout", "", strings.NewReader("terminalId=4"),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/?m=checkout_started" {
		t.Fatalf("%d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, body = f.do(t, "GET", "/portal/checkout", "", nil, nil)
	var h map[string]any
	_ = json.Unmarshal([]byte(body), &h)
	if res.StatusCode != 200 || h["checkout"].(map[string]any)["state"] != "open" {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	// JSON errors.
	res, body = f.do(t, "POST", "/portal/checkout/cancel", "", strings.NewReader(`{}`), map[string]string{"Content-Type": "application/json"})
	if res.StatusCode != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	res, body = f.do(t, "POST", "/portal/checkout/done", "", strings.NewReader(`{}`), map[string]string{"Content-Type": "application/json"})
	if res.StatusCode != 409 || !strings.Contains(body, `"no_checkout"`) {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	// Click-through by form.
	res, _ = f.do(t, "POST", "/portal/clickthrough", "", strings.NewReader("accept=1"),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if res.Header.Get("Location") != "/?m=connected" {
		t.Fatalf("%s", res.Header.Get("Location"))
	}
	// Cross-origin posts are refused.
	res, _ = f.do(t, "POST", "/portal/checkout", "", strings.NewReader("terminalId=4"),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://203.0.113.9"})
	if res.Header.Get("Location") != "/?m=origin_mismatch" {
		t.Fatalf("%s", res.Header.Get("Location"))
	}
}
