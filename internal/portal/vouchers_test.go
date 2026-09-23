package portal

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/link"
	"github.com/capthndsme/perch-agentkit/rpc"
)

// voucherParts signs a list the way the controller's buildVouchersMessages
// does: parts of at most per, one serverNow, part 1 replaces, the rest
// append (envelope reason "append").
func (c *controllerSide) voucherParts(list []WireOfflineVoucher, per int) []VouchersParams {
	parts := (len(list) + per - 1) / per
	if parts == 0 {
		parts = 1
	}
	var out []VouchersParams
	for i := 0; i < parts; i++ {
		end := (i + 1) * per
		if end > len(list) {
			end = len(list)
		}
		p := VouchersParams{Enabled: true, ServerNow: c.now, Nonce: nextNonce(), KeyEpoch: 1,
			Append: i > 0, Part: i + 1, Parts: parts, Vouchers: []SignedOfflineVoucher{}}
		items := []string{}
		for _, v := range list[i*per : end] {
			s, err := c.keys.SignOfflineVoucher(v)
			if err != nil {
				c.t.Fatal(err)
			}
			p.Vouchers = append(p.Vouchers, SignedOfflineVoucher{WireOfflineVoucher: v, Sig: s})
			items = append(items, s)
		}
		env := Envelope{Kind: "vouchers", Full: true, ServerNow: c.now, Nonce: p.Nonce, ItemSignatures: items}
		if p.Append {
			r := "append"
			env.Reason = &r
		}
		p.Sig, _ = c.keys.SignEnvelope(env)
		out = append(out, p)
	}
	return out
}

func manyVouchers(t *testing.T, n int) ([]WireOfflineVoucher, []string) {
	k := vecKeys(t)
	dur := int64(3600)
	list := make([]WireOfflineVoucher, n)
	codes := make([]string, n)
	for i := range list {
		codes[i] = fmt.Sprintf("K%09d", i)
		list[i] = WireOfflineVoucher{VoucherID: int64(1000 + i), Verifier: k.Verifier(codes[i]), PortalIDs: []int64{3},
			GroupKey: fmt.Sprintf("v:%d", 1000+i), DurationMode: ModeWallClock, StartMode: StartFirstUse,
			DurationSeconds: &dur, MaxDevices: 1, Revision: 1}
	}
	return list, codes
}

func TestVouchersInParts(t *testing.T) {
	e, _, c, _ := configured(t)
	ctx := context.Background()
	list, codes := manyVouchers(t, 9000)
	parts := c.voucherParts(list, 4000)
	if len(parts) != 3 {
		t.Fatalf("%d parts", len(parts))
	}
	for i, p := range parts {
		res, err := e.Vouchers(ctx, p)
		if err != nil || res.Rejected != 0 {
			t.Fatalf("part %d: %+v %v", i+1, res, err)
		}
	}
	if len(e.vouchers) != 9000 || len(e.voucherByVerifier) != 9000 {
		t.Fatalf("held %d", len(e.vouchers))
	}
	// A voucher of the last part redeems offline.
	if o := e.Redeem(ctx, Client{PortalID: 3, MAC: macG1, IP: "192.168.20.111"}, codes[8999], false); !o.OK {
		t.Fatalf("%+v", o)
	}
	// The next list's part 1 replaces everything.
	c.now += 60_000
	short := c.voucherParts(list[:10], 4000)
	if _, err := e.Vouchers(ctx, short[0]); err != nil {
		t.Fatal(err)
	}
	if len(e.vouchers) != 10 {
		t.Fatalf("not replaced: %d", len(e.vouchers))
	}
	// The stored list survives a restart (the store is the snapshot's source).
	n := 0
	rows, _ := e.store.Query(`SELECT count(*) FROM vouchers`)
	for rows.Next() {
		_ = rows.Scan(&n)
	}
	rows.Close()
	if n != 10 {
		t.Fatalf("stored %d", n)
	}
}

func TestVoucherPartOutOfOrderRefused(t *testing.T) {
	e, _, c, _ := configured(t)
	ctx := context.Background()
	list, _ := manyVouchers(t, 30)
	old := c.voucherParts(list, 10)
	for _, p := range old {
		if _, err := e.Vouchers(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	// A newer list whose part 1 never arrived: its part 2 is refused.
	c.now += 1000
	newer := c.voucherParts(list[:20], 10)
	_, err := e.Vouchers(ctx, newer[1])
	var re *rpc.Error
	if !errors.As(err, &re) || re.Data.(map[string]any)["error"] != "vouchers_out_of_order" {
		t.Fatalf("%v", err)
	}
	if len(e.vouchers) != 30 {
		t.Fatal("list changed by a refused part")
	}
	// Part 1 of the newer list, then an older list's part (a replay with a
	// fresh nonce would need the signature; the old serverNow gives it away).
	if _, err := e.Vouchers(ctx, newer[0]); err != nil {
		t.Fatal(err)
	}
	stale := c.voucherParts(list, 10)[2]
	stale.ServerNow -= 1000 // what an older list's part carries
	stale.Sig, _ = c.keys.SignEnvelope(Envelope{Kind: "vouchers", Full: true, ServerNow: stale.ServerNow, Nonce: stale.Nonce,
		ItemSignatures: sigsOf(stale.Vouchers), Reason: str("append")})
	if _, err := e.Vouchers(ctx, stale); err == nil {
		t.Fatal("an older list's part was appended")
	}
	// An append part must be signed as one: the same part without the
	// "append" reason does not verify.
	p := newer[1]
	p.Sig, _ = c.keys.SignEnvelope(Envelope{Kind: "vouchers", Full: true, ServerNow: p.ServerNow, Nonce: p.Nonce, ItemSignatures: sigsOf(p.Vouchers)})
	if _, err := e.Vouchers(ctx, p); err == nil {
		t.Fatal("append accepted under a replace signature")
	}
	// The same part again (the controller's retry: a fresh nonce) appends.
	if _, err := e.Vouchers(ctx, c.voucherParts(list[:20], 10)[1]); err != nil || len(e.vouchers) != 20 {
		t.Fatalf("%v %d", err, len(e.vouchers))
	}
}

func sigsOf(list []SignedOfflineVoucher) []string {
	out := []string{}
	for _, v := range list {
		out = append(out, v.Sig)
	}
	return out
}

func TestOfflineRedemptionHonoursFirstUsedAt(t *testing.T) {
	e, _, c, _ := configured(t)
	ctx := context.Background()
	k := vecKeys(t)
	dur := int64(3600)
	past := c.now - 1000
	mk := func(id int64, code string) WireOfflineVoucher {
		return WireOfflineVoucher{VoucherID: id, Verifier: k.Verifier(code), PortalIDs: []int64{3}, GroupKey: fmt.Sprintf("v:%d", id),
			DurationMode: ModeWallClock, StartMode: StartFirstUse, DurationSeconds: &dur, MaxDevices: 2, RedeemBy: &past, Revision: 1}
	}
	unused := mk(1, "AAAAAAAAA1")
	used := mk(2, "AAAAAAAAA2")
	used.FirstUsedAt = i64(c.now - 600_000)
	exp := c.now + 3_000_000
	used.ExpiresAt = &exp
	// Creation-start: a deadline from the start, never redeemed.
	creation := mk(3, "AAAAAAAAA3")
	creation.StartMode = StartCreation
	creation.ExpiresAt = &exp
	if _, err := e.Vouchers(ctx, c.vouchers(unused, used, creation)); err != nil {
		t.Fatal(err)
	}
	cl := Client{PortalID: 3, MAC: macG1, IP: "192.168.20.111"}
	if o := e.Redeem(ctx, cl, "AAAAAAAAA1", false); o.Code != "expired" {
		t.Fatalf("unused past redeemBy: %+v", o)
	}
	if o := e.Redeem(ctx, cl, "AAAAAAAAA3", false); o.Code != "expired" {
		t.Fatalf("unused creation-start voucher past redeemBy: %+v", o)
	}
	// Used (firstUsedAt): redeemBy no longer applies; a second device joins.
	if o := e.Redeem(ctx, cl, "AAAAAAAAA2", false); !o.OK {
		t.Fatalf("used voucher past redeemBy: %+v", o)
	}
}

// sessionAgent is a controller session whose Call blocks until ctx ends,
// or reports the session closed.
type sessionAgent struct {
	fakeAgent
	ctx    context.Context
	closed bool
}

func (a *sessionAgent) Context() context.Context { return a.ctx }

func (a *sessionAgent) Call(ctx context.Context, method string, params, result any) error {
	a.mu.Lock()
	a.calls = append(a.calls, method)
	a.mu.Unlock()
	if a.closed {
		return link.ErrClosed
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestNoOfflineRedemptionWhileAnAnswerMayCome(t *testing.T) {
	e, sys, c, _ := configured(t)
	dur := int64(600)
	if _, err := e.Vouchers(context.Background(), c.vouchers(offlineVoucher(t, 17, vecCode, nil, &dur, 1))); err != nil {
		t.Fatal(err)
	}
	cl := Client{PortalID: 3, MAC: macG1, IP: "192.168.20.111"}
	defer func(d time.Duration) { redeemTimeout = d }(redeemTimeout)
	redeemTimeout = 50 * time.Millisecond
	// The guest gives up after a moment; the session is alive, so the call
	// runs its full 8 s and answers unreachable: never offline.
	a := &sessionAgent{ctx: context.Background()}
	e.SetAgent(a)
	guest, cancel := context.WithCancel(context.Background())
	cancel()
	o := e.Redeem(guest, cl, vecCode, false)
	if o.Code != "controller_unreachable" || sys.has("inet", "p3_auth", macG1) || len(eventsOf(e, EvOfflineRedeemed)) != 0 {
		t.Fatalf("redeemed offline while the controller could still answer: %+v", o)
	}
	// The session ends under the call: no answer can come, offline runs.
	a.closed = true
	if o := e.Redeem(context.Background(), cl, vecCode, false); !o.OK || !sys.has("inet", "p3_auth", macG1) {
		t.Fatalf("%+v", o)
	}
	// A session already ended is no session.
	done, stop := context.WithCancel(context.Background())
	stop()
	b := &sessionAgent{ctx: done}
	e.SetAgent(b)
	if o := e.Redeem(context.Background(), Client{PortalID: 3, MAC: macG2, IP: "192.168.20.112"}, vecCode, false); !o.OK || len(b.calls) != 0 {
		t.Fatalf("%+v calls %v", o, b.calls)
	}
}
