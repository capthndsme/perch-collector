package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Envelope checks (docs/gateway/portal.md §6.3): key epoch, signature,
// nonce (the last 256 are remembered), freshness (10 minutes behind the
// newest accepted serverNow).
// ---------------------------------------------------------------------------

func (e *Engine) checkEnvelopeLocked(keyEpoch int64, env Envelope, sig string) error {
	if e.keys == nil {
		return errRPC(codeFailed, "no_keys", "the router holds no portal key yet; send portal.configure with keys")
	}
	if keyEpoch != e.keys.Epoch {
		return errRPC(codeFailed, "key_epoch_mismatch", "key epoch %d, the router holds %d", keyEpoch, e.keys.Epoch)
	}
	want, err := e.keys.SignEnvelope(env)
	if err != nil {
		return errRPC(codeInvalidParams, "bad_envelope", "%v", err)
	}
	if !SignatureMatches(want, sig) {
		return errRPC(codeFailed, "bad_signature", "envelope signature does not verify")
	}
	for _, n := range e.nonces {
		if n == env.Nonce {
			return errRPC(codeFailed, "replayed", "nonce already seen")
		}
	}
	if e.newestServerNow > 0 && env.ServerNow < e.newestServerNow-freshness {
		return errRPC(codeFailed, "stale", "serverNow is more than 10 minutes older than the newest accepted")
	}
	e.nonces = append(e.nonces, env.Nonce)
	_ = e.store.Exec(ClassGrant, `INSERT OR REPLACE INTO nonces (nonce, at) VALUES (?, ?)`, env.Nonce, env.ServerNow)
	if len(e.nonces) > nonceMemory {
		drop := e.nonces[:len(e.nonces)-nonceMemory]
		e.nonces = append([]string(nil), e.nonces[len(e.nonces)-nonceMemory:]...)
		for _, n := range drop {
			_ = e.store.Exec(ClassGrant, `DELETE FROM nonces WHERE nonce = ?`, n)
		}
	}
	if env.ServerNow > e.newestServerNow {
		e.newestServerNow = env.ServerNow
		_ = e.store.SetMeta(ClassGrant, "newestServerNow", fmt.Sprint(env.ServerNow))
	}
	e.clock.Observe(env.ServerNow)
	return nil
}

// ---------------------------------------------------------------------------
// portal.authorize
// ---------------------------------------------------------------------------

// Authorize applies portal.authorize (full set or delta).
func (e *Engine) Authorize(ctx context.Context, p AuthorizeParams) (AuthorizeResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	items := make([]string, 0, len(p.Groups)+len(p.Grants))
	for _, g := range p.Groups {
		items = append(items, g.Sig)
	}
	for _, g := range p.Grants {
		items = append(items, g.Sig)
	}
	env := Envelope{Kind: "authorize", Full: p.Full, ServerNow: p.ServerNow, Nonce: p.Nonce,
		ItemSignatures: items, AckedEventSeq: p.AckedEventSeq, Externals: p.RevertExternals}
	if err := e.checkEnvelopeLocked(p.KeyEpoch, env, p.Sig); err != nil {
		return AuthorizeResult{}, err
	}
	now := e.clock.Now()
	res := AuthorizeResult{Results: []AuthorizeItemResult{}, Ended: []GrantRef{}}

	// Groups first: a grant needs its group.
	accepted := map[string]bool{}
	for _, sg := range p.Groups {
		want, err := e.keys.SignGroup(sg.WireGroup)
		if !verify(want, err, sg.Sig) {
			e.log.Warn("portal: group signature does not verify", "group", sg.GroupKey)
			continue
		}
		accepted[sg.GroupKey] = true
		e.upsertGroupLocked(sg, p.AckedEventSeq)
	}
	ops := &ElementOps{}
	listed := map[int64]bool{} // lid
	for _, sg := range p.Grants {
		r := AuthorizeItemResult{GrantID: sg.GrantID, LocalRef: sg.LocalRef, Revision: sg.Revision}
		want, err := e.keys.SignGrant(sg.WireGrant)
		switch {
		case !verify(want, err, sg.Sig):
			r.State, r.Error = "rejected", "bad_signature"
		case e.groups[sg.GroupKey] == nil:
			r.State, r.Error = "rejected", "unknown_group"
		case e.portalFor(sg.PortalID) == nil:
			r.State, r.Error = "rejected", "unknown_portal"
		default:
			g := e.upsertGrantLocked(sg, now, ops)
			listed[g.LID] = true
			r.State = g.State
			if g.State == StateQueued {
				r.State = StatePending
			}
		}
		res.Results = append(res.Results, r)
	}
	if p.Full {
		// The controller recorded every payment up to its acked seq.
		e.dropAckedLocalVouchersLocked(p.AckedEventSeq)
		for _, g := range e.sortedGrants() {
			if listed[g.LID] {
				continue
			}
			// Offline grants the controller has not seen yet stay.
			if g.CreatedSeq > p.AckedEventSeq {
				continue
			}
			if g.State == StateQueued {
				e.dropGrantLocked(g) // the controller holds the queue now
				continue
			}
			res.Ended = append(res.Ended, g.Ref())
			e.endGrantLocked(g, EndRemoved, now, ops)
		}
		// Groups no grant uses any more.
		used := map[string]bool{}
		for _, g := range e.grants {
			used[g.GroupKey] = true
		}
		for key := range e.groups {
			if !used[key] && !accepted[key] {
				delete(e.groups, key)
				e.deleteGroup(key)
			}
		}
	}
	for _, x := range p.RevertExternals {
		e.revertExternalLocked(x, ops)
	}
	e.applyOpsLocked(ops)
	e.saveMetaJSON("lastAuthorizeSeq", p.AckedEventSeq)
	e.snapshotIfDue()
	return res, nil
}

func (e *Engine) portalFor(id int64) *portalRuntime {
	p := e.portals[id]
	if p == nil {
		return nil
	}
	return p
}

// upsertGroupLocked stores a verified group. Its base* reflects the journal
// up to ackedSeq: ended usage recorded up to there is in it now.
func (e *Engine) upsertGroupLocked(sg SignedGroup, ackedSeq int64) {
	old := e.groups[sg.GroupKey]
	g := &Group{WireGroup: sg.WireGroup, Sig: sg.Sig, AckedSeq: ackedSeq}
	if old != nil && old.ClockStartedAt != nil && g.ExpiresAt == nil {
		g.ClockStartedAt = old.ClockStartedAt
	}
	e.groups[sg.GroupKey] = g
	e.pruneEndedLocked(sg.GroupKey, ackedSeq)
	e.saveGroup(g)
}

func (e *Engine) pruneEndedLocked(key string, upTo int64) {
	kept := e.ended[:0]
	for _, u := range e.ended {
		if u.GroupKey == key && u.Seq <= upTo {
			continue
		}
		kept = append(kept, u)
	}
	e.ended = kept
	_ = e.store.Exec(ClassGrant, `DELETE FROM ended_usage WHERE group_key = ? AND seq <= ?`, key, upTo)
}

// findGrantLocked finds a held grant by id, else by localRef.
func (e *Engine) findGrantLocked(id *int64, localRef *string) *Grant {
	for _, g := range e.grants {
		if id != nil && g.GrantID != nil && *g.GrantID == *id {
			return g
		}
	}
	if localRef != nil && *localRef != "" {
		for _, g := range e.grants {
			if g.LocalRef != nil && *g.LocalRef == *localRef {
				return g
			}
		}
	}
	return nil
}

// upsertGrantLocked applies one verified grant: new ones are authorised at
// once; a known one takes the new revision (and learns its id).
func (e *Engine) upsertGrantLocked(sg SignedGrant, now int64, ops *ElementOps) *Grant {
	g := e.findGrantLocked(sg.GrantID, sg.LocalRef)
	if g == nil {
		e.nextLID++
		g = &Grant{LID: e.nextLID, State: StatePending, CreatedAt: now}
		e.grants[g.LID] = g
	}
	wasLive := g.Live()
	oldMAC, oldPortal, oldKey := g.MAC, g.PortalID, g.GroupKey
	if sg.GrantID != nil {
		id := *sg.GrantID
		g.GrantID = &id
	}
	if sg.LocalRef != nil {
		ref := *sg.LocalRef
		g.LocalRef = &ref
	}
	g.PortalID, g.GroupKey, g.MAC = sg.PortalID, sg.GroupKey, sg.MAC
	g.ExpiresAt, g.Revision, g.Sig = sg.ExpiresAt, sg.Revision, sg.Sig
	if g.State == StateQueued {
		g.State = StatePending
	}
	// Once the controller knows it, it is the controller's grant.
	g.CreatedSeq = 0
	if wasLive && (oldMAC != g.MAC || oldPortal != g.PortalID) {
		e.unauthorizeMACLocked(oldPortal, oldMAC, ops, g)
	}
	e.authorizeMACLocked(g.PortalID, g.MAC, ops)
	e.startGroupClockLocked(g, now)
	e.saveGrant(g, ClassGrant)
	if oldKey != "" && oldKey != g.GroupKey && isLocalGroupKey(oldKey) {
		// The controller took over a checkout's or click-through's grant.
		e.renameLocalGroupLocked(oldKey, g.GroupKey)
	}
	return g
}

// startGroupClockLocked: a wall-clock group without a deadline starts its
// clock when a grant of it runs (safety net, see Group.ClockStartedAt).
func (e *Engine) startGroupClockLocked(g *Grant, now int64) {
	grp := e.groups[g.GroupKey]
	if grp == nil || grp.DurationMode != ModeWallClock || grp.ExpiresAt != nil || grp.DurationSeconds == nil || grp.ClockStartedAt != nil {
		return
	}
	if !g.Live() {
		return
	}
	t := now
	grp.ClockStartedAt = &t
	e.saveGroup(grp)
}

func (e *Engine) authorizeMACLocked(portalID int64, mac string, ops *ElementOps) {
	p := e.portals[portalID]
	if p == nil || !p.cfg.Enabled || p.device == "" {
		return
	}
	ops.Authorize(portalID, mac, e.countingOf(p))
}

// unauthorizeMACLocked takes a MAC out of a portal's sets unless another
// live grant (other than except) still holds it.
func (e *Engine) unauthorizeMACLocked(portalID int64, mac string, ops *ElementOps, except *Grant) {
	for _, o := range e.grants {
		if o != except && o.Live() && o.PortalID == portalID && o.MAC == mac {
			return
		}
	}
	p := e.portals[portalID]
	if p == nil || !p.cfg.Enabled || p.device == "" {
		return
	}
	ops.Deauthorize(portalID, mac, e.countingOf(p))
}

// applyOpsLocked runs queued element changes; on failure the next tick
// re-renders everything.
func (e *Engine) applyOpsLocked(ops *ElementOps) {
	if !e.enf.Nft || len(e.enforcing()) == 0 {
		return
	}
	if e.structural {
		_ = e.applyStructuralLocked()
		return
	}
	// The data cut follows every change of the sets in the same
	// transaction: a device authorised here is cut at its quota from its
	// first byte, not from the next tick.
	script := &ElementOps{}
	var nextQ map[string]*kernelQuota
	var nextQMap, nextQAddr map[int64]map[string]string
	if e.enf.Quota {
		pre, post := &ElementOps{}, &ElementOps{}
		nextQ, nextQMap, nextQAddr = e.quotaOpsLocked(pre, post, e.kqReseed)
		script.Append(pre)
		script.Append(ops)
		script.Append(post)
	} else {
		script.Append(ops)
	}
	if script.Empty() {
		e.kqReseed = nil
		return
	}
	if err := e.sys.Apply(script.Script()); err != nil {
		e.log.Warn("portal: set update failed; re-rendering the ruleset", "err", err)
		e.structural = true
		_ = e.applyStructuralLocked()
		return
	}
	if e.enf.Quota {
		e.kq, e.kqMap, e.kqAddr, e.kqReseed = nextQ, nextQMap, nextQAddr, nil
	}
	for _, p := range e.enforcing() {
		e.applied[p.cfg.PortalID] = e.desiredAuth(p.cfg.PortalID)
	}
}

// endGrantLocked ends a live grant: out of the sets, its connections
// flushed, its final usage journaled and kept for its group.
func (e *Engine) endGrantLocked(g *Grant, reason string, now int64, ops *ElementOps) {
	wasLive := g.Live()
	if wasLive {
		e.unauthorizeMACLocked(g.PortalID, g.MAC, ops, g)
	}
	g.State = "ended"
	if wasLive && g.Bound != "" {
		if p := e.portals[g.PortalID]; p != nil && p.cfg.IPBinding && p.device != "" {
			ops.Unbind(g.PortalID, g.MAC, g.Bound)
		}
	}
	up, down, act := g.BytesUp, g.BytesDown, g.ActiveSeconds()
	pid := g.PortalID
	ev := Event{Type: EvGrantEnded, PortalID: &pid, MAC: g.MAC, GrantID: g.GrantID, LocalRef: g.LocalRef,
		Reason: reason, BytesUp: &up, BytesDown: &down, ActiveSeconds: &act}
	seq := e.journalLocked(ev, now)
	u := endedUsage{GroupKey: g.GroupKey, Seq: seq, TimeUsed: act, Bytes: up + down}
	e.ended = append(e.ended, u)
	_ = e.store.Exec(ClassGrant, `INSERT INTO ended_usage (group_key, seq, time_used, bytes_used) VALUES (?, ?, ?, ?)`,
		u.GroupKey, u.Seq, u.TimeUsed, u.Bytes)
	if wasLive {
		e.flushLocked(g)
	}
	e.dropGrantLocked(g)
}

func (e *Engine) dropGrantLocked(g *Grant) {
	delete(e.grants, g.LID)
	e.deleteGrant(g)
}

// flushLocked deletes the device's conntrack entries so running flows stop
// (deauth leaves established flows running otherwise: amendment §7).
func (e *Engine) flushLocked(g *Grant) {
	ips := map[string]bool{}
	for _, ip := range g.IPs {
		ips[ip] = true
	}
	if g.IP != nil {
		ips[*g.IP] = true
	}
	if p := e.portals[g.PortalID]; p != nil && p.device != "" {
		if list, err := e.sys.Neighbors(); err == nil {
			for _, n := range list {
				if n.Device == p.device && strings.EqualFold(n.MAC, g.MAC) {
					ips[n.IP] = true
				}
			}
		}
	}
	if len(ips) == 0 {
		return
	}
	list := make([]string, 0, len(ips))
	for ip := range ips {
		list = append(list, ip)
	}
	sort.Strings(list)
	if n, err := e.sys.FlushConntrack(list); err != nil {
		e.log.Warn("portal: conntrack flush failed", "mac", g.MAC, "err", err)
	} else if n > 0 {
		e.log.Debug("portal: flows flushed", "mac", g.MAC, "flows", n)
	}
}

// revertExternalLocked undoes an authorisation made outside Perch.
func (e *Engine) revertExternalLocked(x ExternalRef, ops *ElementOps) {
	mac := NormalizeMAC(x.MAC)
	if mac == "" {
		return
	}
	for _, id := range e.portalIDs() {
		if x.PortalID != nil && *x.PortalID != id {
			continue
		}
		if e.desiredAuth(id)[mac] {
			continue // a Perch grant holds it now
		}
		p := e.portals[id]
		if p.device == "" || !p.cfg.Enabled {
			continue
		}
		ops.Deauthorize(id, mac, e.countingOf(p))
		delete(e.externals, fmt.Sprintf("%d|%s", id, mac))
	}
}

// ---------------------------------------------------------------------------
// portal.deauthorize
// ---------------------------------------------------------------------------

// Deauthorize applies portal.deauthorize.
func (e *Engine) Deauthorize(ctx context.Context, p DeauthorizeParams) (DeauthorizeResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	reason := p.Reason
	env := Envelope{Kind: "deauthorize", ServerNow: p.ServerNow, Nonce: p.Nonce, ItemSignatures: []string{},
		GrantIDs: p.GrantIDs, Reason: &reason}
	if err := e.checkEnvelopeLocked(p.KeyEpoch, env, p.Sig); err != nil {
		return DeauthorizeResult{}, err
	}
	now := e.clock.Now()
	ops := &ElementOps{}
	res := DeauthorizeResult{Ended: []int64{}}
	for _, id := range p.GrantIDs {
		id := id
		g := e.findGrantLocked(&id, nil)
		if g == nil {
			continue
		}
		if g.State == StateQueued {
			e.dropGrantLocked(g)
		} else {
			e.endGrantLocked(g, EndRemoved, now, ops)
		}
		res.Ended = append(res.Ended, id)
	}
	e.applyOpsLocked(ops)
	e.snapshotIfDue()
	return res, nil
}

// ---------------------------------------------------------------------------
// portal.vouchers
// ---------------------------------------------------------------------------

// Vouchers takes the offline voucher list: part 1 (append false) replaces
// the held list, later parts of the same list (append true, same
// serverNow) add to it.
func (e *Engine) Vouchers(ctx context.Context, p VouchersParams) (VouchersResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	items := make([]string, len(p.Vouchers))
	for i, v := range p.Vouchers {
		items[i] = v.Sig
	}
	env := Envelope{Kind: "vouchers", Full: p.Enabled, ServerNow: p.ServerNow, Nonce: p.Nonce, ItemSignatures: items}
	if p.Append {
		reason := "append"
		env.Reason = &reason
	}
	if err := e.checkEnvelopeLocked(p.KeyEpoch, env, p.Sig); err != nil {
		return VouchersResult{}, err
	}
	if p.Append && (e.voucherSeries == 0 || p.ServerNow != e.voucherSeries) {
		// A part without the list it belongs to (its part 1 failed, or a
		// replay of an older list's part): refused, the controller sends
		// the whole list again.
		return VouchersResult{}, errRPC(codeFailed, "vouchers_out_of_order",
			"part %d of %d does not belong to the list held (serverNow %d)", p.Part, p.Parts, p.ServerNow)
	}
	res := VouchersResult{}
	next := map[int64]*Voucher{}
	if p.Append {
		for id, v := range e.vouchers {
			next[id] = v
		}
	}
	added := map[int64]*Voucher{}
	if p.Enabled && *e.settings.OfflineRedemption {
		for _, sv := range p.Vouchers {
			want, err := e.keys.SignOfflineVoucher(sv.WireOfflineVoucher)
			if !verify(want, err, sv.Sig) {
				res.Rejected++
				continue
			}
			v := &Voucher{SignedOfflineVoucher: sv}
			if old := e.vouchers[sv.VoucherID]; old != nil {
				// What the router did offline stays until the list reflects it.
				if sv.ExpiresAt == nil {
					v.LocalStartsAt, v.LocalExpiresAt = old.LocalStartsAt, old.LocalExpiresAt
				}
				v.FirstUsed = old.FirstUsed
			}
			next[sv.VoucherID] = v
			added[sv.VoucherID] = v
		}
	}
	if !p.Append {
		e.voucherSeries = p.ServerNow
	}
	e.vouchers = next
	err := e.store.Tx(ClassGrant, func(tx sqlTx) error {
		if !p.Append {
			if _, err := tx.Exec(`DELETE FROM vouchers`); err != nil {
				return err
			}
		}
		for _, v := range added {
			b, _ := json.Marshal(v)
			if _, err := tx.Exec(`INSERT OR REPLACE INTO vouchers (voucher_id, data) VALUES (?, ?)`, v.VoucherID, string(b)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		e.log.Error("portal: storing vouchers", "err", err)
	}
	e.voucherByVerifier = make(map[string]int64, len(next))
	for id, v := range next {
		e.voucherByVerifier[v.Verifier] = id
	}
	e.dropListedLocalVouchersLocked()
	res.Stored = len(added)
	if p.Parts > 1 {
		e.log.Debug("portal: offline vouchers part", "part", p.Part, "parts", p.Parts, "stored", res.Stored, "held", len(next))
	}
	e.snapshotIfDue()
	return res, nil
}

func (e *Engine) dropVouchersLocked() {
	if len(e.vouchers) == 0 {
		return
	}
	e.vouchers = map[int64]*Voucher{}
	e.voucherByVerifier = map[string]int64{}
	e.voucherSeries = 0
	_ = e.store.Exec(ClassGrant, `DELETE FROM vouchers`)
}

// ---------------------------------------------------------------------------
// portal.sync
// ---------------------------------------------------------------------------

// Sync answers portal.sync: the journal after ackedEventSeq, every held
// grant with its usage, and outside authorisations still present.
func (e *Engine) Sync(ctx context.Context, p SyncParams) (SyncResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := SyncResult{LastEventSeq: e.lastSeq, Events: []Event{}, Grants: []GrantUsage{}, Externals: []External{}}
	first := int64(0)
	if len(e.events) > 0 {
		first = e.events[0].Seq
	}
	acked := p.AckedEventSeq
	if acked > e.lastSeq {
		// The controller is ahead of this journal (it restarted): send all.
		acked = -1
	}
	if first > 0 && acked+1 < first && acked < e.lastSeq {
		res.Truncated = true
	}
	for _, ev := range e.events {
		if ev.Seq > acked {
			res.Events = append(res.Events, ev)
		}
	}
	for _, g := range e.sortedGrants() {
		if !g.Live() {
			continue
		}
		res.Grants = append(res.Grants, e.usageOfLocked(g))
	}
	for _, x := range e.externals {
		res.Externals = append(res.Externals, *x)
	}
	sort.Slice(res.Externals, func(a, b int) bool { return res.Externals[a].MAC < res.Externals[b].MAC })
	return res, nil
}

func (e *Engine) usageOfLocked(g *Grant) GrantUsage {
	rev := g.Revision
	u := GrantUsage{GrantID: g.GrantID, LocalRef: g.LocalRef, PortalID: g.PortalID, MAC: g.MAC, IP: g.IP,
		BytesUp: g.BytesUp, BytesDown: g.BytesDown, ActiveSeconds: g.ActiveSeconds(), State: g.State,
		LastSeenAt: g.LastSeenAt, Revision: &rev}
	if g.Revision == 0 {
		u.Revision = nil // an offline grant the controller has not answered
	}
	return u
}

// journalLocked appends an event (grant class: written at once) and sends
// it to the controller when a session is open.
func (e *Engine) journalLocked(ev Event, now int64) int64 {
	e.lastSeq++
	ev.Seq = e.lastSeq
	ev.At = now
	e.events = append(e.events, ev)
	if len(e.events) > journalMax {
		drop := len(e.events) - journalMax
		cut := e.events[drop-1].Seq
		e.events = append([]Event(nil), e.events[drop:]...)
		_ = e.store.Exec(ClassGrant, `DELETE FROM events WHERE seq <= ?`, cut)
	}
	b, _ := json.Marshal(ev)
	_ = e.store.Exec(ClassGrant, `INSERT OR REPLACE INTO events (seq, data) VALUES (?, ?)`, ev.Seq, string(b))
	_ = e.store.SetMeta(ClassGrant, "lastEventSeq", fmt.Sprint(e.lastSeq))
	if a := e.currentAgent(); a != nil {
		go func() { _ = a.Notify("portal.event", ev) }()
	}
	return ev.Seq
}

// ---------------------------------------------------------------------------
// portal.template
// ---------------------------------------------------------------------------

// StoreTemplate checks and stores a custom template.
func (e *Engine) StoreTemplate(ctx context.Context, p TemplateParams) (map[string]any, error) {
	sha := strings.ToLower(strings.TrimSpace(p.SHA256))
	if !hex64Re.MatchString(sha) {
		return nil, errRPC(codeInvalidParams, "invalid_params", "sha256 must be 64 hex characters")
	}
	var files []TemplateFileData
	for _, f := range p.Files {
		data, err := base64.StdEncoding.DecodeString(f.DataBase64)
		if err != nil {
			return nil, errRPC(codeInvalidParams, "invalid_template", "%s: bad base64", f.Name)
		}
		checked, err := CheckTemplateFile(f.Name, data)
		if err != nil {
			return nil, errRPC(codeInvalidParams, "invalid_template", "%v", err)
		}
		files = append(files, checked)
	}
	if err := CheckTemplateSet(files); err != nil {
		return nil, errRPC(codeInvalidParams, "invalid_template", "%v", err)
	}
	if got := TemplateSetSHA256(files); got != sha {
		return nil, errRPC(codeInvalidParams, "sha256_mismatch", "the files hash to %s", got)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	err := e.store.Tx(ClassGrant, func(tx sqlTx) error {
		if _, err := tx.Exec(`DELETE FROM templates WHERE sha = ?`, sha); err != nil {
			return err
		}
		for _, f := range files {
			if _, err := tx.Exec(`INSERT INTO templates (sha, name, content_type, data) VALUES (?, ?, ?, ?)`, sha, f.Name, f.ContentType, f.Data); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, errRPC(codeFailed, "store_failed", "%v", err)
	}
	e.pruneTemplatesLocked(sha)
	e.snapshotIfDue()
	return map[string]any{"stored": true}, nil
}

// pruneTemplatesLocked drops templates no portal uses (keep: just stored).
func (e *Engine) pruneTemplatesLocked(keep string) {
	used := map[string]bool{keep: true}
	for _, p := range e.portals {
		used[strings.ToLower(p.cfg.TemplateSHA256)] = true
	}
	rows, err := e.store.Query(`SELECT DISTINCT sha FROM templates`)
	if err != nil {
		return
	}
	var drop []string
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil && !used[s] {
			drop = append(drop, s)
		}
	}
	rows.Close()
	for _, s := range drop {
		_ = e.store.Exec(ClassGrant, `DELETE FROM templates WHERE sha = ?`, s)
	}
}

func (e *Engine) hasTemplate(sha string) bool {
	var n int
	_ = e.store.QueryRow(`SELECT count(*) FROM templates WHERE sha = ? AND name = ?`, sha, LoginPage).Scan(&n)
	return n > 0
}

// templateFor is a portal's template: its custom set when held, else the
// builtin one.
func (e *Engine) templateFor(p *portalRuntime) *Template {
	sha := strings.ToLower(p.cfg.TemplateSHA256)
	if sha == "" || sha == EmptySetSHA256 {
		return BuiltinTemplate()
	}
	rows, err := e.store.Query(`SELECT name, content_type, data FROM templates WHERE sha = ?`, sha)
	if err != nil {
		return BuiltinTemplate()
	}
	defer rows.Close()
	t := &Template{SHA256: sha, Files: map[string]TemplateFileData{}}
	for rows.Next() {
		var f TemplateFileData
		if rows.Scan(&f.Name, &f.ContentType, &f.Data) == nil {
			t.Files[f.Name] = f
		}
	}
	if _, ok := t.Files[LoginPage]; !ok {
		return BuiltinTemplate()
	}
	return t
}
