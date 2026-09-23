package portal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
)

// Grant states on the router.
const (
	StatePending = "pending_device"
	StateActive  = "active"
	// StateQueued is an entitlement the router redeemed offline behind the
	// device's current one (decision 23). It is not in the enforcement sets
	// and not in portal.sync's grants (the controller holds it as queued);
	// the router promotes it itself only while the controller is away.
	StateQueued = "queued"
)

// Grant is one held grant. Persisted as JSON in the grants table.
type Grant struct {
	LID       int64   `json:"lid"`
	GrantID   *int64  `json:"grantId"`
	LocalRef  *string `json:"localRef"`
	PortalID  int64   `json:"portalId"`
	GroupKey  string  `json:"groupKey"`
	MAC       string  `json:"mac"`
	ExpiresAt *int64  `json:"expiresAt"`
	Revision  int64   `json:"revision"`
	Sig       string  `json:"sig,omitempty"`
	State     string  `json:"state"`
	CreatedAt int64   `json:"createdAt"`
	// CreatedSeq is the journal seq of the offline_redeemed event that made
	// it (0 = from the controller): a full set keeps it while newer than
	// the set's ackedEventSeq.
	CreatedSeq       int64    `json:"createdSeq"`
	StartedAt        *int64   `json:"startedAt"`
	SessionStartedAt *int64   `json:"sessionStartedAt"`
	LastSeenAt       *int64   `json:"lastSeenAt"`
	IP               *string  `json:"ip"`
	IPs              []string `json:"ips,omitempty"`
	Hostname         *string  `json:"hostname"`
	BytesUp          int64    `json:"bytesUp"`
	BytesDown        int64    `json:"bytesDown"`
	ActiveMs         int64    `json:"activeMs"`
	// CtrUp/CtrDown are the last nft counter values read for this grant's
	// MAC (the baseline of the next delta).
	CtrUp   int64 `json:"ctrUp"`
	CtrDown int64 `json:"ctrDown"`
	// Bound is the IPv4 address in the portal's binding set.
	Bound string `json:"bound,omitempty"`
}

// ActiveSeconds is the charged active time in whole seconds.
func (g *Grant) ActiveSeconds() int64 { return g.ActiveMs / 1000 }

// Live reports whether the grant is in the enforcement sets.
func (g *Grant) Live() bool { return g.State == StatePending || g.State == StateActive }

// Order is the grant's rank among equals: its id, else after every id.
func (g *Grant) Order() int64 {
	if g.GrantID != nil {
		return *g.GrantID
	}
	return maxSafeInt + g.LID
}

// Ref names the grant on the wire.
func (g *Grant) Ref() GrantRef { return GrantRef{GrantID: g.GrantID, LocalRef: g.LocalRef} }

// Group is a held group. Local = created by an offline redemption.
type Group struct {
	WireGroup
	Sig   string `json:"sig,omitempty"`
	Local bool   `json:"local,omitempty"`
	// AckedSeq is the journal position its base* usage reflects: ended
	// usage recorded after it still has to be added.
	AckedSeq int64 `json:"ackedSeq"`
	// ClockStartedAt: a wall-clock group sent without a deadline gets one
	// when its first grant runs (safety net; the controller normally
	// starts the clock itself).
	ClockStartedAt *int64 `json:"clockStartedAt,omitempty"`
}

// EffectiveLimits are the limits with the local clock applied.
func (g *Group) EffectiveLimits() Limits {
	l := LimitsOf(g.WireGroup)
	if l.DurationMode == ModeWallClock && l.ExpiresAt == nil && l.DurationSeconds != nil && g.ClockStartedAt != nil {
		e := *g.ClockStartedAt + *l.DurationSeconds*1000
		l.ExpiresAt = &e
	}
	return l
}

// Voucher is a held offline voucher plus what the router did with it.
type Voucher struct {
	SignedOfflineVoucher
	// FirstUsed: redeemed here while offline.
	FirstUsed bool `json:"firstUsed,omitempty"`
	// StartedAt/ExpiresAt: the wall clock the router started offline.
	LocalStartsAt  *int64 `json:"localStartsAt,omitempty"`
	LocalExpiresAt *int64 `json:"localExpiresAt,omitempty"`
}

// Effective is the wire voucher with the local clock applied.
func (v *Voucher) Effective() WireOfflineVoucher {
	w := v.WireOfflineVoucher
	if w.ExpiresAt == nil && v.LocalExpiresAt != nil {
		e := *v.LocalExpiresAt
		w.ExpiresAt = &e
	}
	return w
}

// endedUsage is a grant's final usage kept for its group until the
// controller's base* includes it.
type endedUsage struct {
	GroupKey string
	Seq      int64
	TimeUsed int64
	Bytes    int64
}

// ---------------------------------------------------------------------------
// Persistence of the working set.
// ---------------------------------------------------------------------------

func (e *Engine) saveGrant(g *Grant, class int) {
	b, _ := json.Marshal(g)
	if err := e.store.Exec(class, `INSERT OR REPLACE INTO grants (lid, data) VALUES (?, ?)`, g.LID, string(b)); err != nil {
		e.log.Error("portal: saving a grant", "err", err)
	}
}

func (e *Engine) deleteGrant(g *Grant) {
	if err := e.store.Exec(ClassGrant, `DELETE FROM grants WHERE lid = ?`, g.LID); err != nil {
		e.log.Error("portal: deleting a grant", "err", err)
	}
}

func (e *Engine) saveGroup(g *Group) {
	b, _ := json.Marshal(g)
	if err := e.store.Exec(ClassGrant, `INSERT OR REPLACE INTO groups (group_key, data) VALUES (?, ?)`, g.GroupKey, string(b)); err != nil {
		e.log.Error("portal: saving a group", "err", err)
	}
}

func (e *Engine) deleteGroup(key string) {
	_ = e.store.Exec(ClassGrant, `DELETE FROM groups WHERE group_key = ?`, key)
	_ = e.store.Exec(ClassGrant, `DELETE FROM ended_usage WHERE group_key = ?`, key)
}

func (e *Engine) saveVoucher(v *Voucher) {
	b, _ := json.Marshal(v)
	if err := e.store.Exec(ClassGrant, `INSERT OR REPLACE INTO vouchers (voucher_id, data) VALUES (?, ?)`, v.VoucherID, string(b)); err != nil {
		e.log.Error("portal: saving a voucher", "err", err)
	}
}

func (e *Engine) saveMetaJSON(k string, v any) {
	b, _ := json.Marshal(v)
	if err := e.store.SetMeta(ClassGrant, k, string(b)); err != nil {
		e.log.Error("portal: saving state", "key", k, "err", err)
	}
}

func loadJSONRows[T any](s *Store, q string) ([]T, error) {
	rows, err := s.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return nil, fmt.Errorf("decoding a stored row: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (e *Engine) loadState() error {
	grants, err := loadJSONRows[Grant](e.store, `SELECT data FROM grants ORDER BY lid`)
	if err != nil {
		return err
	}
	for i := range grants {
		g := grants[i]
		e.grants[g.LID] = &g
		if g.LID > e.nextLID {
			e.nextLID = g.LID
		}
	}
	groups, err := loadJSONRows[Group](e.store, `SELECT data FROM groups`)
	if err != nil {
		return err
	}
	for i := range groups {
		g := groups[i]
		e.groups[g.GroupKey] = &g
	}
	vouchers, err := loadJSONRows[Voucher](e.store, `SELECT data FROM vouchers`)
	if err != nil {
		return err
	}
	for i := range vouchers {
		v := vouchers[i]
		e.vouchers[v.VoucherID] = &v
		e.voucherByVerifier[v.Verifier] = v.VoucherID
	}
	events, err := loadJSONRows[Event](e.store, `SELECT data FROM events ORDER BY seq`)
	if err != nil {
		return err
	}
	e.events = events
	rows, err := e.store.Query(`SELECT group_key, seq, time_used, bytes_used FROM ended_usage ORDER BY id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var u endedUsage
		if err := rows.Scan(&u.GroupKey, &u.Seq, &u.TimeUsed, &u.Bytes); err != nil {
			rows.Close()
			return err
		}
		e.ended = append(e.ended, u)
	}
	rows.Close()
	nrows, err := e.store.Query(`SELECT nonce FROM nonces ORDER BY at, nonce`)
	if err != nil {
		return err
	}
	for nrows.Next() {
		var n string
		if err := nrows.Scan(&n); err == nil {
			e.nonces = append(e.nonces, n)
		}
	}
	nrows.Close()
	var seq sql.NullInt64
	_ = e.store.QueryRow(`SELECT MAX(seq) FROM events`).Scan(&seq)
	fmt.Sscan(e.store.Meta("lastEventSeq"), &e.lastSeq)
	if seq.Valid && seq.Int64 > e.lastSeq {
		e.lastSeq = seq.Int64
	}
	fmt.Sscan(e.store.Meta("newestServerNow"), &e.newestServerNow)
	if raw := e.store.Meta("config"); raw != "" {
		var c Config
		if err := json.Unmarshal([]byte(raw), &c); err == nil {
			e.cfg = &c
		}
	}
	if raw := e.store.Meta("keys"); raw != "" {
		var k storedKeys
		if json.Unmarshal([]byte(raw), &k) == nil {
			if key, err := DecodeGatewayKey(k.GatewayKey); err == nil {
				if keys, err := KeysFrom(key, k.GatewayID, k.Epoch); err == nil {
					e.keys = keys
				}
			}
		}
	}
	return nil
}

type storedKeys struct {
	GatewayID  int64  `json:"gatewayId"`
	Epoch      int64  `json:"epoch"`
	GatewayKey string `json:"gatewayKey"`
}

// sortedGrants is the grants in a stable order (lid).
func (e *Engine) sortedGrants() []*Grant {
	out := make([]*Grant, 0, len(e.grants))
	for _, g := range e.grants {
		out = append(out, g)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].LID < out[b].LID })
	return out
}
