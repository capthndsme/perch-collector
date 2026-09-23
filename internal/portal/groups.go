package portal

import "sort"

// Group math, a port of the controller's portal/groups.ts and
// portal/redemption.ts (docs/gateway/portal.md §4.3–4.6): the router runs
// the same rules for its enforcement tick and for offline redemptions.
// Times are epoch milliseconds.

// Limits are a group's limits.
type Limits struct {
	DurationMode    string
	ExpiresAt       *int64
	DurationSeconds *int64
	QuotaBytes      *int64
	MaxDevices      int64
}

// Usage is a whole group's usage.
type Usage struct {
	TimeUsedSeconds int64
	BytesUsed       int64
}

// LimitsOf are a wire group's limits.
func LimitsOf(g WireGroup) Limits {
	return Limits{DurationMode: g.DurationMode, ExpiresAt: g.ExpiresAt, DurationSeconds: g.DurationSeconds,
		QuotaBytes: g.QuotaBytes, MaxDevices: g.MaxDevices}
}

// GrantLimits tightens a group's deadline by a grant's own.
func GrantLimits(l Limits, grantExpiresAt *int64) Limits {
	if grantExpiresAt == nil {
		return l
	}
	out := l
	if l.ExpiresAt == nil || *grantExpiresAt < *l.ExpiresAt {
		v := *grantExpiresAt
		out.ExpiresAt = &v
	}
	return out
}

// Exhaustion is why a group is used up: "expired", "quota" or "".
// Time is checked first.
func Exhaustion(l Limits, u Usage, now int64) string {
	if l.ExpiresAt != nil && now >= *l.ExpiresAt {
		return EndExpired
	}
	if l.DurationMode == ModeActiveTime && l.DurationSeconds != nil && u.TimeUsedSeconds >= *l.DurationSeconds {
		return EndExpired
	}
	if l.QuotaBytes != nil && u.BytesUsed >= *l.QuotaBytes {
		return EndQuota
	}
	return ""
}

// Remaining is the seconds and bytes left (nil = no such limit).
func Remaining(l Limits, u Usage, now int64) (seconds, bytes *int64) {
	if l.ExpiresAt != nil {
		s := (*l.ExpiresAt - now) / 1000
		if s < 0 {
			s = 0
		}
		seconds = &s
	}
	if l.DurationSeconds != nil {
		var from *int64
		switch {
		case l.DurationMode == ModeActiveTime:
			v := *l.DurationSeconds - u.TimeUsedSeconds
			if v < 0 {
				v = 0
			}
			from = &v
		case l.ExpiresAt == nil:
			v := *l.DurationSeconds
			from = &v
		}
		if from != nil && (seconds == nil || *from < *seconds) {
			seconds = from
		}
	}
	if l.QuotaBytes != nil {
		b := *l.QuotaBytes - u.BytesUsed
		if b < 0 {
			b = 0
		}
		bytes = &b
	}
	return seconds, bytes
}

// Entitlement classes (decision 23: time before data buckets).
const (
	ClassTime = "time"
	ClassData = "data"
	ClassOpen = "open"
)

// EntitlementClass of a group's limits.
func EntitlementClass(l Limits) string {
	if l.DurationSeconds != nil || l.ExpiresAt != nil {
		return ClassTime
	}
	if l.QuotaBytes != nil {
		return ClassData
	}
	return ClassOpen
}

// Entitlement is one device's grant in consumption order.
type Entitlement struct {
	// Order is the grant id, or a large number for a grant known only by
	// its localRef.
	Order     int64
	Limits    Limits
	CreatedAt int64
}

func classRank(l Limits) int {
	if EntitlementClass(l) == ClassData {
		return 1
	}
	return 0
}

// CompareEntitlements orders one device's entitlements (compareEntitlements).
func CompareEntitlements(a, b Entitlement) int {
	if d := classRank(a.Limits) - classRank(b.Limits); d != 0 {
		return d
	}
	ae, be := a.Limits.ExpiresAt, b.Limits.ExpiresAt
	switch {
	case ae != nil && be == nil:
		return -1
	case ae == nil && be != nil:
		return 1
	case ae != nil && be != nil && *ae != *be:
		return sign(*ae - *be)
	}
	if a.CreatedAt != b.CreatedAt {
		return sign(a.CreatedAt - b.CreatedAt)
	}
	return sign(a.Order - b.Order)
}

func sign(v int64) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	}
	return 0
}

// PlaceBehindCurrent: "swap" when a time (or open) entitlement arrives over
// a running data bucket, else "queue".
func PlaceBehindCurrent(current, candidate Limits) string {
	if EntitlementClass(candidate) != ClassData && EntitlementClass(current) == ClassData {
		return "swap"
	}
	return "queue"
}

// SlotHolder is a grant holding one of a group's device slots.
type SlotHolder struct {
	Ref       string // the store's row key
	MAC       string
	StartedAt int64
	Order     int64
}

// EvictOldest lists the holders to end so one more device fits into
// maxDevices (decision 23: the device that joined first leaves).
func EvictOldest(holders []SlotHolder, maxDevices int64) []string {
	if maxDevices < 1 {
		maxDevices = 1
	}
	excess := int64(len(holders)) - maxDevices + 1
	if excess <= 0 {
		return nil
	}
	list := append([]SlotHolder(nil), holders...)
	sort.SliceStable(list, func(a, b int) bool {
		if list[a].StartedAt != list[b].StartedAt {
			return list[a].StartedAt < list[b].StartedAt
		}
		return list[a].Order < list[b].Order
	})
	out := make([]string, 0, excess)
	for _, h := range list[:excess] {
		out = append(out, h.Ref)
	}
	return out
}

// VoucherLimits of an offline voucher (voucherGroupLimits): an active-time
// voucher has no deadline of its own.
func VoucherLimits(v WireOfflineVoucher) Limits {
	l := Limits{DurationMode: v.DurationMode, DurationSeconds: v.DurationSeconds, QuotaBytes: v.QuotaBytes, MaxDevices: v.MaxDevices}
	if v.DurationMode == ModeWallClock {
		l.ExpiresAt = v.ExpiresAt
	}
	if l.MaxDevices < 1 {
		l.MaxDevices = 1
	}
	return l
}

// StartClock is the wall clock of a voucher that starts now, or nil.
func StartClock(v WireOfflineVoucher, now int64) (startsAt, expiresAt *int64) {
	if v.DurationMode != ModeWallClock || v.DurationSeconds == nil || v.ExpiresAt != nil {
		return nil, nil
	}
	s, e := now, now+*v.DurationSeconds*1000
	return &s, &e
}

// VoucherStatus of an offline voucher (voucherStatus); a voucher on the
// list is never revoked (revoked ones drop off it).
func VoucherStatus(v WireOfflineVoucher, u Usage, firstUsed bool, now int64) string {
	switch Exhaustion(VoucherLimits(v), u, now) {
	case EndExpired:
		return "expired"
	case EndQuota:
		return "exhausted"
	}
	if !firstUsed {
		if v.RedeemBy != nil && now >= *v.RedeemBy {
			return "expired"
		}
		return "unused"
	}
	return "active"
}
