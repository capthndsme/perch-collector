package qos

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// DeviceEntry is one per-MAC entry of qos.devices.set, exactly as the
// controller's planner produces it (metrics-be qos_plan.ts DeviceEntry,
// docs/gateway/qos.md section 3.5).
type DeviceEntry struct {
	MAC string `json:"mac"`
	// Bucket is a perch-qos bucket section name; with no caps the MAC sits
	// in its rest leaf.
	Bucket *string `json:"bucket"`
	// DownKbit / UpKbit: null = unlimited that way.
	DownKbit  *int64       `json:"downKbit"`
	UpKbit    *int64       `json:"upKbit"`
	Quota     *DeviceQuota `json:"quota"`
	ExpiresAt *string      `json:"expiresAt"`
	// IncludeLan also shapes the MAC's LAN-to-LAN traffic (decision 13).
	IncludeLan bool `json:"includeLan,omitempty"`
	// Schedules are perch-qos schedule sections, in precedence order.
	Schedules []string `json:"schedules,omitempty"`
}

// DeviceQuota is a DeviceEntry's data quota.
type DeviceQuota struct {
	LimitBytes       int64  `json:"limitBytes"`
	UsedBytes        int64  `json:"usedBytes"`
	OnExhausted      string `json:"onExhausted"` // block | throttle
	ThrottleDownKbit *int64 `json:"throttleDownKbit"`
	ThrottleUpKbit   *int64 `json:"throttleUpKbit"`
	// ResetAt is set by an admin reset (metrics-be docs/gateway/qos.md
	// section 6.2): a newer one than the agent holds starts the count over
	// from UsedBytes; otherwise the agent keeps the larger count.
	ResetAt *string `json:"resetAt,omitempty"`
}

// DevicesSetParams are qos.devices.set's params.
type DevicesSetParams struct {
	Revision int64         `json:"revision"`
	Devices  []DeviceEntry `json:"devices"`
}

// DevicesSetResult is qos.devices.set's result.
type DevicesSetResult struct {
	Revision int64       `json:"revision"`
	Accepted int         `json:"accepted"`
	Rejected []Rejection `json:"rejected"`
}

// Rejection is one entry the agent refused.
type Rejection struct {
	MAC   string `json:"mac"`
	Error string `json:"error"`
}

// Entry is a validated DeviceEntry.
type Entry struct {
	MAC        string
	Bucket     string // "" = none
	Caps       *Rate  // nil = no own caps; a 0 direction = unlimited
	Quota      *DeviceQuota
	Expires    time.Time // zero = never
	IncludeLan bool
	Schedules  []string
}

// DeviceEntry renders the entry back in the wire shape (the cache).
func (e Entry) DeviceEntry() DeviceEntry {
	d := DeviceEntry{MAC: e.MAC, IncludeLan: e.IncludeLan, Schedules: e.Schedules}
	if e.Bucket != "" {
		b := e.Bucket
		d.Bucket = &b
	}
	if e.Caps != nil {
		if e.Caps.Down > 0 {
			v := e.Caps.Down
			d.DownKbit = &v
		}
		if e.Caps.Up > 0 {
			v := e.Caps.Up
			d.UpKbit = &v
		}
	}
	if e.Quota != nil {
		q := *e.Quota
		d.Quota = &q
	}
	if !e.Expires.IsZero() {
		s := e.Expires.UTC().Format(time.RFC3339Nano)
		d.ExpiresAt = &s
	}
	return d
}

// NormalizeMAC returns the MAC in lower-case colon form, "" when it is not
// a unicast Ethernet address.
func NormalizeMAC(s string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(strings.ReplaceAll(s, "-", ":")))
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
		return ""
	}
	if hw.String() == "00:00:00:00:00:00" {
		return ""
	}
	return hw.String()
}

// ValidateDevices checks a qos.devices.set: entries it cannot use are
// rejected one by one; minDeviceKbit raises caps below the floor;
// routerMACs are refused (plan 3 section 8: the agent never shapes the
// router itself). The result is sorted by MAC.
func ValidateDevices(list []DeviceEntry, minDeviceKbit int64, routerMACs map[string]bool) ([]Entry, []Rejection) {
	var out []Entry
	rejected := []Rejection{}
	seen := map[string]bool{}
	for _, d := range list {
		mac := NormalizeMAC(d.MAC)
		reject := func(code string) { rejected = append(rejected, Rejection{MAC: d.MAC, Error: code}) }
		switch {
		case mac == "":
			reject("invalid_mac")
			continue
		case seen[mac]:
			reject("duplicate_mac")
			continue
		case routerMACs[mac]:
			reject("router_mac")
			continue
		}
		seen[mac] = true
		e := Entry{MAC: mac, IncludeLan: d.IncludeLan}
		if d.Bucket != nil {
			e.Bucket = strings.TrimSpace(*d.Bucket)
		}
		if d.DownKbit != nil || d.UpKbit != nil {
			var r Rate
			bad := false
			for _, p := range []struct {
				v   *int64
				dst *int64
			}{{d.DownKbit, &r.Down}, {d.UpKbit, &r.Up}} {
				if p.v == nil {
					continue
				}
				if *p.v < 0 {
					bad = true
				}
				*p.dst = *p.v
				if *p.dst > 0 && *p.dst < minDeviceKbit {
					*p.dst = minDeviceKbit
				}
			}
			if bad {
				reject("invalid_rate")
				continue
			}
			if r.Down > 0 || r.Up > 0 {
				e.Caps = &r
			}
		}
		if d.Quota != nil {
			q := *d.Quota
			if q.LimitBytes <= 0 || q.UsedBytes < 0 || (q.OnExhausted != "block" && q.OnExhausted != "throttle") {
				reject("invalid_quota")
				continue
			}
			for _, p := range []**int64{&q.ThrottleDownKbit, &q.ThrottleUpKbit} {
				if *p != nil {
					v := **p
					if v < 0 {
						v = 0
					}
					if v > 0 && v < minDeviceKbit {
						v = minDeviceKbit
					}
					*p = &v
				}
			}
			e.Quota = &q
		}
		if d.ExpiresAt != nil && *d.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339Nano, *d.ExpiresAt)
			if err != nil {
				reject("invalid_expires_at")
				continue
			}
			e.Expires = t
		}
		for _, s := range d.Schedules {
			if s = strings.TrimSpace(s); s != "" {
				e.Schedules = append(e.Schedules, s)
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, rejected
}

// Devices is the per-MAC state the controller sent, plus the quota
// counters the agent keeps: what the cache files hold.
type Devices struct {
	Revision int64         `json:"revision"`
	Entries  []DeviceEntry `json:"devices"`
	// Quotas are the agent's counters, by MAC.
	Quotas map[string]*QuotaState `json:"quotas,omitempty"`
	// SetAt is when the controller last sent the set.
	SetAt time.Time `json:"setAt"`
	// FromFlash marks a set loaded from the flash cache after a reboot: its
	// quotas fail open until the controller sends a new set (plan 3 Q4).
	FromFlash bool `json:"-"`
}

// QuotaState counts one MAC's quota.
type QuotaState struct {
	// ResetAt is the controller's last reset this count started from.
	ResetAt string `json:"resetAt,omitempty"`
	// Used is the running total.
	Used int64 `json:"used"`
	// Exhausted since (zero = not exhausted).
	ExhaustedAt time.Time `json:"exhaustedAt,omitempty"`
}

// Decode reads a cache file.
func DecodeDevices(data []byte) (*Devices, error) {
	var d Devices
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("devices cache: %w", err)
	}
	if d.Quotas == nil {
		d.Quotas = map[string]*QuotaState{}
	}
	return &d, nil
}

// mergeQuota applies a quota the controller sent to the agent's count
// (docs/gateway/qos.md section 6.2): the larger of the two counts, unless
// the entry carries a reset newer than the one the count started from.
func mergeQuota(old *QuotaState, q *DeviceQuota) *QuotaState {
	reset := ""
	if q.ResetAt != nil {
		reset = *q.ResetAt
	}
	if old == nil || resetNewer(reset, old.ResetAt) {
		return &QuotaState{Used: q.UsedBytes, ResetAt: reset}
	}
	n := *old
	if q.UsedBytes > n.Used {
		n.Used = q.UsedBytes
	}
	return &n
}

// resetNewer compares two resetAt stamps (RFC 3339; "" = never).
func resetNewer(a, b string) bool {
	if a == "" || a == b {
		return false
	}
	if b == "" {
		return true
	}
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	if errA != nil || errB != nil {
		return true // unreadable but different: the controller changed it
	}
	return ta.After(tb)
}
