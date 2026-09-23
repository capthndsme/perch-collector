package portal

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Paid Hotspot configuration, pricing and the texts the guest pages show
// (docs/gateway/portal.md §14 in the controller repository; the controller's
// portal/hotspot.ts implements the same functions and pins the vectors).

// PaymentConfig is a portal's checkout method (portal.configure).
type PaymentConfig struct {
	IdleTimeoutSeconds int              `json:"idleTimeoutSeconds"`
	PriceTableID       *int64           `json:"priceTableId"`
	Terminals          []TerminalConfig `json:"terminals"`
	PriceTables        []PriceTable     `json:"priceTables"`
}

// TerminalConfig is one coin terminal of a portal.
type TerminalConfig struct {
	TerminalID int64   `json:"terminalId"`
	Name       string  `json:"name"`
	Token      string  `json:"token"`
	MAC        *string `json:"mac"`
	Enabled    bool    `json:"enabled"`
	// PriceTableID overrides the portal's table (nil = the portal's).
	PriceTableID *int64 `json:"priceTableId"`
}

// PriceTable is an operator's rates: amount (minor units) → time, data, speed.
type PriceTable struct {
	PriceTableID int64        `json:"priceTableId"`
	Revision     int64        `json:"revision"`
	Name         string       `json:"name"`
	Currency     string       `json:"currency"`
	Decimals     int          `json:"decimals"`
	DurationMode string       `json:"durationMode"`
	Entries      []PriceEntry `json:"entries"`
}

// PriceEntry is one rate.
type PriceEntry struct {
	Amount     int64  `json:"amount"`
	Minutes    int64  `json:"minutes"`
	QuotaBytes *int64 `json:"quotaBytes"`
	DownKbps   *int64 `json:"downKbps"`
	UpKbps     *int64 `json:"upKbps"`
}

// ClickThroughConfig is a portal's click-through method (decision 32).
type ClickThroughConfig struct {
	Minutes     int64  `json:"minutes"`
	QuotaBytes  *int64 `json:"quotaBytes"`
	DownKbps    *int64 `json:"downKbps"`
	UpKbps      *int64 `json:"upKbps"`
	WindowHours int    `json:"windowHours"`
	PerWindow   int    `json:"perWindow"`
	Terms       string `json:"terms"`
}

// normalized clamps the click-through settings like the controller does.
func (c ClickThroughConfig) normalized() ClickThroughConfig {
	if c.Minutes == 0 {
		c.Minutes = 30
	}
	c.Minutes = int64(clampInt(int(c.Minutes), 1, 1440))
	if c.WindowHours == 0 {
		c.WindowHours = 24
	}
	c.WindowHours = clampInt(c.WindowHours, 1, 720)
	if c.PerWindow == 0 {
		c.PerWindow = 1
	}
	c.PerWindow = clampInt(c.PerWindow, 1, 24)
	if len(c.Terms) > 4000 {
		c.Terms = c.Terms[:4000]
	}
	return c
}

// idleTimeoutMs is a payment config's idle timeout (15–600 s, 0 = 60).
func (p *PaymentConfig) idleTimeoutMs() int64 {
	s := p.IdleTimeoutSeconds
	if s == 0 {
		s = 60
	}
	return int64(clampInt(s, 15, 600)) * 1000
}

// table is a listed price table by id.
func (p *PaymentConfig) table(id *int64) *PriceTable {
	if p == nil || id == nil {
		return nil
	}
	for i := range p.PriceTables {
		if p.PriceTables[i].PriceTableID == *id {
			return &p.PriceTables[i]
		}
	}
	return nil
}

// tableFor is a terminal's effective price table (its override, else the
// portal's), or nil when it has none.
func (p *PaymentConfig) tableFor(t *TerminalConfig) *PriceTable {
	if t.PriceTableID != nil {
		return p.table(t.PriceTableID)
	}
	return p.table(p.PriceTableID)
}

// Checkout limits.
const (
	MaxCheckoutSeconds = 525600 * 60
	MaxCheckoutAmount  = 10_000_000
	MaxCheckoutCoins   = 500
	MaxCoinAmount      = 1_000_000
	maxQuotaBytes      = int64(10_000_000_000_000)
)

// PriceResult is what an amount buys.
type PriceResult struct {
	Amount          int64  `json:"amount"`
	DurationMode    string `json:"durationMode"`
	DurationSeconds int64  `json:"durationSeconds"`
	QuotaBytes      *int64 `json:"quotaBytes"`
	DownKbps        *int64 `json:"downKbps"`
	UpKbps          *int64 `json:"upKbps"`
	UnusedAmount    int64  `json:"unusedAmount"`
}

// PriceEntitlement is the greedy fill (priceEntitlement): the largest rate
// that fits as often as it fits, then the next smaller one; time and data
// add up, the speed tier is the most expensive rate taken, what is left
// below the smallest rate is unused.
func PriceEntitlement(t PriceTable, amount int64) PriceResult {
	if amount < 0 {
		amount = 0
	}
	entries := append([]PriceEntry(nil), t.Entries...)
	sort.SliceStable(entries, func(a, b int) bool { return entries[a].Amount > entries[b].Amount })
	rest := amount
	var minutes, quota int64
	hasQuota := false
	var tier *PriceEntry
	for i := range entries {
		e := entries[i]
		if e.Amount <= 0 || rest < e.Amount {
			continue
		}
		n := rest / e.Amount
		rest -= n * e.Amount
		minutes += n * e.Minutes
		if e.QuotaBytes != nil {
			hasQuota = true
			quota += n * *e.QuotaBytes
		}
		if tier == nil {
			tier = &entries[i]
		}
	}
	r := PriceResult{Amount: amount, DurationMode: t.DurationMode, UnusedAmount: rest}
	if tier == nil {
		return r
	}
	r.DurationSeconds = minutes * 60
	if r.DurationSeconds > MaxCheckoutSeconds {
		r.DurationSeconds = MaxCheckoutSeconds
	}
	if hasQuota {
		q := quota
		if q > maxQuotaBytes {
			q = maxQuotaBytes
		}
		r.QuotaBytes = &q
	}
	r.DownKbps, r.UpKbps = copyInt(tier.DownKbps), copyInt(tier.UpKbps)
	return r
}

func copyInt(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// ---------------------------------------------------------------------------
// Texts (identical on the controller: previews)
// ---------------------------------------------------------------------------

// MoneyText formats a minor-unit amount: "PHP 5", "PHP 5.25".
func MoneyText(amount int64, currency string, decimals int) string {
	if decimals <= 0 {
		return fmt.Sprintf("%s %d", currency, amount)
	}
	div := int64(math.Pow10(decimals))
	return fmt.Sprintf("%s %d.%0*d", currency, amount/div, decimals, amount%div)
}

// DurationText: "0 min", "25 min", "1 h 30 min", "2 d 3 h".
func DurationText(s int64) string {
	switch {
	case s <= 0:
		return "0 min"
	case s < 3600:
		return fmt.Sprintf("%d min", (s+59)/60)
	case s < 86400:
		out := fmt.Sprintf("%d h", s/3600)
		if m := s % 3600 / 60; m > 0 {
			out += fmt.Sprintf(" %d min", m)
		}
		return out
	}
	out := fmt.Sprintf("%d d", s/86400)
	if h := s % 86400 / 3600; h > 0 {
		out += fmt.Sprintf(" %d h", h)
	}
	return out
}

// oneDecimal rounds half up to tenths and drops a ".0".
func oneDecimal(v float64) string {
	tenths := int64(math.Floor(v*10 + 0.5))
	if tenths%10 == 0 {
		return strconv.FormatInt(tenths/10, 10)
	}
	return fmt.Sprintf("%d.%d", tenths/10, tenths%10)
}

// BytesText: "999 B", "500 MB", "1.5 GB" (1000-based).
func BytesText(b int64) string {
	if b < 1000 {
		return fmt.Sprintf("%d B", b)
	}
	units := []string{"kB", "MB", "GB", "TB"}
	v := float64(b) / 1000
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	return oneDecimal(v) + " " + units[i]
}

// SpeedText: "5 Mbit/s", "512 kbit/s".
func SpeedText(kbps int64) string {
	if kbps >= 1000 {
		return oneDecimal(float64(kbps)/1000) + " Mbit/s"
	}
	return fmt.Sprintf("%d kbit/s", kbps)
}

// EntitlementText: "1 h 20 min · 500 MB · 5 Mbit/s down".
func EntitlementText(seconds int64, quota, down *int64) string {
	parts := []string{DurationText(seconds)}
	if quota != nil {
		parts = append(parts, BytesText(*quota))
	}
	if down != nil {
		parts = append(parts, SpeedText(*down)+" down")
	}
	return strings.Join(parts, " · ")
}

// PreviewText is what a checkout's amount buys so far.
func PreviewText(r PriceResult, currency string, decimals int) string {
	switch {
	case r.DurationSeconds > 0:
		s := EntitlementText(r.DurationSeconds, r.QuotaBytes, r.DownKbps)
		if r.UnusedAmount > 0 {
			s += " (" + MoneyText(r.UnusedAmount, currency, decimals) + " unused)"
		}
		return s
	case r.Amount == 0:
		return "Insert coins"
	}
	return "Not enough for a rate yet"
}

// RateText is one line of the rates list.
func RateText(e PriceEntry, currency string, decimals int) string {
	return MoneyText(e.Amount, currency, decimals) + ": " + EntitlementText(e.Minutes*60, e.QuotaBytes, e.DownKbps)
}

// ReceiptTimeText is a receipt's time: "2026-09-23 12:00 UTC".
func ReceiptTimeText(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04") + " UTC"
}

// FormatCode is a code's display form: groups of 5 when the length is a
// multiple of 5, else of 4, joined by "-".
func FormatCode(code string) string {
	size := 4
	if len(code)%5 == 0 {
		size = 5
	}
	var parts []string
	for i := 0; i < len(code); i += size {
		end := i + size
		if end > len(code) {
			end = len(code)
		}
		parts = append(parts, code[i:end])
	}
	return strings.Join(parts, "-")
}
