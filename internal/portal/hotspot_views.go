package portal

import (
	"sort"
	"strconv"
	"strings"
)

// What the guest pages and the terminals see of checkouts (§14.7).

// CheckoutPreview is what a checkout's amount buys so far.
type CheckoutPreview struct {
	DurationSeconds int64  `json:"durationSeconds"`
	QuotaBytes      *int64 `json:"quotaBytes"`
	DownKbps        *int64 `json:"downKbps"`
	UpKbps          *int64 `json:"upKbps"`
	UnusedAmount    int64  `json:"unusedAmount"`
}

func previewOf(r PriceResult) CheckoutPreview {
	return CheckoutPreview{DurationSeconds: r.DurationSeconds, QuotaBytes: r.QuotaBytes, DownKbps: r.DownKbps,
		UpKbps: r.UpKbps, UnusedAmount: r.UnusedAmount}
}

// TerminalCheckout is a checkout as its terminal sees it (never the MAC).
type TerminalCheckout struct {
	CheckoutRef     string          `json:"checkoutRef"`
	State           string          `json:"state"`
	Amount          int64           `json:"amount"`
	AmountText      string          `json:"amountText"`
	Currency        string          `json:"currency"`
	Decimals        int             `json:"decimals"`
	Preview         CheckoutPreview `json:"preview"`
	PreviewText     string          `json:"previewText"`
	OpenedAt        int64           `json:"openedAt"`
	IdleDeadline    int64           `json:"idleDeadline"`
	IdleSecondsLeft int64           `json:"idleSecondsLeft"`
	ReferenceCode   string          `json:"referenceCode,omitempty"`
}

func idleLeft(ck *Checkout, now int64) int64 {
	if ck.State != CheckoutOpen {
		return 0
	}
	left := (ck.idleDeadline() - now + 999) / 1000
	if left < 0 {
		return 0
	}
	return left
}

func (e *Engine) terminalCheckoutLocked(terminalID int64, now int64) *TerminalCheckout {
	ck := e.openCheckoutOfTerminalLocked(terminalID)
	if ck == nil {
		ck = e.latestClosedLocked(func(c *Checkout) bool { return c.TerminalID == terminalID })
		if ck == nil || now-ck.ClosedAt > terminalReceiptMs {
			return nil
		}
	}
	r := PriceEntitlement(ck.Price, ck.Amount)
	v := &TerminalCheckout{CheckoutRef: ck.Ref, State: ck.State, Amount: ck.Amount,
		AmountText: MoneyText(ck.Amount, ck.Price.Currency, ck.Price.Decimals), Currency: ck.Price.Currency,
		Decimals: ck.Price.Decimals, Preview: previewOf(r), PreviewText: PreviewText(r, ck.Price.Currency, ck.Price.Decimals),
		OpenedAt: ck.OpenedAt, IdleDeadline: ck.idleDeadline(), IdleSecondsLeft: idleLeft(ck, now)}
	if ck.State == CheckoutFinalized && ck.Result != nil {
		v.ReferenceCode = FormatCode(ck.Result.ReferenceCode)
	}
	return v
}

// GuestCheckout is a checkout as its guest sees it.
type GuestCheckout struct {
	CheckoutRef     string          `json:"checkoutRef"`
	TerminalID      int64           `json:"terminalId"`
	TerminalName    string          `json:"terminalName"`
	State           string          `json:"state"`
	Amount          int64           `json:"amount"`
	AmountText      string          `json:"amountText"`
	Currency        string          `json:"currency"`
	Decimals        int             `json:"decimals"`
	Preview         CheckoutPreview `json:"preview"`
	PreviewText     string          `json:"previewText"`
	IdleSecondsLeft int64           `json:"idleSecondsLeft"`
	TerminalOnline  bool            `json:"terminalOnline"`
	OpenedAt        int64           `json:"openedAt"`
	ClosedAt        *int64          `json:"closedAt"`
}

// GuestTerminal is one terminal in the guest's picker.
type GuestTerminal struct {
	TerminalID int64  `json:"terminalId"`
	Name       string `json:"name"`
	// State: free | busy | offline | yours.
	State string `json:"state"`
}

// GuestRate is one line of the rates.
type GuestRate struct {
	Amount     int64  `json:"amount"`
	AmountText string `json:"amountText"`
	Minutes    int64  `json:"minutes"`
	QuotaBytes *int64 `json:"quotaBytes"`
	DownKbps   *int64 `json:"downKbps"`
	UpKbps     *int64 `json:"upKbps"`
	Text       string `json:"text"`
}

// GuestRates is the portal's default price table.
type GuestRates struct {
	Currency string      `json:"currency"`
	Decimals int         `json:"decimals"`
	Entries  []GuestRate `json:"entries"`
}

// GuestReceipt is the device's latest payment (24 h).
type GuestReceipt struct {
	ReferenceCode   string `json:"referenceCode"`
	Amount          int64  `json:"amount"`
	AmountText      string `json:"amountText"`
	DurationSeconds int64  `json:"durationSeconds"`
	QuotaBytes      *int64 `json:"quotaBytes"`
	Text            string `json:"text"`
	FinalizedAt     int64  `json:"finalizedAt"`
}

// GuestClickThrough is the click-through offer for the device.
type GuestClickThrough struct {
	Available         bool   `json:"available"`
	RetryAfterSeconds *int64 `json:"retryAfterSeconds"`
	Minutes           int64  `json:"minutes"`
	Terms             string `json:"terms"`
}

// GuestHotspot is GET /portal/checkout (and status_json's hotspot).
type GuestHotspot struct {
	Checkout     *GuestCheckout     `json:"checkout"`
	Terminals    []GuestTerminal    `json:"terminals"`
	Rates        *GuestRates        `json:"rates"`
	Receipt      *GuestReceipt      `json:"receipt"`
	ClickThrough *GuestClickThrough `json:"clickThrough"`

	payment, clickThrough bool
}

// GuestHotspot is the hotspot view of a guest, nil when the portal offers
// neither payment nor click-through.
func (e *Engine) GuestHotspot(c Client) *GuestHotspot {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock.Now()
	ops := &ElementOps{}
	e.sweepCheckoutsLocked(now, ops)
	e.applyOpsLocked(ops)
	return e.guestHotspotLocked(c, now)
}

func (e *Engine) guestHotspotLocked(c Client, now int64) *GuestHotspot {
	p := e.portals[c.PortalID]
	if p == nil {
		return nil
	}
	pay := p.cfg.Methods.Payment && p.cfg.Payment != nil
	click := p.cfg.Methods.ClickThrough && p.cfg.ClickThrough != nil
	if !pay && !click {
		return nil
	}
	h := &GuestHotspot{Terminals: []GuestTerminal{}, payment: pay, clickThrough: click}
	if pay {
		ck := e.openCheckoutOfMACLocked(c.PortalID, c.MAC)
		if ck == nil {
			ck = e.latestClosedLocked(func(x *Checkout) bool { return x.PortalID == c.PortalID && x.MAC == c.MAC })
			if ck != nil && now-ck.ClosedAt > guestRecentCheckoutMs {
				ck = nil
			}
		}
		if ck != nil {
			r := PriceEntitlement(ck.Price, ck.Amount)
			gc := &GuestCheckout{CheckoutRef: ck.Ref, TerminalID: ck.TerminalID, TerminalName: ck.TerminalName, State: ck.State,
				Amount: ck.Amount, AmountText: MoneyText(ck.Amount, ck.Price.Currency, ck.Price.Decimals),
				Currency: ck.Price.Currency, Decimals: ck.Price.Decimals, Preview: previewOf(r),
				PreviewText: PreviewText(r, ck.Price.Currency, ck.Price.Decimals), IdleSecondsLeft: idleLeft(ck, now),
				TerminalOnline: e.terminalOnlineLocked(ck.TerminalID, now), OpenedAt: ck.OpenedAt}
			if ck.State != CheckoutOpen {
				v := ck.ClosedAt
				gc.ClosedAt = &v
			}
			h.Checkout = gc
		}
		for _, t := range p.cfg.Payment.Terminals {
			if !t.Enabled {
				continue
			}
			st := "offline"
			if cur := e.openCheckoutOfTerminalLocked(t.TerminalID); cur != nil {
				st = "busy"
				if cur.MAC == c.MAC && cur.PortalID == c.PortalID {
					st = "yours"
				}
			} else if e.terminalOnlineLocked(t.TerminalID, now) {
				st = "free"
			}
			h.Terminals = append(h.Terminals, GuestTerminal{TerminalID: t.TerminalID, Name: t.Name, State: st})
		}
		sort.SliceStable(h.Terminals, func(a, b int) bool {
			if h.Terminals[a].Name != h.Terminals[b].Name {
				return h.Terminals[a].Name < h.Terminals[b].Name
			}
			return h.Terminals[a].TerminalID < h.Terminals[b].TerminalID
		})
		if t := p.cfg.Payment.table(p.cfg.Payment.PriceTableID); t != nil {
			rates := &GuestRates{Currency: t.Currency, Decimals: t.Decimals, Entries: []GuestRate{}}
			entries := append([]PriceEntry(nil), t.Entries...)
			sort.SliceStable(entries, func(a, b int) bool { return entries[a].Amount < entries[b].Amount })
			for _, en := range entries {
				rates.Entries = append(rates.Entries, GuestRate{Amount: en.Amount, AmountText: MoneyText(en.Amount, t.Currency, t.Decimals),
					Minutes: en.Minutes, QuotaBytes: en.QuotaBytes, DownKbps: en.DownKbps, UpKbps: en.UpKbps,
					Text: RateText(en, t.Currency, t.Decimals)})
			}
			h.Rates = rates
		}
		rc := e.latestClosedLocked(func(x *Checkout) bool {
			return x.State == CheckoutFinalized && x.PortalID == c.PortalID && x.MAC == c.MAC && x.Result != nil
		})
		if rc != nil && now-rc.ClosedAt <= receiptMs {
			h.Receipt = &GuestReceipt{ReferenceCode: FormatCode(rc.Result.ReferenceCode), Amount: rc.Amount,
				AmountText: MoneyText(rc.Amount, rc.Price.Currency, rc.Price.Decimals), DurationSeconds: rc.Result.DurationSeconds,
				QuotaBytes: rc.Result.QuotaBytes, Text: EntitlementText(rc.Result.DurationSeconds, rc.Result.QuotaBytes, rc.Result.DownKbps),
				FinalizedAt: rc.ClosedAt}
		}
	}
	if click {
		cfg := p.cfg.ClickThrough.normalized()
		ct := &GuestClickThrough{Available: true, Minutes: cfg.Minutes, Terms: cfg.Terms}
		if wait := e.clickRetryLocked(c.PortalID, c.MAC, cfg, now); wait > 0 {
			s := (wait + 999) / 1000
			ct.Available, ct.RetryAfterSeconds = false, &s
		}
		h.ClickThrough = ct
	}
	return h
}

// HotspotSnippets renders checkout_form, clickthrough_form, receipt and the
// reference_code value from a guest's hotspot view (§14.7, exact HTML).
func HotspotSnippets(h *GuestHotspot) map[string]string {
	out := map[string]string{"checkout_form": "", "clickthrough_form": "", "receipt": "", "reference_code": ""}
	if h == nil {
		return out
	}
	E := EscapeHTML
	if h.payment {
		if ck := h.Checkout; ck != nil && ck.State == CheckoutOpen {
			state := ""
			if !ck.TerminalOnline {
				state = "The terminal is not responding."
			}
			out["checkout_form"] = `<section class="perch-checkout" data-perch-checkout="open" data-ref="` + E(ck.CheckoutRef) + `">` +
				`<h2>Insert coins at ` + E(ck.TerminalName) + `</h2>` +
				`<p class="perch-total" data-perch-amount>` + E(ck.AmountText) + `</p>` +
				`<p class="perch-preview" data-perch-preview>` + E(ck.PreviewText) + `</p>` +
				`<p class="perch-idle">Closes after <span data-perch-idle>` + strconv.FormatInt(ck.IdleSecondsLeft, 10) + `</span> s without a coin.</p>` +
				`<p class="perch-terminal-state" data-perch-terminal-state>` + E(state) + `</p>` +
				`<form class="perch-form" method="post" action="/portal/checkout/done"><button type="submit">Done</button></form>` +
				`<form class="perch-form" method="post" action="/portal/checkout/cancel"><button type="submit" class="secondary">Cancel</button></form>` +
				`<p><a href="/">Refresh</a></p></section>`
		} else if len(h.Terminals) > 0 {
			var b strings.Builder
			b.WriteString(`<form class="perch-form perch-checkout-start" method="post" action="/portal/checkout" data-perch-checkout="picker">` +
				`<label for="perch-terminal">Pay at a coin terminal</label><select id="perch-terminal" name="terminalId">`)
			for _, t := range h.Terminals {
				id := strconv.FormatInt(t.TerminalID, 10)
				switch t.State {
				case "busy", "offline":
					b.WriteString(`<option value="` + id + `" disabled>` + E(t.Name) + ` (` + t.State + `)</option>`)
				default:
					b.WriteString(`<option value="` + id + `">` + E(t.Name) + `</option>`)
				}
			}
			b.WriteString(`</select><button type="submit">Start</button></form>`)
			if h.Rates != nil {
				b.WriteString(`<ul class="perch-rates">`)
				for _, r := range h.Rates.Entries {
					b.WriteString(`<li>` + E(r.Text) + `</li>`)
				}
				b.WriteString(`</ul>`)
			}
			out["checkout_form"] = b.String()
		}
		if r := h.Receipt; r != nil {
			detail := r.AmountText + " · " + r.Text + " · " + ReceiptTimeText(r.FinalizedAt)
			out["receipt"] = `<section class="perch-receipt"><h2>Your reference code</h2><p class="perch-code">` + E(r.ReferenceCode) + `</p>` +
				`<p>Screenshot or save this code. If this device's address changes, enter it as a voucher code to move your remaining time.</p>` +
				`<p class="perch-receipt-detail">` + E(detail) + `</p></section>`
			out["reference_code"] = r.ReferenceCode
		}
	}
	if ct := h.ClickThrough; h.clickThrough && ct != nil {
		if ct.Available {
			terms := ""
			if ct.Terms != "" {
				terms = `<p class="perch-terms">` + E(ct.Terms) + `</p>`
			}
			out["clickthrough_form"] = `<form class="perch-form perch-clickthrough" method="post" action="/portal/clickthrough">` + terms +
				`<label class="perch-accept"><input type="checkbox" name="accept" value="1" required> I accept the terms of use</label>` +
				`<button type="submit">Free access: ` + E(DurationText(ct.Minutes*60)) + `</button></form>`
		} else {
			var wait int64
			if ct.RetryAfterSeconds != nil {
				wait = *ct.RetryAfterSeconds
			}
			out["clickthrough_form"] = `<p class="perch-clickthrough-used">Free access used. It is available again in ` + E(DurationText(wait)) + `.</p>`
		}
	}
	return out
}
