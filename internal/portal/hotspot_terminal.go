package portal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// The coin terminals' API on the guest-page listener (§14.6): every request
// is signed with the terminal's token (HMAC, the token never crosses the
// guest network), within a session the router handed out, with a strictly
// increasing sequence number, so a captured request can be neither forged
// nor replayed.

// TerminalPathPrefix is where the terminals' API lives.
const TerminalPathPrefix = "/portal/v1/terminal/"

var (
	terminalNonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	coinEventRe     = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

// TerminalRequest is one request of a terminal as the pages received it.
type TerminalRequest struct {
	Method    string
	Path      string
	Terminal  string // X-Perch-Terminal
	Session   string // X-Perch-Session
	Seq       string // X-Perch-Seq
	Signature string // X-Perch-Signature
	Body      []byte
}

// TerminalAnswer is the HTTP answer to a terminal.
type TerminalAnswer struct {
	Status     int
	Body       any
	RetryAfter time.Duration
}

var terminalMessages = map[string]string{
	"rate_limited":       "Too many requests.",
	"bad_request":        "The request is malformed.",
	"unknown_terminal":   "This terminal is not known here.",
	"wrong_portal":       "This terminal belongs to another portal.",
	"invalid_signature":  "The signature does not verify.",
	"terminal_disabled":  "This terminal is disabled.",
	"mac_mismatch":       "The request did not come from the terminal's device.",
	"session_unknown":    "Open a new session.",
	"stale_seq":          "The sequence number was used already.",
	"nonce_reused":       "This nonce was used before.",
	"not_found":          "No such operation.",
	"method_not_allowed": "Wrong method for this operation.",
	"checkout_closed":    "There is no open checkout with that reference on this terminal.",
	"checkout_full":      "The checkout cannot take more.",
	"bad_amount":         "The amount must be a whole number from 1 to 1000000.",
	"no_checkout":        "There is no payment in progress.",
	"below_minimum":      "That is not enough for a rate yet.",
	"not_ready":          "Payments are not available right now.",
}

func terr(status int, code string, extra map[string]any) TerminalAnswer {
	body := map[string]any{"error": code, "message": terminalMessages[code]}
	for k, v := range extra {
		body[k] = v
	}
	return TerminalAnswer{Status: status, Body: body}
}

var terminalOps = map[string]string{
	"session": http.MethodPost, "heartbeat": http.MethodPost, "checkout": http.MethodGet,
	"coins": http.MethodPost, "done": http.MethodPost,
}

// Terminal serves one terminal request on portal pv from client c.
func (e *Engine) Terminal(pv PortalView, c Client, r TerminalRequest) TerminalAnswer {
	wall := e.tickNow()
	if b, retry := e.termFail.Blocked(c.IP, wall); b {
		a := terr(http.StatusTooManyRequests, "rate_limited", nil)
		a.RetryAfter = retry
		return a
	}
	if ok, retry := e.termLimit.Allow(c.IP, wall); !ok {
		a := terr(http.StatusTooManyRequests, "rate_limited", nil)
		a.RetryAfter = retry
		return a
	}
	op := r.Path[len(TerminalPathPrefix):]
	method, known := terminalOps[op]
	if !known {
		return terr(http.StatusNotFound, "not_found", nil)
	}
	if r.Method != method {
		return terr(http.StatusMethodNotAllowed, "method_not_allowed", nil)
	}
	id, err1 := strconv.ParseInt(r.Terminal, 10, 64)
	seq, err2 := strconv.ParseInt(r.Seq, 10, 64)
	if err1 != nil || err2 != nil || id < 1 || seq < 0 || len(r.Session) > 64 || len(r.Signature) != 43 {
		return terr(http.StatusBadRequest, "bad_request", nil)
	}
	failed := func(status int, code string) TerminalAnswer {
		e.termFail.Hit(c.IP, wall)
		return terr(status, code, nil)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.terminalLocked(id)
	if !ok {
		return failed(http.StatusUnauthorized, "unknown_terminal")
	}
	if t.portal.cfg.PortalID != pv.ID {
		return failed(http.StatusForbidden, "wrong_portal")
	}
	want := SignTerminalRequest(t.cfg.Token, r.Method, r.Path, id, r.Session, seq, r.Body)
	if t.cfg.Token == "" || !SignatureMatches(want, r.Signature) {
		return failed(http.StatusUnauthorized, "invalid_signature")
	}
	if !t.cfg.Enabled {
		return terr(http.StatusForbidden, "terminal_disabled", nil)
	}
	if t.cfg.MAC != nil && *t.cfg.MAC != "" && NormalizeMAC(*t.cfg.MAC) != c.MAC {
		return terr(http.StatusForbidden, "mac_mismatch", nil)
	}
	ts := e.terminalStateLocked(id)
	now := e.clock.Now()
	table := t.portal.cfg.Payment.tableFor(t.cfg)

	if op == "session" {
		var body struct {
			Nonce string `json:"nonce"`
		}
		if seq != 0 || r.Session != "" || json.Unmarshal(r.Body, &body) != nil || !terminalNonceRe.MatchString(body.Nonce) {
			return terr(http.StatusBadRequest, "bad_request", nil)
		}
		for _, n := range ts.Nonces {
			if n == body.Nonce {
				return terr(http.StatusConflict, "nonce_reused", nil)
			}
		}
		ts.Nonces = append(ts.Nonces, body.Nonce)
		if len(ts.Nonces) > terminalNonceMemory {
			ts.Nonces = append([]string(nil), ts.Nonces[len(ts.Nonces)-terminalNonceMemory:]...)
		}
		ts.Session, ts.LastSeq, ts.LastSeenAt = newSession(), 0, now
		e.saveTerminalState(ts, ClassGrant)
		e.sendTerminalsLocked(true)
		out := map[string]any{"session": ts.Session, "heartbeatSeconds": terminalHeartbeatSeconds,
			"terminal": map[string]any{"terminalId": id, "name": t.cfg.Name, "portalId": pv.ID},
			"currency": "", "decimals": 0, "now": now}
		if table != nil {
			out["currency"], out["decimals"] = table.Currency, table.Decimals
		}
		return TerminalAnswer{Status: http.StatusOK, Body: out}
	}
	if ts.Session == "" || r.Session != ts.Session {
		return terr(http.StatusUnauthorized, "session_unknown", nil)
	}
	if seq <= ts.LastSeq {
		return terr(http.StatusConflict, "stale_seq", map[string]any{"lastSeq": ts.LastSeq})
	}
	wasOnline := e.terminalOnlineLocked(id, now)
	ts.LastSeq, ts.LastSeenAt = seq, now
	ops := &ElementOps{}
	e.sweepCheckoutsLocked(now, ops)
	e.applyOpsLocked(ops)
	if !wasOnline {
		e.sendTerminalsLocked(true)
	}

	switch op {
	case "heartbeat":
		var body struct {
			Status *TerminalStatus `json:"status"`
		}
		if len(bytes.TrimSpace(r.Body)) > 0 && json.Unmarshal(r.Body, &body) != nil {
			e.saveTerminalState(ts, ClassCounter)
			return terr(http.StatusBadRequest, "bad_request", nil)
		}
		if body.Status != nil {
			ts.Status = cleanTerminalStatus(*body.Status)
		}
		e.saveTerminalState(ts, ClassCounter)
		return TerminalAnswer{Status: http.StatusOK, Body: map[string]any{
			"checkout": e.terminalCheckoutLocked(id, now), "heartbeatSeconds": terminalHeartbeatSeconds, "now": now}}
	case "checkout":
		e.saveTerminalState(ts, ClassCounter)
		return TerminalAnswer{Status: http.StatusOK, Body: map[string]any{"checkout": e.terminalCheckoutLocked(id, now)}}
	case "coins":
		e.saveTerminalState(ts, ClassGrant)
		var body struct {
			CheckoutRef string `json:"checkoutRef"`
			EventID     string `json:"eventId"`
			Amount      *int64 `json:"amount"`
		}
		if json.Unmarshal(r.Body, &body) != nil || !coinEventRe.MatchString(body.EventID) || !localRefRe.MatchString(body.CheckoutRef) {
			return terr(http.StatusBadRequest, "bad_request", nil)
		}
		if body.Amount == nil || *body.Amount < 1 || *body.Amount > MaxCoinAmount {
			return terr(http.StatusUnprocessableEntity, "bad_amount", nil)
		}
		amount := *body.Amount
		ck := e.checkouts[body.CheckoutRef]
		currency := ""
		if table != nil {
			currency = table.Currency
		}
		unclaimed := func(status int, code, reason string) TerminalAnswer {
			seen := false
			for _, x := range ts.Unclaimed {
				seen = seen || x == body.EventID
			}
			if !seen {
				ts.Unclaimed = append(ts.Unclaimed, body.EventID)
				if len(ts.Unclaimed) > terminalUnclaimedMemory {
					ts.Unclaimed = append([]string(nil), ts.Unclaimed[len(ts.Unclaimed)-terminalUnclaimedMemory:]...)
				}
				e.saveTerminalState(ts, ClassGrant)
				e.journalUnclaimedLocked(pv.ID, id, body.EventID, amount, currency, body.CheckoutRef, reason, now)
				e.snapshotIfDue()
			}
			return terr(status, code, map[string]any{"recorded": true})
		}
		if ck == nil || ck.State != CheckoutOpen || ck.TerminalID != id {
			if ck != nil && ck.TerminalID == id {
				for _, coin := range ck.Coins {
					if coin.EventID == body.EventID {
						// Counted before the checkout closed: a retry.
						return TerminalAnswer{Status: http.StatusOK, Body: map[string]any{"accepted": false, "checkout": e.terminalCheckoutLocked(id, now)}}
					}
				}
			}
			return unclaimed(http.StatusConflict, "checkout_closed", "late")
		}
		for _, coin := range ck.Coins {
			if coin.EventID == body.EventID {
				return TerminalAnswer{Status: http.StatusOK, Body: map[string]any{"accepted": false, "checkout": e.terminalCheckoutLocked(id, now)}}
			}
		}
		if len(ck.Coins) >= MaxCheckoutCoins || ck.Amount+amount > MaxCheckoutAmount {
			return unclaimed(http.StatusConflict, "checkout_full", "full")
		}
		ck.Coins = append(ck.Coins, Coin{EventID: body.EventID, Amount: amount, At: now})
		ck.Amount += amount
		ck.LastActivityAt = now
		e.saveCheckout(ck)
		e.snapshotIfDue()
		e.sendTerminalsLocked(false)
		return TerminalAnswer{Status: http.StatusOK, Body: map[string]any{"accepted": true, "checkout": e.terminalCheckoutLocked(id, now)}}
	case "done":
		e.saveTerminalState(ts, ClassGrant)
		var body struct {
			CheckoutRef string `json:"checkoutRef"`
		}
		if json.Unmarshal(r.Body, &body) != nil || !localRefRe.MatchString(body.CheckoutRef) {
			return terr(http.StatusBadRequest, "bad_request", nil)
		}
		ck := e.checkouts[body.CheckoutRef]
		if ck == nil || ck.State != CheckoutOpen || ck.TerminalID != id {
			return terr(http.StatusConflict, "no_checkout", nil)
		}
		o := e.doneLocked(ck, ReasonTerminal, now)
		if !o.OK {
			return terr(o.Status, o.Code, nil)
		}
		return TerminalAnswer{Status: http.StatusOK, Body: map[string]any{"checkout": e.terminalCheckoutLocked(id, now)}}
	}
	return terr(http.StatusNotFound, "not_found", nil)
}

func printable(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}

func cleanTerminalStatus(s TerminalStatus) *TerminalStatus {
	out := &TerminalStatus{Firmware: printable(s.Firmware, 32), Error: printable(s.Error, 64)}
	if s.Acceptor == "on" || s.Acceptor == "off" {
		out.Acceptor = s.Acceptor
	}
	return out
}
