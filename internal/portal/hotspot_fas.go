package portal

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Guest-page routes of the Paid Hotspot and click-through, and the
// terminals' API (§14.6–14.7).

// withHotspot adds the hotspot view to a status object (when offered).
func withHotspot(status map[string]any, h *GuestHotspot) map[string]any {
	if h != nil {
		status["hotspot"] = h
	}
	return status
}

func retryHeader(w http.ResponseWriter, d time.Duration) {
	if d > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int((d+time.Second-1)/time.Second)))
	}
}

// hotspot serves GET /portal/checkout and the checkout and click-through
// actions (form posts answer 303 /?m=<code>, JSON posts JSON).
func (f *FAS) hotspot(w http.ResponseWriter, r *http.Request, pv PortalView, c Client, base string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/portal/checkout" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		h := f.e.GuestHotspot(c)
		w.Header().Set("Content-Type", "application/json")
		if h == nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad_request", "message": PortalMessages["bad_request"]})
			return
		}
		_ = json.NewEncoder(w).Encode(h)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	isJSON := strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
	reply := func(o Outcome) {
		retryHeader(w, o.RetryAfter)
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			if o.OK {
				st := f.e.StatusOf(c)
				h := f.e.GuestHotspot(c)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "code": o.Code, "status": withHotspot(statusJSON(pv, c, st), h), "hotspot": h})
				return
			}
			w.WriteHeader(o.Status)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": o.Code, "message": PortalMessages[o.Code]})
			return
		}
		http.Redirect(w, r, "/?m="+url.QueryEscape(o.Code), http.StatusSeeOther)
	}
	if !sameOrigin(r, base) {
		reply(fail("origin_mismatch"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, fasMaxBody)
	var terminalID string
	accept := false
	if isJSON {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			reply(fail("bad_request"))
			return
		}
		switch v := body["terminalId"].(type) {
		case float64:
			terminalID = strconv.FormatFloat(v, 'f', -1, 64)
		case string:
			terminalID = v
		}
		switch v := body["accept"].(type) {
		case bool:
			accept = v
		case string:
			accept = v == "1" || v == "true"
		}
	} else {
		if err := r.ParseForm(); err != nil {
			reply(fail("bad_request"))
			return
		}
		terminalID = r.PostForm.Get("terminalId")
		a := r.PostForm.Get("accept")
		accept = a == "1" || a == "true" || a == "on"
	}
	switch r.URL.Path {
	case "/portal/checkout":
		id, err := strconv.ParseInt(terminalID, 10, 64)
		if err != nil || id < 1 {
			reply(fail("bad_request"))
			return
		}
		reply(f.e.OpenCheckout(c, id))
	case "/portal/checkout/done":
		reply(f.e.CheckoutDone(c))
	case "/portal/checkout/cancel":
		reply(f.e.CheckoutCancel(c))
	case "/portal/clickthrough":
		reply(f.e.ClickThrough(c, accept))
	}
}

// terminal serves a coin terminal's request.
func (f *FAS) terminal(w http.ResponseWriter, r *http.Request, pv PortalView, c Client) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, fasMaxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad_request", "message": terminalMessages["bad_request"]})
		return
	}
	a := f.e.Terminal(pv, c, TerminalRequest{Method: r.Method, Path: r.URL.Path,
		Terminal: r.Header.Get("X-Perch-Terminal"), Session: r.Header.Get("X-Perch-Session"),
		Seq: r.Header.Get("X-Perch-Seq"), Signature: r.Header.Get("X-Perch-Signature"), Body: body})
	retryHeader(w, a.RetryAfter)
	w.WriteHeader(a.Status)
	_ = json.NewEncoder(w).Encode(a.Body)
}
