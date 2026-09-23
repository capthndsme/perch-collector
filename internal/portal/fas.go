package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The guest pages (the "FAS", plan 4 §8) on portal_port, plain HTTP
// (decision 24). One listener per router address of the enforcing portals'
// networks (never the wildcard: the LAN and the WAN do not see the port),
// opened and closed as portals come and go, none while no portal runs.
// The portal is the one whose device holds the connection's local address,
// and the guest is the
// MAC behind the TCP source address on that device (the neighbour table),
// never anything the request says. Port 80 of unauthorised guests is
// redirected here by perch_portal's dstnat chain, so the operating systems'
// captive-portal probes land here and open their login sheets.

// FAS limits (plan 4 §8).
const (
	fasMaxBody       = 4 << 10
	fasMaxConcurrent = 16
	fasTimeout       = 10 * time.Second
)

// PortalView is what the pages need about one portal.
type PortalView struct {
	ID            int64
	Name          string
	GatewayName   string
	Device        string
	Methods       Methods
	CSP           []string
	Relay         bool
	PrivacyNotice string
	Template      *Template
}

// portalByAddr finds the portal whose device holds addr.
func (e *Engine) portalByAddr(addr netip.Addr) (PortalView, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	addr = addr.Unmap()
	for _, id := range e.portalIDs() {
		p := e.portals[id]
		if !p.cfg.Enabled || p.device == "" {
			continue
		}
		for _, a := range p.addrs {
			if a.Addr() == addr {
				return PortalView{ID: id, Name: p.cfg.Name, GatewayName: p.cfg.GatewayName, Device: p.device,
					Methods: p.cfg.Methods, CSP: p.csp, Relay: p.cfg.Relay, PrivacyNotice: p.cfg.PrivacyNotice,
					Template: e.templateFor(p)}, true
			}
		}
	}
	return PortalView{}, false
}

// clientOf finds the guest's MAC on the portal's device.
func (e *Engine) clientOf(pv PortalView, remote netip.Addr) (Client, bool) {
	list, err := e.sys.Neighbors()
	if err != nil {
		return Client{}, false
	}
	ip := remote.Unmap().String()
	for _, n := range list {
		if n.IP == ip && n.Device == pv.Device {
			if mac := NormalizeMAC(n.MAC); mac != "" {
				return Client{PortalID: pv.ID, MAC: mac, IP: ip, Hostname: e.hostnameOf(mac)}, true
			}
		}
	}
	return Client{}, false
}

// hostnameOf is the DHCP lease's host name of a MAC, when there is one.
func (e *Engine) hostnameOf(mac string) *string {
	if e.leases == nil {
		return nil
	}
	if h := e.leases(mac); h != "" {
		return &h
	}
	return nil
}

// FAS serves the guest pages.
type FAS struct {
	e      *Engine
	log    *slog.Logger
	sem    chan struct{}
	server *http.Server
	port   int

	mu        sync.Mutex
	listeners map[netip.Addr]net.Listener
	failed    map[netip.Addr]string // last bind error per address (logged once)
	closed    bool
	listen    func(network, address string) (net.Listener, error)
}

// NewFAS builds the server for the guest pages' port. It listens on
// nothing until Sync names the addresses (Engine.SetListener).
func NewFAS(e *Engine, port int, log *slog.Logger) *FAS {
	if log == nil {
		log = slog.Default()
	}
	f := &FAS{e: e, log: log, sem: make(chan struct{}, fasMaxConcurrent), port: port,
		listeners: map[netip.Addr]net.Listener{}, failed: map[netip.Addr]string{}, listen: net.Listen}
	f.server = &http.Server{
		Handler:           f,
		ReadTimeout:       fasTimeout,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      fasTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          nil,
	}
	return f
}

// Sync listens on exactly addrs (the portals' router addresses): it opens
// what is missing (a bind that fails is retried on the next Sync, each
// tick) and closes what is no longer wanted. Connections in flight on a
// closed listener finish.
func (f *FAS) Sync(addrs []netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	want := map[netip.Addr]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		want[a] = true
		if f.listeners[a] != nil {
			continue
		}
		hp := netip.AddrPortFrom(a, uint16(f.port)).String()
		l, err := f.listen("tcp", hp)
		if err != nil {
			if f.failed[a] != err.Error() {
				f.failed[a] = err.Error()
				f.log.Warn("portal: guest pages cannot listen", "address", hp, "err", err)
			}
			continue
		}
		delete(f.failed, a)
		f.listeners[a] = l
		f.log.Info("portal: guest pages listening", "address", hp)
		go func() { _ = f.server.Serve(l) }()
	}
	for a, l := range f.listeners {
		if !want[a] {
			_ = l.Close()
			delete(f.listeners, a)
			f.log.Info("portal: guest pages stopped listening", "address", netip.AddrPortFrom(a, uint16(f.port)).String())
		}
	}
	for a := range f.failed {
		if !want[a] {
			delete(f.failed, a)
		}
	}
}

// Listening is the addresses listened on now (sorted).
func (f *FAS) Listening() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]netip.Addr, 0, len(f.listeners))
	for a := range f.listeners {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Serve runs the server on a listener (tests).
func (f *FAS) Serve(l net.Listener) error { return f.server.Serve(l) }

// Shutdown stops the server and every listener.
func (f *FAS) Shutdown(ctx context.Context) error {
	f.mu.Lock()
	f.closed = true
	for a, l := range f.listeners {
		_ = l.Close()
		delete(f.listeners, a)
	}
	f.mu.Unlock()
	return f.server.Shutdown(ctx)
}

func securityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
}

// ServeHTTP implements http.Handler.
func (f *FAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case f.sem <- struct{}{}:
		defer func() { <-f.sem }()
	case <-time.After(2 * time.Second):
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	securityHeaders(w.Header())
	local, ok := localAddr(r)
	if !ok {
		http.Error(w, "no local address", http.StatusForbidden)
		return
	}
	pv, ok := f.e.portalByAddr(local.Addr())
	if !ok {
		http.Error(w, "not a guest portal address", http.StatusForbidden)
		return
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "bad peer", http.StatusForbidden)
		return
	}
	c, ok := f.e.clientOf(pv, remote.Addr())
	if !ok {
		http.Error(w, "this device is not on the guest network", http.StatusForbidden)
		return
	}
	base := "http://" + hostPort(local)
	if !isPortalHost(r.Host, local) {
		f.foreign(w, r, pv, c, base)
		return
	}
	switch {
	case r.URL.Path == "/" || r.URL.Path == "/index.html":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.page(w, r, pv, c, base, r.URL.Query().Get("m"), r.URL.Query().Get("o"))
	case r.URL.Path == "/portal/api/status":
		f.apiStatus(w, pv, c, base)
	case r.URL.Path == "/portal/voucher" || r.URL.Path == "/portal/login" || r.URL.Path == "/portal/logout":
		f.action(w, r, pv, c, base)
	case r.URL.Path == "/portal/checkout" || r.URL.Path == "/portal/checkout/done" ||
		r.URL.Path == "/portal/checkout/cancel" || r.URL.Path == "/portal/clickthrough":
		f.hotspot(w, r, pv, c, base)
	case strings.HasPrefix(r.URL.Path, TerminalPathPrefix):
		f.terminal(w, r, pv, c)
	case strings.HasPrefix(r.URL.Path, "/assets/"):
		f.asset(w, r, pv)
	case strings.HasPrefix(r.URL.Path, "/portal/v1/authorizations"):
		f.relay(w, r, pv, c)
	default:
		http.Redirect(w, r, base+"/", http.StatusFound)
	}
}

func localAddr(r *http.Request) (netip.AddrPort, bool) {
	a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func hostPort(ap netip.AddrPort) string {
	return net.JoinHostPort(ap.Addr().String(), strconv.Itoa(int(ap.Port())))
}

// isPortalHost: the request names the portal itself (not a redirected
// request for another site).
func isPortalHost(host string, local netip.AddrPort) bool {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil && a.Unmap() == local.Addr() && p == strconv.Itoa(int(local.Port()))
}

// Captive-portal probes and their "online" answers (served to an
// authorised device whose probe still reached us).
var probeAnswers = map[string]struct {
	status int
	body   string
	ctype  string
}{
	"/generate_204":              {http.StatusNoContent, "", ""},
	"/gen_204":                   {http.StatusNoContent, "", ""},
	"/hotspot-detect.html":       {http.StatusOK, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>", "text/html"},
	"/library/test/success.html": {http.StatusOK, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>", "text/html"},
	"/connecttest.txt":           {http.StatusOK, "Microsoft Connect Test", "text/plain"},
	"/ncsi.txt":                  {http.StatusOK, "Microsoft NCSI", "text/plain"},
	"/canonical.html":            {http.StatusOK, `<meta http-equiv="refresh" content="0;url=https://support.mozilla.org/kb/captive-portal"/>`, "text/html"},
	"/success.txt":               {http.StatusOK, "success\n", "text/plain"},
}

// foreign handles a request for another site that reached the pages
// through the port-80 redirect: to the portal while not authorised (what
// makes Android, Apple, Windows and Firefox show their login sheet), else
// back where it was going.
func (f *FAS) foreign(w http.ResponseWriter, r *http.Request, pv PortalView, c Client, base string) {
	w.Header().Set("Cache-Control", "no-store")
	origin := "http://" + r.Host + r.URL.RequestURI()
	st := f.e.StatusOf(c)
	if st.State == StateActive || st.State == StatePending {
		if a, ok := probeAnswers[r.URL.Path]; ok {
			if a.ctype != "" {
				w.Header().Set("Content-Type", a.ctype)
			}
			w.WriteHeader(a.status)
			_, _ = io.WriteString(w, a.body)
			return
		}
		http.Redirect(w, r, origin, http.StatusFound)
		return
	}
	loc := base + "/"
	if len(origin) <= 1024 {
		loc += "?o=" + url.QueryEscape(origin)
	}
	w.Header().Set("Location", loc)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusFound)
	fmt.Fprintf(w, "<!doctype html><title>Sign in</title><a href=\"%s\" data-perch-portal>Sign in to the network</a>\n", EscapeHTML(loc))
}

func formatDuration(s *int64) string {
	if s == nil {
		return "no limit"
	}
	v := *s
	switch {
	case v >= 86400:
		return fmt.Sprintf("%d d %d h", v/86400, v%86400/3600)
	case v >= 3600:
		return fmt.Sprintf("%d h %d min", v/3600, v%3600/60)
	case v >= 60:
		return fmt.Sprintf("%d min", (v+59)/60)
	}
	return fmt.Sprintf("%d s", v)
}

func formatBytes(b *int64) string {
	if b == nil {
		return "no limit"
	}
	v := float64(*b)
	units := []string{"B", "kB", "MB", "GB", "TB"}
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", *b)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// statusJSON is the perch object of /portal/api/status (and status_json).
func statusJSON(pv PortalView, c Client, st GuestStatus) map[string]any {
	perch := map[string]any{"state": st.State, "mac": c.MAC, "methods": pv.Methods}
	if st.Grant != nil {
		g := st.Grant
		perch["grant"] = map[string]any{
			"grantId": g.GrantID, "localRef": g.LocalRef, "state": g.State, "expiresAt": st.ExpiresAt,
			"remainingSeconds": st.RemainingSeconds, "remainingBytes": st.RemainingBytes,
			"bytesUp": g.BytesUp, "bytesDown": g.BytesDown,
		}
	} else {
		perch["grant"] = nil
	}
	return perch
}

func (f *FAS) page(w http.ResponseWriter, r *http.Request, pv PortalView, c Client, base, msg, origin string) {
	st := f.e.StatusOf(c)
	t := pv.Template
	page := LoginPage
	online := st.State == StateActive || st.State == StatePending
	if online {
		page = StatusPage
	}
	file, ok := t.Files[page]
	if !ok {
		// A custom set without status.html uses the builtin one with the
		// builtin assets.
		t = BuiltinTemplate()
		file = t.Files[page]
	}
	if _, known := PortalMessages[msg]; !known {
		msg = ""
	}
	methods := []string{}
	if pv.Methods.Voucher {
		methods = append(methods, "voucher")
	}
	if pv.Methods.Password {
		methods = append(methods, "password")
	}
	if pv.Methods.Payment {
		methods = append(methods, "payment")
	}
	if pv.Methods.ClickThrough {
		methods = append(methods, "clickthrough")
	}
	hs := f.e.GuestHotspot(c)
	snippets := Snippets(pv.Methods.Voucher || pv.Methods.Payment, pv.Methods.Password)
	extra := HotspotSnippets(hs)
	for _, k := range []string{"checkout_form", "clickthrough_form", "receipt"} {
		snippets[k] = extra[k]
	}
	expires := ""
	if st.ExpiresAt != nil {
		expires = time.UnixMilli(*st.ExpiresAt).UTC().Format(time.RFC3339)
	}
	values := map[string]string{
		"portal_name": pv.Name, "gateway_name": pv.GatewayName, "client_mac": c.MAC, "client_ip": c.IP,
		"origin_url": SafeOriginURL(origin), "message": PortalMessages[msg], "message_code": msg,
		"assets": "/assets/" + t.SHA256, "remaining_time": formatDuration(st.RemainingSeconds),
		"remaining_data": formatBytes(st.RemainingBytes), "expires_at": expires,
		"privacy_notice": pv.PrivacyNotice, "methods": strings.Join(methods, ","),
		"reference_code": extra["reference_code"],
	}
	body := RenderPageSnippets(file.Data, values, withHotspot(statusJSON(pv, c, st), hs), snippets)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", CSP(t.Builtin, pv.CSP))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (f *FAS) apiStatus(w http.ResponseWriter, pv PortalView, c Client, base string) {
	st := f.e.StatusOf(c)
	online := st.State == StateActive || st.State == StatePending
	out := map[string]any{"captive": !online, "user-portal-url": base + "/", "can-extend-session": false,
		"perch": withHotspot(statusJSON(pv, c, st), f.e.GuestHotspot(c))}
	if online && st.RemainingSeconds != nil {
		out["seconds-remaining"] = *st.RemainingSeconds
	}
	if online && st.RemainingBytes != nil {
		out["bytes-remaining"] = *st.RemainingBytes
	}
	h := w.Header()
	h.Set("Content-Type", "application/captive+json")
	h.Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// sameOrigin: POSTs must come from the portal's own pages (or carry no
// Origin / Referer at all, like an OS login sheet may).
func sameOrigin(r *http.Request, base string) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return o == base
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return ref == base || strings.HasPrefix(ref, base+"/") || strings.HasPrefix(ref, base+"?")
	}
	return true
}

func (f *FAS) action(w http.ResponseWriter, r *http.Request, pv PortalView, c Client, base string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	isJSON := strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
	reply := func(o Outcome) {
		if o.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int((o.RetryAfter+time.Second-1)/time.Second)))
		}
		w.Header().Set("Cache-Control", "no-store")
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			if o.OK {
				st := f.e.StatusOf(c)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": withHotspot(statusJSON(pv, c, st), f.e.GuestHotspot(c))})
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
	fields := map[string]string{}
	var replace bool
	if isJSON {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			reply(fail("bad_request"))
			return
		}
		for k, v := range body {
			switch x := v.(type) {
			case string:
				fields[k] = x
			case bool:
				if k == "replace" {
					replace = x
				}
			}
		}
	} else {
		if err := r.ParseForm(); err != nil {
			reply(fail("bad_request"))
			return
		}
		for _, k := range []string{"code", "username", "password"} {
			fields[k] = r.PostForm.Get(k)
		}
		replace = r.PostForm.Get("replace") == "1" || r.PostForm.Get("replace") == "true"
	}
	switch r.URL.Path {
	case "/portal/voucher":
		if fields["code"] == "" {
			reply(fail("bad_request"))
			return
		}
		reply(f.e.Redeem(r.Context(), c, fields["code"], replace))
	case "/portal/login":
		reply(f.e.Login(r.Context(), c, fields["username"], fields["password"], replace))
	case "/portal/logout":
		reply(f.e.Logout(r.Context(), c))
	}
}

func (f *FAS) asset(w http.ResponseWriter, r *http.Request, pv PortalView) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/assets/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	t := pv.Template
	if parts[0] != t.SHA256 {
		// The builtin assets stay available to a custom set without its own
		// status page.
		if parts[0] != EmptySetSHA256 {
			http.NotFound(w, r)
			return
		}
		t = BuiltinTemplate()
	}
	file, ok := t.Files[parts[1]]
	if !ok || extOf(file.Name) == "html" {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", file.ContentType)
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	if extOf(file.Name) == "svg" {
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(file.Data)
	}
}

// relay passes an integration's request on the guest network to the
// controller (decision 22): the token is checked there, never stored here;
// requests are rate-limited per client address and per portal.
func (f *FAS) relay(w http.ResponseWriter, r *http.Request, pv PortalView, c Client) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeErr := func(status int, code string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": code})
	}
	if !pv.Relay {
		writeErr(http.StatusNotFound, "relay_disabled")
		return
	}
	now := time.Now()
	if ok, retry := f.e.relayLimit.Allow(c.IP, now); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)+1))
		writeErr(http.StatusTooManyRequests, "rate_limited")
		return
	}
	if ok, retry := f.e.relayPortal.Allow(fmt.Sprint(pv.ID), now); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)+1))
		writeErr(http.StatusTooManyRequests, "rate_limited")
		return
	}
	auth := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if !strings.HasPrefix(auth, "Bearer ") || token == "" || len(token) > 256 {
		writeErr(http.StatusUnauthorized, "invalid_api_token")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/portal/v1/authorizations")
	p := RelayParams{PortalID: pv.ID, Token: token, ClientIP: c.IP}
	switch {
	case rest == "" && r.Method == http.MethodPost:
		p.Op = "authorize"
		r.Body = http.MaxBytesReader(w, r.Body, fasMaxBody)
		body, err := io.ReadAll(r.Body)
		if err != nil || !json.Valid(body) {
			writeErr(http.StatusBadRequest, "bad_request")
			return
		}
		p.Body = body
	case strings.HasPrefix(rest, "/") && (r.Method == http.MethodGet || r.Method == http.MethodDelete):
		mac := NormalizeMAC(strings.TrimPrefix(rest, "/"))
		if mac == "" {
			writeErr(http.StatusUnprocessableEntity, "invalid_mac")
			return
		}
		p.MAC = mac
		p.Op = "status"
		if r.Method == http.MethodDelete {
			p.Op = "deauthorize"
		}
	default:
		writeErr(http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	res, err := f.e.Relay(r.Context(), p)
	if err != nil {
		writeErr(http.StatusServiceUnavailable, "controller_unreachable")
		return
	}
	status := res.Status
	if status < 200 || status > 599 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	if len(res.Body) > 0 && json.Valid(res.Body) {
		_, _ = w.Write(res.Body)
	} else {
		_, _ = io.WriteString(w, "{}")
	}
}

// Relay forwards portal.relay.
func (e *Engine) Relay(ctx context.Context, p RelayParams) (RelayResult, error) {
	a := e.currentAgent()
	if a == nil {
		return RelayResult{}, ErrOffline
	}
	cctx, cancel := context.WithTimeout(ctx, redeemTimeout)
	defer cancel()
	var res RelayResult
	if err := a.Call(cctx, "portal.relay", p, &res); err != nil {
		return RelayResult{}, errors.New("relay failed")
	}
	return res, nil
}
