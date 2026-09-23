package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/capthndsme/perch-collector/internal/observe"
)

// fasFixture runs the pages on 127.0.0.1 with "lo" as the portal device and
// the test client as MAC macG1.
type fasFixture struct {
	e    *Engine
	sys  *fakeSystem
	c    *controllerSide
	base string
	cl   *http.Client
}

func newFAS(t *testing.T, mutate func(*PortalConfig)) *fasFixture {
	t.Helper()
	sys := newFakeSystem()
	sys.devices["lo"] = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}
	sys.neighbors = []observe.Neighbor{{IP: "127.0.0.1", MAC: macG1, Device: "lo", Reachable: true}}
	e, _ := newTestEngine(t, sys, filepath.Join(t.TempDir(), "s.db"))
	c := newController(t)
	pc := guestPortal(3)
	pc.Network, pc.Device = "", "lo"
	if mutate != nil {
		mutate(&pc)
	}
	if _, err := e.Configure(context.Background(), c.configure(pc)); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := NewFAS(e, 0, quietLog)
	go f.Serve(l)
	t.Cleanup(func() { f.Shutdown(context.Background()) })
	return &fasFixture{e: e, sys: sys, c: c, base: "http://" + l.Addr().String(),
		cl: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (f *fasFixture) do(t *testing.T, method, path, host string, body io.Reader, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, f.base+path, body)
	if host != "" {
		req.Host = host
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := f.cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func TestFASCaptiveProbesRedirect(t *testing.T) {
	f := newFAS(t, nil)
	for _, probe := range []struct{ host, path string }{
		{"connectivitycheck.gstatic.com", "/generate_204"},
		{"captive.apple.com", "/hotspot-detect.html"},
		{"www.msftconnecttest.com", "/connecttest.txt"},
		{"detectportal.firefox.com", "/canonical.html"},
	} {
		res, _ := f.do(t, "GET", probe.path, probe.host, nil, nil)
		if res.StatusCode != http.StatusFound {
			t.Fatalf("%s: %d", probe.host, res.StatusCode)
		}
		loc := res.Header.Get("Location")
		want := f.base + "/?o=" + url.QueryEscape("http://"+probe.host+probe.path)
		if loc != want {
			t.Fatalf("location %s, want %s", loc, want)
		}
	}
}

func TestFASLoginPageAndVoucherFlow(t *testing.T) {
	f := newFAS(t, nil)
	res, body := f.do(t, "GET", "/", "", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "data-perch-portal") || !strings.Contains(body, `action="/portal/voucher"`) {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self';") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("csp %q", csp)
	}
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("headers")
	}
	if !strings.Contains(body, macG1) {
		t.Fatal("client MAC missing")
	}
	dur := int64(600)
	if _, err := f.e.Vouchers(context.Background(), f.c.vouchers(offlineVoucher(t, 17, vecCode, nil, &dur, 1))); err != nil {
		t.Fatal(err)
	}
	// A wrong code over a form post: 303 back with the message.
	res, _ = f.do(t, "POST", "/portal/voucher", "", strings.NewReader("code=AAAAAAAAAA"),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/?m=invalid_code" {
		t.Fatalf("%d %s", res.StatusCode, res.Header.Get("Location"))
	}
	_, body = f.do(t, "GET", "/?m=invalid_code", "", nil, nil)
	if !strings.Contains(body, PortalMessages["invalid_code"]) {
		t.Fatal("message not shown")
	}
	// Another origin is refused.
	res, body = f.do(t, "POST", "/portal/voucher", "", strings.NewReader(`{"code":"K7Q2M9XH4D"}`),
		map[string]string{"Content-Type": "application/json", "Origin": "http://evil.example.com"})
	if res.StatusCode != 403 || !strings.Contains(body, "origin_mismatch") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	// A held voucher, redeemed offline over JSON.
	res, body = f.do(t, "POST", "/portal/voucher", "", strings.NewReader(`{"code":"K7Q2M-9XH4D"}`),
		map[string]string{"Content-Type": "application/json", "Origin": f.base})
	if res.StatusCode != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if !f.sys.has("inet", "p3_auth", macG1) {
		t.Fatal("not authorised")
	}
	_, body = f.do(t, "GET", "/", "", nil, nil)
	if !strings.Contains(body, "You are online") || !strings.Contains(body, "10 min") {
		t.Fatalf("status page: %s", body)
	}
	res, body = f.do(t, "GET", "/portal/api/status", "", nil, nil)
	var st map[string]any
	_ = json.Unmarshal([]byte(body), &st)
	if res.Header.Get("Content-Type") != "application/captive+json" || st["captive"] != false || st["seconds-remaining"] != float64(600) {
		t.Fatalf("%s %s", res.Header.Get("Content-Type"), body)
	}
	// Once online, a probe that still reaches the pages gets its answer.
	res, _ = f.do(t, "GET", "/generate_204", "connectivitycheck.gstatic.com", nil, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("probe %d", res.StatusCode)
	}
	// Logout.
	res, _ = f.do(t, "POST", "/portal/logout", "", strings.NewReader(""), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Referer": f.base + "/"})
	if res.StatusCode != http.StatusSeeOther || f.sys.has("inet", "p3_auth", macG1) {
		t.Fatal("logout failed")
	}
	if ev := eventsOf(f.e, EvGrantEnded); len(ev) != 1 || ev[0].Reason != EndLogout {
		t.Fatalf("%+v", ev)
	}
}

func TestFASRateLimit(t *testing.T) {
	f := newFAS(t, nil)
	dur := int64(600)
	_, _ = f.e.Vouchers(context.Background(), f.c.vouchers(offlineVoucher(t, 17, vecCode, nil, &dur, 1)))
	var res *http.Response
	var body string
	for i := 0; i < 6; i++ {
		res, body = f.do(t, "POST", "/portal/voucher", "", strings.NewReader(`{"code":"AAAAAAAAAA"}`), map[string]string{"Content-Type": "application/json"})
	}
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" || !strings.Contains(body, "rate_limited") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
}

func TestFASAssetsAndUnknownDevice(t *testing.T) {
	f := newFAS(t, nil)
	res, body := f.do(t, "GET", "/assets/"+EmptySetSHA256+"/style.css", "", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Cache-Control"), "immutable") || !strings.Contains(body, ".card") {
		t.Fatalf("%d", res.StatusCode)
	}
	res, _ = f.do(t, "GET", "/assets/"+EmptySetSHA256+"/login.html", "", nil, nil)
	if res.StatusCode != 404 {
		t.Fatal("template HTML served as an asset")
	}
	f.sys.neighbors = nil
	res, _ = f.do(t, "GET", "/", "", nil, nil)
	if res.StatusCode != 403 {
		t.Fatalf("unknown device got %d", res.StatusCode)
	}
}

func TestFASCustomTemplate(t *testing.T) {
	login := []byte(`<!doctype html><html data-perch-portal><body><h1>{{portal_name}}</h1><p id="mac">{{client_mac}}</p>` +
		`<script type="application/json" id="s">{{status_json}}</script><script>fetch('/portal/api/status')</script>{{voucher_form}}` +
		`<img src="{{assets}}/logo.svg"></body></html>`)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)
	files := []TemplateFileData{{Name: "login.html", Data: login}, {Name: "logo.svg", Data: svg}}
	sha := TemplateSetSHA256(files)
	f := newFAS(t, func(pc *PortalConfig) {
		pc.TemplateSHA256 = sha
		pc.Name = `<Guest & "Co">`
		pc.CSPConnectSrc = []string{"http://192.168.20.5:8080", "http://bad; script-src *"}
	})
	res, err := f.e.Configure(context.Background(), f.c.configure(func() PortalConfig {
		pc := guestPortal(3)
		pc.Network, pc.Device, pc.TemplateSHA256 = "", "lo", sha
		pc.Name = `<Guest & "Co">`
		pc.CSPConnectSrc = []string{"http://192.168.20.5:8080", "http://bad; script-src *"}
		return pc
	}()))
	if err != nil || len(res.MissingTemplates) != 1 || res.MissingTemplates[0] != sha {
		t.Fatalf("missing templates %+v %v", res.MissingTemplates, err)
	}
	var tf []TemplateFile
	for _, x := range files {
		tf = append(tf, TemplateFile{Name: x.Name, DataBase64: base64.StdEncoding.EncodeToString(x.Data)})
	}
	if _, err := f.e.StoreTemplate(context.Background(), TemplateParams{SHA256: strings.Repeat("0", 64), Files: tf}); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, err := f.e.StoreTemplate(context.Background(), TemplateParams{SHA256: sha, Files: tf}); err != nil {
		t.Fatal(err)
	}
	resp, body := f.do(t, "GET", "/", "", nil, nil)
	if !strings.Contains(body, `<h1>&lt;Guest &amp; &#34;Co&#34;&gt;</h1>`) && !strings.Contains(body, `<h1>&lt;Guest &amp; &quot;Co&quot;&gt;</h1>`) {
		t.Fatalf("name not escaped: %s", body)
	}
	if !strings.Contains(body, `<p id="mac">`+macG1) || !strings.Contains(body, `"state":"unauthenticated"`) {
		t.Fatalf("%s", body)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "'unsafe-inline'") || !strings.Contains(csp, "connect-src 'self' http://192.168.20.5:8080;") || strings.Contains(csp, "bad") {
		t.Fatalf("csp %q", csp)
	}
	resp, _ = f.do(t, "GET", "/assets/"+sha+"/logo.svg", "", nil, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("svg %d %q", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}
	// No status.html in the set: the builtin one is used once online.
	dur := int64(600)
	_, _ = f.e.Vouchers(context.Background(), f.c.vouchers(offlineVoucher(t, 17, vecCode, nil, &dur, 1)))
	f.e.Redeem(context.Background(), Client{PortalID: 3, MAC: macG1, IP: "127.0.0.1"}, vecCode, false)
	_, body = f.do(t, "GET", "/", "", nil, nil)
	if !strings.Contains(body, "You are online") {
		t.Fatalf("%s", body)
	}
}

func TestFASRelay(t *testing.T) {
	f := newFAS(t, func(pc *PortalConfig) { pc.Relay = true })
	res, body := f.do(t, "POST", "/portal/v1/authorizations", "", strings.NewReader(`{"mac":"02:00:00:00:20:12","minutes":30}`), nil)
	if res.StatusCode != 401 || !strings.Contains(body, "invalid_api_token") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	res, _ = f.do(t, "POST", "/portal/v1/authorizations", "", strings.NewReader(`{}`), map[string]string{"Authorization": "Bearer perch_pa_x"})
	if res.StatusCode != 503 {
		t.Fatalf("offline relay %d", res.StatusCode)
	}
	var got RelayParams
	f.e.SetAgent(&fakeAgent{handler: func(method string, params any, result any) error {
		got = params.(RelayParams)
		r := result.(*RelayResult)
		r.Status, r.Body = 201, json.RawMessage(`{"data":{"delivery":"applied"}}`)
		return nil
	}})
	res, body = f.do(t, "POST", "/portal/v1/authorizations", "", strings.NewReader(`{"mac":"02:00:00:00:20:12","minutes":30}`), map[string]string{"Authorization": "Bearer perch_pa_x"})
	if res.StatusCode != 201 || !strings.Contains(body, "applied") || got.Op != "authorize" || got.Token != "perch_pa_x" || got.PortalID != 3 {
		t.Fatalf("%d %s %+v", res.StatusCode, body, got)
	}
	res, _ = f.do(t, "DELETE", "/portal/v1/authorizations/02-00-00-00-20-12", "", nil, map[string]string{"Authorization": "Bearer perch_pa_x"})
	if res.StatusCode != 201 || got.Op != "deauthorize" || got.MAC != macG2 {
		t.Fatalf("%d %+v", res.StatusCode, got)
	}
}

// fakeListener records what the pages would listen on.
type fakeListener struct {
	net.Listener
	addr   string
	closed bool
}

func (l *fakeListener) Close() error { l.closed = true; return nil }
func (l *fakeListener) Accept() (net.Conn, error) {
	for !l.closed {
		time.Sleep(10 * time.Millisecond)
	}
	return nil, net.ErrClosed
}
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestGuestPagesListenOnlyOnPortalAddresses(t *testing.T) {
	sys := newFakeSystem()
	sys.devices["guest"] = []netip.Prefix{netip.MustParsePrefix("192.168.20.1/24"), netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("2001:db8:20::1/64")}
	e, _ := newTestEngine(t, sys, filepath.Join(t.TempDir(), "s.db"))
	f := NewFAS(e, 2080, quietLog)
	var mu sync.Mutex
	open := map[string]*fakeListener{}
	f.listen = func(network, address string) (net.Listener, error) {
		mu.Lock()
		defer mu.Unlock()
		if address == "[2001:db8:20::1]:2080" && open["fail"] == nil {
			open["fail"] = &fakeListener{}
			return nil, errors.New("bind: cannot assign requested address")
		}
		l := &fakeListener{addr: address}
		open[address] = l
		return l, nil
	}
	e.SetListener(f.Sync)
	t.Cleanup(func() { f.Shutdown(context.Background()) })
	// No portal: nothing listens.
	e.Start(context.Background())
	if got := f.Listening(); len(got) != 0 {
		t.Fatalf("listening without a portal: %v", got)
	}
	c := newController(t)
	if _, err := e.Configure(context.Background(), c.configure(guestPortal(3))); err != nil {
		t.Fatal(err)
	}
	// The portal's addresses only (no link-local); the failed bind is
	// retried on the next tick.
	if got := fmt.Sprint(f.Listening()); got != "[192.168.20.1]" {
		t.Fatalf("listening on %s", got)
	}
	e.Tick(context.Background())
	if got := fmt.Sprint(f.Listening()); got != "[192.168.20.1 2001:db8:20::1]" {
		t.Fatalf("after the retry: %s", got)
	}
	// The last portal goes: every listener closes.
	if _, err := e.Configure(context.Background(), c.configure()); err != nil {
		t.Fatal(err)
	}
	if got := f.Listening(); len(got) != 0 {
		t.Fatalf("still listening: %v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for a, l := range open {
		if a != "fail" && !l.closed {
			t.Fatalf("%s not closed", a)
		}
	}
}
