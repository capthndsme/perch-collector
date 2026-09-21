package announce

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	// Stand-in for a collector's own bearer token. Its fingerprint is
	// checked against an independently computed SHA-256 in TestFingerprint.
	testKey = "7f3c9d21ab64e8f0"
	// The 32-hex-character identity shape ResolveInstanceID produces.
	testInstanceID = "9d4c1a0f6b2e47c8a15d3e9f7b0c2a68"
)

// capture records what the stub server received.
type capture struct {
	mu      sync.Mutex
	calls   int
	method  string
	path    string
	header  http.Header
	body    map[string]any
	rawBody []byte
}

func (c *capture) record(r *http.Request, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.method = r.Method
	c.path = r.URL.Path
	c.header = r.Header.Clone()
	c.rawBody = append([]byte(nil), body...)
	c.body = map[string]any{}
	_ = json.Unmarshal(body, &c.body)
}

func (c *capture) snapshot() capture {
	c.mu.Lock()
	defer c.mu.Unlock()
	return capture{calls: c.calls, method: c.method, path: c.path, header: c.header, body: c.body, rawBody: c.rawBody}
}

// stubServer answers every announce with the given lifecycle and cadence.
func stubServer(t *testing.T, rec *capture, status string, intervalSeconds int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readAll(r)
		if rec != nil {
			rec.record(r, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"status":                  status,
				"collectorId":             4,
				"announceIntervalSeconds": intervalSeconds,
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func readAll(r *http.Request) []byte {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r.Body)
	return buf.Bytes()
}

// newTestAnnouncer keeps the production schedule (so backoff and clamping
// assertions are real) but removes the jitter so waits are exact.
func newTestAnnouncer(t *testing.T, srv *httptest.Server, mutate func(*Options)) *Announcer {
	t.Helper()
	opts := Options{
		ServerURL:        srv.URL,
		InstanceID:       testInstanceID,
		APIKey:           testKey,
		SendAPIKey:       true,
		Port:             9800,
		TLS:              false,
		BaseURL:          "http://192.168.1.1:9800",
		Hostname:         "OpenWrt",
		Version:          "1.2.3",
		CaptureInterface: "br-lan",
		Interval:         60 * time.Second,
		Client:           srv.Client(),
	}
	if mutate != nil {
		mutate(&opts)
	}
	a := New(opts)
	a.jitterFraction = 0
	t.Cleanup(a.Stop)
	return a
}

func TestAnnouncePayloadAndHeaders(t *testing.T) {
	rec := &capture{}
	srv := stubServer(t, rec, "pending", 60)
	a := newTestAnnouncer(t, srv, nil)

	if got := a.beat(); got != 60*time.Second {
		t.Fatalf("next beat = %s, want 60s", got)
	}
	got := rec.snapshot()

	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.path != announcePath {
		t.Errorf("path = %s, want %s", got.path, announcePath)
	}
	if h := got.header.Get("Authorization"); h != "Bearer "+testKey {
		t.Errorf("Authorization = %q, want the bearer key", h)
	}
	if h := got.header.Get("User-Agent"); h != "perch-collector/1.2.3" {
		t.Errorf("User-Agent = %q, want perch-collector/1.2.3", h)
	}
	if h := got.header.Get("Content-Type"); h != "application/json" {
		t.Errorf("Content-Type = %q", h)
	}

	want := map[string]any{
		"instanceId":        testInstanceID,
		"hostname":          "OpenWrt",
		"version":           "1.2.3",
		"captureInterface":  "br-lan",
		"port":              float64(9800),
		"tls":               false,
		"baseUrl":           "http://192.168.1.1:9800",
		"apiKey":            testKey,
		"apiKeyFingerprint": Fingerprint(testKey),
	}
	for k, v := range want {
		if got.body[k] != v {
			t.Errorf("body[%q] = %#v, want %#v", k, got.body[k], v)
		}
	}
	if len(got.body) != len(want) {
		t.Errorf("body has %d fields (%v), want exactly %d", len(got.body), keysOf(got.body), len(want))
	}

	if s := a.Status(); s.State != StatePending || s.LastAnnounce.IsZero() {
		t.Errorf("status = %+v, want pending with a timestamp", s)
	}
	if s := a.StatusString(); s != "pending" {
		t.Errorf("StatusString = %q, want pending", s)
	}
}

// The fingerprint is the first 8 hex characters of the key's SHA-256 — the
// value the dashboard shows next to a pending collector.
func TestFingerprint(t *testing.T) {
	// echo -n "abc" | sha256sum → ba7816bf8f01cfea…
	if got := Fingerprint("abc"); got != "ba7816bf" {
		t.Errorf("Fingerprint(\"abc\") = %q, want ba7816bf", got)
	}
	if got := Fingerprint(""); got != "" {
		t.Errorf("Fingerprint(\"\") = %q, want empty", got)
	}
}

// announce_api_key false: the key is still proven with the header, but it
// never appears in the body.
func TestAnnounceWithoutKeyInBody(t *testing.T) {
	rec := &capture{}
	srv := stubServer(t, rec, "adopted", 900)
	a := newTestAnnouncer(t, srv, func(o *Options) { o.SendAPIKey = false })

	a.beat()
	got := rec.snapshot()

	if _, ok := got.body["apiKey"]; ok {
		t.Error("body carries apiKey although SendAPIKey is false")
	}
	if strings.Contains(string(got.rawBody), testKey) {
		t.Errorf("the raw body contains the key: %s", got.rawBody)
	}
	if got.body["apiKeyFingerprint"] != Fingerprint(testKey) {
		t.Errorf("fingerprint = %v, want it sent even without the key", got.body["apiKeyFingerprint"])
	}
	if h := got.header.Get("Authorization"); h != "Bearer "+testKey {
		t.Errorf("Authorization = %q, want the bearer key regardless", h)
	}
}

// A collector with no API key at all announces with no credentials and no
// fingerprint.
func TestAnnounceWithoutAnyKey(t *testing.T) {
	rec := &capture{}
	srv := stubServer(t, rec, "pending", 60)
	a := newTestAnnouncer(t, srv, func(o *Options) { o.APIKey = ""; o.SendAPIKey = true })

	a.beat()
	got := rec.snapshot()

	if _, ok := got.body["apiKey"]; ok {
		t.Error("body carries apiKey although there is no key")
	}
	if _, ok := got.body["apiKeyFingerprint"]; ok {
		t.Error("body carries a fingerprint although there is no key")
	}
	if h := got.header.Get("Authorization"); h != "" {
		t.Errorf("Authorization = %q, want none", h)
	}
}

// The daemon listens on a wildcard: it reports the port only and lets the
// server derive the address from the TCP source.
func TestAnnounceOmitsUnknownBaseURL(t *testing.T) {
	rec := &capture{}
	srv := stubServer(t, rec, "pending", 60)
	a := newTestAnnouncer(t, srv, func(o *Options) { o.BaseURL = "" })

	a.beat()
	got := rec.snapshot()

	if _, ok := got.body["baseUrl"]; ok {
		t.Errorf("body carries baseUrl %v, want it omitted", got.body["baseUrl"])
	}
	if got.body["port"] != float64(9800) {
		t.Errorf("port = %v, want it sent anyway", got.body["port"])
	}
}

// A trailing slash on server_url must not produce a doubled path.
func TestAnnounceEndpointJoin(t *testing.T) {
	rec := &capture{}
	srv := stubServer(t, rec, "pending", 60)
	a := newTestAnnouncer(t, srv, func(o *Options) { o.ServerURL = srv.URL + "/" })

	a.beat()
	if got := rec.snapshot(); got.path != announcePath {
		t.Errorf("path = %q, want %q", got.path, announcePath)
	}
}

func TestAnnounceFollowsServerInterval(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		want    time.Duration
	}{
		{"server cadence is used verbatim", 900, 900 * time.Second},
		{"adopted cadence", 60, 60 * time.Second},
		{"dismissed cadence", 21600, 6 * time.Hour},
		{"below the floor is clamped up", 1, defaultMinInterval},
		{"above the ceiling is clamped down", 999999, defaultMaxInterval},
		{"absent keeps the configured cadence", 0, 60 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := stubServer(t, nil, "pending", tt.seconds)
			a := newTestAnnouncer(t, srv, nil)
			if got := a.beat(); got != tt.want {
				t.Errorf("next beat = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestAnnounceBackoffGrowsOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	a := newTestAnnouncer(t, srv, nil)

	want := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 300 * time.Second, 900 * time.Second, 900 * time.Second}
	for i, w := range want {
		if got := a.beat(); got != w {
			t.Fatalf("failure %d: next beat = %s, want %s", i+1, got, w)
		}
	}
	if s := a.Status(); s.State != StateError || s.LastError == "" {
		t.Errorf("status = %+v, want an error state with a reason", s)
	}
	if !strings.HasPrefix(a.StatusString(), "error: ") {
		t.Errorf("StatusString = %q, want an \"error: …\" string", a.StatusString())
	}

	// A success clears the failure count and the error.
	ok := stubServer(t, nil, "adopted", 300)
	a.opts.ServerURL = ok.URL
	a.endpoint = ok.URL + announcePath
	if got := a.beat(); got != 300*time.Second {
		t.Fatalf("after recovery: next beat = %s, want 300s", got)
	}
	if s := a.Status(); s.State != StateAdopted || s.LastError != "" {
		t.Errorf("status = %+v, want adopted with no error", s)
	}
}

// A transport failure (nothing listening) backs off exactly like a 5xx.
func TestAnnounceBackoffOnTransportError(t *testing.T) {
	srv := stubServer(t, nil, "pending", 60)
	a := newTestAnnouncer(t, srv, nil)
	srv.Close()

	if got := a.beat(); got != 30*time.Second {
		t.Fatalf("next beat = %s, want the first backoff step", got)
	}
	if got := a.beat(); got != 60*time.Second {
		t.Fatalf("next beat = %s, want the second backoff step", got)
	}
}

func TestAnnounceHonoursRetryAfter(t *testing.T) {
	var retryAfter atomic.Value
	retryAfter.Store("45")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := retryAfter.Load().(string); v != "" {
			w.Header().Set("Retry-After", v)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"announce_rate_limited","retryAfterSeconds":60}`))
	}))
	defer srv.Close()
	a := newTestAnnouncer(t, srv, nil)

	if got := a.beat(); got != 45*time.Second {
		t.Errorf("next beat = %s, want the 45 s Retry-After", got)
	}

	// An HTTP-date Retry-After works too.
	retryAfter.Store(time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat))
	got := a.beat()
	if got < 80*time.Second || got > 95*time.Second {
		t.Errorf("next beat = %s, want roughly 90 s from the Retry-After date", got)
	}

	// Without the header, a 429 falls back to the normal backoff.
	retryAfter.Store("")
	if got := a.beat(); got != 30*time.Second {
		t.Errorf("next beat = %s, want the first backoff step", got)
	}
}

// A 429 whose Retry-After is absurd is still bounded by the schedule.
func TestAnnounceRetryAfterIsClamped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2592000") // 30 days
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	a := newTestAnnouncer(t, srv, nil)

	if got := a.beat(); got != defaultMaxInterval {
		t.Errorf("next beat = %s, want the 6 h ceiling", got)
	}
}

// 401: retrying cannot help, so the daemon drops to the slowest beat and
// says so once.
func TestAnnounceKeyMismatchDropsToSlowBeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"announce_key_mismatch"}`))
	}))
	defer srv.Close()
	a := newTestAnnouncer(t, srv, nil)

	if got := a.beat(); got != defaultMaxInterval {
		t.Errorf("next beat = %s, want the 6 h beat", got)
	}
	if got := a.beat(); got != defaultMaxInterval {
		t.Errorf("second beat = %s, want the 6 h beat (no escalation)", got)
	}
	s := a.Status()
	if s.State != StateError || !strings.Contains(s.LastError, "different API key") {
		t.Errorf("status = %+v, want an explanatory error state", s)
	}
	if strings.Contains(s.LastError, testKey) {
		t.Error("the error message leaks the API key")
	}
}

// The loop itself: first announce lands quickly, then the cadence the server
// asked for, and Stop ends it.
func TestAnnounceLoop(t *testing.T) {
	var calls atomic.Int64
	seen := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case seen <- struct{}{}:
		default:
		}
		_, _ = w.Write([]byte(`{"data":{"status":"adopted","collectorId":4,"announceIntervalSeconds":60}}`))
	}))
	defer srv.Close()

	a := newTestAnnouncer(t, srv, nil)
	// Compress the whole schedule: the 60 s the stub asks for is clamped
	// down to maxInterval, exactly as a real reply is clamped up to 15 s.
	a.firstDelayMin, a.firstDelayMax = time.Millisecond, 2*time.Millisecond
	a.minInterval, a.maxInterval = time.Millisecond, 5*time.Millisecond

	done := make(chan struct{})
	go func() { a.Run(); close(done) }()

	deadline := time.After(3 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case <-seen:
		case <-deadline:
			t.Fatalf("only %d announces in 3 s, want at least 3", calls.Load())
		}
	}
	if s := a.Status(); s.State != StateAdopted {
		t.Errorf("status = %+v, want adopted", s)
	}

	start := time.Now()
	a.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Stop")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Stop took %s, want it to be prompt", elapsed)
	}

	after := calls.Load()
	time.Sleep(50 * time.Millisecond)
	if now := calls.Load(); now != after {
		t.Errorf("%d more announces after Stop", now-after)
	}
}

// Stop must not wait for an announce that is in flight against an
// unresponsive server.
func TestStopAbortsInFlightAnnounce(t *testing.T) {
	inFlight := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case inFlight <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)

	a := newTestAnnouncer(t, srv, nil)
	a.firstDelayMin, a.firstDelayMax = time.Millisecond, 2*time.Millisecond

	done := make(chan struct{})
	go func() { a.Run(); close(done) }()

	select {
	case <-inFlight:
	case <-time.After(3 * time.Second):
		t.Fatal("the stub server was never called")
	}

	start := time.Now()
	a.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return while an announce was in flight")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Stop took %s, want it to abort the request", elapsed)
	}
}

// Stop before Run, and Stop twice, are both safe.
func TestStopIsIdempotent(t *testing.T) {
	srv := stubServer(t, nil, "pending", 60)
	a := newTestAnnouncer(t, srv, nil)

	a.Stop()
	a.Stop()

	done := make(chan struct{})
	go func() { a.Run(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return immediately when already stopped")
	}
}

// One line per state change — never per beat, and never the key.
func TestLoggingIsPerStateChange(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	var status atomic.Value
	status.Store("pending")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"status":"` + status.Load().(string) + `","collectorId":4,"announceIntervalSeconds":60}}`))
	}))
	defer srv.Close()
	a := newTestAnnouncer(t, srv, nil)

	for i := 0; i < 5; i++ {
		a.beat()
	}
	if n := strings.Count(buf.String(), "announce:"); n != 1 {
		t.Errorf("%d log lines for 5 identical beats, want 1:\n%s", n, buf.String())
	}

	status.Store("adopted")
	a.beat()
	a.beat()
	if n := strings.Count(buf.String(), "announce:"); n != 2 {
		t.Errorf("%d log lines after the state changed, want 2:\n%s", n, buf.String())
	}
	if strings.Contains(buf.String(), testKey) {
		t.Errorf("the log leaks the API key:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), Fingerprint(testKey)) {
		t.Errorf("the log leaks the key fingerprint:\n%s", buf.String())
	}
}

func TestSelfAddress(t *testing.T) {
	tests := []struct {
		name     string
		listen   string
		tls      bool
		wantPort int
		wantURL  string
		wantErr  bool
	}{
		{name: "loopback", listen: "127.0.0.1:9800", wantPort: 9800, wantURL: "http://127.0.0.1:9800"},
		{name: "lan address", listen: "192.168.1.1:9800", wantPort: 9800, wantURL: "http://192.168.1.1:9800"},
		{name: "tls", listen: "192.168.1.1:9800", tls: true, wantPort: 9800, wantURL: "https://192.168.1.1:9800"},
		{name: "ipv4 wildcard reports only the port", listen: "0.0.0.0:9800", wantPort: 9800, wantURL: ""},
		{name: "ipv6 wildcard reports only the port", listen: "[::]:9800", wantPort: 9800, wantURL: ""},
		{name: "empty host reports only the port", listen: ":9800", wantPort: 9800, wantURL: ""},
		{name: "ipv6 literal is bracketed", listen: "[fd00::1]:9800", wantPort: 9800, wantURL: "http://[fd00::1]:9800"},
		{name: "zoned ipv6 literal is bracketed too", listen: "[fe80::1%eth0]:9800", wantPort: 9800, wantURL: "http://[fe80::1%eth0]:9800"},
		{name: "hostname", listen: "router.lan:9800", wantPort: 9800, wantURL: "http://router.lan:9800"},
		{name: "no port", listen: "192.168.1.1", wantErr: true},
		{name: "empty", listen: "", wantErr: true},
		{name: "port out of range", listen: "127.0.0.1:99999", wantErr: true},
		{name: "named port", listen: "127.0.0.1:http", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, url, err := SelfAddress(tt.listen, tt.tls)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SelfAddress(%q) = (%d, %q, nil), want an error", tt.listen, port, url)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelfAddress(%q): %v", tt.listen, err)
			}
			if port != tt.wantPort || url != tt.wantURL {
				t.Errorf("SelfAddress(%q) = (%d, %q), want (%d, %q)", tt.listen, port, url, tt.wantPort, tt.wantURL)
			}
		})
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		name string
		in   Status
		want string
	}{
		{"fresh", Status{}, "starting"},
		{"pending", Status{State: StatePending}, "pending"},
		{"adopted", Status{State: StateAdopted}, "adopted"},
		{"dismissed", Status{State: StateDismissed}, "dismissed"},
		{"error with a reason", Status{State: StateError, LastError: "connection refused"}, "error: connection refused"},
		{"error without one", Status{State: StateError}, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStateOf(t *testing.T) {
	tests := map[string]State{
		"pending":   StatePending,
		"adopted":   StateAdopted,
		"dismissed": StateDismissed,
		" adopted ": StateAdopted,
		"":          StatePending,
		"nonsense":  StatePending,
	}
	for in, want := range tests {
		if got := stateOf(in); got != want {
			t.Errorf("stateOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("60"); got != time.Minute {
		t.Errorf("parseRetryAfter(60) = %s, want 1m", got)
	}
	if got := parseRetryAfter(" 15 "); got != 15*time.Second {
		t.Errorf("parseRetryAfter(padded) = %s, want 15s", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("parseRetryAfter(empty) = %s, want 0", got)
	}
	if got := parseRetryAfter("later"); got != 0 {
		t.Errorf("parseRetryAfter(garbage) = %s, want 0", got)
	}
	if got := parseRetryAfter("-5"); got != 0 {
		t.Errorf("parseRetryAfter(negative) = %s, want 0", got)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(past); got != 0 {
		t.Errorf("parseRetryAfter(past date) = %s, want 0", got)
	}
}

// M3: replies only an admin can clear get one loud line and the slow beat.
func TestAnnounceAdminActionRepliesDropToSlowBeat(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"announcing switched off", http.StatusForbidden, `{"error":"announce_disabled"}`, "switched off"},
		{"pending list full", http.StatusConflict, `{"error":"announce_pending_limit"}`, "pending-collector list is full"},
		{"some other 403", http.StatusForbidden, `{"error":"nope"}`, "refuses this announce"},
		{"some other 409", http.StatusConflict, `{"error":"nope"}`, "conflicting"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			a := newTestAnnouncer(t, srv, nil)

			if got := a.beat(); got != defaultMaxInterval {
				t.Errorf("next beat = %s, want the 6 h beat", got)
			}
			if got := a.beat(); got != defaultMaxInterval {
				t.Errorf("second beat = %s, want the 6 h beat (no escalation)", got)
			}
			if s := a.Status(); !strings.Contains(s.LastError, tt.want) {
				t.Errorf("LastError = %q, want it to mention %q", s.LastError, tt.want)
			}
		})
	}
}

// M2: a server-supplied error string is attacker-influenced text that lands
// in a log line and in meta.announce_status. It must be bounded and scrubbed.
func TestAnnounceBoundsTheServerErrorString(t *testing.T) {
	huge := strings.Repeat("A", 20<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "\n\n2026-01-01 forged log line\x00" + huge,
		})
	}))
	defer srv.Close()
	a := newTestAnnouncer(t, srv, nil)

	a.beat()
	status := a.StatusString()

	if len(status) > 400 {
		t.Errorf("announce_status is %d bytes, want the server's error bounded", len(status))
	}
	if strings.ContainsAny(status, "\n\r\x00") {
		t.Errorf("announce_status carries control characters: %q", status)
	}
	if !strings.Contains(status, "...") {
		t.Errorf("announce_status = %q, want the truncation to be visible", status)
	}
}

func TestSanitiseCode(t *testing.T) {
	if got := sanitiseCode("announce_disabled"); got != "announce_disabled" {
		t.Errorf("a normal code was altered: %q", got)
	}
	if got := sanitiseCode("a\nb\tc\x00d"); got != "abcd" {
		t.Errorf("sanitiseCode = %q, want the control characters gone", got)
	}
	long := sanitiseCode(strings.Repeat("é", 500))
	if n := len([]rune(long)); n != maxErrorCodeRunes+3 {
		t.Errorf("sanitiseCode kept %d runes, want %d plus the ellipsis", n, maxErrorCodeRunes)
	}
	if !utf8.ValidString(long) {
		t.Error("sanitiseCode cut a multi-byte rune in half")
	}
}

// L1: shutdown cancels the request in flight; that is not a state change.
func TestStopDoesNotRecordAFailure(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	inFlight := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case inFlight <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)

	a := newTestAnnouncer(t, srv, nil)
	a.firstDelayMin, a.firstDelayMax = time.Millisecond, 2*time.Millisecond

	done := make(chan struct{})
	go func() { a.Run(); close(done) }()

	select {
	case <-inFlight:
	case <-time.After(3 * time.Second):
		t.Fatal("the stub server was never called")
	}
	a.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Stop")
	}

	if s := a.Status(); s.State == StateError {
		t.Errorf("status = %+v, want no error state from our own shutdown", s)
	}
	if strings.Contains(buf.String(), "context canceled") || strings.Contains(buf.String(), "-> error") {
		t.Errorf("shutdown logged a failure:\n%s", buf.String())
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
