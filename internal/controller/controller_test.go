package controller

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/capthndsme/perch-agentkit/hoststat"
	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/classifier"
	"github.com/capthndsme/perch-collector/internal/gateway"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

var started = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

// fakeController serves the collector endpoint. With status set it refuses
// the upgrade; otherwise it reads the hello and hands the session over.
type fakeController struct {
	t          *testing.T
	status     int
	body       string
	retryAfter string
	session    func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message)

	mu      sync.Mutex
	headers []http.Header
}

func (f *fakeController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	f.headers = append(f.headers, r.Header.Clone())
	f.mu.Unlock()
	if f.status != 0 {
		if f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		io.WriteString(w, f.body)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{Subprotocol},
		CompressionMode: websocket.CompressionNoContextTakeover,
	})
	if err != nil {
		f.t.Errorf("accept: %v", err)
		return
	}
	defer c.CloseNow()
	ctx := r.Context()
	// One reader for the whole session: a Read whose context times out
	// would close the connection.
	frames := make(chan []byte, 64)
	go func() {
		defer close(frames)
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			frames <- data
		}
	}()
	var hello rpc.Message
	select {
	case data, ok := <-frames:
		if !ok {
			return
		}
		json.Unmarshal(data, &hello)
	case <-time.After(3 * time.Second):
		f.t.Error("no hello")
		return
	}
	if f.session != nil {
		f.session(ctx, c, frames, hello)
	}
}

func (f *fakeController) header(i int) http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.headers[i]
}

func send(ctx context.Context, c *websocket.Conn, frame string) {
	c.Write(ctx, websocket.MessageText, []byte(frame))
}

func answerHello(ctx context.Context, c *websocket.Conn, hello rpc.Message, lifecycle string) {
	send(ctx, c, `{"jsonrpc":"2.0","id":`+string(hello.ID)+`,"result":{"collectorId":1,"lifecycle":"`+lifecycle+`","name":"gateway"}}`)
}

func testSource() Source {
	return Source{
		Summary: func() aggregator.Summary {
			return aggregator.Summary{TotalDevices: 1, TotalBytes: 30, StartedAt: started, UptimeSecs: 1234.5}
		},
		Devices: func() []aggregator.DeviceStats {
			return []aggregator.DeviceStats{{MAC: "02:00:00:00:00:01", IPs: []string{"192.168.1.20"}, BytesIn: 10, BytesOut: 20}}
		},
		Gateway: func() *gateway.Stats {
			return &gateway.Stats{CollectedAt: started, WAN: []gateway.Interface{{Name: "wan", RxBytes: 5, TxBytes: 6}}, WANSource: gateway.SourceDefaultRoute}
		},
		Protocols: func() []classifier.ProtocolCategory {
			return []classifier.ProtocolCategory{{Protocol: "TLS", Category: "Web"}}
		},
	}
}

// newTestClient runs a client against srv until the first wait between
// sessions, which it returns.
func newTestClient(t *testing.T, srv *httptest.Server, edit func(*Options)) (*Client, <-chan time.Duration, func()) {
	t.Helper()
	waits := make(chan time.Duration, 4)
	o := Options{
		ServerURL:        srv.URL,
		InstanceID:       "e56204aa00000000000000000000beef",
		APIKey:           "0123456789abcdef0123456789abcdef",
		SendAPIKey:       true,
		Hostname:         "OpenWrt",
		Version:          "0.2.0",
		CaptureInterface: "br-lan",
		Listen:           "127.0.0.1:9800",
		System:           &System{OS: "OpenWrt 24.10.2", Arch: "amd64"},
		Source:           testSource(),
		Log:              quiet,
		Sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case waits <- d:
			default:
			}
			<-ctx.Done()
			return ctx.Err()
		},
		intervalOf: func(secs float64) time.Duration { return time.Duration(secs * float64(time.Second)) },
		minGap:     10 * time.Millisecond,
	}
	if edit != nil {
		edit(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	return c, waits, func() { cancel(); <-done }
}

type frameKind int

const (
	anyFrame frameKind = iota
	pushFrame
	responseFrame
)

// next returns the next frame of a kind, or fails after d.
func next(t *testing.T, frames <-chan []byte, kind frameKind, d time.Duration) (rpc.Message, []byte) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case data, ok := <-frames:
			if !ok {
				t.Fatal("session closed")
			}
			var m rpc.Message
			json.Unmarshal(data, &m)
			switch {
			case kind == pushFrame && m.Method != "collector.push":
				continue
			case kind == responseFrame && !m.IsResponse():
				continue
			}
			return m, data
		case <-deadline:
			t.Fatal("timed out waiting for a frame")
		}
	}
}

func quietFor(t *testing.T, frames <-chan []byte, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case data, ok := <-frames:
			if !ok {
				return
			}
			if strings.Contains(string(data), `"collector.push"`) {
				t.Fatalf("unexpected push: %.120s", data)
			}
		case <-deadline:
			return
		}
	}
}

type pushed struct {
	Seq         uint64           `json:"seq"`
	CollectedAt string           `json:"collectedAt"`
	Summary     map[string]any   `json:"summary"`
	Meta        map[string]any   `json:"meta"`
	Devices     []map[string]any `json:"devices"`
	Gateway     *gateway.Stats   `json:"gateway"`
}

func TestSession(t *testing.T) {
	result := make(chan error, 1)
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		defer close(result)
		if hello.Method != "collector.hello" || !hello.IsRequest() {
			t.Errorf("first frame %+v", hello)
		}
		var p map[string]any
		json.Unmarshal(hello.Params, &p)
		want := map[string]any{
			"instanceId": "e56204aa00000000000000000000beef", "hostname": "OpenWrt", "version": "0.2.0",
			"captureInterface": "br-lan", "apiKey": "0123456789abcdef0123456789abcdef", "apiKeyFingerprint": "3eb1bd43",
		}
		for k, v := range want {
			if p[k] != v {
				t.Errorf("hello %s = %v, want %v", k, p[k], v)
			}
		}
		for _, k := range []string{"port", "tls", "baseUrl"} {
			if _, ok := p[k]; ok {
				t.Errorf("hello has %s with a loopback-only API: %v", k, p[k])
			}
		}
		if caps, _ := json.Marshal(p["capabilities"]); string(caps) != `["gateway_stats"]` {
			t.Errorf("capabilities %s", caps)
		}
		if sys, _ := json.Marshal(p["system"]); string(sys) != `{"arch":"amd64","os":"OpenWrt 24.10.2"}` {
			t.Errorf("system %s", sys)
		}

		answerHello(ctx, c, hello, "pending")
		// Pending: configure pauses, and nothing is pushed.
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0,"lifecycle":"pending"}}`)
		quietFor(t, frames, 300*time.Millisecond)

		// Adopted: pushes every 200 ms, the first one right away.
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0.2,"lifecycle":"adopted"}}`)
		m1, raw := next(t, frames, pushFrame, 2*time.Second)
		t1 := time.Now()
		if m1.IsRequest() || m1.ID != nil {
			t.Errorf("push is not a notification: %s", raw)
		}
		if strings.Contains(string(raw), "\n") {
			t.Errorf("push is not compact JSON")
		}
		var p1 pushed
		json.Unmarshal(m1.Params, &p1)
		if p1.Seq != 1 || p1.CollectedAt == "" || p1.Summary["started_at"] != "2026-09-21T10:00:00Z" || p1.Summary["total_devices"] != float64(1) {
			t.Errorf("push 1 %+v", p1)
		}
		if p1.Meta["capture_interface"] != "br-lan" || p1.Meta["version"] != "0.2.0" {
			t.Errorf("meta %+v", p1.Meta)
		}
		if len(p1.Devices) != 1 || p1.Devices[0]["mac"] != "02:00:00:00:00:01" || p1.Devices[0]["bytes_out"] != float64(20) {
			t.Errorf("devices %+v", p1.Devices)
		}
		if p1.Gateway == nil || p1.Gateway.WANSource != "default-route" || p1.Gateway.WAN[0].Name != "wan" {
			t.Errorf("gateway %+v", p1.Gateway)
		}
		m2, _ := next(t, frames, pushFrame, 2*time.Second)
		var p2 pushed
		json.Unmarshal(m2.Params, &p2)
		if gap := time.Since(t1); p2.Seq != 2 || gap < 120*time.Millisecond || gap > time.Second {
			t.Errorf("push 2 seq %d after %v", p2.Seq, gap)
		}

		// The controller's requests.
		send(ctx, c, `{"jsonrpc":"2.0","id":41,"method":"collector.status"}`)
		st, _ := next(t, frames, responseFrame, 2*time.Second)
		if string(st.ID) != "41" || string(st.Result) != `{"startedAt":"2026-09-21T10:00:00Z","totalDevices":1,"captureInterface":"br-lan","version":"0.2.0","uptimeSeconds":1234}` {
			t.Errorf("status %s %s", st.ID, st.Result)
		}
		send(ctx, c, `{"jsonrpc":"2.0","id":42,"method":"collector.protocols"}`)
		pr, _ := next(t, frames, responseFrame, 2*time.Second)
		if string(pr.ID) != "42" || string(pr.Result) != `{"protocols":[{"protocol":"TLS","category":"Web"}]}` {
			t.Errorf("protocols %s %s", pr.ID, pr.Result)
		}
		send(ctx, c, `{"jsonrpc":"2.0","id":43,"method":"collector.reset"}`)
		if nf, _ := next(t, frames, responseFrame, 2*time.Second); nf.Error == nil || nf.Error.Code != rpc.CodeMethodNotFound {
			t.Errorf("unknown method %+v", nf)
		}

		// Pause, then resume.
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0,"lifecycle":"adopted"}}`)
		time.Sleep(50 * time.Millisecond)
		quietFor(t, frames, 400*time.Millisecond)
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0.2,"lifecycle":"adopted"}}`)
		m3, _ := next(t, frames, pushFrame, 2*time.Second)
		var p3 pushed
		json.Unmarshal(m3.Params, &p3)
		if p3.Seq < 3 {
			t.Errorf("resumed seq %d", p3.Seq)
		}
		c.Close(4002, "replaced by a newer session")
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	client, waits, stop := newTestClient(t, srv, nil)
	defer stop()
	<-result
	if got := <-waits; got != replacedRetry {
		t.Fatalf("wait after 4002 = %v", got)
	}
	if s := client.StatusString(); s != "error: "+msgReplaced {
		t.Fatalf("status %q", s)
	}
	h := fc.header(0)
	if h.Get("Authorization") != "Bearer 0123456789abcdef0123456789abcdef" || h.Get(InstanceHeader) != "e56204aa00000000000000000000beef" ||
		h.Get("User-Agent") != "perch-collector/0.2.0" || h.Get("Sec-WebSocket-Protocol") != Subprotocol ||
		!strings.Contains(h.Get("Sec-WebSocket-Extensions"), "permessage-deflate") {
		t.Fatalf("upgrade headers %v", h)
	}
}

func TestStatusFollowsTheLifecycle(t *testing.T) {
	adopted := make(chan struct{})
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		answerHello(ctx, c, hello, "pending")
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0,"lifecycle":"pending"}}`)
		time.Sleep(100 * time.Millisecond)
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":5,"lifecycle":"adopted"}}`)
		next(t, frames, pushFrame, 2*time.Second)
		close(adopted)
		<-ctx.Done()
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	client, _, stop := newTestClient(t, srv, nil)
	if s := client.StatusString(); s != "starting" && s != "pending" {
		t.Fatalf("status before the hello %q", s)
	}
	<-adopted
	if s := client.StatusString(); s != "adopted" {
		t.Fatalf("status %q", s)
	}
	stop()
}

func TestRetryTable(t *testing.T) {
	closeAfterHello := func(lifecycle string, code websocket.StatusCode) func(context.Context, *websocket.Conn, <-chan []byte, rpc.Message) {
		return func(ctx context.Context, c *websocket.Conn, _ <-chan []byte, hello rpc.Message) {
			answerHello(ctx, c, hello, lifecycle)
			time.Sleep(100 * time.Millisecond) // let the collector take the answer in
			c.Close(code, "bye")
		}
	}
	refuseHello := func(dataError string, code websocket.StatusCode) func(context.Context, *websocket.Conn, <-chan []byte, rpc.Message) {
		return func(ctx context.Context, c *websocket.Conn, _ <-chan []byte, hello rpc.Message) {
			send(ctx, c, `{"jsonrpc":"2.0","id":`+string(hello.ID)+`,"error":{"code":-32000,"message":"refused","data":{"error":"`+dataError+`"}}}`)
			c.Close(code, "refused")
		}
	}
	cases := []struct {
		name     string
		fc       *fakeController
		min, max time.Duration
		status   string
	}{
		{"401 key", &fakeController{status: 401, body: `{"error":"invalid_collector_key","message":"Unknown key."}`}, slowRetry, slowRetry, "error: " + msgKey},
		{"403 discovery off", &fakeController{status: 403, body: `{"error":"announce_disabled"}`}, slowRetry, slowRetry, "error: " + msgDiscovery},
		{"409 pending full", &fakeController{status: 409, body: `{"error":"announce_pending_limit"}`}, slowRetry, slowRetry, "error: " + msgPending},
		{"404 old controller", &fakeController{status: 404, body: `Cannot GET`}, slowRetry, slowRetry, "error: " + msgNoSocket},
		{"429 retry-after", &fakeController{status: 429, retryAfter: "7", body: `{"error":"rate_limited"}`}, 7 * time.Second, 7 * time.Second, "error: rate limited by the controller"},
		{"400 bad request", &fakeController{status: 400, body: `{"error":"unsupported_protocol","message":"This server speaks perch-collector.v1."}`}, slowRetry, slowRetry, ""},
		{"503 backoff", &fakeController{status: 503, body: `{"error":"shutting_down"}`}, 900 * time.Millisecond, 1100 * time.Millisecond, ""},
		{"close 4001", &fakeController{session: closeAfterHello("adopted", 4001)}, slowRetry, slowRetry, "error: " + msgKey},
		{"close 4002", &fakeController{session: closeAfterHello("adopted", 4002)}, replacedRetry, replacedRetry, "error: " + msgReplaced},
		{"close 4003", &fakeController{session: closeAfterHello("dismissed", 4003)}, dismissedRetry, dismissedRetry, "dismissed"},
		{"close 1001", &fakeController{session: closeAfterHello("adopted", websocket.StatusGoingAway)}, 2 * time.Second, 5 * time.Second, "adopted"},
		{"close 1000", &fakeController{session: closeAfterHello("adopted", websocket.StatusNormalClosure)}, 900 * time.Millisecond, 1100 * time.Millisecond, ""},
		{"hello refused pending limit", &fakeController{session: refuseHello("announce_pending_limit", websocket.StatusPolicyViolation)}, slowRetry, slowRetry, "error: " + msgPending},
		{"hello refused key", &fakeController{session: refuseHello("announce_key_mismatch", 4001)}, slowRetry, slowRetry, "error: " + msgKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := tc.fc
			fc.t = t
			srv := httptest.NewServer(fc)
			defer srv.Close()
			client, waits, stop := newTestClient(t, srv, nil)
			defer stop()
			select {
			case got := <-waits:
				if got < tc.min || got > tc.max {
					t.Fatalf("wait %v, want [%v, %v]", got, tc.min, tc.max)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("no retry decision")
			}
			if tc.status != "" {
				if s := client.StatusString(); s != tc.status {
					t.Fatalf("status %q, want %q", s, tc.status)
				}
			}
		})
	}
}

func TestHelloAddress(t *testing.T) {
	for _, tc := range []struct {
		listen string
		want   string
	}{
		{"127.0.0.1:9800", `{"instanceId":"i","apiKeyFingerprint":"2c26b46b","capabilities":[]}`},
		{"localhost:9800", `{"instanceId":"i","apiKeyFingerprint":"2c26b46b","capabilities":[]}`},
		{"[::1]:9800", `{"instanceId":"i","apiKeyFingerprint":"2c26b46b","capabilities":[]}`},
		{"192.168.1.1:9800", `{"instanceId":"i","apiKeyFingerprint":"2c26b46b","port":9800,"tls":false,"baseUrl":"http://192.168.1.1:9800","capabilities":[]}`},
		{"0.0.0.0:9800", `{"instanceId":"i","apiKeyFingerprint":"2c26b46b","port":9800,"tls":false,"capabilities":[]}`},
		{":9800", `{"instanceId":"i","apiKeyFingerprint":"2c26b46b","port":9800,"tls":false,"capabilities":[]}`},
	} {
		c, err := New(Options{ServerURL: "https://perch.example.com", InstanceID: "i", APIKey: "foo", Listen: tc.listen})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(c.hello())
		if string(b) != tc.want {
			t.Errorf("%s:\n got  %s\n want %s", tc.listen, b, tc.want)
		}
	}
}

func TestNewNeedsAKey(t *testing.T) {
	if _, err := New(Options{ServerURL: "https://perch.example.com", InstanceID: "i"}); err == nil {
		t.Fatal("no api_key accepted")
	}
	if _, err := New(Options{ServerURL: "ftp://perch.example.com", InstanceID: "i", APIKey: "k"}); err == nil {
		t.Fatal("ftp accepted")
	}
	c, _ := New(Options{ServerURL: "https://perch.example.com/", InstanceID: "i", APIKey: "k"})
	if c.url != "wss://perch.example.com/api/v1/collector-agent/ws" || c.StatusString() != "starting" {
		t.Fatalf("%s %s", c.url, c.StatusString())
	}
}

func TestSystemInfo(t *testing.T) {
	root := t.TempDir()
	write := func(p, body string) {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(body), 0o644)
	}
	write("etc/os-release", "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")
	if s := SystemInfo(hoststat.FS{Root: root}, "arm64"); s.OS != "Debian GNU/Linux 12 (bookworm)" || s.Arch != "arm64" {
		t.Fatalf("%+v", s)
	}
	write("etc/openwrt_release", "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.2'\nDISTRIB_REVISION='r28739-d9340319c6'\n")
	if s := SystemInfo(hoststat.FS{Root: root}, "amd64"); s.OS != "OpenWrt 24.10.2" {
		t.Fatalf("%+v", s)
	}
}

// firstPush runs a session whose gateway source is gw (nil = gateway stats
// off) and returns the params of its first collector.push, raw.
func firstPush(t *testing.T, gw func() *gateway.Stats) map[string]json.RawMessage {
	t.Helper()
	got := make(chan map[string]json.RawMessage, 1)
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		answerHello(ctx, c, hello, "adopted")
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":5,"lifecycle":"adopted"}}`)
		for data := range frames {
			var m rpc.Message
			if json.Unmarshal(data, &m) != nil || m.Method != "collector.push" {
				continue
			}
			var p map[string]json.RawMessage
			json.Unmarshal(m.Params, &p)
			got <- p
			break
		}
		for range frames { // until the collector hangs up
		}
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	_, _, stop := newTestClient(t, srv, func(o *Options) { o.Source.Gateway = gw })
	defer stop()
	select {
	case p := <-got:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no push")
	}
	return nil
}

// collector.push carries the Gateway agent's ports inside `gateway`: absent
// with ports off, [] when the router has none, the list otherwise; and with
// gateway stats off there is no gateway object at all.
func TestPushCarriesGatewayPorts(t *testing.T) {
	up := true
	speed := 10000
	some := []hoststat.Port{{Name: "wan0", Label: "wan0", Role: "wan", Medium: "virtual", MAC: "02:00:00:00:00:31", AdminUp: &up, Carrier: &up, Operstate: "up", SpeedMbps: &speed, Duplex: "full"}}
	report := func(ports *[]hoststat.Port) func() *gateway.Stats {
		return func() *gateway.Stats {
			return &gateway.Stats{CollectedAt: started, WAN: []gateway.Interface{{Name: "wan0", RxBytes: 5, TxBytes: 6}}, WANSource: gateway.SourceDefaultRoute, Ports: ports}
		}
	}
	for _, tc := range []struct {
		name  string
		gw    func() *gateway.Stats
		ports string // raw gateway.ports; "" = absent, "-" = no gateway object
	}{
		{"gateway stats off", nil, "-"},
		{"ports off", report(nil), ""},
		{"no ports", report(&[]hoststat.Port{}), `[]`},
		{"one port", report(&some), `[{"name":"wan0","label":"wan0","role":"wan","medium":"virtual","mac":"02:00:00:00:00:31","adminUp":true,"carrier":true,"operstate":"up","speedMbps":10000,"duplex":"full"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := firstPush(t, tc.gw)
			raw, ok := p["gateway"]
			if tc.ports == "-" {
				if ok {
					t.Fatalf("gateway = %s with gateway stats off", raw)
				}
				return
			}
			var g map[string]json.RawMessage
			if !ok || json.Unmarshal(raw, &g) != nil || string(g["wanSource"]) != `"default-route"` {
				t.Fatalf("gateway = %s", raw)
			}
			ports, ok := g["ports"]
			switch {
			case tc.ports == "" && ok:
				t.Fatalf("gateway.ports = %s with ports off, want the key absent", ports)
			case tc.ports != "" && string(ports) != tc.ports:
				t.Fatalf("gateway.ports = %s (present %v)\nwant %s", ports, ok, tc.ports)
			}
		})
	}
}
