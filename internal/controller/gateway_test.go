package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/gatewayops"
	"github.com/capthndsme/perch-collector/internal/observe"
)

// fakeObservation serves fixed parts; set changes a part's fingerprint.
type fakeObservation struct {
	mu    sync.Mutex
	parts []observe.Part
	items map[observe.Part]observe.Item
	reads int
}

func (f *fakeObservation) Parts() []observe.Part { return f.parts }

func (f *fakeObservation) Read(p observe.Part, fresh bool) (observe.Item, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	it, ok := f.items[p]
	return it, ok
}

func (f *fakeObservation) set(p observe.Part, it observe.Item) {
	f.mu.Lock()
	f.items[p] = it
	f.mu.Unlock()
}

func newFakeObservation() *fakeObservation {
	neighbors := []observe.Neighbor{{IP: "192.168.1.21", MAC: "02:00:00:00:10:21", Device: "br-lan", Reachable: true, State: "reachable"}}
	return &fakeObservation{
		// mwan3 is announced but has nothing to report (not installed).
		parts: []observe.Part{observe.PartDHCP, observe.PartNeighbors, observe.PartMWAN3, observe.PartSystem},
		items: map[observe.Part]observe.Item{
			observe.PartDHCP:      {Value: &observe.DHCP{Leases4: []observe.Lease4{}, Leases6: []observe.Lease6{}, Hosts: []observe.StaticHost{}}, FP: "d1"},
			observe.PartNeighbors: {Value: neighbors, FP: "n1"},
			observe.PartSystem:    {Value: &observe.System{Hostname: "gateway", UptimeSeconds: 5}, FP: "s1"},
		},
	}
}

// The push carries every part in a session's first push (full), then only
// the parts that changed; the hello names every capability.
func TestPushCarriesObservationParts(t *testing.T) {
	obs := newFakeObservation()
	type seen struct {
		caps    string
		observe []map[string]json.RawMessage
	}
	result := make(chan seen, 1)
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		var s seen
		var hp map[string]json.RawMessage
		json.Unmarshal(hello.Params, &hp)
		s.caps = string(hp["capabilities"])
		answerHello(ctx, c, hello, "adopted")
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0.1,"lifecycle":"adopted"}}`)
		for i := 0; i < 4; i++ {
			m, _ := next(t, frames, pushFrame, 2*time.Second)
			var p map[string]json.RawMessage
			json.Unmarshal(m.Params, &p)
			var o map[string]json.RawMessage
			json.Unmarshal(p["observe"], &o)
			s.observe = append(s.observe, o)
			if i == 1 {
				obs.set(observe.PartSystem, observe.Item{Value: &observe.System{Hostname: "renamed"}, FP: "s2"})
			}
		}
		result <- s
		c.Close(4002, "done")
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	_, _, stop := newTestClient(t, srv, func(o *Options) {
		o.Source.Observe = obs
		o.Conntrack = &gatewayops.Flusher{Dial: func() (gatewayops.Table, error) { return nil, errors.New("none") }}
		o.Backup = &gatewayops.Backuper{}
	})
	defer stop()
	var s seen
	select {
	case s = <-result:
	case <-time.After(10 * time.Second):
		t.Fatal("no pushes")
	}
	want := `["gateway_stats","observe.dhcp","observe.neighbors","observe.mwan3","observe.system","gateway.observe","net.conntrack_flush","gateway.backup"]`
	if s.caps != want {
		t.Errorf("capabilities %s\nwant %s", s.caps, want)
	}
	first := s.observe[0]
	if string(first["full"]) != "true" || first["dhcp"] == nil || first["neighbors"] == nil || first["system"] == nil {
		t.Errorf("first push observe = %v", first)
	}
	if _, ok := first["mwan3"]; ok {
		t.Error("a part with nothing to report must be absent")
	}
	if s.observe[1] != nil {
		t.Errorf("unchanged parts resent: %v", s.observe[1])
	}
	changed := s.observe[2]
	if changed == nil {
		changed = s.observe[3]
	}
	if changed == nil || !strings.Contains(string(changed["system"]), "renamed") || changed["dhcp"] != nil || changed["full"] != nil {
		t.Errorf("changed part = %v", changed)
	}
}

// gateway.observe answers every part fresh; net.conntrack_flush refuses bad
// params with data.error; gateway.backup returns the archive.
func TestGatewayRequests(t *testing.T) {
	obs := newFakeObservation()
	archive := []byte("not really a tar.gz")
	type answers struct {
		observe, observeSome, flushBad, flushOK, backup, backupFull rpc.Message
	}
	result := make(chan answers, 1)
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		answerHello(ctx, c, hello, "adopted")
		var a answers
		ask := func(id int, method, params string) rpc.Message {
			send(ctx, c, `{"jsonrpc":"2.0","id":`+string(rune('0'+id))+`,"method":"`+method+`","params":`+params+`}`)
			m, _ := next(t, frames, responseFrame, 3*time.Second)
			return m
		}
		a.observe = ask(1, "gateway.observe", `{}`)
		a.observeSome = ask(2, "gateway.observe", `{"parts":["system","wireguard"]}`)
		a.flushBad = ask(3, "net.conntrack_flush", `{"ips":["203.0.113.10"]}`)
		a.flushOK = ask(4, "net.conntrack_flush", `{"ips":["192.168.1.21"],"dryRun":true}`)
		a.backup = ask(5, "gateway.backup", `{}`)
		a.backupFull = ask(6, "gateway.backup", `{"redact":false}`)
		result <- a
		c.Close(4002, "done")
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	_, _, stop := newTestClient(t, srv, func(o *Options) {
		o.Source.Observe = obs
		o.Conntrack = &gatewayops.Flusher{
			Dial:       func() (gatewayops.Table, error) { return nil, errors.New("no ctnetlink here") },
			LocalAddrs: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.10")} },
		}
		o.Backup = &gatewayops.Backuper{Policy: gatewayops.BackupRedacted, TempDir: t.TempDir(),
			Create: func(_ context.Context, path string) error { return os.WriteFile(path, archive, 0o600) }}
	})
	defer stop()
	var a answers
	select {
	case a = <-result:
	case <-time.After(10 * time.Second):
		t.Fatal("no answers")
	}
	var sec map[string]json.RawMessage
	if a.observe.Error != nil || json.Unmarshal(a.observe.Result, &sec) != nil || string(sec["full"]) != "true" ||
		sec["collectedAt"] == nil || sec["dhcp"] == nil || sec["neighbors"] == nil || sec["system"] == nil {
		t.Errorf("gateway.observe = %s %v", a.observe.Result, a.observe.Error)
	}
	sec = nil
	if json.Unmarshal(a.observeSome.Result, &sec) != nil || sec["system"] == nil || sec["dhcp"] != nil || sec["full"] != nil {
		t.Errorf("gateway.observe {parts} = %s", a.observeSome.Result)
	}
	if e := a.flushBad.Error; e == nil || e.Code != -32602 || !strings.Contains(string(mustJSON(e.Data)), "conntrack_router_address") {
		t.Errorf("flush of the router's address = %+v", a.flushBad.Error)
	}
	var fr gatewayops.FlushResult
	if a.flushOK.Error != nil || json.Unmarshal(a.flushOK.Result, &fr) != nil || fr.Flushed || !strings.Contains(fr.Reason, "no ctnetlink") {
		t.Errorf("flush without ctnetlink = %s %v", a.flushOK.Result, a.flushOK.Error)
	}
	// The archive is not a tar.gz, so the redaction pass fails cleanly.
	if e := a.backup.Error; e == nil || e.Code != -32000 || !strings.Contains(string(mustJSON(e.Data)), "backup_failed") {
		t.Errorf("backup = %s %+v", a.backup.Result, a.backup.Error)
	}
	if e := a.backupFull.Error; e == nil || !strings.Contains(string(mustJSON(e.Data)), "backup_redaction_required") {
		t.Errorf("full backup on a redacted router = %+v", a.backupFull.Error)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ── last good address ─────────────────────────────────────────────────────

func TestFallbackDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	file := filepath.Join(t.TempDir(), "sub", "controller-address")

	resolves := true
	d := newFallbackDialer(file)
	d.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "perch.example.com" {
			t.Errorf("looked up %q", host)
		}
		if !resolves {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	ctx := context.Background()

	// Nothing remembered and no DNS: the lookup error.
	resolves = false
	if _, err := d.DialContext(ctx, "tcp", "perch.example.com:"+port); err == nil {
		t.Fatal("dialed without an address")
	}
	// Resolves: dials, but only a confirmed session makes it the last good one.
	resolves = true
	conn, err := d.DialContext(ctx, "tcp", "perch.example.com:"+port)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if d.lastGoodAddr().IsValid() {
		t.Error("remembered before the hello was accepted")
	}
	local, remote := d.endpoints()
	if remote.String() != "127.0.0.1:"+port || !local.IsValid() {
		t.Errorf("endpoints = %s %s", local, remote)
	}
	d.confirm()
	if b, err := os.ReadFile(file); err != nil || strings.TrimSpace(string(b)) != "127.0.0.1" {
		t.Fatalf("address file = %q %v", b, err)
	}
	// DNS breaks: the last good address is dialed.
	resolves = false
	conn, err = d.DialContext(ctx, "tcp", "perch.example.com:"+port)
	if err != nil {
		t.Fatalf("fallback dial: %v", err)
	}
	conn.Close()
	// A new process finds it on disk.
	d2 := newFallbackDialer(file)
	d2.lookup = d.lookup
	if conn, err := d2.DialContext(ctx, "tcp", "perch.example.com:"+port); err != nil {
		t.Fatalf("fallback after restart: %v", err)
	} else {
		conn.Close()
	}
	// A literal address is dialed as is, no lookup.
	if conn, err := d2.DialContext(ctx, "tcp", "127.0.0.1:"+port); err != nil {
		t.Fatal(err)
	} else {
		conn.Close()
	}
}

// The dialer is installed on the default client and keeps the URL's name:
// a session through it reaches the controller, and the accepted hello
// records the address.
func TestClientRemembersControllerAddress(t *testing.T) {
	fc := &fakeController{t: t}
	accepted := make(chan struct{}, 1)
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		answerHello(ctx, c, hello, "adopted")
		select {
		case accepted <- struct{}{}:
		default:
		}
		<-ctx.Done()
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "controller-address")
	u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	c, _, stop := newTestClient(t, srv, func(o *Options) {
		o.ServerURL = u
		o.AddressCache = file
	})
	defer stop()
	if c.dialer == nil {
		t.Fatal("no dialer on the default client")
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("no session")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := os.ReadFile(file)
		if a := strings.TrimSpace(string(b)); a == "127.0.0.1" || a == "::1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("address not remembered: %q", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
