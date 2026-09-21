package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/gateway"
)

func newTestServer() *Server {
	agg := aggregator.New(nil, nil, 50, 50)
	return New("127.0.0.1:0", agg, "", "br-lan", "1.2.3")
}

func get(t *testing.T, s *Server, path string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s: decoding %s: %v", path, rec.Body.String(), err)
	}
	return body
}

// meta.announce_status only exists once the daemon is actually announcing.
func TestMetaAnnounceStatus(t *testing.T) {
	s := newTestServer()

	m, _ := get(t, s, "/api/v1/summary")["meta"].(map[string]any)
	if m == nil {
		t.Fatal("no meta block")
	}
	if _, ok := m["announce_status"]; ok {
		t.Errorf("announce_status = %v with no announcer, want the field omitted", m["announce_status"])
	}
	if m["version"] != "1.2.3" || m["capture_interface"] != "br-lan" {
		t.Errorf("meta = %v, want the existing fields untouched", m)
	}

	s.SetAnnounceStatus(func() string { return "pending" })
	for _, path := range []string{"/api/v1/summary", "/api/v1/devices", "/api/v1/protocols"} {
		m, _ := get(t, s, path)["meta"].(map[string]any)
		if m == nil {
			t.Fatalf("GET %s: no meta block", path)
		}
		if m["announce_status"] != "pending" {
			t.Errorf("GET %s: announce_status = %v, want pending", path, m["announce_status"])
		}
	}
}

// The Bearer gate in front of everything the meta block rides on.
func TestAuthGate(t *testing.T) {
	const key = "7f3c9d21ab64e8f0"
	agg := aggregator.New(nil, nil, 50, 50)
	s := New("127.0.0.1:0", agg, key, "br-lan", "1.2.3")
	s.SetAnnounceStatus(func() string { return "adopted" })

	do := func(header string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		s.mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no Authorization header = %d, want 401", rec.Code)
	}
	if rec := do("Bearer wrong-key"); rec.Code != http.StatusForbidden {
		t.Errorf("wrong key = %d, want 403", rec.Code)
	}

	rec := do("Bearer " + key)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct key = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	m, _ := body["meta"].(map[string]any)
	if m == nil || m["announce_status"] != "adopted" {
		t.Errorf("meta = %v, want announce_status once past the gate", m)
	}

	// /healthz stays open, as the poller's liveness check.
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz with a key configured = %d, want 200", rec.Code)
	}
}

// /healthz is unauthenticated: it must not name the server this collector
// talks to, nor how that conversation is going.
func TestHealthzHasNoAnnounceStatus(t *testing.T) {
	s := newTestServer()
	s.SetAnnounceStatus(func() string { return "error: dial tcp 10.0.0.5:8080: connection refused" })

	body := get(t, s, "/healthz")
	if _, ok := body["announce_status"]; ok {
		t.Errorf("/healthz exposes announce_status: %v", body)
	}
	if _, ok := body["meta"]; ok {
		t.Errorf("/healthz grew a meta block: %v", body)
	}
	if body["status"] != "ok" || body["version"] != "1.2.3" {
		t.Errorf("/healthz = %v, want the existing shape", body)
	}
}

// GET /api/v1/summary carries the gateway stats only when they are on, and
// meta.transport always says how the collector reaches its controller.
func TestSummaryGatewayAndTransport(t *testing.T) {
	s := newTestServer()
	body := get(t, s, "/api/v1/summary")
	if _, ok := body["gateway"]; ok {
		t.Errorf("gateway = %v with gateway stats off, want the field omitted", body["gateway"])
	}
	if m, _ := body["meta"].(map[string]any); m["transport"] != "poll" {
		t.Errorf("meta.transport = %v, want the poll default", m["transport"])
	}

	s.SetTransport("websocket")
	s.SetGatewayStats(func() *gateway.Stats {
		return &gateway.Stats{WAN: []gateway.Interface{{Name: "wan", RxBytes: 1, TxBytes: 2}}, WANSource: gateway.SourceDefaultRoute}
	})
	body = get(t, s, "/api/v1/summary")
	g, _ := body["gateway"].(map[string]any)
	if g == nil || g["wanSource"] != "default-route" {
		t.Fatalf("gateway = %v", body["gateway"])
	}
	if wan, _ := g["wan"].([]any); len(wan) != 1 {
		t.Errorf("gateway.wan = %v", g["wan"])
	}
	if m, _ := body["meta"].(map[string]any); m["transport"] != "websocket" {
		t.Errorf("meta.transport = %v", m["transport"])
	}
	if _, ok := body["summary"].(map[string]any); !ok {
		t.Errorf("summary missing: %v", body)
	}
}
