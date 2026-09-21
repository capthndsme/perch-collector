// Package api exposes the read-only JSON HTTP surface for perch-collector.
// Responses are MAC-keyed (one entry per LAN device); see internal/aggregator
// for the data model.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/classifier"
	"github.com/capthndsme/perch-collector/internal/gateway"
)

// Server is the HTTP JSON API server.
type Server struct {
	agg     *aggregator.Aggregator
	apiKey  string
	iface   string
	version string
	mux     *http.ServeMux
	srv     *http.Server
	// protocolCategories is the classifier's default category per protocol
	// label, exported once at startup for GET /api/v1/protocols. Never nil
	// after New so the JSON shows [] rather than null.
	protocolCategories []classifier.ProtocolCategory
	// announceStatus reports how the daemon's registration with its Perch
	// controller is going (announce or socket), for the authenticated meta
	// block. nil when the daemon talks to no controller. Set once before
	// ListenAndServe.
	announceStatus func() string
	// transport is meta.transport: "websocket" when the daemon pushes over
	// its own socket, "poll" when it waits to be polled.
	transport string
	// gatewayStats fills the top-level `gateway` of GET /api/v1/summary; nil
	// when gateway stats are off. Set once before ListenAndServe.
	gatewayStats func() *gateway.Stats
}

// devicesResponse is the JSON shape for GET /api/v1/devices.
type devicesResponse struct {
	Devices []aggregator.DeviceStats `json:"devices"`
	Meta    meta                     `json:"meta"`
}

// deviceResponse is the JSON shape for GET /api/v1/devices/{mac}.
type deviceResponse struct {
	Device *aggregator.DeviceStats `json:"device"`
	Meta   meta                    `json:"meta"`
}

// summaryResponse is the JSON shape for GET /api/v1/summary. Gateway is the
// router's own health, present only with gateway stats on (the controller's
// poller records it like a pushed one).
type summaryResponse struct {
	Summary aggregator.Summary `json:"summary"`
	Gateway *gateway.Stats     `json:"gateway,omitempty"`
	Meta    meta               `json:"meta"`
}

// protocolsResponse is the JSON shape for GET /api/v1/protocols: every
// protocol label the classifier can emit with its default application
// category, so consumers can group protocol traffic by category without
// shipping their own table.
type protocolsResponse struct {
	Protocols []classifier.ProtocolCategory `json:"protocols"`
	Meta      meta                          `json:"meta"`
}

type meta struct {
	CaptureInterface string `json:"capture_interface"`
	QueryTime        string `json:"query_time"`
	Version          string `json:"version"`
	// Transport is "websocket" (the collector dials its controller and
	// pushes) or "poll" (it is polled on this API).
	Transport string `json:"transport"`
	// AnnounceStatus is "pending", "adopted", "dismissed", "starting" or
	// "error: …", for either transport. Omitted when the daemon talks to no
	// controller, and never served on the unauthenticated /healthz: it names
	// the server this collector talks to.
	AnnounceStatus string `json:"announce_status,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// New creates a new API server.
func New(listenAddr string, agg *aggregator.Aggregator, apiKey string, iface string, version string) *Server {
	s := &Server{
		agg:                agg,
		apiKey:             apiKey,
		iface:              iface,
		version:            version,
		mux:                http.NewServeMux(),
		protocolCategories: []classifier.ProtocolCategory{},
		transport:          "poll",
	}

	s.mux.HandleFunc("GET /api/v1/devices", s.withAuth(s.handleDevices))
	s.mux.HandleFunc("GET /api/v1/devices/", s.withAuth(s.handleDeviceByMAC))
	s.mux.HandleFunc("GET /api/v1/summary", s.withAuth(s.handleSummary))
	s.mux.HandleFunc("GET /api/v1/protocols", s.withAuth(s.handleProtocols))
	s.mux.HandleFunc("POST /api/v1/reset", s.withAuth(s.handleReset))
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	s.srv = &http.Server{
		Addr:         listenAddr,
		Handler:      s.securityHeaders(s.mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// securityHeaders wraps a handler to set security-related HTTP headers.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// withAuth wraps a handler with optional Bearer-token authentication.
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "missing Authorization header"})
				return
			}
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] != s.apiKey {
				writeJSON(w, http.StatusForbidden, errorResponse{Error: "invalid API key"})
				return
			}
		}
		next(w, r)
	}
}

// handleDevices returns all tracked devices, optionally filtered by activity.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		var err error
		since, err = time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error: "invalid 'since' parameter, expected RFC 3339 format",
			})
			return
		}
	}

	devices := s.agg.Snapshot(since)
	writeJSON(w, http.StatusOK, devicesResponse{
		Devices: devices,
		Meta:    s.makeMeta(),
	})
}

// handleDeviceByMAC returns stats for a single device by MAC.
func (s *Server) handleDeviceByMAC(w http.ResponseWriter, r *http.Request) {
	mac := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/devices/"))
	if mac == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "missing MAC address"})
		return
	}

	dev := s.agg.GetDevice(mac)
	if dev == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "device not found"})
		return
	}

	writeJSON(w, http.StatusOK, deviceResponse{
		Device: dev,
		Meta:   s.makeMeta(),
	})
}

// SetAnnounceStatus registers the callback that fills meta.announce_status.
// Call before ListenAndServe; nil turns the field off again.
func (s *Server) SetAnnounceStatus(fn func() string) {
	s.announceStatus = fn
}

// SetTransport sets meta.transport ("websocket" or "poll", the default).
// Call before ListenAndServe.
func (s *Server) SetTransport(transport string) {
	s.transport = transport
}

// SetGatewayStats registers the reader behind the summary's `gateway`
// field. Call before ListenAndServe; nil turns the field off.
func (s *Server) SetGatewayStats(fn func() *gateway.Stats) {
	s.gatewayStats = fn
}

// SetProtocolCategories replaces the list served by GET /api/v1/protocols.
// Call before ListenAndServe; nil is stored as an empty list.
func (s *Server) SetProtocolCategories(list []classifier.ProtocolCategory) {
	if list == nil {
		list = []classifier.ProtocolCategory{}
	}
	s.protocolCategories = list
}

// handleProtocols returns the protocol → category table.
func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, protocolsResponse{
		Protocols: s.protocolCategories,
		Meta:      s.makeMeta(),
	})
}

// handleSummary returns aggregate totals.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	resp := summaryResponse{Summary: s.agg.GetSummary(), Meta: s.makeMeta()}
	if s.gatewayStats != nil {
		resp.Gateway = s.gatewayStats()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleReset clears all counters.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	s.agg.Reset()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "counters reset"})
}

// handleHealthz is a simple health check.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) makeMeta() meta {
	m := meta{
		CaptureInterface: s.iface, Version: s.version,
		QueryTime: time.Now().UTC().Format(time.RFC3339),
		Transport: s.transport,
	}
	if s.announceStatus != nil {
		m.AnnounceStatus = s.announceStatus()
	}
	return m
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	log.Printf("api: listening on %s", s.srv.Addr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown() error {
	log.Println("api: shutting down")
	ctx, cancel := newTimeoutContext(5 * time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// writeJSON marshals v to JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Printf("api: error encoding JSON response: %v", err)
	}
}
