// Package controller keeps the collector connected to its Perch controller
// over a WebSocket it dials itself (protocol perch-collector.v1,
// docs/collector-agent.md section 3 in the controller repository). The
// collector introduces itself with collector.hello, pushes its counters on
// the schedule the controller sets with agent.configure, and answers
// collector.status and collector.protocols. For a collector on this
// transport it replaces the HTTP announce, and nothing has to reach the
// collector: the router needs no open port.
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/capthndsme/perch-agentkit/link"
	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/announce"
	"github.com/capthndsme/perch-collector/internal/classifier"
	"github.com/capthndsme/perch-collector/internal/gateway"
	"github.com/capthndsme/perch-collector/internal/observe"
)

// Protocol constants.
const (
	// Path is appended to server_url.
	Path = "/api/v1/collector-agent/ws"
	// Subprotocol is protocol v1.
	Subprotocol = "perch-collector.v1"
	// InstanceHeader carries the instance id on the upgrade request.
	InstanceHeader = "X-Perch-Instance-Id"
	// CapabilityGatewayStats is announced when pushes carry gateway stats.
	CapabilityGatewayStats = "gateway_stats"
	// CapabilityObserveDHCP is announced when pushes carry observe.dhcp.
	CapabilityObserveDHCP = "observe.dhcp"
)

// DefaultDHCPRefresh is how often the DHCP observation is resent unchanged.
const DefaultDHCPRefresh = 10 * time.Minute

// Reconnect waits (section 3.3).
const (
	slowRetry     = 5 * time.Minute
	replacedRetry = 60 * time.Second
	// reconnectMin/Max bound the transport-error ladder (1 s doubling, ±10 %
	// jitter): a controller that is down for a restart or an upgrade is back
	// in the dashboard within about 30 s of coming up. Refusals that retrying
	// cannot fix (bad key, pending, 4xx) keep slowRetry.
	reconnectMin   = time.Second
	reconnectMax   = 30 * time.Second
	dismissedRetry = 6 * time.Hour

	helloTimeout = 15 * time.Second
	// The controller closes a session whose hello it refused; this is how
	// long to wait for that before closing it ourselves.
	refusedCloseWait = 5 * time.Second
	// A push is one compressed message of every device's counters: allow a
	// slow uplink more than the kit's 10 s default.
	pushWriteTimeout = 60 * time.Second
)

// States, served as meta.announce_status: the HTTP announcer's vocabulary.
const (
	StateStarting  = "starting"
	StatePending   = "pending"
	StateAdopted   = "adopted"
	StateDismissed = "dismissed"
	StateError     = "error"
)

// Messages for the outcomes that need a human (section 3.3).
const (
	msgKey       = "the controller has a different API key for this collector: re-adopt it or align the keys"
	msgDiscovery = "discovery is off on the controller: an admin has to turn it on or add this collector"
	msgPending   = "the controller's pending list is full: an admin has to adopt or dismiss the collectors waiting there"
	msgNoSocket  = "no collector socket on this controller: update Perch Network Controller"
	msgReplaced  = "another collector uses this instance id"
)

// Source is what the collector reports.
type Source struct {
	Summary func() aggregator.Summary
	Devices func() []aggregator.DeviceStats
	// Gateway returns the gateway stats; nil when they are off.
	Gateway func() *gateway.Stats
	// Protocols is the classifier's protocol → category table (nil = none).
	Protocols func() []classifier.ProtocolCategory
	// DHCP returns the router's DHCP observation and its fingerprint; nil
	// when the observation is off. A push carries it when the fingerprint
	// differs from the last one sent in this session, and every DHCPRefresh.
	DHCP func() (*observe.DHCP, string)
}

// System describes the host in the hello (display only).
type System struct {
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
}

// Options configure a Client.
type Options struct {
	// ServerURL is the controller root, e.g. "https://perch.example.com".
	ServerURL string
	// InstanceID and APIKey identify and authenticate the collector.
	InstanceID string
	APIKey     string
	// SendAPIKey puts the key in the hello as well, so an admin adopting the
	// collector never has to copy it (announce_api_key).
	SendAPIKey bool

	Hostname         string
	Version          string
	CaptureInterface string
	// Listen is the local API's address. Its port (and base URL) are in the
	// hello only when it answers on something other than loopback.
	Listen string
	TLS    link.TLSOptions
	System *System
	Source Source
	// DHCPRefresh resends an unchanged DHCP observation; 0 = DefaultDHCPRefresh.
	DHCPRefresh time.Duration

	// HTTPClient performs the handshake (tests); nil = link.NewHTTPClient(TLS).
	HTTPClient *http.Client
	// Sleep waits between sessions (tests); nil = a context-aware sleep.
	Sleep func(ctx context.Context, d time.Duration) error
	// Log is the kit's logger; nil = slog.Default(), i.e. the std log.
	Log *slog.Logger
	// PingInterval overrides the kit's 30 s (tests).
	PingInterval time.Duration

	// Tests only: sub-second schedules.
	intervalOf func(float64) time.Duration
	minGap     time.Duration
}

// Status is the state for meta.announce_status.
type Status struct {
	State     string
	LastError string
}

// String is the bare state, or "error: <reason>".
func (s Status) String() string {
	switch {
	case s.State == StateError && s.LastError != "":
		return StateError + ": " + s.LastError
	case s.State == "":
		return StateStarting
	}
	return s.State
}

// Client runs the session loop.
type Client struct {
	o          Options
	url        string
	http       *http.Client
	sleep      func(ctx context.Context, d time.Duration) error
	log        *slog.Logger
	dispatcher *rpc.Dispatcher
	intervalOf func(float64) time.Duration

	mu          sync.Mutex
	status      Status
	collectorID int
	name        string
	interval    time.Duration
	configured  bool
	// The DHCP observation last sent, per session (dhcpGen).
	dhcpGen    uint64
	dhcpFP     string
	dhcpSentAt time.Time
	// gen counts sessions. A session's goroutines may still report (a hello
	// answered just before the close) after Run has moved on; anything they
	// report for an older generation is dropped.
	gen uint64
}

// New prepares a client; nothing is sent until Run.
func New(o Options) (*Client, error) {
	u, err := link.WebSocketURL(o.ServerURL, Path)
	if err != nil {
		return nil, fmt.Errorf("server_url: %w", err)
	}
	if o.InstanceID == "" || o.APIKey == "" {
		return nil, errors.New("the WebSocket transport needs an instance id and an api_key")
	}
	client := o.HTTPClient
	if client == nil {
		if client, err = link.NewHTTPClient(o.TLS); err != nil {
			return nil, err
		}
	}
	c := &Client{o: o, url: u, http: client, sleep: o.Sleep, log: o.Log, intervalOf: o.intervalOf}
	if c.sleep == nil {
		c.sleep = sleepCtx
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.intervalOf == nil {
		c.intervalOf = link.IntervalFromSeconds
	}
	c.status = Status{State: StateStarting}
	c.dispatcher = rpc.NewDispatcher()
	c.dispatcher.Register("collector.status", c.handleStatus)
	c.dispatcher.Register("collector.protocols", c.handleProtocols)
	return c, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Status returns a snapshot. Safe from any goroutine.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// StatusString is Status().String(), shaped for the API's meta block.
func (c *Client) StatusString() string { return c.Status().String() }

// Run keeps a session open until ctx is done, reconnecting per section 3.3.
func (c *Client) Run(ctx context.Context) {
	log.Printf("controller: WebSocket transport, server=%s instance=%s", c.o.ServerURL, c.o.InstanceID)
	if c.o.TLS.Insecure {
		log.Printf("controller: WARNING certificate verification is DISABLED for %s (announce_tls_insecure)", c.o.ServerURL)
	}
	bo := link.Backoff{Min: reconnectMin, Max: reconnectMax}
	for ctx.Err() == nil {
		c.mu.Lock()
		gen := c.gen
		c.mu.Unlock()
		configs := make(chan link.Schedule, 1)
		note := &helloNote{}
		started := time.Now()
		err := link.Run(ctx, link.Options{
			URL:            c.url,
			Subprotocol:    Subprotocol,
			Header:         c.header(),
			HTTPClient:     c.http,
			Compression:    true,
			Log:            c.log,
			Dispatcher:     c.dispatcher,
			OnNotification: c.onNotification(gen, configs),
			OnOpen:         c.onOpen(gen, configs, note),
			WriteTimeout:   pushWriteTimeout,
			PingInterval:   c.o.PingInterval,
		})
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			bo.Reset()
		}
		o := classify(err, note, &bo)
		c.ended(o)
		_ = c.sleep(ctx, o.wait)
	}
}

func (c *Client) header() http.Header {
	v := c.o.Version
	if v == "" {
		v = "dev"
	}
	return http.Header{
		"Authorization": {"Bearer " + c.o.APIKey},
		InstanceHeader:  {c.o.InstanceID},
		"User-Agent":    {"perch-collector/" + v},
	}
}

// helloParams is collector.hello's params (section 3.2).
type helloParams struct {
	InstanceID        string   `json:"instanceId"`
	Hostname          string   `json:"hostname,omitempty"`
	Version           string   `json:"version,omitempty"`
	CaptureInterface  string   `json:"captureInterface,omitempty"`
	APIKey            string   `json:"apiKey,omitempty"`
	APIKeyFingerprint string   `json:"apiKeyFingerprint,omitempty"`
	Port              int      `json:"port,omitempty"`
	TLS               *bool    `json:"tls,omitempty"`
	BaseURL           string   `json:"baseUrl,omitempty"`
	Capabilities      []string `json:"capabilities"`
	System            *System  `json:"system,omitempty"`
}

type helloResult struct {
	CollectorID int    `json:"collectorId"`
	Lifecycle   string `json:"lifecycle"`
	Name        string `json:"name"`
}

func (c *Client) hello() helloParams {
	p := helloParams{
		InstanceID:        c.o.InstanceID,
		Hostname:          c.o.Hostname,
		Version:           c.o.Version,
		CaptureInterface:  c.o.CaptureInterface,
		APIKeyFingerprint: announce.Fingerprint(c.o.APIKey),
		Capabilities:      []string{},
		System:            c.o.System,
	}
	if c.o.SendAPIKey {
		p.APIKey = c.o.APIKey
	}
	if port, baseURL, ok := PollableAddress(c.o.Listen); ok {
		// The local API is plain HTTP.
		tls := false
		p.Port, p.TLS, p.BaseURL = port, &tls, baseURL
	}
	if c.o.Source.Gateway != nil {
		p.Capabilities = append(p.Capabilities, CapabilityGatewayStats)
	}
	if c.o.Source.DHCP != nil {
		p.Capabilities = append(p.Capabilities, CapabilityObserveDHCP)
	}
	return p
}

// PollableAddress is what the hello may say about the local API: its port
// and, when the daemon knows it, its base URL. ok is false when the API only
// answers on loopback (the OpenWrt default with this transport), so the
// controller is not handed an address it cannot poll.
func PollableAddress(listen string) (port int, baseURL string, ok bool) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return 0, "", false
	}
	if strings.EqualFold(host, "localhost") {
		return 0, "", false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return 0, "", false
	}
	port, baseURL, err = announce.SelfAddress(listen, false)
	if err != nil {
		return 0, "", false
	}
	return port, baseURL, true
}

// helloNote records why the controller refused a hello, for the retry
// decision after the session ends.
type helloNote struct {
	mu      sync.Mutex
	refused bool
	code    string // data.error of the refusal
	message string
}

func (n *helloNote) set(code, message string) {
	n.mu.Lock()
	n.refused, n.code, n.message = true, code, message
	n.mu.Unlock()
}

func (n *helloNote) get() (bool, string, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.refused, n.code, n.message
}

func (c *Client) onOpen(gen uint64, configs chan link.Schedule, note *helloNote) func(ctx context.Context, s *link.Session) {
	return func(ctx context.Context, s *link.Session) {
		hctx, cancel := context.WithTimeout(ctx, helloTimeout)
		var res helloResult
		err := s.Call(hctx, "collector.hello", c.hello(), &res)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return // the session ended first; its end says why
			}
			var rerr *rpc.Error
			if errors.As(err, &rerr) {
				note.set(errorCode(rerr), rerr.Message)
				select {
				case <-ctx.Done():
					return
				case <-time.After(refusedCloseWait):
				}
			} else {
				c.log.Warn("no answer to collector.hello", "err", err)
			}
			s.Close(websocket.StatusPolicyViolation, "hello failed")
			return
		}
		c.helloAccepted(gen, res)
		link.RunPusher(ctx, link.PushOptions{
			Configs: configs,
			Push:    func(_ context.Context, seq uint64) { c.push(s, seq, gen) },
			MinGap:  c.o.minGap,
			Log:     c.log,
		})
	}
}

// errorCode is `data.error` of a JSON-RPC error, when the controller set one.
func errorCode(e *rpc.Error) string {
	if m, ok := e.Data.(map[string]any); ok {
		if s, ok := m["error"].(string); ok {
			return s
		}
	}
	return ""
}

func (c *Client) onNotification(gen uint64, configs chan link.Schedule) func(ctx context.Context, s *link.Session, m *rpc.Message) {
	return func(_ context.Context, _ *link.Session, m *rpc.Message) {
		if m.Method != "agent.configure" {
			c.log.Debug("notification from the controller", "method", m.Method)
			return
		}
		var p struct {
			MetricsIntervalSeconds *float64 `json:"metricsIntervalSeconds"`
			Lifecycle              string   `json:"lifecycle"`
		}
		if err := rpc.Params(m.Params, &p); err != nil {
			c.log.Warn("bad agent.configure from the controller", "err", err)
			return
		}
		secs := 0.0 // no interval = do not push
		if p.MetricsIntervalSeconds != nil {
			secs = *p.MetricsIntervalSeconds
		}
		interval := c.intervalOf(secs)
		link.Offer(configs, link.Schedule{Interval: interval})
		c.scheduleChanged(gen, p.Lifecycle, interval)
	}
}

// pushParams is collector.push's params (section 3.2): what GET
// /api/v1/summary and GET /api/v1/devices serve, in one compact message.
type pushParams struct {
	Seq         uint64                   `json:"seq"`
	CollectedAt string                   `json:"collectedAt"`
	Summary     aggregator.Summary       `json:"summary"`
	Meta        pushMeta                 `json:"meta"`
	Devices     []aggregator.DeviceStats `json:"devices"`
	Gateway     *gateway.Stats           `json:"gateway,omitempty"`
	// Observe is runtime state of the router beside the traffic
	// (docs/collector-agent.md section 4.3). Absent = nothing to report in
	// this push; the controller keeps what it has.
	// A part is present only in the pushes that carry it: when it changed,
	// at the start of a session, and every refresh.
	Observe *observe.Section `json:"observe,omitempty"`
}

type pushMeta struct {
	CaptureInterface string `json:"capture_interface"`
	Version          string `json:"version"`
}

func (c *Client) push(s *link.Session, seq uint64, gen uint64) {
	p := pushParams{
		Seq:         seq,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:     c.o.Source.Summary(),
		Meta:        pushMeta{CaptureInterface: c.o.CaptureInterface, Version: c.o.Version},
		Devices:     c.o.Source.Devices(),
	}
	if p.Devices == nil {
		p.Devices = []aggregator.DeviceStats{}
	}
	if c.o.Source.Gateway != nil {
		p.Gateway = c.o.Source.Gateway()
	}
	dhcpFP := ""
	if c.o.Source.DHCP != nil {
		if d, fp := c.o.Source.DHCP(); d != nil && c.dhcpDue(gen, fp) {
			p.Observe = &observe.Section{DHCP: d}
			dhcpFP = fp
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		c.log.Error("encoding a push", "err", err)
		return
	}
	if err := s.NotifyRaw("collector.push", b); err != nil {
		c.log.Debug("push not sent", "seq", seq, "err", err)
		return
	}
	if dhcpFP != "" {
		c.dhcpSent(gen, dhcpFP)
	}
	if seq == 1 {
		log.Printf("controller: first push of this session: %d devices, %d KiB before compression", len(p.Devices), len(b)/1024)
	}
}

// dhcpDue reports whether a push of session gen should carry the DHCP
// observation with fingerprint fp: first in the session, changed, or the
// refresh is due.
func (c *Client) dhcpDue(gen uint64, fp string) bool {
	refresh := c.o.DHCPRefresh
	if refresh <= 0 {
		refresh = DefaultDHCPRefresh
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dhcpGen != gen || c.dhcpFP != fp || time.Since(c.dhcpSentAt) >= refresh
}

func (c *Client) dhcpSent(gen uint64, fp string) {
	c.mu.Lock()
	c.dhcpGen, c.dhcpFP, c.dhcpSentAt = gen, fp, time.Now()
	c.mu.Unlock()
}

type statusResult struct {
	StartedAt        time.Time `json:"startedAt"`
	TotalDevices     int       `json:"totalDevices"`
	CaptureInterface string    `json:"captureInterface"`
	Version          string    `json:"version"`
	UptimeSeconds    int64     `json:"uptimeSeconds"`
}

func (c *Client) handleStatus(context.Context, json.RawMessage) (any, error) {
	s := c.o.Source.Summary()
	return statusResult{
		StartedAt:        s.StartedAt,
		TotalDevices:     s.TotalDevices,
		CaptureInterface: c.o.CaptureInterface,
		Version:          c.o.Version,
		UptimeSeconds:    int64(s.UptimeSecs),
	}, nil
}

func (c *Client) handleProtocols(context.Context, json.RawMessage) (any, error) {
	var list []classifier.ProtocolCategory
	if c.o.Source.Protocols != nil {
		list = c.o.Source.Protocols()
	}
	if list == nil {
		list = []classifier.ProtocolCategory{}
	}
	return map[string]any{"protocols": list}, nil
}

// outcome is how a session ended and what to do about it.
type outcome struct {
	wait  time.Duration
	state string // "" keeps the current state
	err   string // with StateError
	note  string // logged once, without a state change
}

// classify applies section 3.3's table.
func classify(err error, note *helloNote, bo *link.Backoff) outcome {
	var se *link.StatusError
	if errors.As(err, &se) {
		switch {
		case se.Status == http.StatusUnauthorized:
			return outcome{wait: slowRetry, state: StateError, err: msgKey}
		case se.Status == http.StatusForbidden && se.Code == "announce_disabled":
			return outcome{wait: slowRetry, state: StateError, err: msgDiscovery}
		case se.Status == http.StatusConflict:
			return outcome{wait: slowRetry, state: StateError, err: msgPending}
		case se.Status == http.StatusNotFound:
			return outcome{wait: slowRetry, state: StateError, err: msgNoSocket}
		case se.Status == http.StatusTooManyRequests:
			wait := se.RetryAfter
			if wait <= 0 {
				wait = bo.Next()
			}
			return outcome{wait: wait, state: StateError, err: "rate limited by the controller"}
		case se.Status >= 400 && se.Status < 500:
			// A bad request or another refusal: retrying soon cannot help.
			return outcome{wait: slowRetry, state: StateError, err: "the controller refused the connection: " + sanitize(se.Error())}
		case se.RetryAfter > 0 && se.RetryAfter < reconnectMax:
			// 503 gateway_starting (Retry-After: 1): the controller is
			// seconds away from taking the socket.
			return outcome{wait: se.RetryAfter, state: StateError, err: sanitize(se.Error())}
		}
		return outcome{wait: bo.Next(), state: StateError, err: sanitize(se.Error())}
	}
	if refused, code, message := note.get(); refused {
		switch code {
		case "announce_key_mismatch":
			return outcome{wait: slowRetry, state: StateError, err: msgKey}
		case "announce_pending_limit":
			return outcome{wait: slowRetry, state: StateError, err: msgPending}
		}
		return outcome{wait: slowRetry, state: StateError, err: "the controller refused the hello: " + sanitize(message)}
	}
	switch websocket.CloseStatus(err) {
	case link.CloseRevoked:
		return outcome{wait: slowRetry, state: StateError, err: msgKey}
	case link.CloseReplaced:
		return outcome{wait: replacedRetry, state: StateError, err: msgReplaced}
	case link.CloseDismissed:
		return outcome{wait: dismissedRetry, state: StateDismissed}
	case websocket.StatusGoingAway:
		return outcome{wait: 2*time.Second + time.Duration(rand.Intn(3000))*time.Millisecond, note: "the controller is restarting; reconnecting shortly"}
	}
	return outcome{wait: bo.Next(), state: StateError, err: describe(err)}
}

func describe(err error) string {
	if err == nil {
		return "the controller closed the session"
	}
	var cerr websocket.CloseError
	if errors.As(err, &cerr) {
		reason := sanitize(cerr.Reason)
		if reason == "" {
			return fmt.Sprintf("closed by the controller (%d)", cerr.Code)
		}
		return fmt.Sprintf("closed by the controller (%d %s)", cerr.Code, reason)
	}
	return sanitize(err.Error())
}

// sanitize keeps controller-supplied text to one bounded line: it ends up in
// a log line and in meta.announce_status.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "..."
	}
	return s
}

// helloAccepted records the hello's answer.
func (c *Client) helloAccepted(gen uint64, res helloResult) {
	c.mu.Lock()
	if gen != c.gen {
		c.mu.Unlock()
		return
	}
	c.collectorID, c.name = res.CollectorID, res.Name
	c.mu.Unlock()
	c.setState(&gen, lifecycleState(res.Lifecycle), "")
}

// scheduleChanged records an agent.configure: its lifecycle, and the
// schedule (logged when it changes).
func (c *Client) scheduleChanged(gen uint64, lifecycle string, interval time.Duration) {
	c.mu.Lock()
	if gen != c.gen {
		c.mu.Unlock()
		return
	}
	changed := !c.configured || interval != c.interval
	c.configured, c.interval = true, interval
	c.mu.Unlock()
	if lifecycle != "" {
		c.setState(&gen, lifecycleState(lifecycle), "")
	}
	if !changed {
		return
	}
	if interval > 0 {
		log.Printf("controller: pushing every %s", interval)
	} else {
		log.Printf("controller: pushes paused by the controller")
	}
}

// ended closes the books on a session: later reports from it are dropped.
func (c *Client) ended(o outcome) {
	c.mu.Lock()
	c.gen++
	c.configured, c.interval = false, 0
	c.mu.Unlock()
	if o.note != "" {
		log.Printf("controller: %s", o.note)
	}
	if o.state != "" {
		c.setState(nil, o.state, o.err)
	}
	if o.wait >= time.Minute {
		log.Printf("controller: next attempt in %s", o.wait.Round(time.Second))
	}
}

// lifecycleState maps the controller's lifecycle onto a state. Anything
// unexpected reads as "not adopted yet", the safe assumption.
func lifecycleState(lifecycle string) string {
	switch lifecycle {
	case StateAdopted:
		return StateAdopted
	case StateDismissed:
		return StateDismissed
	}
	return StatePending
}

// setState updates the status and logs one line per change. With gen set
// the update only applies while that session is the current one.
func (c *Client) setState(gen *uint64, state, errText string) {
	next := Status{State: state, LastError: errText}
	c.mu.Lock()
	if gen != nil && *gen != c.gen {
		c.mu.Unlock()
		return
	}
	prev := c.status
	c.status = next
	id, name := c.collectorID, c.name
	c.mu.Unlock()
	if prev == next {
		return
	}
	from := prev.String()
	if prev.State == StateError {
		from = StateError
	}
	switch state {
	case StateError:
		log.Printf("controller: %s -> error: %s", from, errText)
	case StatePending:
		log.Printf("controller: %s -> pending; %s has the collector, waiting for an admin to adopt it", from, c.o.ServerURL)
	case StateAdopted:
		log.Printf("controller: %s -> adopted by %s (collector %d %q)", from, c.o.ServerURL, id, name)
	case StateDismissed:
		log.Printf("controller: %s -> dismissed by %s; nothing is pushed", from, c.o.ServerURL)
	default:
		log.Printf("controller: %s -> %s", from, state)
	}
}
