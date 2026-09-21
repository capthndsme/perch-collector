// Package announce tells a Perch controller that this collector exists, over
// HTTP (transport poll; the WebSocket transport says hello on its socket
// instead, see internal/controller).
//
// It is strictly one-way and idempotent: the daemon POSTs an identity
// document to the server, the server records an identity and an address, and
// an administrator decides whether to poll it. Nothing the server replies
// with changes what the collector captures or serves — the only thing it can
// influence is how often the next announce is sent.
//
// The address the server will poll is derived from the TCP source address of
// the announce, not from anything in the body, so this package reports only
// what it can honestly claim: its port, whether its own API speaks TLS, and
// the base URL it believes it has.
package announce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// announcePath is appended to the configured server URL.
const announcePath = "/api/v1/collectors/announce"

// Schedule bounds. The server owns the cadence (announceIntervalSeconds in
// its reply) but a collector must never take a bad reply as licence to
// hammer it, nor to go quiet for a week.
const (
	defaultMinInterval = 15 * time.Second
	defaultMaxInterval = 6 * time.Hour

	// First announce lands 2-5 s after start, so a router bringing its whole
	// network up does not have every daemon fire at the same instant.
	defaultFirstDelayMin = 2 * time.Second
	defaultFirstDelayMax = 5 * time.Second

	// ±10 % on every wait, same reason.
	defaultJitterFraction = 0.10

	// How long a single announce may take, in total.
	requestTimeout = 10 * time.Second

	// Enough for the reply envelope; a server that sends more is broken.
	maxResponseBytes = 64 << 10

	// The server's error code is attacker-influenced text that ends up in a
	// log line and in meta.announce_status, so it is bounded and scrubbed
	// before it is embedded anywhere.
	maxErrorCodeRunes = 120
)

// failureBackoff is the wait after 1, 2, 3, … consecutive failed announces.
// The last entry repeats. A collector whose server is down is not urgent.
var failureBackoff = []time.Duration{
	30 * time.Second,
	60 * time.Second,
	120 * time.Second,
	300 * time.Second,
	900 * time.Second,
}

// State is what the server last said about this collector, or how the last
// announce failed. It is exposed verbatim as meta.announce_status.
type State string

const (
	// StateStarting is the state before the first announce has completed.
	StateStarting State = "starting"
	// StatePending means the server has the collector but no admin has
	// adopted it: nothing is being polled.
	StatePending State = "pending"
	// StateAdopted means an admin adopted it and the server polls it.
	StateAdopted State = "adopted"
	// StateDismissed means an admin said no. The daemon keeps announcing at
	// the (long) interval the server hands out so that un-dismissing works.
	StateDismissed State = "dismissed"
	// StateError means the last announce did not get an answer the daemon
	// could use. Capture and the local API are unaffected.
	StateError State = "error"
)

// Status is a snapshot of the announcer for operators and for
// meta.announce_status.
type Status struct {
	// Server is the configured server URL (no path, no credentials).
	Server string
	// State is the last known lifecycle, or StateError.
	State State
	// LastAnnounce is when the last *successful* announce completed.
	LastAnnounce time.Time
	// LastError is why the last announce failed, empty when it did not.
	LastError string
}

// String renders the status the way the API exposes it: the bare state, or
// "error: <reason>".
func (s Status) String() string {
	if s.State == StateError {
		if s.LastError != "" {
			return "error: " + s.LastError
		}
		return string(StateError)
	}
	if s.State == "" {
		return string(StateStarting)
	}
	return string(s.State)
}

// Options configures an Announcer. Everything except ServerURL and
// InstanceID is optional.
type Options struct {
	// ServerURL is the Perch controller root, e.g. "http://192.168.1.10:8080".
	ServerURL string
	// InstanceID is this collector's stable identity (see ResolveInstanceID).
	InstanceID string
	// APIKey is the collector's own bearer token. When set it is always sent
	// as an Authorization header — that is what proves an adopted collector
	// is really itself — and its fingerprint is always in the body.
	APIKey string
	// SendAPIKey additionally puts the key in the announce body so the admin
	// never has to copy it. Ignored when APIKey is empty.
	SendAPIKey bool
	// Port is the port the collector's own API listens on.
	Port int
	// TLS reports whether that API speaks https.
	TLS bool
	// BaseURL is what the daemon believes its own address is. Advisory: the
	// server records it for display and polls the announce source address
	// instead. Empty when the daemon listens on a wildcard and cannot know.
	BaseURL string
	// Hostname, Version and CaptureInterface are self-reported metadata the
	// dashboard shows next to a pending collector.
	Hostname         string
	Version          string
	CaptureInterface string
	// Interval is the opening cadence. The server's reply overrides it.
	Interval time.Duration
	// TLSInsecure accepts a self-signed certificate on an https ServerURL.
	TLSInsecure bool
	// Client is a test seam; nil means a 10 s-timeout client.
	Client *http.Client
}

// Announcer runs the announce loop. Create it with New, run it in its own
// goroutine with Run, and stop it with Stop.
type Announcer struct {
	opts     Options
	endpoint string
	client   *http.Client

	// Schedule parameters, overridden by tests.
	firstDelayMin  time.Duration
	firstDelayMax  time.Duration
	minInterval    time.Duration
	maxInterval    time.Duration
	jitterFraction float64

	// Owned by the goroutine that calls beat().
	interval time.Duration
	failures int

	mu     sync.Mutex
	status Status

	stopOnce sync.Once
	stop     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

// New builds an Announcer. It performs no I/O; nothing is sent until Run.
func New(opts Options) *Announcer {
	client := opts.Client
	if client == nil {
		client = newClient(opts.TLSInsecure)
	}
	ctx, cancel := context.WithCancel(context.Background())

	a := &Announcer{
		opts:           opts,
		endpoint:       strings.TrimRight(opts.ServerURL, "/") + announcePath,
		client:         client,
		firstDelayMin:  defaultFirstDelayMin,
		firstDelayMax:  defaultFirstDelayMax,
		minInterval:    defaultMinInterval,
		maxInterval:    defaultMaxInterval,
		jitterFraction: defaultJitterFraction,
		stop:           make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
	}
	a.interval = a.clampInterval(opts.Interval)
	a.status = Status{Server: opts.ServerURL, State: StateStarting}
	return a
}

// newClient is the default HTTP client: system roots, one bounded attempt.
func newClient(insecure bool) *http.Client {
	c := &http.Client{Timeout: requestTimeout}
	if insecure {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via announce_tls_insecure
		c.Transport = tr
	}
	return c
}

// Run drives the announce loop until Stop. It blocks; call it as a goroutine.
func (a *Announcer) Run() {
	log.Printf("announce: enabled, server=%s instance=%s interval=%s",
		a.opts.ServerURL, a.opts.InstanceID, a.interval)
	if a.opts.TLSInsecure {
		log.Printf("announce: WARNING certificate verification is DISABLED for %s (announce_tls_insecure)", a.opts.ServerURL)
	}

	timer := time.NewTimer(a.firstDelay())
	defer timer.Stop()

	for {
		select {
		case <-a.stop:
			return
		case <-timer.C:
		}
		timer.Reset(a.beat())
	}
}

// Stop ends the loop and aborts an announce that is in flight. It returns
// immediately and is safe to call more than once, including before Run.
func (a *Announcer) Stop() {
	a.stopOnce.Do(func() {
		close(a.stop)
		a.cancel()
	})
}

// Status returns a snapshot. Safe from any goroutine.
func (a *Announcer) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

// StatusString is Status().String(), shaped for the API's meta block.
func (a *Announcer) StatusString() string {
	return a.Status().String()
}

// Fingerprint is the first 8 hex characters of the key's SHA-256: enough for
// an admin to compare the key the dashboard was told about against the one
// on the box, useless for recovering the key.
func Fingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:8]
}

// SelfAddress derives what the daemon can honestly say about its own address
// from the API listen address. The port is required by the server; the base
// URL is advisory and comes back empty when the daemon listens on a wildcard
// and genuinely does not know how it is reached.
func SelfAddress(listen string, useTLS bool) (port int, baseURL string, err error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return 0, "", fmt.Errorf("listen address %q is not host:port: %w", listen, err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("listen address %q has no usable port", listen)
	}

	if host == "" || host == "*" {
		return port, "", nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return port, "", nil
	}
	// Any host with a colon in it is an IPv6 literal — including a zoned one
	// such as fe80::1%eth0, which net.ParseIP rejects — and has to be
	// bracketed before it can go into a URL.
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return port, fmt.Sprintf("%s://%s:%d", scheme, host, port), nil
}

// payload is the announce body: section 2.2 of the design, and nothing else.
type payload struct {
	InstanceID        string `json:"instanceId"`
	Hostname          string `json:"hostname,omitempty"`
	Version           string `json:"version,omitempty"`
	CaptureInterface  string `json:"captureInterface,omitempty"`
	Port              int    `json:"port"`
	TLS               bool   `json:"tls"`
	BaseURL           string `json:"baseUrl,omitempty"`
	APIKey            string `json:"apiKey,omitempty"`
	APIKeyFingerprint string `json:"apiKeyFingerprint,omitempty"`
}

// result is the useful half of the server's reply envelope.
type result struct {
	Status                  string `json:"status"`
	CollectorID             int    `json:"collectorId"`
	AnnounceIntervalSeconds int    `json:"announceIntervalSeconds"`
}

// beatError is a failed announce: a transport error (StatusCode 0) or an
// HTTP status the daemon could not use.
type beatError struct {
	StatusCode int
	Code       string
	RetryAfter time.Duration
	Err        error
}

func (e *beatError) Error() string {
	switch {
	case e.StatusCode == 0 && e.Err != nil:
		return e.Err.Error()
	case e.Code != "" && e.Err != nil:
		return fmt.Sprintf("server replied %d %s: %v", e.StatusCode, e.Code, e.Err)
	case e.Code != "":
		return fmt.Sprintf("server replied %d %s", e.StatusCode, e.Code)
	case e.Err != nil:
		return fmt.Sprintf("server replied %d: %v", e.StatusCode, e.Err)
	default:
		return fmt.Sprintf("server replied %d", e.StatusCode)
	}
}

func (e *beatError) Unwrap() error { return e.Err }

// payloadFor builds the body for one announce.
func (a *Announcer) payloadFor() payload {
	p := payload{
		InstanceID:       a.opts.InstanceID,
		Hostname:         a.opts.Hostname,
		Version:          a.opts.Version,
		CaptureInterface: a.opts.CaptureInterface,
		Port:             a.opts.Port,
		TLS:              a.opts.TLS,
		BaseURL:          a.opts.BaseURL,
	}
	if a.opts.APIKey != "" {
		// The fingerprint always travels: it is what the dashboard shows so
		// an admin can check the key before adopting, and it cannot be
		// turned back into the key.
		p.APIKeyFingerprint = Fingerprint(a.opts.APIKey)
		if a.opts.SendAPIKey {
			p.APIKey = a.opts.APIKey
		}
	}
	return p
}

// userAgent identifies the build to the server's logs.
func (a *Announcer) userAgent() string {
	v := a.opts.Version
	if v == "" {
		v = "dev"
	}
	return "perch-collector/" + v
}

// post sends one announce and returns the server's reply.
func (a *Announcer) post() (*result, error) {
	body, err := json.Marshal(a.payloadFor())
	if err != nil {
		return nil, &beatError{Err: fmt.Errorf("encoding the announce: %w", err)}
	}

	req, err := http.NewRequestWithContext(a.ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &beatError{Err: fmt.Errorf("building the request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", a.userAgent())
	if a.opts.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.opts.APIKey)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &beatError{Err: err}
	}
	defer resp.Body.Close()

	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &beatError{
			StatusCode: resp.StatusCode,
			Code:       errorCodeOf(data),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}
	if readErr != nil {
		return nil, &beatError{StatusCode: resp.StatusCode, Err: fmt.Errorf("reading the reply: %w", readErr)}
	}

	var envelope struct {
		Data result `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, &beatError{StatusCode: resp.StatusCode, Err: fmt.Errorf("decoding the reply: %w", err)}
	}
	return &envelope.Data, nil
}

// beat performs one announce and returns how long to wait before the next.
func (a *Announcer) beat() time.Duration {
	res, err := a.post()
	if err != nil {
		// Shutdown cancels the request in flight. That is not a failure and
		// must not show up as a state change on the way out.
		if a.stopping() {
			return a.interval
		}
		return a.onFailure(err)
	}
	return a.onSuccess(res)
}

// stopping reports whether Stop has been called. Checked before recording a
// failure, so "context canceled" never reaches the status or the log.
func (a *Announcer) stopping() bool {
	select {
	case <-a.stop:
		return true
	default:
		return a.ctx.Err() != nil
	}
}

// onSuccess records the server's answer and adopts its schedule.
func (a *Announcer) onSuccess(res *result) time.Duration {
	a.failures = 0
	if res.AnnounceIntervalSeconds > 0 {
		a.interval = a.clampInterval(time.Duration(res.AnnounceIntervalSeconds) * time.Second)
	}
	a.setState(stateOf(res.Status), "", res.CollectorID)
	return a.withJitter(a.interval)
}

// onFailure records why an announce failed and returns the retry delay.
func (a *Announcer) onFailure(err error) time.Duration {
	be, _ := err.(*beatError)
	msg := err.Error()

	// Some answers say "nothing will change until a human does something":
	// a key the server does not recognise, announcing switched off, a full
	// pending list. Retrying sooner cannot help, so say it once, loudly, and
	// drop to the slowest beat. The failure counter is left alone — this is
	// not the kind of failure backoff is for.
	if be != nil {
		if reason, slow := adminActionNeeded(be, msg); slow {
			a.setState(StateError, reason, 0)
			return a.withJitter(a.maxInterval)
		}

		// 429: the server told us when to come back, so come back then.
		if be.StatusCode == http.StatusTooManyRequests && be.RetryAfter > 0 {
			a.setState(StateError, msg, 0)
			return a.clampInterval(be.RetryAfter)
		}
	}

	a.failures++
	a.setState(StateError, msg, 0)
	return a.withJitter(backoffFor(a.failures))
}

// adminActionNeeded recognises the replies that only an administrator can
// clear, and returns the line to log for them.
func adminActionNeeded(be *beatError, msg string) (string, bool) {
	switch be.StatusCode {
	case http.StatusUnauthorized:
		return "the server has a different API key for this instance id (" + msg +
			"); re-adopt this collector or align the keys", true
	case http.StatusForbidden:
		if be.Code == "announce_disabled" {
			return "the server has collector announcing switched off (" + msg +
				"); an admin has to turn it back on under Settings -> Collectors", true
		}
		return "the server refuses this announce (" + msg + "); an admin has to look at it", true
	case http.StatusConflict:
		if be.Code == "announce_pending_limit" {
			return "the server's pending-collector list is full (" + msg +
				"); an admin has to adopt or dismiss the collectors waiting there", true
		}
		return "the server rejected this announce as conflicting (" + msg + "); an admin has to look at it", true
	}
	return "", false
}

// setState updates the status and logs ONE line per change — never per beat.
// A stable failure logs once, not every 30 seconds, but a failure whose
// reason changes is worth a second line.
func (a *Announcer) setState(state State, errText string, collectorID int) {
	a.mu.Lock()
	prev := a.status
	a.status.State = state
	if state == StateError {
		a.status.LastError = errText
	} else {
		a.status.LastError = ""
		a.status.LastAnnounce = time.Now()
	}
	a.mu.Unlock()

	if prev.State == state && prev.LastError == errText {
		return
	}
	switch state {
	case StateError:
		log.Printf("announce: %s -> error: %s", prev.State, errText)
	case StatePending:
		log.Printf("announce: %s -> pending; %s has the collector, waiting for an admin to adopt it", prev.State, a.opts.ServerURL)
	case StateAdopted:
		log.Printf("announce: %s -> adopted by %s (collector %d)", prev.State, a.opts.ServerURL, collectorID)
	case StateDismissed:
		log.Printf("announce: %s -> dismissed by %s; still announcing, nothing is being polled", prev.State, a.opts.ServerURL)
	default:
		log.Printf("announce: %s -> %s", prev.State, state)
	}
}

// stateOf maps the server's lifecycle string onto a State. Anything
// unexpected is read as "not adopted yet", which is the safe assumption.
func stateOf(status string) State {
	switch State(strings.TrimSpace(status)) {
	case StateAdopted:
		return StateAdopted
	case StateDismissed:
		return StateDismissed
	default:
		return StatePending
	}
}

// backoffFor returns the wait after n consecutive failures (n >= 1).
func backoffFor(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	if n > len(failureBackoff) {
		n = len(failureBackoff)
	}
	return failureBackoff[n-1]
}

// clampInterval keeps a server-supplied cadence inside the bounds.
func (a *Announcer) clampInterval(d time.Duration) time.Duration {
	if d < a.minInterval {
		return a.minInterval
	}
	if d > a.maxInterval {
		return a.maxInterval
	}
	return d
}

// withJitter spreads a wait by ±jitterFraction so a fleet of collectors does
// not synchronise on the server.
func (a *Announcer) withJitter(d time.Duration) time.Duration {
	if a.jitterFraction <= 0 || d <= 0 {
		return d
	}
	spread := float64(d) * a.jitterFraction
	out := time.Duration(float64(d) + (rand.Float64()*2-1)*spread)
	if out < time.Millisecond {
		out = time.Millisecond
	}
	return out
}

// firstDelay is the wait before the very first announce.
func (a *Announcer) firstDelay() time.Duration {
	lo, hi := a.firstDelayMin, a.firstDelayMax
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(rand.Int63n(int64(hi-lo)))
}

// errorCodeOf pulls the machine-readable code out of an error body
// ({"error":"announce_rate_limited"}). Empty when there is none.
func errorCodeOf(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return ""
	}
	return sanitiseCode(e.Error)
}

// sanitiseCode makes a server-supplied string safe to put in a log line and
// in meta.announce_status: no control characters (a reply must not be able
// to forge log lines) and a hard length cap (a reply must not be able to
// print 20 KB of itself on every state change).
func sanitiseCode(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxErrorCodeRunes {
		s = string([]rune(s)[:maxErrorCodeRunes]) + "..."
	}
	return s
}

// parseRetryAfter reads a Retry-After header in either of its forms. 0 means
// absent or unusable.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
