package gwconfig

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Pairing, the router side (owner decision 29; the controller's
// docs/gateway/config-plane.md section 4.4). A router that takes config
// writes over plain HTTP (config_allow_insecure '1') verifies them with a
// key it agreed with the controller over the socket, never with the
// api_key (the Bearer token every plain-HTTP listener sees):
//
//	controller                                   router
//	gateway.pair.begin {pairingId, gatewayId, controllerPub}
//	                                  ──►  key pair + nonce; commit to the nonce
//	                                  ◄──  {routerPub, commitment, expiresAt}
//	gateway.pair.reveal {pairingId, controllerNonce}   (once per pairing)
//	                                  ──►  key, SAS; the code goes to the log
//	                                  ◄──  {routerNonce}
//	checks the commitment, derives the same key and code; the admin types
//	the router's code on the controller and runs, on the router,
//	`perch-collector pair confirm <code>`
//	                                  ◄──  gateway.pair.state {state: paired, keyId}
//
// Only one pairing is in progress at a time (a new begin replaces an
// unfinished one). An unfinished pairing lives in memory for PairWindow;
// the paired key is kept on flash (PairingFile, 0600) until
// `perch-collector pair forget`, a signed gateway.pair.forget from the
// paired controller, a factory reset or the package's removal.

// Pairing RPCs and the notification.
const (
	MethodPairBegin  = "gateway.pair.begin"
	MethodPairReveal = "gateway.pair.reveal"
	MethodPairStatus = "gateway.pair.status"
	MethodPairCancel = "gateway.pair.cancel"
	MethodPairForget = "gateway.pair.forget"
	NotifyPairState  = "gateway.pair.state"
)

// PairMethods are the methods ServePair handles.
var PairMethods = []string{MethodPairBegin, MethodPairReveal, MethodPairStatus, MethodPairCancel, MethodPairForget}

// Pairing states (gateway.pair.status, gateway.pair.state).
const (
	PairWaitingLocal = "waiting_local"
	PairPaired       = "paired"
	PairExpired      = "expired"
	PairCancelled    = "cancelled"
	PairRejected     = "rejected"
	PairUnknown      = "unknown"
	PairForgotten    = "forgotten"
)

// Error codes of the pairing RPCs.
const (
	CodePairingNotNeeded  = "pairing_not_needed"
	CodeUnknownPairing    = "unknown_pairing"
	CodeAlreadyRevealed   = "already_revealed"
	CodeSignKeyConfigured = "sign_key_configured"
	CodeNotPaired         = "not_paired"
	CodeUnknownKey        = "unknown_key"
)

// Local confirmation errors (`perch-collector pair confirm`).
var (
	ErrNoPairing       = errors.New("no pairing is waiting for a confirmation")
	ErrNotRevealed     = errors.New("the controller has not finished its half of the pairing yet; try again in a moment")
	ErrBadCode         = errors.New("the code is 6 digits")
	ErrCodeMismatch    = errors.New("the code does not match this router's code")
	ErrPairingEnded    = errors.New("the pairing was rejected: 3 wrong codes")
	ErrNothingToForget = errors.New("this router holds no paired key")
)

const (
	// PairWindow bounds each step: begin to reveal, and reveal to the local
	// confirm (the controller's own window is 10 minutes from its start).
	PairWindow = 10 * time.Minute
	// PairMaxAttempts: wrong local codes before the pairing is rejected.
	PairMaxAttempts = 3
	// PairingFile keeps the paired key (root only).
	PairingFile = StateDir + "/pairing.json"
	// PairSocket is the daemon's local socket for `perch-collector pair`.
	PairSocket = RunDir + "/pair.sock"
)

var (
	pairingIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
	sasRe       = regexp.MustCompile(`^[0-9]{6}$`)
)

// PairStateNote is gateway.pair.state.
type PairStateNote struct {
	PairingID string `json:"pairingId"`
	State     string `json:"state"`
	KeyID     string `json:"keyId,omitempty"`
}

// pairing is one pairing in progress.
type pairing struct {
	id            string
	gatewayID     int64
	server        string
	controllerPub []byte
	routerPub     []byte
	nonce         []byte
	shared        []byte
	revealed      bool
	key           []byte
	sas           string
	keyID         string
	started       time.Time
	expires       time.Time
	attempts      int
	stop          func() bool
}

// pairedKey is PairingFile.
type pairedKey struct {
	Version   int       `json:"version"`
	Key       string    `json:"key"`
	KeyID     string    `json:"keyId"`
	PairingID string    `json:"pairingId"`
	GatewayID int64     `json:"gatewayId"`
	Server    string    `json:"server,omitempty"`
	PairedAt  time.Time `json:"pairedAt"`
	raw       []byte
}

// pairState is the plane's pairing state.
type pairState struct {
	mu     sync.Mutex
	cur    *pairing
	last   struct{ id, state string }
	key    *pairedKey
	loaded bool
}

func (p *Plane) pairingPath() string { return rooted(p.o.Root, PairingFile) }

// PairSocketPath is the local socket under the plane's root.
func (p *Plane) PairSocketPath() string { return rooted(p.o.Root, PairSocket) }

// loadPairLocked reads PairingFile once. A file readable by others is
// tightened to 0600; an unreadable one counts as unpaired (logged).
func (p *Plane) loadPairLocked() {
	if p.pair.loaded {
		return
	}
	p.pair.loaded = true
	k, err := readPairedKey(p.pairingPath())
	if err != nil {
		log.Printf("config plane: %v; this router is not paired", err)
		return
	}
	p.pair.key = k
}

func readPairedKey(path string) (*pairedKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(path, 0o600)
	}
	var k pairedKey
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	raw, ok := hex32(k.Key)
	if !ok || PairKeyID(raw) != k.KeyID {
		return nil, fmt.Errorf("%s: the key does not match its id", path)
	}
	k.raw = raw
	return &k, nil
}

// pairedKeyNow is the paired key (nil = not paired).
func (p *Plane) pairedKeyNow() *pairedKey {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	p.loadPairLocked()
	return p.pair.key
}

// expireLocked ends a pairing past its window; the note goes out after the
// lock is released.
func (p *Plane) expireLocked(now time.Time) *PairStateNote {
	c := p.pair.cur
	if c == nil || now.Before(c.expires) {
		return nil
	}
	return p.endLocked(PairExpired)
}

// endLocked drops the pairing in progress with a final state.
func (p *Plane) endLocked(state string) *PairStateNote {
	c := p.pair.cur
	if c == nil {
		return nil
	}
	if c.stop != nil {
		c.stop()
	}
	p.pair.cur = nil
	p.pair.last.id, p.pair.last.state = c.id, state
	log.Printf("config plane: pairing %s %s", c.id, state)
	return &PairStateNote{PairingID: c.id, State: state}
}

func (p *Plane) notifyPair(n *PairStateNote) {
	if n == nil {
		return
	}
	if h := p.hooksNow().PairState; h != nil {
		h(*n)
	}
}

func (p *Plane) armLocked(c *pairing) {
	if c.stop != nil {
		c.stop()
	}
	id := c.id
	c.stop = p.clock.AfterFunc(c.expires.Sub(p.clock.Now()), func() {
		p.pair.mu.Lock()
		var n *PairStateNote
		if p.pair.cur != nil && p.pair.cur.id == id {
			n = p.expireLocked(p.clock.Now())
		}
		p.pair.mu.Unlock()
		p.notifyPair(n)
	})
}

// PairBeginParams, PairRevealParams, PairIDParams, PairForgetParams.
type PairBeginParams struct {
	PairingID     string `json:"pairingId"`
	GatewayID     int64  `json:"gatewayId"`
	ControllerPub string `json:"controllerPub"`
}
type PairRevealParams struct {
	PairingID       string `json:"pairingId"`
	ControllerNonce string `json:"controllerNonce"`
}
type PairIDParams struct {
	PairingID string `json:"pairingId"`
}
type PairForgetParams struct {
	KeyID string `json:"keyId"`
}

// PairBeginResult is gateway.pair.begin's result.
type PairBeginResult struct {
	PairingID  string `json:"pairingId"`
	RouterPub  string `json:"routerPub"`
	Commitment string `json:"commitment"`
	ExpiresAt  string `json:"expiresAt"`
}

// PairRevealResult is gateway.pair.reveal's result.
type PairRevealResult struct {
	PairingID   string `json:"pairingId"`
	RouterNonce string `json:"routerNonce"`
}

// PairStatusResult is gateway.pair.status's (and cancel's) result.
type PairStatusResult struct {
	PairingID string `json:"pairingId"`
	State     string `json:"state"`
	KeyID     string `json:"keyId,omitempty"`
}

// pairGate: pairing needs write access, the router's opt-in for plain
// HTTP, and a transport that is not verified TLS already.
func (p *Plane) pairGate() error {
	if p.o.Access != AccessWrite {
		return &AccessError{Code: ErrNotManaged, Message: "the router does not allow config writes (config_access '" + p.o.Access + "' in /etc/config/perch-collector)"}
	}
	if p.o.TransportOK {
		return perr(CodePairingNotNeeded, "this router talks to the controller over verified TLS: writes need no pairing")
	}
	if !p.o.AllowInsecure {
		return &AccessError{Code: ErrInsecure, Message: "the router does not accept config writes over plain HTTP (config_allow_insecure '0' in /etc/config/perch-collector)"}
	}
	if p.o.SignKey != "" {
		return perr(CodeSignKeyConfigured, "this router signs with its config_sign_key: enter that key on the controller, or remove it to pair")
	}
	return nil
}

// PairBegin is gateway.pair.begin.
func (p *Plane) PairBegin(a *PairBeginParams) (*PairBeginResult, error) {
	if err := p.pairGate(); err != nil {
		return nil, err
	}
	if !pairingIDRe.MatchString(a.PairingID) {
		return nil, perr(CodeBadParams, "pairingId is 16 lowercase hex digits")
	}
	if a.GatewayID <= 0 {
		return nil, perr(CodeBadParams, "gatewayId is a positive number")
	}
	cpub, ok := hex32(a.ControllerPub)
	if !ok {
		return nil, perr(CodeBadParams, "controllerPub is 64 lowercase hex digits")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := X25519Shared(priv, cpub)
	if err != nil {
		return nil, perr(CodeBadParams, "controllerPub: %v", err)
	}
	now := p.clock.Now()
	c := &pairing{
		id: a.PairingID, gatewayID: a.GatewayID, server: p.o.ServerURL,
		controllerPub: cpub, routerPub: priv.PublicKey().Bytes(), nonce: newPairNonce(), shared: shared,
		started: now, expires: now.Add(PairWindow),
	}
	p.pair.mu.Lock()
	p.loadPairLocked()
	if old := p.pair.cur; old != nil {
		p.endLocked(PairCancelled)
		log.Printf("config plane: pairing %s replaced by %s", old.id, c.id)
	}
	p.pair.cur = c
	p.armLocked(c)
	paired := p.pair.key != nil
	p.pair.mu.Unlock()
	log.Printf("config plane: pairing %s begun by the controller (gateway %d)%s", c.id, c.gatewayID,
		map[bool]string{true: "; the confirmed code would replace this router's current key", false: ""}[paired])
	return &PairBeginResult{
		PairingID:  c.id,
		RouterPub:  hex.EncodeToString(c.routerPub),
		Commitment: hex.EncodeToString(PairCommitment(c.nonce, c.routerPub, c.controllerPub)),
		ExpiresAt:  c.expires.UTC().Format(time.RFC3339),
	}, nil
}

// PairReveal is gateway.pair.reveal: once per pairing (a second reveal
// could let a man in the middle choose the controller nonce after seeing
// the router's, so it ends the pairing).
func (p *Plane) PairReveal(a *PairRevealParams) (*PairRevealResult, error) {
	cnonce, ok := hex32(a.ControllerNonce)
	if !ok {
		return nil, perr(CodeBadParams, "controllerNonce is 64 lowercase hex digits")
	}
	p.pair.mu.Lock()
	n := p.expireLocked(p.clock.Now())
	c := p.pair.cur
	if c == nil || c.id != a.PairingID {
		p.pair.mu.Unlock()
		p.notifyPair(n)
		return nil, perr(CodeUnknownPairing, "no pairing %q in progress on this router", a.PairingID)
	}
	if c.revealed {
		n = p.endLocked(PairCancelled)
		p.pair.mu.Unlock()
		p.notifyPair(n)
		return nil, perr(CodeAlreadyRevealed, "pairing %s was revealed already; it is cancelled, start a new one", a.PairingID)
	}
	t := PairTranscript{GatewayID: c.gatewayID, ControllerPub: c.controllerPub, RouterPub: c.routerPub, ControllerNonce: cnonce, RouterNonce: c.nonce}
	c.key = PairKey(c.shared, t)
	c.sas = PairSAS(t)
	c.keyID = PairKeyID(c.key)
	c.revealed = true
	c.expires = p.clock.Now().Add(PairWindow)
	p.armLocked(c)
	res := &PairRevealResult{PairingID: c.id, RouterNonce: hex.EncodeToString(c.nonce)}
	server, sas, expires := c.server, c.sas, c.expires
	p.pair.mu.Unlock()
	// The admin with a shell reads the code here (logread).
	log.Printf("config plane: PAIRING REQUEST from the controller %s: code %s. If the Perch dashboard shows the same code, run on this router: perch-collector pair confirm %s (until %s UTC; otherwise ignore it or run perch-collector pair reject)",
		displayServer(server), sas, sas, expires.UTC().Format("15:04"))
	return res, nil
}

// displayServer is the controller's URL without credentials.
func displayServer(s string) string {
	if s == "" {
		return "(no server_url)"
	}
	if i := strings.Index(s, "@"); i >= 0 {
		if j := strings.Index(s, "://"); j >= 0 && j < i {
			return s[:j+3] + s[i+1:]
		}
	}
	return s
}

// PairStatus is gateway.pair.status.
func (p *Plane) PairStatus(id string) *PairStatusResult {
	p.pair.mu.Lock()
	n := p.expireLocked(p.clock.Now())
	p.loadPairLocked()
	out := &PairStatusResult{PairingID: id, State: PairUnknown}
	switch {
	case p.pair.cur != nil && p.pair.cur.id == id:
		out.State = PairWaitingLocal
	case p.pair.key != nil && p.pair.key.PairingID == id:
		out.State, out.KeyID = PairPaired, p.pair.key.KeyID
	case p.pair.last.id == id && p.pair.last.state != "":
		out.State = p.pair.last.state
		if out.State == PairRejected {
			// The status vocabulary has no "rejected": the pairing is over.
			out.State = PairCancelled
		}
	}
	p.pair.mu.Unlock()
	p.notifyPair(n)
	return out
}

// PairCancel is gateway.pair.cancel: drops the pairing if it is the one in
// progress.
func (p *Plane) PairCancel(id string) *PairStatusResult {
	p.pair.mu.Lock()
	if p.pair.cur != nil && p.pair.cur.id == id {
		p.endLocked(PairCancelled)
	}
	p.pair.mu.Unlock()
	return &PairStatusResult{PairingID: id, State: PairCancelled}
}

// PairForget is gateway.pair.forget: the paired controller drops the key.
// Signed with that key (verified TLS may send it unsigned).
func (p *Plane) PairForget(method string, raw json.RawMessage, sess SessionRef) (any, error) {
	k := p.pairedKeyNow()
	if k == nil {
		return nil, perr(CodeNotPaired, "this router holds no paired key")
	}
	params, signed, err := p.verify(method, raw, sess, k.raw)
	if err != nil {
		return nil, err
	}
	if !signed && !p.o.TransportOK {
		return nil, perr(CodeSignatureRequired, "gateway.pair.forget is signed with the paired key")
	}
	var a PairForgetParams
	if err := json.Unmarshal(params, &a); err != nil {
		return nil, perr(CodeBadParams, "params: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(a.KeyID), []byte(k.KeyID)) != 1 {
		return nil, perr(CodeUnknownKey, "this router's key is not %q", a.KeyID)
	}
	if err := p.dropPairedKey(k); err != nil {
		return nil, err
	}
	log.Printf("config plane: the controller forgot the pairing (key %s)", k.KeyID)
	return map[string]string{"state": PairForgotten}, nil
}

// dropPairedKey removes PairingFile if it still holds k.
func (p *Plane) dropPairedKey(k *pairedKey) error {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	if p.pair.key != k {
		return nil
	}
	if err := os.Remove(p.pairingPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_ = syncDir(filepath.Dir(p.pairingPath()))
	p.pair.key = nil
	return nil
}

// ServePair runs one pairing method.
func (p *Plane) ServePair(_ context.Context, method string, raw json.RawMessage, sess SessionRef) (any, error) {
	decode := func(v any) error {
		if len(raw) == 0 || string(raw) == "null" {
			return perr(CodeBadParams, "params are required")
		}
		if err := json.Unmarshal(raw, v); err != nil {
			return perr(CodeBadParams, "params: %v", err)
		}
		return nil
	}
	switch method {
	case MethodPairBegin:
		var a PairBeginParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.PairBegin(&a)
	case MethodPairReveal:
		var a PairRevealParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.PairReveal(&a)
	case MethodPairStatus:
		var a PairIDParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.PairStatus(a.PairingID), nil
	case MethodPairCancel:
		var a PairIDParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.PairCancel(a.PairingID), nil
	case MethodPairForget:
		return p.PairForget(method, raw, sess)
	}
	return nil, fmt.Errorf("gwconfig: %s is not a pairing method", method)
}

// ── the local side (`perch-collector pair`) ─────────────────────────────

// PairLocal is what `perch-collector pair status` shows.
type PairLocal struct {
	// State: "none", waiting_local (with the code) or "waiting_controller"
	// (begun, not revealed yet).
	Pending *PairPending `json:"pending,omitempty"`
	// Paired: the key this router verifies signed writes with.
	Paired *PairInfo `json:"paired,omitempty"`
	// SignKey: config_sign_key is set (it signs instead of any pairing).
	SignKey bool `json:"configSignKey,omitempty"`
	// Last is the previous pairing's outcome in this run.
	Last *PairStatusResult `json:"last,omitempty"`
}

// PairPending is a pairing in progress.
type PairPending struct {
	PairingID string    `json:"pairingId"`
	GatewayID int64     `json:"gatewayId"`
	Server    string    `json:"server,omitempty"`
	State     string    `json:"state"`
	Code      string    `json:"code,omitempty"`
	Started   time.Time `json:"startedAt"`
	Expires   time.Time `json:"expiresAt"`
	Attempts  int       `json:"attemptsLeft"`
}

// PairInfo describes the paired key (never the key itself).
type PairInfo struct {
	KeyID     string    `json:"keyId"`
	PairingID string    `json:"pairingId"`
	GatewayID int64     `json:"gatewayId"`
	Server    string    `json:"server,omitempty"`
	PairedAt  time.Time `json:"pairedAt"`
}

func (k *pairedKey) info() *PairInfo {
	if k == nil {
		return nil
	}
	return &PairInfo{KeyID: k.KeyID, PairingID: k.PairingID, GatewayID: k.GatewayID, Server: displayServer(k.Server), PairedAt: k.PairedAt}
}

// PairLocalStatus is `perch-collector pair status`.
func (p *Plane) PairLocalStatus() *PairLocal {
	p.pair.mu.Lock()
	n := p.expireLocked(p.clock.Now())
	p.loadPairLocked()
	out := &PairLocal{Paired: p.pair.key.info(), SignKey: p.o.SignKey != ""}
	if c := p.pair.cur; c != nil {
		pp := &PairPending{PairingID: c.id, GatewayID: c.gatewayID, Server: displayServer(c.server), State: "waiting_controller",
			Started: c.started, Expires: c.expires, Attempts: PairMaxAttempts - c.attempts}
		if c.revealed {
			pp.State, pp.Code = PairWaitingLocal, c.sas
		}
		out.Pending = pp
	}
	if p.pair.last.id != "" {
		out.Last = &PairStatusResult{PairingID: p.pair.last.id, State: p.pair.last.state}
	}
	p.pair.mu.Unlock()
	p.notifyPair(n)
	return out
}

// NormalizeCode strips spaces and dashes ("331 510", "331-510").
func NormalizeCode(code string) string {
	return strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(code))
}

// PairConfirmLocal is `perch-collector pair confirm <code>`: with the
// router's code the key is stored and from then on verifies signed writes;
// the controller hears gateway.pair.state paired. Three wrong codes reject
// the pairing.
func (p *Plane) PairConfirmLocal(code string) (*PairInfo, error) {
	code = NormalizeCode(code)
	if !sasRe.MatchString(code) {
		return nil, ErrBadCode
	}
	p.pair.mu.Lock()
	n := p.expireLocked(p.clock.Now())
	c := p.pair.cur
	if c == nil {
		p.pair.mu.Unlock()
		p.notifyPair(n)
		return nil, ErrNoPairing
	}
	if !c.revealed {
		p.pair.mu.Unlock()
		return nil, ErrNotRevealed
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(c.sas)) != 1 {
		c.attempts++
		if c.attempts >= PairMaxAttempts {
			n = p.endLocked(PairRejected)
			p.pair.mu.Unlock()
			p.notifyPair(n)
			return nil, ErrPairingEnded
		}
		left := PairMaxAttempts - c.attempts
		p.pair.mu.Unlock()
		return nil, fmt.Errorf("%w (%d attempt%s left)", ErrCodeMismatch, left, map[bool]string{true: "", false: "s"}[left == 1])
	}
	k := &pairedKey{Version: 1, Key: hex.EncodeToString(c.key), KeyID: c.keyID, PairingID: c.id, GatewayID: c.gatewayID,
		Server: c.server, PairedAt: p.clock.Now().UTC(), raw: c.key}
	data, _ := json.MarshalIndent(k, "", "  ")
	if err := writeFileSync(p.pairingPath(), append(data, '\n'), 0o600); err != nil {
		p.pair.mu.Unlock()
		return nil, fmt.Errorf("storing the key: %w", err)
	}
	if c.stop != nil {
		c.stop()
	}
	p.pair.key = k
	p.pair.loaded = true
	p.pair.cur = nil
	p.pair.last.id, p.pair.last.state = c.id, PairPaired
	p.pair.mu.Unlock()
	log.Printf("config plane: pairing %s confirmed on the router: signed writes use key %s from now on", c.id, k.KeyID)
	p.notifyPair(&PairStateNote{PairingID: c.id, State: PairPaired, KeyID: k.KeyID})
	return k.info(), nil
}

// PairRejectLocal is `perch-collector pair reject`: ends the pairing in
// progress (the controller hears gateway.pair.state rejected).
func (p *Plane) PairRejectLocal() error {
	p.pair.mu.Lock()
	if p.pair.cur == nil {
		p.pair.mu.Unlock()
		return ErrNoPairing
	}
	n := p.endLocked(PairRejected)
	p.pair.mu.Unlock()
	p.notifyPair(n)
	return nil
}

// PairForgetLocal is `perch-collector pair forget`: drops the key; the
// session is redialed so the new hello tells the controller (it marks the
// pairing lost).
func (p *Plane) PairForgetLocal() (*PairInfo, error) {
	k := p.pairedKeyNow()
	if k == nil {
		return nil, ErrNothingToForget
	}
	if err := p.dropPairedKey(k); err != nil {
		return nil, err
	}
	log.Printf("config plane: pairing forgotten on the router (key %s); reconnecting so the controller knows", k.KeyID)
	if h := p.hooksNow().Reconnect; h != nil {
		h("pairing forgotten on the router")
	}
	return k.info(), nil
}

// ForgetPairingFile removes the key without a daemon (the CLI when the
// daemon is not running); nil when there was none.
func ForgetPairingFile(root string) (*PairInfo, error) {
	path := rooted(root, PairingFile)
	k, err := readPairedKey(path)
	if err != nil {
		// A damaged file is removed all the same.
		if rmErr := os.Remove(path); rmErr != nil {
			return nil, err
		}
		return &PairInfo{}, nil
	}
	if k == nil {
		return nil, nil
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return k.info(), nil
}

// ReadPairingFile describes the stored key without a daemon.
func ReadPairingFile(root string) (*PairInfo, error) {
	k, err := readPairedKey(rooted(root, PairingFile))
	if err != nil {
		return nil, err
	}
	return k.info(), nil
}
