package gwconfig

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// Signed config RPCs (README 3.3 / 7.1). Over plain HTTP, or an https
// connection whose certificate is not verified, a write is accepted only
// when the router opted in (config_allow_insecure '1') and the request is
// signed. The controller wraps the params:
//
//	{"payload":"<the method's params as a JSON string>",
//	 "sig":{"v":1,"ts":<unix seconds>,"nonce":"<16-128 of [A-Za-z0-9_-]>",
//	        "challenge":"<this session's challenge from the hello>",
//	        "mac":"<hex HMAC-SHA256>"}}
//
// mac = HMAC-SHA256(key, "perch-config-sig-v1\n" + method + "\n" + challenge
// + "\n" + ts + "\n" + nonce + "\n" + hex(SHA-256(payload))), key = the
// router's config_sign_key when set, else the collector's api_key (the
// hello says which). The payload is carried as a string so both ends MAC
// the same bytes without a canonical JSON form.
//
// This gives integrity and replay protection, not confidentiality: the
// method is bound (a signed confirm cannot be replayed as a rollback), the
// challenge binds the request to one session (a new one per connection),
// the timestamp must be within SignatureWindow of the router's clock, and a
// nonce is accepted once.

// SignatureVersion and SignatureWindow of the envelope.
const (
	SignatureVersion = 1
	SignatureWindow  = 300 * time.Second
	sigLabel         = "perch-config-sig-v1"
	maxNonces        = 4096
)

var nonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// Signing is the hello's (and capabilities') signing block: what the
// controller needs to sign.
type Signing struct {
	// Required: this session's writes must be signed (the transport is not
	// verified TLS).
	Required  bool   `json:"required"`
	Challenge string `json:"challenge,omitempty"`
	// Key is "api_key" or "config_sign_key".
	Key           string `json:"key"`
	WindowSeconds int    `json:"windowSeconds"`
}

type envelope struct {
	Payload *string `json:"payload"`
	Sig     *struct {
		V         int    `json:"v"`
		TS        int64  `json:"ts"`
		Nonce     string `json:"nonce"`
		Challenge string `json:"challenge"`
		MAC       string `json:"mac"`
	} `json:"sig"`
}

// SignatureMessage is the text the MAC covers.
func SignatureMessage(method, challenge string, ts int64, nonce string, payload []byte) []byte {
	sum := sha256.Sum256(payload)
	var b bytes.Buffer
	b.WriteString(sigLabel)
	b.WriteByte('\n')
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(challenge)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(ts, 10))
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	return b.Bytes()
}

// Sign builds the envelope for params (the controller's side; tests and the
// lab's fake controller use it).
func Sign(key []byte, method, challenge string, ts int64, nonce string, params any) (json.RawMessage, error) {
	payload, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write(SignatureMessage(method, challenge, ts, nonce, payload))
	env := map[string]any{
		"payload": string(payload),
		"sig": map[string]any{"v": SignatureVersion, "ts": ts, "nonce": nonce, "challenge": challenge,
			"mac": hex.EncodeToString(m.Sum(nil))},
	}
	return json.Marshal(env)
}

// NewChallenge returns a fresh session challenge.
func NewChallenge() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// nonceCache remembers accepted nonces until they could no longer pass the
// timestamp check.
type nonceCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	order []string
}

func (n *nonceCache) use(nonce string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = map[string]time.Time{}
	}
	if exp, ok := n.seen[nonce]; ok && now.Before(exp) {
		return false
	}
	if len(n.order) >= maxNonces {
		// Drop expired ones, then the oldest.
		kept := n.order[:0]
		for _, k := range n.order {
			if now.Before(n.seen[k]) {
				kept = append(kept, k)
			} else {
				delete(n.seen, k)
			}
		}
		n.order = kept
		for len(n.order) >= maxNonces {
			delete(n.seen, n.order[0])
			n.order = n.order[1:]
		}
	}
	n.seen[nonce] = now.Add(2 * SignatureWindow)
	n.order = append(n.order, nonce)
	return true
}

// signKey is the HMAC key and its name.
func (p *Plane) signKey() ([]byte, string) {
	if p.o.SignKey != "" {
		return []byte(p.o.SignKey), "config_sign_key"
	}
	return []byte(p.o.APIKey), "api_key"
}

// SigningFor is the signing block of a session with this challenge.
func (p *Plane) SigningFor(challenge string) *Signing {
	_, name := p.signKey()
	return &Signing{Required: !p.o.TransportOK, Challenge: challenge, Key: name, WindowSeconds: int(SignatureWindow / time.Second)}
}

// Unwrap returns a request's params: the payload of a verified envelope
// (signed true), or the params as they are.
func (p *Plane) Unwrap(method string, raw json.RawMessage, sess SessionRef) (json.RawMessage, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return raw, false, nil
	}
	var env envelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return raw, false, nil
	}
	if env.Payload == nil && env.Sig == nil {
		return raw, false, nil
	}
	if env.Payload == nil || env.Sig == nil {
		return nil, false, perr(CodeBadSignature, "a signed request has both payload and sig")
	}
	s := env.Sig
	if s.V != SignatureVersion {
		return nil, false, perr(CodeBadSignature, "signature version %d is not supported (want %d)", s.V, SignatureVersion)
	}
	if !nonceRe.MatchString(s.Nonce) {
		return nil, false, perr(CodeBadSignature, "the nonce is 16-128 characters of [A-Za-z0-9_-]")
	}
	if sess.Challenge == "" || !hmac.Equal([]byte(s.Challenge), []byte(sess.Challenge)) {
		return nil, false, perr(CodeBadSignature, "signed for another session (challenge mismatch)")
	}
	now := p.o.Now()
	skew := now.Sub(time.Unix(s.TS, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > SignatureWindow {
		e := perr(CodeStaleSignature, "the signature's timestamp is %s away from the router's clock (window %s)", skew.Round(time.Second), SignatureWindow)
		e.Data = map[string]any{"agentTime": now.UTC().Unix()}
		return nil, false, e
	}
	mac, err := hex.DecodeString(s.MAC)
	if err != nil || len(mac) != sha256.Size {
		return nil, false, perr(CodeBadSignature, "mac is 64 hex digits")
	}
	key, _ := p.signKey()
	m := hmac.New(sha256.New, key)
	payload := []byte(*env.Payload)
	m.Write(SignatureMessage(method, s.Challenge, s.TS, s.Nonce, payload))
	if !hmac.Equal(mac, m.Sum(nil)) {
		return nil, false, perr(CodeBadSignature, "the signature does not verify")
	}
	if !p.nonces.use(s.Nonce, now) {
		return nil, false, perr(CodeReplayed, "this nonce was used already")
	}
	return payload, true, nil
}

// writeGate decides whether a write may go ahead: access write, and a
// verified transport or (the router's opt-in and a signed request).
func (p *Plane) writeGate(signed bool) error {
	if p.o.Access != AccessWrite {
		return &AccessError{Code: ErrNotManaged, Message: "the router does not allow config writes (config_access '" + p.o.Access + "' in /etc/config/perch-collector)"}
	}
	if p.o.TransportOK {
		return nil
	}
	if !p.o.AllowInsecure {
		return &AccessError{Code: ErrInsecure, Message: "writes need https with a verified certificate, or config_allow_insecure '1' on the router and signed requests"}
	}
	if !signed {
		return perr(CodeSignatureRequired, "this router accepts writes over an unverified transport only when they are signed (see the hello's signing block)")
	}
	return nil
}
