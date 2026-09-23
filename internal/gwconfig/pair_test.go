package gwconfig

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The controller's pinned vector (docs/gateway/config-plane.md 4.4, RFC
// 7748 section 6.1 keys): both ends must derive the same bytes.
func TestPairingVector(t *testing.T) {
	cpriv, err := ecdh.X25519().NewPrivateKey(unhex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	rpriv, _ := ecdh.X25519().NewPrivateKey(unhex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	cpub, rpub := cpriv.PublicKey().Bytes(), rpriv.PublicKey().Bytes()
	if hex.EncodeToString(cpub) != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" ||
		hex.EncodeToString(rpub) != "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f" {
		t.Fatal("public keys")
	}
	shared, err := X25519Shared(rpriv, cpub)
	if err != nil || hex.EncodeToString(shared) != "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" {
		t.Fatalf("shared %x %v", shared, err)
	}
	if other, _ := X25519Shared(cpriv, rpub); !bytes.Equal(other, shared) {
		t.Fatal("both ends")
	}
	cn, rn := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	if got := hex.EncodeToString(PairCommitment(rn, rpub, cpub)); got != "ff24b3e804967019f7662f53a2499f330b0c5fc227540479bcecea5dc678e9c4" {
		t.Fatal("commitment", got)
	}
	tr := PairTranscript{GatewayID: 7, ControllerPub: cpub, RouterPub: rpub, ControllerNonce: cn, RouterNonce: rn}
	key := PairKey(shared, tr)
	if hex.EncodeToString(key) != "6ab9f1d40416ea38eb9b448cecef75bc2ab631a5940225c5fd80df386f1edacb" {
		t.Fatalf("key %x", key)
	}
	if sas := PairSAS(tr); sas != "331510" {
		t.Fatal("sas", sas)
	}
	if id := PairKeyID(key); id != "38545dab8f16e8a2" {
		t.Fatal("keyId", id)
	}
	// A low-order controller key (all zeros) is refused.
	if _, err := X25519Shared(rpriv, make([]byte, 32)); err == nil {
		t.Fatal("low-order key accepted")
	}
}

// ctlPair is the controller's half, as pairing.ts does it.
type ctlPair struct {
	id    string
	gw    int64
	priv  *ecdh.PrivateKey
	nonce []byte
	begin *PairBeginResult
	key   []byte
	sas   string
	keyID string
}

func newCtlPair(id string) *ctlPair {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return &ctlPair{id: id, gw: 7, priv: priv, nonce: newPairNonce()}
}

func (c *ctlPair) beginParams() *PairBeginParams {
	return &PairBeginParams{PairingID: c.id, GatewayID: c.gw, ControllerPub: hex.EncodeToString(c.priv.PublicKey().Bytes())}
}

func (c *ctlPair) revealParams() *PairRevealParams {
	return &PairRevealParams{PairingID: c.id, ControllerNonce: hex.EncodeToString(c.nonce)}
}

// finish checks the commitment and derives key and code.
func (c *ctlPair) finish(rev *PairRevealResult) error {
	rpub, _ := hex.DecodeString(c.begin.RouterPub)
	rn, _ := hex.DecodeString(rev.RouterNonce)
	commit, _ := hex.DecodeString(c.begin.Commitment)
	if !hmac.Equal(commit, PairCommitment(rn, rpub, c.priv.PublicKey().Bytes())) {
		return errors.New("commitment mismatch")
	}
	shared, err := X25519Shared(c.priv, rpub)
	if err != nil {
		return err
	}
	tr := PairTranscript{GatewayID: c.gw, ControllerPub: c.priv.PublicKey().Bytes(), RouterPub: rpub, ControllerNonce: c.nonce, RouterNonce: rn}
	c.key, c.sas = PairKey(shared, tr), PairSAS(tr)
	c.keyID = PairKeyID(c.key)
	return nil
}

type pairNotes struct {
	mu    sync.Mutex
	notes []PairStateNote
}

func (n *pairNotes) hook(p *Plane) {
	h := p.hooksNow()
	h.PairState = func(s PairStateNote) bool {
		n.mu.Lock()
		n.notes = append(n.notes, s)
		n.mu.Unlock()
		return true
	}
	p.SetHooks(h)
}

func (n *pairNotes) last() PairStateNote {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.notes) == 0 {
		return PairStateNote{}
	}
	return n.notes[len(n.notes)-1]
}

// pairUp runs a whole pairing on e and returns the controller's half.
func pairUp(t *testing.T, e *env, id string) *ctlPair {
	t.Helper()
	c := newCtlPair(id)
	var err error
	if c.begin, err = e.p.PairBegin(c.beginParams()); err != nil {
		t.Fatal(err)
	}
	rev, err := e.p.PairReveal(c.revealParams())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.finish(rev); err != nil {
		t.Fatal(err)
	}
	if st := e.p.PairLocalStatus(); st.Pending == nil || st.Pending.Code != c.sas || st.Pending.State != PairWaitingLocal {
		t.Fatalf("the router shows %+v, the controller %s", st.Pending, c.sas)
	}
	if _, err := e.p.PairConfirmLocal(c.sas); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPairingRoundTripAndSignedWrites(t *testing.T) {
	e := newEnv(t, insecure)
	var notes pairNotes
	notes.hook(e.p)
	ctx := context.Background()
	sess := SessionRef{Gen: 1, Challenge: "chal-1"}
	now := e.clock.Now()
	var params map[string]any
	json.Unmarshal([]byte(reservationJSON(e, "a1")), &params)

	// Unpaired: the hello names no key, and nothing signs: the api_key is
	// refused like any other key.
	if s := e.p.Hello(ctx, "chal-1").Signing; s.Key != SignKeyNone || s.KeyID != "" || !s.Required {
		t.Fatalf("%+v", s)
	}
	if _, err := e.p.ServeWrite(ctx, MethodApply, signed(t, e, "test-api-key", MethodApply, "chal-1", now, "nonce-0000000001", params), sess); code(err) != CodeNotPaired {
		t.Fatalf("api_key-signed write: %v", err)
	}

	c := newCtlPair("00112233aabbccdd")
	begin, err := e.p.ServePair(ctx, MethodPairBegin, rawJSON(c.beginParams()), sess)
	if err != nil {
		t.Fatal(err)
	}
	c.begin = begin.(*PairBeginResult)
	if exp, _ := time.Parse(time.RFC3339, c.begin.ExpiresAt); !exp.Equal(now.Add(PairWindow)) {
		t.Fatal(c.begin.ExpiresAt)
	}
	if st, _ := e.p.ServePair(ctx, MethodPairStatus, json.RawMessage(`{"pairingId":"00112233aabbccdd"}`), sess); st.(*PairStatusResult).State != PairWaitingLocal {
		t.Fatalf("%+v", st)
	}
	// No code before the reveal.
	if _, err := e.p.PairConfirmLocal("123456"); !errors.Is(err, ErrNotRevealed) {
		t.Fatal(err)
	}
	rev, err := e.p.ServePair(ctx, MethodPairReveal, rawJSON(c.revealParams()), sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.finish(rev.(*PairRevealResult)); err != nil {
		t.Fatal(err)
	}
	st := e.p.PairLocalStatus()
	if st.Pending.Code != c.sas || st.Paired != nil {
		t.Fatalf("codes differ: router %+v, controller %s", st.Pending, c.sas)
	}
	// A code with a space is fine; the key lands on flash, root only.
	info, err := e.p.PairConfirmLocal(c.sas[:3] + " " + c.sas[3:])
	if err != nil || info.KeyID != c.keyID || info.GatewayID != 7 {
		t.Fatalf("%+v %v", info, err)
	}
	if n := notes.last(); n != (PairStateNote{PairingID: c.id, State: PairPaired, KeyID: c.keyID}) {
		t.Fatalf("%+v", n)
	}
	fi, err := os.Stat(filepath.Join(e.root, "etc/perch-collector/pairing.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal(fi, err)
	}
	if s := e.p.Hello(ctx, "chal-1").Signing; s.Key != SignKeyPaired || s.KeyID != c.keyID {
		t.Fatalf("%+v", s)
	}
	if st, _ := e.p.ServePair(ctx, MethodPairStatus, json.RawMessage(`{"pairingId":"00112233aabbccdd"}`), sess); *st.(*PairStatusResult) != (PairStatusResult{PairingID: c.id, State: PairPaired, KeyID: c.keyID}) {
		t.Fatalf("%+v", st)
	}

	// Signed with the paired key: accepted. The api_key: refused.
	if _, err := e.p.ServeWrite(ctx, MethodApply, signed(t, e, "test-api-key", MethodApply, "chal-1", now, "nonce-0000000002", params), sess); code(err) != CodeBadSignature {
		t.Fatal(err)
	}
	res, err := e.p.ServeWrite(ctx, MethodApply, signed(t, e, string(c.key), MethodApply, "chal-1", now, "nonce-0000000003", params), sess)
	if err != nil || res.(*ApplyResult).State != StatePendingConfirm {
		t.Fatalf("%v %v", res, err)
	}

	// The key survives a restart of the daemon.
	p2 := New(e.p.o)
	if s := p2.Hello(ctx, "x").Signing; s.Key != SignKeyPaired || s.KeyID != c.keyID {
		t.Fatalf("after a restart: %+v", s)
	}

	// Forget: only signed with that key, and only for its id.
	forget := func(key, keyID, nonce string) error {
		_, err := e.p.ServePair(ctx, MethodPairForget, signed(t, e, key, MethodPairForget, "chal-1", now, nonce, map[string]string{"keyId": keyID}), sess)
		return err
	}
	if _, err := e.p.ServePair(ctx, MethodPairForget, rawJSON(map[string]string{"keyId": c.keyID}), sess); code(err) != CodeSignatureRequired {
		t.Fatal(err)
	}
	if err := forget("test-api-key", c.keyID, "nonce-0000000010"); code(err) != CodeBadSignature {
		t.Fatal(err)
	}
	if err := forget(string(c.key), "0000000000000000", "nonce-0000000011"); code(err) != CodeUnknownKey {
		t.Fatal(err)
	}
	// A signed forget cannot be replayed as a write (the method is bound).
	fw, _ := Sign(c.key, MethodPairForget, "chal-1", now.Unix(), "nonce-0000000012", map[string]string{"keyId": c.keyID})
	if _, err := e.p.ServeWrite(ctx, MethodAck, fw, sess); code(err) != CodeBadSignature {
		t.Fatal(err)
	}
	if err := forget(string(c.key), c.keyID, "nonce-0000000013"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.root, "etc/perch-collector/pairing.json")); !os.IsNotExist(err) {
		t.Fatal("key file left", err)
	}
	if s := e.p.Hello(ctx, "chal-1").Signing; s.Key != SignKeyNone {
		t.Fatalf("%+v", s)
	}
	// Forgotten: the paired key signs nothing any more.
	if _, err := e.p.ServeWrite(ctx, MethodAck, signed(t, e, string(c.key), MethodAck, "chal-1", now, "nonce-0000000014", map[string]any{"applyIds": []string{}}), sess); code(err) != CodeNotPaired {
		t.Fatal(err)
	}
	if err := forget(string(c.key), c.keyID, "nonce-0000000015"); code(err) != CodeNotPaired {
		t.Fatal(err)
	}
}

func rawJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func TestPairingGates(t *testing.T) {
	c := newCtlPair("00112233aabbccdd")
	for _, tc := range []struct {
		name string
		opt  envOpt
		want string
	}{
		{"read access", func(o *Options) { insecure(o); o.Access = AccessRead }, ErrNotManaged.Error()},
		{"verified TLS", func(o *Options) {}, CodePairingNotNeeded},
		{"no opt-in", func(o *Options) { o.TransportOK = false }, ErrInsecure.Error()},
		{"config_sign_key", func(o *Options) { insecure(o); o.SignKey = "a-separate-signing-key" }, CodeSignKeyConfigured},
	} {
		e := newEnv(t, tc.opt)
		if _, err := e.p.PairBegin(c.beginParams()); code(err) != tc.want {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	e := newEnv(t, insecure)
	bad := []*PairBeginParams{
		{PairingID: "short", GatewayID: 7, ControllerPub: c.beginParams().ControllerPub},
		{PairingID: c.id, GatewayID: 0, ControllerPub: c.beginParams().ControllerPub},
		{PairingID: c.id, GatewayID: 7, ControllerPub: strings.ToUpper(c.beginParams().ControllerPub)},
		{PairingID: c.id, GatewayID: 7, ControllerPub: strings.Repeat("0", 64)}, // low order
	}
	for i, b := range bad {
		if _, err := e.p.PairBegin(b); code(err) != CodeBadParams {
			t.Errorf("%d: %v", i, err)
		}
	}
	if _, err := e.p.ServePair(context.Background(), MethodPairBegin, nil, SessionRef{}); code(err) != CodeBadParams {
		t.Fatal(err)
	}
	if e.p.PairLocalStatus().Pending != nil {
		t.Fatal("a refused begin left a pairing")
	}
}

// A man in the middle who swaps the router's key breaks the commitment.
func TestPairingMITMWrongCommitment(t *testing.T) {
	e := newEnv(t, insecure)
	c := newCtlPair("00112233aabbccdd")
	begin, err := e.p.PairBegin(c.beginParams())
	if err != nil {
		t.Fatal(err)
	}
	// The attacker forwards its own public key with the router's commitment.
	evil, _ := ecdh.X25519().GenerateKey(rand.Reader)
	c.begin = &PairBeginResult{PairingID: begin.PairingID, RouterPub: hex.EncodeToString(evil.PublicKey().Bytes()), Commitment: begin.Commitment}
	rev, err := e.p.PairReveal(c.revealParams())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.finish(rev); err == nil {
		t.Fatal("a swapped router key passed the commitment")
	}
	// ... and a forged nonce with a genuine key does too.
	c.begin = begin
	forged := *rev
	forged.RouterNonce = hex.EncodeToString(newPairNonce())
	if err := c.finish(&forged); err == nil {
		t.Fatal("a forged nonce passed the commitment")
	}
	if err := c.finish(rev); err != nil {
		t.Fatal(err)
	}
}

// A man in the middle who runs one exchange with each side: the router's
// code differs from the controller's, so the admin's confirm fails.
func TestPairingMITMCodesDiffer(t *testing.T) {
	e := newEnv(t, insecure)
	var notes pairNotes
	notes.hook(e.p)
	ctl := newCtlPair("00112233aabbccdd")
	mitm := newCtlPair("00112233aabbccdd") // the attacker, to the router
	var err error
	if mitm.begin, err = e.p.PairBegin(mitm.beginParams()); err != nil {
		t.Fatal(err)
	}
	rev, err := e.p.PairReveal(mitm.revealParams())
	if err != nil {
		t.Fatal(err)
	}
	if err := mitm.finish(rev); err != nil {
		t.Fatal(err)
	}
	// The attacker plays the router to the controller with its own key and
	// nonce; the controller's code comes from that transcript.
	fakeRouter := newCtlPair("00112233aabbccdd")
	fpub := fakeRouter.priv.PublicKey().Bytes()
	ctl.begin = &PairBeginResult{PairingID: ctl.id, RouterPub: hex.EncodeToString(fpub),
		Commitment: hex.EncodeToString(PairCommitment(fakeRouter.nonce, fpub, ctl.priv.PublicKey().Bytes()))}
	if err := ctl.finish(&PairRevealResult{PairingID: ctl.id, RouterNonce: hex.EncodeToString(fakeRouter.nonce)}); err != nil {
		t.Fatal(err)
	}
	routerCode := e.p.PairLocalStatus().Pending.Code
	if routerCode == ctl.sas {
		t.Skip("1 in 10^6: the codes collided")
	}
	// The admin types the controller's code on the router: refused, and
	// after three tries the pairing is rejected and the controller told.
	for i := 1; i <= PairMaxAttempts; i++ {
		_, err := e.p.PairConfirmLocal(ctl.sas)
		if i < PairMaxAttempts && !errors.Is(err, ErrCodeMismatch) {
			t.Fatal(i, err)
		}
		if i == PairMaxAttempts && !errors.Is(err, ErrPairingEnded) {
			t.Fatal(err)
		}
	}
	if n := notes.last(); n.State != PairRejected || n.PairingID != ctl.id {
		t.Fatalf("%+v", n)
	}
	if st := e.p.PairLocalStatus(); st.Pending != nil || st.Paired != nil {
		t.Fatalf("%+v", st)
	}
	// Even the right code is too late now.
	if _, err := e.p.PairConfirmLocal(routerCode); !errors.Is(err, ErrNoPairing) {
		t.Fatal(err)
	}
	if st := e.p.PairStatus(ctl.id); st.State != PairCancelled {
		t.Fatalf("%+v", st)
	}
}

// One reveal per pairing: a second one (a replay, or an attacker trying
// another controller nonce after seeing the router's) ends it.
func TestPairingReplayedReveal(t *testing.T) {
	e := newEnv(t, insecure)
	var notes pairNotes
	notes.hook(e.p)
	c := newCtlPair("00112233aabbccdd")
	var err error
	if c.begin, err = e.p.PairBegin(c.beginParams()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.PairReveal(c.revealParams()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.PairReveal(c.revealParams()); code(err) != CodeAlreadyRevealed {
		t.Fatal(err)
	}
	if n := notes.last(); n.State != PairCancelled || n.PairingID != c.id {
		t.Fatalf("%+v", n)
	}
	if _, err := e.p.PairConfirmLocal("000000"); !errors.Is(err, ErrNoPairing) {
		t.Fatal(err)
	}
	// Reveal of another pairing, or a bad nonce.
	c2 := newCtlPair("aaaaaaaaaaaaaaaa")
	if _, err := e.p.PairBegin(c2.beginParams()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.PairReveal(c.revealParams()); code(err) != CodeUnknownPairing {
		t.Fatal(err)
	}
	if _, err := e.p.PairReveal(&PairRevealParams{PairingID: c2.id, ControllerNonce: "xyz"}); code(err) != CodeBadParams {
		t.Fatal(err)
	}
	// The failed attempts did not spend c2's reveal.
	if _, err := e.p.PairReveal(c2.revealParams()); err != nil {
		t.Fatal(err)
	}
}

func TestPairingWindowsAndReplacement(t *testing.T) {
	e := newEnv(t, insecure)
	var notes pairNotes
	notes.hook(e.p)
	c := newCtlPair("00112233aabbccdd")
	if _, err := e.p.PairBegin(c.beginParams()); err != nil {
		t.Fatal(err)
	}
	// Never revealed: expires after the window, and the controller hears it.
	e.clock.Advance(PairWindow + time.Second)
	if n := notes.last(); n != (PairStateNote{PairingID: c.id, State: PairExpired}) {
		t.Fatalf("%+v", n)
	}
	if st := e.p.PairStatus(c.id); st.State != PairExpired {
		t.Fatalf("%+v", st)
	}
	if _, err := e.p.PairReveal(c.revealParams()); code(err) != CodeUnknownPairing {
		t.Fatal(err)
	}

	// Revealed, then the local confirm comes too late.
	c = newCtlPair("1111111111111111")
	var err error
	if c.begin, err = e.p.PairBegin(c.beginParams()); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(PairWindow - time.Minute)
	rev, err := e.p.PairReveal(c.revealParams())
	if err != nil {
		t.Fatal(err)
	}
	c.finish(rev)
	e.clock.Advance(PairWindow - time.Second) // the reveal restarted the window
	if st := e.p.PairLocalStatus(); st.Pending == nil {
		t.Fatal("expired early")
	}
	e.clock.Advance(2 * time.Second)
	if _, err := e.p.PairConfirmLocal(c.sas); !errors.Is(err, ErrNoPairing) {
		t.Fatal(err)
	}

	// A new begin replaces an unfinished pairing.
	a, b := newCtlPair("2222222222222222"), newCtlPair("3333333333333333")
	if _, err := e.p.PairBegin(a.beginParams()); err != nil {
		t.Fatal(err)
	}
	if b.begin, err = e.p.PairBegin(b.beginParams()); err != nil {
		t.Fatal(err)
	}
	if st := e.p.PairStatus(a.id); st.State != PairCancelled {
		t.Fatalf("%+v", st)
	}
	if _, err := e.p.PairReveal(a.revealParams()); code(err) != CodeUnknownPairing {
		t.Fatal(err)
	}
	// Cancel only drops its own pairing.
	if st := e.p.PairCancel(a.id); st.State != PairCancelled || e.p.PairLocalStatus().Pending == nil {
		t.Fatal("cancel of another id dropped the pairing")
	}
	e.p.PairCancel(b.id)
	if e.p.PairLocalStatus().Pending != nil {
		t.Fatal("not cancelled")
	}
	if st := e.p.PairStatus("4444444444444444"); st.State != PairUnknown {
		t.Fatalf("%+v", st)
	}
	// Local reject.
	if err := e.p.PairRejectLocal(); !errors.Is(err, ErrNoPairing) {
		t.Fatal(err)
	}
	if _, err := e.p.PairBegin(a.beginParams()); err != nil {
		t.Fatal(err)
	}
	if err := e.p.PairRejectLocal(); err != nil || notes.last().State != PairRejected {
		t.Fatal(err, notes.last())
	}
	if e.clock.active() != 0 {
		t.Fatalf("%d timers left", e.clock.active())
	}
}

func TestPairingRepairAndLocalForget(t *testing.T) {
	e := newEnv(t, insecure)
	first := pairUp(t, e, "00112233aabbccdd")
	// A second pairing (a restored controller) replaces the key once confirmed.
	second := pairUp(t, e, "5555555555555555")
	if first.keyID == second.keyID {
		t.Fatal("same key")
	}
	if s := e.p.SigningFor("c"); s.KeyID != second.keyID {
		t.Fatalf("%+v", s)
	}
	// Forget on the router: the key goes, and the session is redialed so
	// the controller sees the hello without it.
	info, err := e.p.PairForgetLocal()
	if err != nil || info.KeyID != second.keyID {
		t.Fatal(info, err)
	}
	select {
	case r := <-e.reconCh:
		if !strings.Contains(r, "pairing") {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("no reconnect")
	}
	if _, err := e.p.PairForgetLocal(); !errors.Is(err, ErrNothingToForget) {
		t.Fatal(err)
	}
	// Without a daemon.
	pairUp(t, e, "6666666666666666")
	if info, err := ReadPairingFile(e.root); err != nil || info == nil {
		t.Fatal(info, err)
	}
	if info, err := ForgetPairingFile(e.root); err != nil || info == nil {
		t.Fatal(info, err)
	}
	if info, err := ForgetPairingFile(e.root); err != nil || info != nil {
		t.Fatal(info, err)
	}
}

func TestPairingFileChecks(t *testing.T) {
	e := newEnv(t, insecure)
	c := pairUp(t, e, "00112233aabbccdd")
	path := filepath.Join(e.root, "etc/perch-collector/pairing.json")
	// Loosened permissions are tightened at load.
	os.Chmod(path, 0o644)
	if s := New(e.p.o).SigningFor("c"); s.KeyID != c.keyID {
		t.Fatalf("%+v", s)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	// A key that does not match its id is not used.
	data, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.Replace(data, []byte(c.keyID), []byte("0000000000000000"), 1), 0o600)
	if s := New(e.p.o).SigningFor("c"); s.Key != SignKeyNone {
		t.Fatalf("%+v", s)
	}
}

func TestPairLocalSocket(t *testing.T) {
	e := newEnv(t, insecure)
	var notes pairNotes
	notes.hook(e.p)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.p.ServePairSocket(ctx) }()
	sock := e.p.PairSocketPath()
	var res *PairResponse
	var err error
	for i := 0; i < 100; i++ {
		if res, err = PairCall(sock, PairRequest{Cmd: "status"}); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || !res.OK || res.Status.Paired != nil || res.Status.Pending != nil {
		t.Fatal(res, err)
	}
	fi, _ := os.Stat(sock)
	if fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	if di, _ := os.Stat(filepath.Dir(sock)); di.Mode().Perm() != 0o700 {
		t.Fatal(di.Mode())
	}
	c := newCtlPair("00112233aabbccdd")
	c.begin, _ = e.p.PairBegin(c.beginParams())
	rev, _ := e.p.PairReveal(c.revealParams())
	c.finish(rev)
	res, _ = PairCall(sock, PairRequest{Cmd: "status"})
	if res.Status.Pending.Code != c.sas {
		t.Fatalf("%+v", res.Status.Pending)
	}
	wrong := "000000"
	if c.sas == wrong {
		wrong = "111111"
	}
	res, _ = PairCall(sock, PairRequest{Cmd: "confirm", Code: wrong})
	if res.OK || !strings.Contains(res.Error, "does not match") || res.Status.Pending.Attempts != 2 {
		t.Fatalf("%+v", res)
	}
	res, _ = PairCall(sock, PairRequest{Cmd: "confirm", Code: c.sas})
	if !res.OK || res.Paired.KeyID != c.keyID || notes.last().State != PairPaired {
		t.Fatalf("%+v", res)
	}
	res, _ = PairCall(sock, PairRequest{Cmd: "forget"})
	if !res.OK || res.Paired.KeyID != c.keyID {
		t.Fatalf("%+v", res)
	}
	res, _ = PairCall(sock, PairRequest{Cmd: "bogus"})
	if res.OK {
		t.Fatal("bogus command")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := PairCall(sock, PairRequest{Cmd: "status"}); !errors.Is(err, ErrNoDaemon) {
		t.Fatal(err)
	}
}
