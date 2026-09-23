package gwconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func insecure(o *Options) { o.TransportOK = false; o.AllowInsecure = true }

func signed(t *testing.T, e *env, key, method, challenge string, ts time.Time, nonce string, params any) json.RawMessage {
	t.Helper()
	raw, err := Sign([]byte(key), method, challenge, ts.Unix(), nonce, params)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedWritesOverPlainHTTP(t *testing.T) {
	e := newEnv(t, insecure)
	ctx := context.Background()
	sess := SessionRef{Gen: 1, Challenge: "chal-1"}
	var params map[string]any
	json.Unmarshal([]byte(reservationJSON(e, "a1")), &params)
	now := e.clock.Now()

	// Unsigned: refused, and nothing happens.
	raw, _ := json.Marshal(params)
	if _, err := e.p.ServeWrite(ctx, MethodApply, raw, sess); code(err) != CodeSignatureRequired {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{"wrong key", signed(t, e, "other-key", MethodApply, "chal-1", now, "nonce-0000000001", params), CodeBadSignature},
		{"other session", signed(t, e, "test-api-key", MethodApply, "chal-0", now, "nonce-0000000002", params), CodeBadSignature},
		{"other method", signed(t, e, "test-api-key", MethodRollback, "chal-1", now, "nonce-0000000003", params), CodeBadSignature},
		{"too old", signed(t, e, "test-api-key", MethodApply, "chal-1", now.Add(-301*time.Second), "nonce-0000000004", params), CodeStaleSignature},
		{"from the future", signed(t, e, "test-api-key", MethodApply, "chal-1", now.Add(301*time.Second), "nonce-0000000005", params), CodeStaleSignature},
		{"short nonce", signed(t, e, "test-api-key", MethodApply, "chal-1", now, "n1", params), CodeBadSignature},
		{"half an envelope", json.RawMessage(`{"payload":"{}"}`), CodeBadSignature},
		{"version", json.RawMessage(`{"payload":"{}","sig":{"v":2,"ts":1,"nonce":"nonce-0000000006","challenge":"chal-1","mac":"00"}}`), CodeBadSignature},
	}
	for _, c := range cases {
		if _, err := e.p.ServeWrite(ctx, MethodApply, c.raw, sess); code(err) != c.want {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A tampered payload.
	good := signed(t, e, "test-api-key", MethodApply, "chal-1", now, "nonce-0000000007", params)
	var env map[string]any
	json.Unmarshal(good, &env)
	env["payload"] = strings.Replace(env["payload"].(string), "192.168.1.20", "192.168.1.66", 1)
	tampered, _ := json.Marshal(env)
	if _, err := e.p.ServeWrite(ctx, MethodApply, tampered, sess); code(err) != CodeBadSignature {
		t.Fatal(err)
	}
	if e.p.ApplyState().State != StateIdle {
		t.Fatal("a refused request must not take the slot")
	}
	// The good one goes through; replaying it is refused.
	res, err := e.p.ServeWrite(ctx, MethodApply, good, sess)
	if err != nil || res.(*ApplyResult).State != StatePendingConfirm {
		t.Fatalf("%v %v", res, err)
	}
	if _, err := e.p.ServeWrite(ctx, MethodApply, good, sess); code(err) != CodeReplayed {
		t.Fatal(err)
	}
	// Confirm on the next session, signed with its challenge.
	sess2 := SessionRef{Gen: 2, Challenge: "chal-2"}
	c1 := signed(t, e, "test-api-key", MethodConfirm, "chal-1", now, "nonce-0000000008", map[string]string{"applyId": "a1"})
	if _, err := e.p.ServeWrite(ctx, MethodConfirm, c1, sess2); code(err) != CodeBadSignature {
		t.Fatal(err)
	}
	c2 := signed(t, e, "test-api-key", MethodConfirm, "chal-2", now, "nonce-0000000009", map[string]string{"applyId": "a1"})
	if out, err := e.p.ServeWrite(ctx, MethodConfirm, c2, sess2); err != nil || out.(map[string]any)["state"] != StateConfirmed {
		t.Fatalf("%v %v", out, err)
	}
	// Secrets never go over plain HTTP, signed or not.
	sec := map[string]any{"applyId": "s1", "base": e.base("network"),
		"ops":     []any{map[string]any{"op": "put", "config": "network", "section": "wg0", "type": "interface", "options": map[string]any{"private_key": map[string]string{"$secret": "k"}}}},
		"secrets": map[string]string{"k": "v"}}
	if _, err := e.p.ServeWrite(ctx, MethodApply, signed(t, e, "test-api-key", MethodApply, "chal-2", now, "nonce-0000000010", sec), sess2); code(err) != ErrInsecure.Error() {
		t.Fatal(err)
	}
	// Reads need no signature; a stale session has no challenge.
	if _, err := e.p.ServeWrite(ctx, MethodAck, signed(t, e, "test-api-key", MethodAck, "chal-2", now, "nonce-0000000011", map[string]any{"applyIds": []string{}}), SessionRef{}); code(err) != CodeBadSignature {
		t.Fatal(err)
	}
}

func TestSigningWithoutTheOptIn(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.TransportOK = false })
	now := e.clock.Now()
	var params map[string]any
	json.Unmarshal([]byte(reservationJSON(e, "a1")), &params)
	raw := signed(t, e, "test-api-key", MethodApply, "c", now, "nonce-0000000001", params)
	if _, err := e.p.ServeWrite(context.Background(), MethodApply, raw, SessionRef{Gen: 1, Challenge: "c"}); code(err) != ErrInsecure.Error() {
		t.Fatalf("a signature does not replace the router's opt-in: %v", err)
	}
	// Read access only: every write is refused.
	e2 := newEnv(t, func(o *Options) { o.Access = AccessRead })
	if _, err := e2.p.ServeWrite(context.Background(), MethodConfirm, json.RawMessage(`{"applyId":"x"}`), SessionRef{Gen: 1}); code(err) != ErrNotManaged.Error() {
		t.Fatal(err)
	}
}

func TestSignKeyAndHelloBlock(t *testing.T) {
	e := newEnv(t, insecure, func(o *Options) { o.SignKey = "a-separate-signing-key" })
	h := e.p.Hello(context.Background(), "chal")
	if h.Signing == nil || !h.Signing.Required || h.Signing.Key != "config_sign_key" || h.Signing.Challenge != "chal" || h.Signing.WindowSeconds != 300 {
		t.Fatalf("%+v", h.Signing)
	}
	if h.Management == nil || h.Management.NetworkName() != "lan" {
		t.Fatalf("%+v", h.Management)
	}
	now := e.clock.Now()
	var params map[string]any
	json.Unmarshal([]byte(reservationJSON(e, "a1")), &params)
	sess := SessionRef{Gen: 1, Challenge: "chal"}
	if _, err := e.p.ServeWrite(context.Background(), MethodApply, signed(t, e, "test-api-key", MethodApply, "chal", now, "nonce-0000000001", params), sess); code(err) != CodeBadSignature {
		t.Fatalf("the api_key no longer signs: %v", err)
	}
	if _, err := e.p.ServeWrite(context.Background(), MethodApply, signed(t, e, "a-separate-signing-key", MethodApply, "chal", now, "nonce-0000000002", params), sess); err != nil {
		t.Fatal(err)
	}
	// Over verified TLS nothing needs signing, but a signed request is fine.
	e2 := newEnv(t)
	if s := e2.p.Hello(context.Background(), "x").Signing; s.Required || s.Key != "api_key" {
		t.Fatalf("%+v", s)
	}
}

func TestSignatureTestVector(t *testing.T) {
	// The controller implements the same bytes: this vector pins them.
	got := string(SignatureMessage("gateway.config.confirm", "c0ffee", 1790000000, "nonce-0000000001", []byte(`{"applyId":"a1"}`)))
	want := "perch-config-sig-v1\ngateway.config.confirm\nc0ffee\n1790000000\nnonce-0000000001\n" +
		"275ffaf62583a907a897eaad357b77010508dbaed674bbbd8819b344ceba30e8"
	if got != want {
		t.Fatalf("%q", got)
	}
	raw, _ := Sign([]byte("k"), "gateway.config.confirm", "c0ffee", 1790000000, "nonce-0000000001", map[string]string{"applyId": "a1"})
	if string(raw) != `{"payload":"{\"applyId\":\"a1\"}","sig":{"challenge":"c0ffee","mac":"2ae21083603b5bf27157bf935395c42b2d4c607e8d6b93cf3abe9ba59d7b7e9e","nonce":"nonce-0000000001","ts":1790000000,"v":1}}` {
		t.Fatal(string(raw))
	}
}

func TestNonceCacheIsBounded(t *testing.T) {
	var n nonceCache
	now := time.Unix(1790000000, 0)
	for i := 0; i < maxNonces+10; i++ {
		if !n.use(fmt.Sprintf("nonce-%010d", i), now) {
			t.Fatal(i)
		}
	}
	if len(n.order) > maxNonces || len(n.seen) > maxNonces {
		t.Fatal(len(n.order), len(n.seen))
	}
	if n.use(fmt.Sprintf("nonce-%010d", maxNonces+9), now) {
		t.Fatal("recent nonce accepted twice")
	}
	// Expired entries go first.
	later := now.Add(3 * SignatureWindow)
	if !n.use("nonce-fresh-000001", later) || !n.use(fmt.Sprintf("nonce-%010d", maxNonces+9), later) {
		t.Fatal("expired nonces are forgotten")
	}
}
