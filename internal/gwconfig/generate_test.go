package gwconfig

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Vectors from `wg pubkey`: the RFC 7748 6.1 private key of Alice (run on an
// OpenWrt 23.05 router: the output is the RFC's public key), and a key from
// `wg genkey` (wireguard-tools on a Linux host).
var wgVectors = []struct{ priv, pub string }{
	{"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="},
	{"mK80vlVPxDbJ4ADOfM2pL5wUubkWjzagYjjns+u64mo=", "h2JuDOapLIkfnq2pIjYYqAAZSLuMqTNYnph5tS1CB0U="},
}

func TestWGPublicKeyMatchesWgPubkey(t *testing.T) {
	for _, v := range wgVectors {
		got, err := WGPublicKey(v.priv)
		if err != nil || got != v.pub {
			t.Fatalf("WGPublicKey(%s) = %s, %v; wg pubkey says %s", v.priv, got, err, v.pub)
		}
	}
	if _, err := WGPublicKey("short"); err == nil {
		t.Fatal("a malformed key must be refused")
	}
}

func TestGeneratedKeysAreWireGuardPrivateKeys(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		priv, pub, err := generateValue(GenerateWGPrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		b, err := base64.StdEncoding.DecodeString(priv)
		if err != nil || len(b) != 32 || !validWGKey(priv) || !validWGKey(pub) {
			t.Fatalf("%q / %q", priv, pub)
		}
		// Clamped like `wg genkey`.
		if b[0]&7 != 0 || b[31]&128 != 0 || b[31]&64 == 0 {
			t.Fatalf("not clamped: %x", b)
		}
		if want, _ := WGPublicKey(priv); want != pub {
			t.Fatalf("public %s, derived %s", pub, want)
		}
		if seen[priv] {
			t.Fatal("the same key twice")
		}
		seen[priv] = true
	}
	if _, _, err := generateValue("rsa_key"); err == nil {
		t.Fatal("unknown kind")
	}
}

func wgPutJSON(e *env, id string, extra string) string {
	return `{"applyId":"` + id + `","base":` + mustJSON(e.base("network")) + `,"ops":[{"op":"put","config":"network","section":"wg0","type":"interface",
	  "options":{"proto":"wireguard","private_key":{"$generate":"wg_private_key"},"listen_port":"51820","addresses":["192.168.9.1/24"]}}]` + extra + `}`
}

// The router makes the key during the apply: the committed file has it,
// the reply only its public half, and it is never logged or kept anywhere
// but the config (and the rollback snapshot of the config).
func TestGenerateWGPrivateKeyOnApply(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	e := newEnv(t)
	res, err := e.apply(wgPutJSON(e, "g1", ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StatePendingConfirm || len(res.Generated) != 1 {
		t.Fatalf("%+v", res)
	}
	g := res.Generated[0]
	if g.Config != "network" || g.Section != "wg0" || g.Option != "private_key" || !validWGKey(g.PublicKey) {
		t.Fatalf("%+v", g)
	}
	sec := e.load("network").Section("wg0")
	if sec == nil {
		t.Fatal(e.file("network"))
	}
	pv, _ := sec.Get("private_key")
	priv := pv.Str()
	if !validWGKey(priv) || priv == g.PublicKey {
		t.Fatalf("committed private_key %q", priv)
	}
	if pub, _ := WGPublicKey(priv); pub != g.PublicKey {
		t.Fatalf("reported %s, the committed key's is %s", g.PublicKey, pub)
	}
	if p, _ := sec.Get("proto"); p.Str() != "wireguard" {
		t.Fatal(e.file("network"))
	}
	// The reply, a retried apply's reply, the hello, the pending record and
	// the log carry the public key at most.
	again, err := e.apply(wgPutJSON(e, "g1", ""))
	if err != nil || len(again.Generated) != 1 || again.Generated[0] != g {
		t.Fatalf("%+v %v", again, err)
	}
	record, _ := os.ReadFile(filepath.Join(e.root, "etc/perch-collector/rollback/pending.json"))
	if !strings.Contains(string(record), g.PublicKey) {
		t.Fatalf("pending record without the public key: %s", record)
	}
	hello, _ := json.Marshal(e.p.Hello(context.Background(), "c9"))
	for what, text := range map[string]string{"reply": mustJSON(res), "retry": mustJSON(again), "pending record": string(record),
		"hello": string(hello), "log": logs.String()} {
		if strings.Contains(text, priv) {
			t.Fatalf("the private key is in the %s: %s", what, text)
		}
	}
	// A read shows the key's fingerprint only.
	read, err := e.p.Read([]string{"network"})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(read); strings.Contains(string(b), priv) || !strings.Contains(string(b), `"private_key":"hmac:`) {
		t.Fatalf("read: %s", b)
	}

	// No confirm: the rollback takes the key away with the file.
	e.waitReconnect()
	e.clock.Advance(91 * time.Second)
	if strings.Contains(e.file("network"), "wg0") || strings.Contains(e.file("network"), priv) {
		t.Fatal("the rollback must drop the generated key")
	}
	rs := e.sentResults()
	if len(rs) != 1 || rs[0].Outcome != OutcomeRolledBack || strings.Contains(mustJSON(rs[0]), priv) {
		t.Fatalf("%+v", rs)
	}
}

// Nothing secret crosses the wire, so a signed plain-HTTP session may ask
// for a generated key (a {"$secret"} would be refused there).
func TestGenerateOnAnInsecureSession(t *testing.T) {
	e := newEnv(t)
	var a ApplyParams
	if err := json.Unmarshal([]byte(wgPutJSON(e, "g2", "")), &a); err != nil {
		t.Fatal(err)
	}
	res, err := e.p.Apply(context.Background(), &a, SessionRef{Gen: 1, Challenge: "c1"}, false)
	if err != nil || res.State != StatePendingConfirm || len(res.Generated) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

// A dry run shows <generated> and makes no key; a kept proto counts.
func TestGenerateDryRunAndKeptProto(t *testing.T) {
	e := newEnv(t)
	called := 0
	e.p.genValue = func(kind string) (string, string, error) {
		called++
		return generateValue(kind)
	}
	before := e.file("network")
	res, err := e.apply(wgPutJSON(e, "d1", `,"dryRun":true`))
	if err != nil || res.State != StateDryRun || len(res.Generated) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	found := false
	for _, ch := range res.Changes {
		if ch.Option == "private_key" {
			found = true
			if ch.Value != GeneratedPlaceholder || ch.Section != "wg0" || ch.Config != "network" {
				t.Fatalf("%+v", ch)
			}
		}
	}
	if !found || called != 0 || e.file("network") != before {
		t.Fatalf("changes %+v, generator called %d times", res.Changes, called)
	}

	// An owned WireGuard interface gets a new key with its proto kept.
	put(t, e.root, "etc/config/network", fixNetwork+"\nconfig interface 'wg1'\n\toption proto 'wireguard'\n\toption private_key 'old'\n")
	put(t, e.root, "etc/config/"+LedgerConfig, "config synced 'w1'\n\toption config 'network'\n\toption section 'wg1'\n\toption domain 'wireguard'\n")
	e.p.genValue = func(string) (string, string, error) { return wgVectors[0].priv, wgVectors[0].pub, nil }
	res, err = e.apply(`{"applyId":"k1","base":` + mustJSON(e.base("network")) + `,"ops":[{"op":"put","config":"network","section":"wg1","type":"interface",
	  "options":{"proto":{"$keep":true},"private_key":{"$generate":"wg_private_key"}}}]}`)
	if err != nil || len(res.Generated) != 1 || res.Generated[0].PublicKey != wgVectors[0].pub {
		t.Fatalf("%+v %v", res, err)
	}
	if v, _ := e.load("network").Section("wg1").Get("private_key"); v.Str() != wgVectors[0].priv {
		t.Fatal(e.file("network"))
	}
}

// Anything but a WireGuard interface's private_key is refused before
// anything is touched.
func TestGenerateRefusedElsewhere(t *testing.T) {
	e := newEnv(t)
	before := e.file("network")
	base := mustJSON(e.base("network", "dhcp"))
	cases := map[string]string{
		"unknown kind":  `{"op":"put","config":"network","section":"wg0","type":"interface","options":{"proto":"wireguard","private_key":{"$generate":"ssh_key"}}}`,
		"other option":  `{"op":"put","config":"network","section":"wg0","type":"interface","options":{"proto":"wireguard","preshared_key":{"$generate":"wg_private_key"}}}`,
		"peer section":  `{"op":"put","config":"network","section":"peer1","type":"wireguard_wg0","options":{"private_key":{"$generate":"wg_private_key"}}}`,
		"other config":  `{"op":"put","config":"dhcp","section":"wg0","type":"interface","options":{"proto":"wireguard","private_key":{"$generate":"wg_private_key"}}}`,
		"not wireguard": `{"op":"put","config":"network","section":"wg0","type":"interface","options":{"proto":"static","private_key":{"$generate":"wg_private_key"}}}`,
		"no proto":      `{"op":"put","config":"network","section":"wg0","type":"interface","options":{"private_key":{"$generate":"wg_private_key"}}}`,
		"kept, new":     `{"op":"put","config":"network","section":"wg0","type":"interface","options":{"proto":{"$keep":true},"private_key":{"$generate":"wg_private_key"}}}`,
		"not a put":     `{"op":"adopt","config":"network","section":"lan","perchId":"n1","options":{"private_key":{"$generate":"wg_private_key"}}}`,
	}
	for name, op := range cases {
		_, err := e.apply(`{"applyId":"r1","base":` + base + `,"ops":[` + op + `]}`)
		if code(err) != CodeBadParams || data(err)["reason"] != ReasonGenerateNotAllowed || !strings.Contains(err.Error(), ReasonGenerateNotAllowed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if e.file("network") != before || e.p.ApplyState().State != StateIdle {
		t.Fatal("a refusal must leave nothing behind")
	}
}

func TestGenerateFeatureAnnounced(t *testing.T) {
	e := newEnv(t)
	if !hasFeature(e.p.Features(), FeatureGenerateWGKey) {
		t.Fatalf("%v", e.p.Features())
	}
}
