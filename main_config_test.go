package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/gatewayops"
	"github.com/capthndsme/perch-collector/internal/gwconfig"
	"github.com/capthndsme/perch-collector/internal/observe"
)

func TestGatewayConfigCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	none := func() (config.Config, error) {
		cfg, err := config.LoadEnv()
		cfg.ConfigAccess = config.ConfigAccessNone
		return cfg, err
	}
	if code := gatewayConfigCommand(nil, &stdout, &stderr, none); code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["capabilities"]; !ok || !strings.Contains(string(out["readError"]), "config_access") {
		t.Fatalf("%s", stdout.String())
	}

	stdout.Reset()
	if code := gatewayConfigCommand([]string{"--help"}, &stdout, &stderr, none); code != 0 || !strings.Contains(stdout.String(), "usage: perch-collector gateway-config") {
		t.Fatalf("help: %d", code)
	}
	stdout.Reset()
	if code := gatewayConfigCommand([]string{"-x"}, &stdout, &stderr, none); code != 2 {
		t.Fatalf("bad flag: %d", code)
	}
	failing := func() (config.Config, error) { return config.Config{}, errors.New("broken") }
	if code := gatewayConfigCommand(nil, &stdout, &stderr, failing); code != 1 {
		t.Fatalf("broken config: %d", code)
	}
}

func TestConfigGuardCommand(t *testing.T) {
	root := t.TempDir()
	var out, errb bytes.Buffer
	if code := configGuardCommand(nil, &out, &errb, root, func() string { return "" }); code != 0 || !strings.Contains(out.String(), "no pending apply") {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	// A pending apply without its tmpfs marker: the router rebooted.
	os.MkdirAll(filepath.Join(root, "etc/config"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/config/dhcp"), []byte("\nconfig dhcp 'lan'\n\toption start '999'\n"), 0o644)
	snap := filepath.Join(root, "etc/perch-collector/rollback/a1/before")
	os.MkdirAll(snap, 0o755)
	orig := []byte("\nconfig dhcp 'lan'\n\toption start '100'\n")
	os.WriteFile(filepath.Join(snap, "dhcp"), orig, 0o644)
	sum := sha256.Sum256(orig)
	rec := fmt.Sprintf(`{"applyId":"a1","kind":"apply","deadline":"2026-09-23T10:00:00Z","configs":["dhcp"],"hashesBefore":{"dhcp":"%x"},"committed":true}`, sum)
	os.WriteFile(filepath.Join(root, "etc/perch-collector/rollback/pending.json"), []byte(rec), 0o600)
	out.Reset()
	if code := configGuardCommand(nil, &out, &errb, root, func() string { return "k" }); code != 0 || !strings.Contains(out.String(), "apply a1 was pending at the reboot: rolled_back") {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	if data, _ := os.ReadFile(filepath.Join(root, "etc/config/dhcp")); !bytes.Equal(data, orig) {
		t.Fatal(string(data))
	}
	if code := configGuardCommand([]string{"--now"}, &out, &errb, root, func() string { return "" }); code != 2 {
		t.Fatal(code)
	}
}

func TestPairCommand(t *testing.T) {
	root := t.TempDir()
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := pairCommand(args, &stdout, &stderr, root)
		return code, stdout.String(), stderr.String()
	}
	// No daemon: status and forget read the stored key; confirm needs it.
	if code, out, _ := run("status"); code != 0 || !strings.Contains(out, "not paired") || !strings.Contains(out, "daemon is not running") {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, errOut := run("confirm", "123456"); code != 1 || !strings.Contains(errOut, "not running") {
		t.Fatalf("%d %q", code, errOut)
	}
	if code, _, _ := run(); code != 2 {
		t.Fatal(code)
	}
	if code, _, _ := run("confirm"); code != 2 {
		t.Fatal(code)
	}
	if code, _, _ := run("frobnicate"); code != 2 {
		t.Fatal(code)
	}

	p := gwconfig.New(gwconfig.Options{Access: gwconfig.AccessWrite, AllowInsecure: true, Root: root, ServerURL: "http://perch.example.com:8080"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.ServePairSocket(ctx)
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var begin *gwconfig.PairBeginResult
	var err error
	for i := 0; i < 100; i++ {
		if code, _, _ := run("status"); code == 0 {
			if _, err := os.Stat(filepath.Join(root, gwconfig.PairSocket)); err == nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if begin, err = p.PairBegin(&gwconfig.PairBeginParams{PairingID: "0123456789abcdef", GatewayID: 2, ControllerPub: fmt.Sprintf("%x", priv.PublicKey().Bytes())}); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run("status"); code != 0 || !strings.Contains(out, "waiting for the controller") {
		t.Fatalf("%d %q", code, out)
	}
	cnonce := bytes.Repeat([]byte{7}, 32)
	rev, err := p.PairReveal(&gwconfig.PairRevealParams{PairingID: begin.PairingID, ControllerNonce: fmt.Sprintf("%x", cnonce)})
	if err != nil {
		t.Fatal(err)
	}
	rpub, _ := hex.DecodeString(begin.RouterPub)
	rnonce, _ := hex.DecodeString(rev.RouterNonce)
	tr := gwconfig.PairTranscript{GatewayID: 2, ControllerPub: priv.PublicKey().Bytes(), RouterPub: rpub, ControllerNonce: cnonce, RouterNonce: rnonce}
	sas := gwconfig.PairSAS(tr)
	code, out, _ := run("status")
	if code != 0 || !strings.Contains(out, "code:        "+sas) || !strings.Contains(out, "pair confirm "+sas) || !strings.Contains(out, "http://perch.example.com:8080 (gateway 2)") {
		t.Fatalf("%d %q", code, out)
	}
	wrong := "000000"
	if sas == wrong {
		wrong = "111111"
	}
	if code, _, errOut := run("confirm", wrong); code != 1 || !strings.Contains(errOut, "does not match") {
		t.Fatalf("%d %q", code, errOut)
	}
	if code, out, _ := run("confirm", sas[:3], sas[3:]); code != 0 || !strings.Contains(out, "paired: key") {
		t.Fatalf("%d %q", code, out)
	}
	code, out, _ = run("status", "-json")
	var st gwconfig.PairLocal
	if code != 0 || json.Unmarshal([]byte(out), &st) != nil || st.Paired == nil || st.Paired.GatewayID != 2 || strings.Contains(out, `"key"`) {
		t.Fatalf("%d %q", code, out)
	}
	if code, out, _ := run("forget"); code != 0 || !strings.Contains(out, "forgot key "+st.Paired.KeyID) {
		t.Fatalf("%d %q", code, out)
	}
	if code, out, _ := run("forget"); code != 0 || !strings.Contains(out, "nothing to forget") {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, errOut := run("reject"); code != 1 || !strings.Contains(errOut, "no pairing") {
		t.Fatalf("%d %q", code, errOut)
	}
}

// gateway.capabilities announces the runtime actions and the IPv6 prefixes
// only when this daemon serves them (gateway-sync protocol 4).
func TestPlaneFeatures(t *testing.T) {
	if f := (gatewayFeatures{}).planeFeatures(); len(f) != 0 {
		t.Fatalf("nothing built: %v", f)
	}
	gw := gatewayFeatures{upnp: &gatewayops.UPnP{}, ddns: &gatewayops.DDNS{},
		observer: observe.NewObserver(&observe.Env{Root: t.TempDir()}, map[observe.Part]bool{observe.PartInterfaces: true}, "")}
	if f := strings.Join(gw.planeFeatures(), " "); f != "upnp.delete ddns.update observe.ipv6_prefixes" {
		t.Fatalf("%s", f)
	}
	gw.observer = observe.NewObserver(&observe.Env{Root: t.TempDir()}, map[observe.Part]bool{observe.PartSystem: true}, "")
	if f := strings.Join(gw.planeFeatures(), " "); f != "upnp.delete ddns.update" {
		t.Fatalf("without the interfaces part: %s", f)
	}
}

// config-guard --overdue is quiet when there is nothing to do (cron runs it
// every minute) and says what it restored.
func TestConfigGuardOverdue(t *testing.T) {
	root := t.TempDir()
	var out, errb bytes.Buffer
	if code := configGuardCommand([]string{"--overdue"}, &out, &errb, root, func() string { return "" }); code != 0 || out.Len() != 0 || errb.Len() != 0 {
		t.Fatalf("%d %q %q", code, out.String(), errb.String())
	}
	os.MkdirAll(filepath.Join(root, "etc/config"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/config/dhcp"), []byte("\nconfig dhcp 'lan'\n\toption start '999'\n"), 0o644)
	snap := filepath.Join(root, "etc/perch-collector/rollback/a1/before")
	os.MkdirAll(snap, 0o755)
	orig := []byte("\nconfig dhcp 'lan'\n\toption start '100'\n")
	os.WriteFile(filepath.Join(snap, "dhcp"), orig, 0o644)
	os.MkdirAll(filepath.Join(root, "var/run/perch-collector"), 0o700)
	os.WriteFile(filepath.Join(root, "var/run/perch-collector/apply-a1"), []byte("a1\n"), 0o600)
	sum := sha256.Sum256(orig)
	deadline := time.Now().Add(-61 * time.Second).UTC().Format(time.RFC3339)
	rec := fmt.Sprintf(`{"applyId":"a1","kind":"apply","deadline":%q,"configs":["dhcp"],"hashesBefore":{"dhcp":"%x"},"committed":true}`, deadline, sum)
	os.WriteFile(filepath.Join(root, "etc/perch-collector/rollback/pending.json"), []byte(rec), 0o600)
	var reloaded []string
	o := gwconfig.OverdueOptions{Root: root, Now: time.Now(), Reload: func(_ context.Context, c []string) error { reloaded = c; return nil }}
	// A daemon holds the lock: nothing.
	lock, err := gwconfig.TryPlaneLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if code := overdueCommand(&out, &errb, o); code != 0 || out.Len() != 0 {
		t.Fatalf("%d %q", code, out.String())
	}
	lock.Release()
	if code := overdueCommand(&out, &errb, o); code != 0 || !strings.Contains(out.String(), "apply a1 was overdue and no daemon owned it: rolled_back (confirm_timeout); restored by the overdue watchdog") {
		t.Fatalf("%d %q %q", code, out.String(), errb.String())
	}
	if data, _ := os.ReadFile(filepath.Join(root, "etc/config/dhcp")); !bytes.Equal(data, orig) || len(reloaded) != 1 || reloaded[0] != "dhcp" {
		t.Fatalf("%s %v", data, reloaded)
	}
}
