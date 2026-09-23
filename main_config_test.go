package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/capthndsme/perch-collector/internal/config"
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
