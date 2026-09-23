package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
