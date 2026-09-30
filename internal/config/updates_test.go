package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Self-update is on by default; the environment (the OpenWrt init script's
// PERCH_COLLECTOR_SELF_UPDATE / _UPDATE_KEYS) and YAML set it.
func TestUpdatesSettings(t *testing.T) {
	cfg, err := load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SelfUpdate || len(cfg.UpdateKeys) != 0 {
		t.Fatalf("defaults %+v", cfg.Updates)
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(path, []byte("self_update: false\nupdate_keys: [RWyaml, RWyaml, ' ']\n"), 0o600)
	if cfg, err = load(path, cliOverrides{}); err != nil || cfg.SelfUpdate || !reflect.DeepEqual(cfg.UpdateKeys, []string{"RWyaml"}) {
		t.Fatalf("yaml %+v %v", cfg.Updates, err)
	}
	t.Setenv("PERCH_COLLECTOR_SELF_UPDATE", "1")
	t.Setenv("PERCH_COLLECTOR_UPDATE_KEYS", "RWone,RWtwo")
	if cfg, err = load(path, cliOverrides{}); err != nil || !cfg.SelfUpdate || !reflect.DeepEqual(cfg.UpdateKeys, []string{"RWone", "RWtwo"}) {
		t.Fatalf("env %+v %v", cfg.Updates, err)
	}
	t.Setenv("PERCH_COLLECTOR_SELF_UPDATE", "0")
	if cfg, err = load(path, cliOverrides{}); err != nil || cfg.SelfUpdate {
		t.Fatalf("env off %+v %v", cfg.Updates, err)
	}
}

// Perch's own packages never become installable gateway packages, whatever
// package_allow lists: the updater alone updates them.
func TestPackageAllowNeverListsPerchPackages(t *testing.T) {
	t.Setenv("PERCH_COLLECTOR_PACKAGE_ALLOW", "iperf3,perch-collector,perch-qos,perch-apd,tcpdump-mini")
	cfg, err := load(filepath.Join(t.TempDir(), "absent.yaml"), cliOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.PackageAllow, []string{"iperf3", "tcpdump-mini"}) {
		t.Fatalf("package_allow %v", cfg.PackageAllow)
	}
}
