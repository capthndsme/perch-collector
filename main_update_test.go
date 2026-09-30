package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/capthndsme/perch-agentkit/update"

	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/gwconfig"
)

// The package ships the kit's guard byte for byte (the updater keeps it in
// place and reports anything else as outdated): the update step first, then
// the config plane's config-guard.
func TestGuardIsTheKits(t *testing.T) {
	pkg, err := os.ReadFile("openwrt/perch-collector/files/perch-collector-guard.init")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkg, update.CollectorGuardInit) {
		t.Fatal("openwrt/perch-collector/files/perch-collector-guard.init differs from the kit's update/sh/perch-collector-guard.init")
	}
	upd := bytes.Index(pkg, []byte(updateStateDir+"/perch-update.sh"))
	guard := bytes.Index(pkg, []byte("/usr/bin/perch-collector config-guard"))
	if upd < 0 || guard < 0 || upd > guard || !bytes.Contains(pkg, []byte("\nSTART=15\n")) {
		t.Fatal("the update step must come before config-guard, at START=15")
	}
	if g := update.CollectorGuard(); g.InitPath != "/etc/init.d/perch-collector-guard" || g.RCLink != "/etc/rc.d/S15perch-collector-guard" {
		t.Fatalf("guard spec %+v", g)
	}
}

// Perch's own packages are never on gateway.package.install's allowlist:
// only the updater installs them.
func TestOwnPackagesNeverOnThePackageAllowlist(t *testing.T) {
	for _, name := range gwconfig.InstallAllowlist {
		if strings.HasPrefix(name, "perch-") {
			t.Fatalf("%s is on the gateway package allowlist", name)
		}
	}
}

func TestUpdateTarget(t *testing.T) {
	cfg := config.Defaults()
	cfg.UpdateKeys = []string{"RWkey"}
	cfg.ServerCAFile = "/etc/ssl/perch-ca.pem"
	tg := updateTarget(cfg)
	if tg.Product != update.ProductCollector || tg.Service != "perch-collector" || tg.Program != "perch-collector" ||
		tg.Version != version || tg.StateDir != "/etc/perch-collector/update" || tg.RunDir != "/tmp/perch-update/perch-collector" ||
		strings.Join(tg.Candidates, ",") != "/usr/bin/perch-collector" || strings.Join(tg.Packages, ",") != "perch-collector,perch-qos" ||
		strings.Join(tg.RollbackStores, ",") != "flash" || !tg.Enabled || strings.Join(tg.ExtraKeys, ",") != "RWkey" ||
		tg.CAFile != "/etc/ssl/perch-ca.pem" || tg.Kind != nil {
		t.Fatalf("%+v", tg)
	}
	for _, r := range tg.FileAllow {
		if strings.HasPrefix(r.Path, "/etc/config/") || strings.HasPrefix(r.Path, "/etc/uci-defaults/") {
			t.Fatalf("a config on the file allowlist: %s", r.Path)
		}
		if strings.Contains(r.Path, "perch-qos") != r.IfExists {
			t.Fatalf("%s: perch-qos files only where they exist, everything else always", r.Path)
		}
	}
	cfg.SelfUpdate = false
	t.Setenv("PERCH_COLLECTOR_INSTALL", "docker")
	tg = updateTarget(cfg)
	if tg.Enabled || tg.Kind == nil || tg.Kind() != update.InstallDocker {
		t.Fatalf("docker / off: %+v", tg)
	}
}

// An update waits while a config apply is made, waits for its confirm or is
// rolled back.
func TestUpdateBusyFollowsTheConfigPlane(t *testing.T) {
	for state, want := range map[string]string{
		"": "", gwconfig.StateIdle: "", gwconfig.StateApplying: "config_pending",
		gwconfig.StatePendingConfirm: "config_pending", gwconfig.StateRollingBack: "config_pending",
	} {
		busy := updateBusy(func() gwconfig.ApplyState { return gwconfig.ApplyState{State: state} })
		if got := busy(context.Background()); got != want {
			t.Errorf("%q: %q, want %q", state, got, want)
		}
	}
}

// The reported version is the build's, exactly: no -static suffix from the
// static build script (self-update recognises the new process by it).
func TestStaticBuildReportsTheReleaseVersion(t *testing.T) {
	b, err := os.ReadFile("scripts/build-static.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "-static}") || !strings.Contains(s, "-X main.variant=ndpi-static") || !strings.Contains(s, "-X main.version=$VERSION ") {
		t.Fatal("build-static.sh must stamp the exact version and the ndpi-static variant")
	}
}

func TestReleaseArch(t *testing.T) {
	if a := releaseArch(); a == "" || a == "arm" {
		t.Fatalf("arch %q", a)
	}
}
