package gwconfig

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func withWireguard(e *env) {
	e.router.pkgSize = map[string]int64{"wireguard-tools": 28000, "kmod-wireguard": 42000, "kmod-udptunnel4": 9000}
	e.router.pkgDeps = map[string][]string{"wireguard-tools": {"kmod-wireguard"}, "kmod-wireguard": {"kmod-udptunnel4"}}
}

func (e *env) install(id string, names ...string) (*PackageInstallResult, error) {
	return e.p.InstallPackages(context.Background(), &PackageInstallParams{ApplyID: id, Packages: names}, SessionRef{Gen: 1})
}

func TestPackageInstallConfirmed(t *testing.T) {
	e := newEnv(t)
	withWireguard(e)
	res, err := e.install("p1", "wireguard-tools")
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StatePendingConfirm || res.Manager != "opkg" || strings.Join(res.Install, ",") != "kmod-udptunnel4,kmod-wireguard,wireguard-tools" ||
		res.NeedBytes == nil || *res.NeedBytes != 3*79000 || res.ConfirmTimeoutSeconds != 90 {
		t.Fatalf("%+v", res)
	}
	log := strings.Join(e.router.log(), "\n")
	if !strings.Contains(log, "opkg update") || !strings.Contains(log, "opkg install --noaction wireguard-tools") || !strings.Contains(log, "opkg install wireguard-tools") {
		t.Fatal(log)
	}
	e.waitReconnect()
	if st := e.p.ApplyState(); st.Kind != KindPackage || st.State != StatePendingConfirm {
		t.Fatalf("%+v", st)
	}
	if _, err := e.p.Confirm("p1", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}
	if !e.router.installed()["wireguard-tools"] {
		t.Fatal("confirmed install kept")
	}
	// Installing it again is a noop.
	if res, err := e.install("p2", "wireguard-tools"); err != nil || res.State != StateNoop || strings.Join(res.AlreadyInstalled, ",") != "wireguard-tools" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestPackageInstallRolledBackAtTheDeadline(t *testing.T) {
	e := newEnv(t)
	withWireguard(e)
	before := e.router.installed()
	if _, err := e.install("p1", "wireguard-tools"); err != nil {
		t.Fatal(err)
	}
	e.waitReconnect()
	e.clock.Advance(90 * time.Second)
	after := e.router.installed()
	if len(after) != len(before) || after["kmod-wireguard"] || after["wireguard-tools"] {
		t.Fatalf("%v", after)
	}
	r := e.sentResults()[0]
	if r.Kind != KindPackage || r.Reason != ReasonConfirmTimeout || strings.Join(r.Packages, ",") != "kmod-udptunnel4,kmod-wireguard,wireguard-tools" || r.Outcome != OutcomeRolledBack {
		t.Fatalf("%+v", r)
	}
}

func TestPackageInstallFailureRollsBackAtOnce(t *testing.T) {
	e := newEnv(t)
	withWireguard(e)
	e.router.pkgFail["wireguard-tools"] = true
	_, err := e.install("p1", "wireguard-tools")
	if code(err) != CodeInstallFailed || data(err)["rolledBack"] != true {
		t.Fatal(err)
	}
	// Its dependencies went in before the failure, and are gone again.
	if e.router.installed()["kmod-wireguard"] || e.router.installed()["kmod-udptunnel4"] {
		t.Fatal("dependencies left behind")
	}
	res := data(err)["result"].(Result)
	if res.Reason != ReasonInstallFailed || strings.Join(res.Packages, ",") != "kmod-udptunnel4,kmod-wireguard" || !strings.Contains(res.Detail, "check_data_file_clashes") {
		t.Fatalf("%+v", res)
	}
	if e.p.ApplyState().State != StateIdle || e.exists("etc/perch-collector/rollback/pending.json") {
		t.Fatal("slot or record left")
	}
}

func TestPackageInstallRefusals(t *testing.T) {
	e := newEnv(t)
	withWireguard(e)
	if _, err := e.install("p1", "tcpdump"); code(err) != CodePackageNotAllowed {
		t.Fatal(err)
	}
	if _, err := e.install("p1", "Bad Name"); code(err) != CodeBadParams {
		t.Fatal(err)
	}
	if _, err := e.install("p1"); code(err) != CodeBadParams {
		t.Fatal(err)
	}
	// Not enough flash (the estimate is 3 x the package files).
	e.router.pkgSize["wireguard-tools"] = 1 << 50
	if _, err := e.install("p1", "wireguard-tools"); code(err) != CodeInsufficientFlash || data(err)["needBytes"] == nil {
		t.Fatal(err)
	}
	e.router.pkgSize["wireguard-tools"] = 28000
	// Package lists unreachable.
	e.router.updateErr = true
	if _, err := e.install("p1", "wireguard-tools"); code(err) != CodeInstallFailed {
		t.Fatal(err)
	}
	e.router.updateErr = false
	// A dry run installs nothing.
	res, err := e.p.InstallPackages(context.Background(), &PackageInstallParams{ApplyID: "p2", Packages: []string{"wireguard-tools"}, DryRun: true}, SessionRef{Gen: 1})
	if err != nil || res.State != StateDryRun || len(res.Install) != 3 || e.router.installed()["wireguard-tools"] {
		t.Fatalf("%+v %v", res, err)
	}
	// The router's owner can allow more.
	e2 := newEnv(t, func(o *Options) { o.PackageAllow = []string{"tcpdump-mini"} })
	e2.router.pkgSize = map[string]int64{"tcpdump-mini": 1000}
	if res, err := e2.install("p3", "tcpdump-mini"); err != nil || res.State != StatePendingConfirm {
		t.Fatalf("%+v %v", res, err)
	}
	// One job at a time, shared with config applies.
	if _, err := e2.apply(reservationJSON(e2, "a1")); code(err) != CodeBusy {
		t.Fatal(err)
	}
	// No package manager at all.
	e3 := newEnv(t)
	e3.router.writeInstalled(nil)
	removeAll(t, e3.root+"/usr/lib/opkg")
	if _, err := e3.install("p4", "wireguard-tools"); code(err) != CodeNoPackageManager {
		t.Fatal(err)
	}
}

func removeAll(t *testing.T, p string) {
	t.Helper()
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
}
