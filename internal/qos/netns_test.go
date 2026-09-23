package qos

// Tests against the real kernel: the test binary re-runs itself in a new
// user + network namespace (`unshare -rn`), where an unprivileged user may
// create dummy devices and ifbs and run tc. Skipped when unshare, tc, or the
// kernel modules (ifb, sch_htb, sch_cake, cls_flower …) are not available.

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const netnsEnv = "PERCH_QOS_IN_NETNS"

// inNetns runs the calling test inside a fresh namespace; it returns true
// in the child (the test body runs there) and false in the parent (which
// has already reported the child's outcome).
func inNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv(netnsEnv) == "1" {
		return true
	}
	if testing.Short() {
		t.Skip("namespace tests are skipped with -short")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare")
	}
	if _, err := exec.LookPath("tc"); err != nil {
		t.Skip("no tc")
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Skipf("unprivileged network namespaces are not available: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-rn", exe, "-test.run", "^" + t.Name() + "$", "-test.v"}
	if *update {
		args = append(args, "-update")
	}
	cmd := exec.Command("unshare", args...)
	cmd.Env = append(os.Environ(), netnsEnv+"=1")
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "SKIP:") || strings.Contains(string(out), "--- SKIP") {
		t.Skipf("skipped in the namespace:\n%s", out)
	}
	if err != nil {
		t.Fatalf("in the namespace: %v\n%s", err, out)
	}
	t.Logf("in the namespace:\n%s", out)
	return false
}

// nsSys is the real system inside the namespace, with netifd, the
// neighbour table and the clock faked.
type nsSys struct {
	OS
	dump   []byte
	neigh  []Neighbor
	now    time.Time
	synced bool
}

func (s *nsSys) Interfaces() ([]byte, error)    { return s.dump, nil }
func (s *nsSys) Neighbors() ([]Neighbor, error) { return s.neigh, nil }
func (s *nsSys) LocalMACs() map[string]bool     { return map[string]bool{"02:00:00:00:99:01": true} }
func (s *nsSys) Now() time.Time                 { return s.now }
func (s *nsSys) ClockSynced() bool              { return s.synced }

func sh(t *testing.T, cmds ...string) {
	t.Helper()
	for _, c := range cmds {
		if out, err := exec.Command("sh", "-c", c).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", c, err, out)
		}
	}
}

// requireKernel skips when the namespace lacks a qdisc or classifier.
func requireKernel(t *testing.T) {
	t.Helper()
	sh(t, "ip link add qprobe type dummy")
	defer exec.Command("ip", "link", "del", "qprobe").Run()
	for _, c := range []string{
		"tc qdisc add dev qprobe root handle 1: htb default 0",
		"tc class add dev qprobe parent 1: classid 1:2 htb rate 1mbit",
		"tc qdisc add dev qprobe parent 1:2 cake unlimited",
		"tc qdisc add dev qprobe clsact",
		"tc filter add dev qprobe egress pref 1 protocol all flower dst_mac 02:00:00:00:00:01 action skbedit priority 1:2 pipe action mirred egress redirect dev qprobe",
		"ip link add qprobe-ifb type ifb",
	} {
		if out, err := exec.Command("sh", "-c", c).CombinedOutput(); err != nil {
			t.Skipf("kernel feature missing (%s): %s", c, out)
		}
	}
	exec.Command("ip", "link", "del", "qprobe-ifb").Run()
}

func newNsSys(t *testing.T) *nsSys {
	t.Helper()
	root := t.TempDir()
	return &nsSys{OS: OS{Root: root}, now: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC), synced: true}
}

func (s *nsSys) write(t *testing.T, path, content string) {
	t.Helper()
	if err := s.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func tcShow(t *testing.T, args string) string {
	t.Helper()
	out, _ := exec.Command("sh", "-c", "tc "+args).CombinedOutput()
	return string(out)
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}
