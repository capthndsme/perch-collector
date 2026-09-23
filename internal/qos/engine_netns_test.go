package qos

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// labSetup creates the fixture's LAN devices and files in the namespace.
func labSetup(t *testing.T) *nsSys {
	t.Helper()
	requireKernel(t)
	for _, dev := range []string{"lan", "guest", "iot", "mgmt", "wan", "wan2"} {
		sh(t, "ip link add "+dev+" type dummy", "ip link set "+dev+" up")
	}
	s := newNsSys(t)
	dump, err := os.ReadFile("testdata/ubus-interface-dump.json")
	if err != nil {
		t.Fatal(err)
	}
	s.dump = dump
	for name, dst := range map[string]string{"planner-perch-qos": ConfigPath, "firewall": FirewallPath, "sqm": SQMPath} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		s.write(t, dst, string(data))
	}
	s.write(t, TZPath, "UTC0\n")
	s.neigh = []Neighbor{
		{MAC: "02:00:00:00:10:11", Device: "lan", Confirmed: true},
		{MAC: "02:00:00:00:20:11", Device: "guest", Confirmed: true},
		{MAC: "02:00:00:00:20:99", Device: "guest", Confirmed: true}, // dynamic
	}
	return s
}

func setPlannerDevices(t *testing.T, e *Engine) {
	t.Helper()
	data, err := os.ReadFile("testdata/planner-devices.json")
	if err != nil {
		t.Fatal(err)
	}
	var p DevicesSetParams
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	res, err := e.SetDevices(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Accepted != len(p.Devices) || len(res.Rejected) != 0 {
		t.Fatalf("set: %+v", res)
	}
}

func mustApply(t *testing.T, e *Engine, reason string) ApplyResult {
	t.Helper()
	r := e.Reconcile(reason, true)
	if len(r.Errors) > 0 {
		t.Fatalf("%s: %v\nbatch:\n%s", reason, strings.Join(r.Errors, "\n"), readRuntime(t, e, lastBatchPath))
	}
	return r
}

func readRuntime(t *testing.T, e *Engine, p string) string {
	data, _ := e.sys.ReadFile(p)
	return string(data)
}

func TestNetnsApplyIdempotentAndHitless(t *testing.T) {
	if !inNetns(t) {
		return
	}
	s := labSetup(t)
	e := NewEngine(s, true)
	setPlannerDevices(t, e)

	r := mustApply(t, e, "first")
	if !r.Active || r.Commands == 0 {
		t.Fatalf("first apply: %+v", r)
	}
	t.Logf("first apply: %d commands", r.Commands)
	// Idempotent: the kernel read back matches the plan exactly.
	r = mustApply(t, e, "again")
	if r.Commands != 0 {
		t.Fatalf("second apply changed %d things:\n%s", r.Commands, readRuntime(t, e, lastBatchPath))
	}
	classes := tcShow(t, "class show dev ifb-pdn")
	for _, want := range []string{"class htb 1:12 parent 1:1", "class htb 1:13 parent 1:12", "class htb 1:113 parent 1:13", "class htb 1:112 parent 1:12"} {
		if !strings.Contains(classes, want) {
			t.Errorf("missing %q in\n%s", want, classes)
		}
	}

	// A weekday evening: s7 limits the voucher tier b13 to 3000 down.
	s.now = time.Date(2026, 9, 23, 19, 0, 0, 0, time.UTC) // Wednesday
	r = mustApply(t, e, "s7")
	batch := readRuntime(t, e, lastBatchPath)
	if !strings.Contains(batch, "class change dev ifb-pdn parent 1:12 classid 1:13 htb rate 3000kbit ceil 3000kbit") {
		t.Errorf("s7: no rate change:\n%s", batch)
	}
	for _, l := range strings.Split(strings.TrimSpace(batch), "\n") {
		if !strings.HasPrefix(l, "class change ") && !strings.HasPrefix(l, "qdisc change ") {
			t.Errorf("s7 should only change classes in place, got %q", l)
		}
	}
	if r = mustApply(t, e, "s7 again"); r.Commands != 0 {
		t.Fatalf("s7 not idempotent:\n%s", readRuntime(t, e, lastBatchPath))
	}

	// Saturday morning: s9 moves 02:00:00:00:10:11 into bucket b12 with its
	// each caps: a new leaf under b12, the filter re-pointed, the old leaf
	// deleted last.
	s.now = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)
	mustApply(t, e, "s9")
	batch = readRuntime(t, e, lastBatchPath)
	lines := strings.Split(strings.TrimSpace(batch), "\n")
	var addAt, replAt, delAt = -1, -1, -1
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "class add dev ifb-pdn parent 1:12"):
			addAt = i
		case strings.HasPrefix(l, "filter replace dev lan egress pref 10") && strings.Contains(l, "02:00:00:00:10:11"):
			replAt = i
		case strings.HasPrefix(l, "class del dev ifb-pdn"):
			delAt = i
		}
	}
	if addAt < 0 || replAt < 0 || delAt < 0 || !(addAt < replAt && replAt < delAt) {
		t.Errorf("move is not make-before-break (add %d, replace %d, del %d):\n%s", addAt, replAt, delAt, batch)
	}
	if r = mustApply(t, e, "s9 again"); r.Commands != 0 {
		t.Fatalf("s9 not idempotent:\n%s", readRuntime(t, e, lastBatchPath))
	}

	// Sunday 23:00: s8 blocks the device: its filter drops.
	s.now = time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)
	mustApply(t, e, "s8")
	f := tcShow(t, "filter show dev lan egress pref 10")
	if !strings.Contains(f, "dst_mac 02:00:00:00:10:11") || !strings.Contains(f, "action order 1: gact action drop") {
		t.Errorf("s8: c1 not blocked:\n%s", f)
	}

	// The push section reads back every class.
	sec := e.Section()
	if sec == nil || sec.State != "active" || len(sec.Classes) == 0 {
		t.Fatalf("section: %+v", sec)
	}
	b, _ := json.Marshal(sec)
	if len(b) > 64*1024 {
		t.Errorf("section is %d bytes", len(b))
	}

	// Local stop: nothing of Perch's is left.
	r = e.Stop()
	if len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	if out := tcShow(t, "qdisc show dev lan"); strings.Contains(out, "clsact") {
		t.Errorf("clsact left on lan:\n%s", out)
	}
	if out := tcShow(t, "qdisc show dev ifb-pdn"); !strings.Contains(out, "Cannot find device") {
		t.Errorf("ifb-pdn left:\n%s", out)
	}
	if sec := e.Section(); sec.State != "paused" || sec.PausedBy == nil || *sec.PausedBy != "local" {
		t.Errorf("after stop: %+v", sec)
	}
	// And back.
	r = e.Start("apply")
	if len(r.Errors) > 0 || r.Commands == 0 {
		t.Fatalf("start: %+v", r)
	}
}

// kernelFixture is a `tc -s -j -batch` read of the kernel, kept so the
// parser and the diff are tested against real output without a namespace.
type kernelFixture struct {
	Commands []string `json:"commands"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
}

// TestNetnsKernelFixture applies the weekday-noon golden plan with tc and
// reads the kernel back; with -update it stores the read in testdata.
func TestNetnsKernelFixture(t *testing.T) {
	if !inNetns(t) {
		return
	}
	labSetup(t)
	d := Plan(fixtureInputs(t, time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)), NewState("golden"))
	sys := &OS{}
	for _, dir := range dirs {
		if err := sys.EnsureIfb(dir.Ifb()); err != nil {
			t.Fatal(err)
		}
	}
	b := Render(d)
	_, stderr, err := sys.Tc(ctxT(t), b.Lines, false, false)
	if err != nil || len(stderr) > 0 {
		t.Fatalf("apply: %v %s", err, stderr)
	}
	cmds := readCommands(sortedKeys(d.Filters), true)
	out, errOut, _ := sys.Tc(ctxT(t), cmds, true, true)
	fx := kernelFixture{Commands: cmds, Stdout: string(out), Stderr: string(errOut)}
	if *update {
		data, _ := json.MarshalIndent(fx, "", " ")
		if err := os.WriteFile("testdata/kernel-weekday-noon.json", data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	answers, err := parseBatchOutput(cmds, out, errOut)
	if err != nil {
		t.Fatal(err)
	}
	k, err := parseKernel(cmds, answers)
	if err != nil {
		t.Fatal(err)
	}
	if rest := Diff(d, k, nil); !rest.Empty() {
		t.Fatalf("the kernel does not match its own plan:\n%s", rest.Text())
	}
}
