package gwconfig

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// The overdue watchdog (gateway-sync protocol 7): config-guard --overdue
// restores an overdue apply only when no daemon holds the plane lock.

// deadDaemon makes an apply over three configs and then "kills" the
// daemon: its deadline timer is stopped, so only the watchdog is left.
func deadDaemon(t *testing.T) (*env, map[string]string) {
	t.Helper()
	e := newEnv(t)
	before := map[string]string{"network": e.file("network"), "dhcp": e.file("dhcp"), "firewall": e.file("firewall")}
	if _, err := e.apply(fmt.Sprintf(`{"applyId":"w1","base":%s,"ops":[
	  {"op":"put","config":"firewall","section":"perch_r","type":"rule","options":{"name":"a"}},
	  {"op":"put","config":"dhcp","section":"perch_h","type":"host","options":{"name":"b"}},
	  {"op":"put","config":"network","section":"perch_n","type":"route","options":{"target":"192.168.7.0/24"}}],
	  "ledger":{"set":[{"perchId":"h1","config":"dhcp","section":"perch_h","domain":"dhcp_hosts"}]}}`, mustJSON(e.base("network", "dhcp", "firewall")))); err != nil {
		t.Fatal(err)
	}
	e.waitReconnect()
	e.p.ap.mu.Lock()
	if e.p.ap.stop != nil {
		e.p.ap.stop()
	}
	e.p.ap.mu.Unlock()
	return e, before
}

type reloads struct{ got [][]string }

func (r *reloads) reload(_ context.Context, configs []string) error {
	r.got = append(r.got, append([]string(nil), configs...))
	return nil
}

func TestOverdueLockHeldIsANoop(t *testing.T) {
	e, _ := deadDaemon(t)
	applied := e.file("dhcp")
	daemon, err := TryPlaneLock(e.root)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Release()
	var r reloads
	res, err := Overdue(OverdueOptions{Root: e.root, Now: e.clock.Now().Add(time.Hour), Run: e.router.run, Reload: r.reload})
	if err != nil || res != nil || len(r.got) != 0 || e.file("dhcp") != applied || !e.exists("etc/perch-collector/rollback/pending.json") {
		t.Fatalf("%+v %v %v", res, err, r.got)
	}
	// The boot guard leaves a daemon's apply alone too (here even without
	// its marker).
	os.Remove(filepath.Join(e.root, "var/run/perch-collector/apply-w1"))
	if res, err := Guard(e.root, e.router.run, e.clock.Now(), uci.Redactor{}); err != nil || res != nil {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestOverdueRestoresReloadsAndRecords(t *testing.T) {
	e, before := deadDaemon(t)
	var r reloads
	opts := OverdueOptions{Root: e.root, Run: e.router.run, Reload: r.reload, Redact: NewRedactor("test-api-key")}
	// Past the deadline, but not by 60 s: the daemon's timer comes first.
	opts.Now = e.clock.Now().Add(90*time.Second + OverdueGrace)
	if res, err := Overdue(opts); err != nil || res != nil {
		t.Fatalf("%+v %v", res, err)
	}
	opts.Now = opts.Now.Add(time.Second)
	res, err := Overdue(opts)
	if err != nil || res == nil {
		t.Fatalf("%+v %v", res, err)
	}
	if res.ApplyID != "w1" || res.Outcome != OutcomeRolledBack || res.Reason != ReasonConfirmTimeout || res.Detail != OverdueDetail {
		t.Fatalf("%+v", res)
	}
	for c, body := range before {
		if e.file(c) != body {
			t.Fatalf("%s not restored", c)
		}
	}
	if e.exists("etc/config/"+LedgerConfig) || e.exists("etc/perch-collector/rollback/pending.json") || e.exists("etc/perch-collector/rollback/w1") {
		t.Fatal("ledger, record or snapshot left behind")
	}
	// Reloaded once, in apply order, without the ledger (what the daemon's
	// rollback sends).
	if !reflect.DeepEqual(r.got, [][]string{{"network", "dhcp", "firewall"}}) {
		t.Fatalf("reloads %v", r.got)
	}
	if res.Hashes["dhcp"] != e.hash("dhcp") {
		t.Fatalf("%v", res.Hashes)
	}
	// Once: nothing pending any more.
	if again, err := Overdue(opts); err != nil || again != nil {
		t.Fatalf("%+v %v", again, err)
	}
	// The daemon's next start reports it and restores nothing twice.
	reloadsBefore := len(e.be.reloadLog())
	n := New(e.p.o)
	n.Start()
	h := n.Hello(context.Background(), "")
	if h.Apply.State != StateIdle || len(h.Results) != 1 || h.Results[0].Detail != OverdueDetail || len(e.be.reloadLog()) != reloadsBefore {
		t.Fatalf("%+v %v", h, e.be.reloadLog())
	}
}

// The default reload is one `ubus call service event` config.change per
// config, like the daemon's.
func TestOverdueDefaultReload(t *testing.T) {
	e, _ := deadDaemon(t)
	res, err := Overdue(OverdueOptions{Root: e.root, Run: e.router.run, Ubus: e.p.o.Ubus, Now: e.clock.Now().Add(time.Hour)})
	if err != nil || res == nil {
		t.Fatalf("%+v %v", res, err)
	}
	var events []string
	for _, c := range e.router.log() {
		if strings.Contains(c, "call service event") {
			events = append(events, c)
		}
	}
	if len(events) != 3 || !strings.Contains(events[0], `"package":"network"`) || !strings.Contains(events[2], `"package":"firewall"`) {
		t.Fatalf("%v", events)
	}
}

// What the daemon would have said: an apply interrupted mid commit is
// commit_failed, one whose marker is gone (a reboot the boot guard missed)
// is reboot.
func TestOverdueReasons(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(e *env, rec *pendingRecord)
		reason string
	}{
		{"uncommitted", func(e *env, rec *pendingRecord) { rec.Committed = false }, ReasonCommitFailed},
		{"no marker", func(e *env, rec *pendingRecord) {
			os.Remove(filepath.Join(e.root, "var/run/perch-collector/apply-w1"))
		}, ReasonReboot},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, before := deadDaemon(t)
			st := store{root: e.root}
			rec, _ := st.readPending()
			c.mutate(e, rec)
			st.writePending(rec)
			var r reloads
			res, err := Overdue(OverdueOptions{Root: e.root, Run: e.router.run, Reload: r.reload, Now: e.clock.Now().Add(time.Hour)})
			if err != nil || res == nil || res.Reason != c.reason || res.Detail != OverdueDetail || e.file("dhcp") != before["dhcp"] {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
}

// A daemon stopped with SIGSTOP still holds the lock: the watchdog does
// nothing. Once it is gone, the watchdog restores.
func TestOverdueStoppedDaemonStillHoldsTheLock(t *testing.T) {
	e, before := deadDaemon(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperPlaneLockHolder$")
	cmd.Env = append(os.Environ(), "PERCH_TEST_LOCK_ROOT="+e.root)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Signal(syscall.SIGCONT)
		cmd.Process.Kill()
		cmd.Wait()
	}()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		t.Fatalf("helper: %q %v", line, err)
	}
	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	// Wait until the kernel reports it stopped.
	for i := 0; i < 100; i++ {
		stat, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid))
		if f := strings.Fields(string(stat)); len(f) > 2 && f[2] == "T" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var r reloads
	opts := OverdueOptions{Root: e.root, Run: e.router.run, Reload: r.reload, Now: e.clock.Now().Add(time.Hour)}
	if res, err := Overdue(opts); err != nil || res != nil || e.file("dhcp") == before["dhcp"] {
		t.Fatalf("a stopped daemon's apply was touched: %+v %v", res, err)
	}
	if _, err := TryPlaneLock(e.root); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("lock: %v", err)
	}
	cmd.Process.Signal(syscall.SIGCONT)
	cmd.Process.Kill()
	cmd.Wait()
	res, err := Overdue(opts)
	if err != nil || res == nil || res.Reason != ReasonConfirmTimeout || e.file("dhcp") != before["dhcp"] {
		t.Fatalf("after the daemon died: %+v %v", res, err)
	}
}

// TestHelperPlaneLockHolder is the "daemon" of the test above: it takes the
// plane lock, says so and waits to be killed.
func TestHelperPlaneLockHolder(t *testing.T) {
	root := os.Getenv("PERCH_TEST_LOCK_ROOT")
	if root == "" {
		t.Skip("helper process only")
	}
	if err := HoldPlaneLock(root, func(string, ...any) {}); err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	fmt.Println("locked")
	time.Sleep(time.Minute)
	os.Exit(0)
}

// The daemon waits for a config-guard that holds the lock, then owns it.
func TestHoldPlaneLockWaits(t *testing.T) {
	root := t.TempDir()
	guard, err := TryPlaneLock(root)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	var logged []string
	go func() {
		got <- HoldPlaneLock(root, func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	}()
	select {
	case err := <-got:
		t.Fatalf("took a held lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	guard.Release()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("still waiting after the guard released the lock")
	}
	if _, err := TryPlaneLock(root); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("the daemon must hold it now: %v", err)
	}
	daemonLock.Release()
	daemonLock = nil
	if len(logged) == 0 || !strings.Contains(logged[0], "plane.lock is held") {
		t.Fatalf("%v", logged)
	}
}
