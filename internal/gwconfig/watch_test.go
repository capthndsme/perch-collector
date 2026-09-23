package gwconfig

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// inbox records notifications; ok false simulates no session.
type inbox struct {
	got []Changed
	ok  bool
}

func (b *inbox) notify(c Changed) bool {
	if !b.ok {
		return false
	}
	b.got = append(b.got, c)
	return true
}

func seconds(n float64) *float64 { return &n }

// edit rewrites a config and moves its mtime forward, as a commit does.
func edit(t *testing.T, root, name, body string, at time.Time) {
	t.Helper()
	p := filepath.Join(root, "etc/config", name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
}

func watchSetup(t *testing.T) (string, *Plane, *fakeUbus, *clock, *inbox) {
	t.Helper()
	root := newRoot(t)
	clk := &clock{t: time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)}
	p, fu := plane(t, root, Options{Access: AccessRead, Allowlist: DefaultAllowlist, Now: clk.now})
	p.Hello(context.Background(), "") // baseline
	p.Configure(Configure{Mode: ModeObserve, WatchSeconds: seconds(10), DebounceSeconds: seconds(5)})
	return root, p, fu, clk, &inbox{ok: true}
}

func TestWatchPollReportsCLIEditAfterDebounce(t *testing.T) {
	root, p, _, clk, in := watchSetup(t)
	p.Step(in.notify) // first scan: nothing changed
	if len(in.got) != 0 {
		t.Fatalf("%+v", in.got)
	}
	edit(t, root, "firewall", "\nconfig defaults\n\toption input 'DROP'\n", clk.now().Add(time.Hour))
	clk.add(9 * time.Second)
	p.Step(in.notify) // poll not due yet
	if len(in.got) != 0 {
		t.Fatal("reported before the poll")
	}
	clk.add(time.Second)
	wait := p.Step(in.notify) // poll sees it; debounce starts
	if len(in.got) != 0 || wait > 5*time.Second {
		t.Fatalf("reported inside the debounce (wait %s)", wait)
	}
	clk.add(5 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 1 {
		t.Fatalf("%d notifications", len(in.got))
	}
	n := in.got[0]
	fw, _ := p.files.Hash("firewall")
	if n.Origin != OriginRouter || !reflect.DeepEqual(n.Changed, []string{"firewall"}) || n.Author != (Author{Kind: AuthorCLI, Via: "poll"}) ||
		n.Hashes["firewall"] != fw || n.Hashes["network"] == "" || n.At != "2026-09-23T10:00:15Z" {
		t.Fatalf("%+v", n)
	}
	// Reported once.
	clk.add(30 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 1 {
		t.Fatal("reported twice")
	}
}

func TestWatchTriggerAttributesToLuci(t *testing.T) {
	root, p, fu, clk, in := watchSetup(t)
	fu.sessions = `{"ubus_rpc_session":"0","data":{}}` + "\n" + `{"ubus_rpc_session":"1","data":{"username":"root"}}`
	p.Step(in.notify)
	edit(t, root, "network", "\nconfig interface 'lan'\n\toption proto 'static'\n", clk.now().Add(time.Hour))
	clk.add(time.Second)
	p.Trigger() // SIGHUP from the init script: re-hash now, not at the poll
	p.Step(in.notify)
	clk.add(5 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 1 || in.got[0].Author != (Author{Kind: AuthorLuci, User: "root", Via: "trigger"}) {
		t.Fatalf("%+v", in.got)
	}
	// Two sessions logged in: unknown.
	fu.sessions = `{"data":{"username":"root"}}{"data":{"username":"admin"}}`
	edit(t, root, "network", "\nconfig interface 'lan'\n\toption proto 'dhcp'\n", clk.now().Add(2*time.Hour))
	p.Trigger()
	p.Step(in.notify)
	clk.add(5 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 2 || in.got[1].Author != (Author{Kind: AuthorUnknown, Via: "trigger"}) {
		t.Fatalf("%+v", in.got)
	}
	// A trigger that changed nothing does not colour the next CLI edit.
	p.Trigger()
	p.Step(in.notify)
	clk.add(10 * time.Second)
	edit(t, root, "network", "\nconfig interface 'lan'\n\toption proto 'none'\n", clk.now().Add(3*time.Hour))
	p.Step(in.notify)
	clk.add(5 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 3 || in.got[2].Author.Via != "poll" {
		t.Fatalf("%+v", in.got)
	}
}

func TestWatchDebounceRestartsAndRevertsVanish(t *testing.T) {
	root, p, _, clk, in := watchSetup(t)
	orig, _ := os.ReadFile(filepath.Join(root, "etc/config/firewall"))
	p.Step(in.notify)
	edit(t, root, "firewall", "\nconfig defaults\n", clk.now().Add(time.Hour))
	p.Trigger()
	p.Step(in.notify)
	clk.add(4 * time.Second)
	edit(t, root, "firewall", "\nconfig defaults\n\toption x '1'\n", clk.now().Add(2*time.Hour))
	p.Trigger()
	p.Step(in.notify) // changed again: debounce restarts
	clk.add(4 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 0 {
		t.Fatal("reported while still changing")
	}
	// Put back as it was before anything was reported: nothing to say.
	edit(t, root, "firewall", string(orig), clk.now().Add(3*time.Hour))
	p.Trigger()
	p.Step(in.notify)
	clk.add(10 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 0 {
		t.Fatalf("a reverted edit was reported: %+v", in.got)
	}
}

func TestWatchHoldsWhileLuciApplyPending(t *testing.T) {
	root, p, _, clk, in := watchSetup(t)
	p.Step(in.notify)
	put(t, root, "var/run/rpcd/snapshot-files/network", "x")
	edit(t, root, "network", "\nconfig interface 'lan'\n", clk.now().Add(time.Hour))
	p.Trigger()
	p.Step(in.notify)
	clk.add(90 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 0 {
		t.Fatal("reported during the LuCI apply window")
	}
	// Confirmed: the snapshot goes away, the change is reported.
	os.RemoveAll(filepath.Join(root, "var/run/rpcd/snapshot-files"))
	p.Step(in.notify)
	if len(in.got) != 1 {
		t.Fatalf("%+v", in.got)
	}
	// A pending apply that never resolves is reported after the hold.
	put(t, root, "var/run/rpcd/snapshot-files/network", "x")
	edit(t, root, "network", "\nconfig interface 'wan'\n", clk.now().Add(2*time.Hour))
	p.Trigger()
	p.Step(in.notify)
	clk.add(LuciHold)
	p.Step(in.notify)
	if len(in.got) != 2 {
		t.Fatal("held forever")
	}
}

func TestWatchEchoSuppression(t *testing.T) {
	root, p, _, clk, in := watchSetup(t)
	p.Step(in.notify)
	edit(t, root, "network", "\nconfig interface 'lan'\n\toption proto 'static'\n", clk.now().Add(time.Hour))
	edit(t, root, "firewall", "\nconfig defaults\n", clk.now().Add(time.Hour))
	h, _ := p.files.Hash("network")
	p.RecordOwn("network", h, "g3-a41")
	p.Trigger()
	p.Step(in.notify)
	clk.add(5 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 2 {
		t.Fatalf("%+v", in.got)
	}
	own, router := in.got[0], in.got[1]
	if own.Origin != OriginPerch || own.ApplyID != "g3-a41" || !reflect.DeepEqual(own.Changed, []string{"network"}) || own.Author.Kind != AuthorPerch {
		t.Fatalf("own %+v", own)
	}
	if router.Origin != OriginRouter || !reflect.DeepEqual(router.Changed, []string{"firewall"}) {
		t.Fatalf("router %+v", router)
	}
	// The echo is used up: the next change of network is a router edit.
	edit(t, root, "network", "\nconfig interface 'lan'\n\toption proto 'dhcp'\n", clk.now().Add(2*time.Hour))
	p.Trigger()
	p.Step(in.notify)
	clk.add(5 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 3 || in.got[2].Origin != OriginRouter {
		t.Fatalf("%+v", in.got)
	}
}

func TestWatchWithoutSessionAndRebase(t *testing.T) {
	root, p, _, clk, in := watchSetup(t)
	in.ok = false
	p.Step(in.notify)
	edit(t, root, "firewall", "\nconfig defaults\n", clk.now().Add(time.Hour))
	p.Trigger()
	p.Step(in.notify)
	clk.add(5 * time.Second)
	p.Step(in.notify) // cannot send: stays pending
	in.ok = true
	clk.add(time.Second)
	p.Step(in.notify)
	if len(in.got) != 1 {
		t.Fatalf("pending change lost: %+v", in.got)
	}
	// Changed while disconnected, then a new session: the hello carries the
	// new hash, so nothing is notified for it.
	in.ok = false
	edit(t, root, "firewall", "\nconfig defaults\n\toption x '2'\n", clk.now().Add(2*time.Hour))
	p.Trigger()
	p.Step(in.notify)
	h := p.Hello(context.Background(), "")
	in.ok = true
	clk.add(10 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 1 {
		t.Fatalf("notified what the hello already said: %+v", in.got)
	}
	fw, _ := p.files.Hash("firewall")
	if h.Hashes["firewall"] != fw {
		t.Fatal("hello hash")
	}
	// A deleted config is a change; its hash is absent.
	os.Remove(filepath.Join(root, "etc/config/firewall"))
	p.Trigger()
	p.Step(in.notify)
	clk.add(5 * time.Second)
	p.Step(in.notify)
	if len(in.got) != 2 || !reflect.DeepEqual(in.got[1].Changed, []string{"firewall"}) {
		t.Fatalf("%+v", in.got)
	}
	if _, ok := in.got[1].Hashes["firewall"]; ok {
		t.Fatal("deleted config has a hash")
	}
}

func TestWatchModeOffAndClamps(t *testing.T) {
	root, p, _, clk, in := watchSetup(t)
	p.Configure(Configure{Mode: ModeOff})
	edit(t, root, "firewall", "\nconfig defaults\n", clk.now().Add(time.Hour))
	p.Trigger()
	if wait := p.Step(in.notify); wait != time.Minute {
		t.Fatal(wait)
	}
	clk.add(time.Hour)
	p.Step(in.notify)
	if len(in.got) != 0 || p.Mode() != ModeOff {
		t.Fatal("watched with mode off")
	}
	p.Configure(Configure{Mode: "weird"})
	if p.Mode() != ModeOff {
		t.Fatal("unknown mode is off")
	}
	p.Configure(Configure{Mode: ModeManaged, WatchSeconds: seconds(1), DebounceSeconds: seconds(1000)})
	p.mu.Lock()
	w, d := p.w.watch, p.w.debounce
	p.mu.Unlock()
	if w != MinWatchSeconds*time.Second || d != MaxDebounceSeconds*time.Second {
		t.Fatalf("%s %s", w, d)
	}
	p.Configure(Configure{Mode: ModeManaged})
	p.mu.Lock()
	w, d = p.w.watch, p.w.debounce
	p.mu.Unlock()
	if w != DefaultWatchSeconds*time.Second || d != DefaultDebounceSeconds*time.Second {
		t.Fatalf("defaults %s %s", w, d)
	}
	// Access none never watches.
	pn, _ := plane(t, root, Options{Access: AccessNone, Now: clk.now})
	pn.Configure(Configure{Mode: ModeManaged})
	if wait := pn.Step(in.notify); wait != time.Minute {
		t.Fatal(wait)
	}
}

func TestRunStopsAndWakes(t *testing.T) {
	root, p, _, _, _ := watchSetup(t)
	p.o.Now = time.Now
	var mu sync.Mutex
	var got []Changed
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx, func(c Changed) bool {
			mu.Lock()
			got = append(got, c)
			mu.Unlock()
			return true
		})
		close(done)
	}()
	p.Configure(Configure{Mode: ModeObserve, WatchSeconds: seconds(10), DebounceSeconds: seconds(1)})
	time.Sleep(50 * time.Millisecond)
	edit(t, root, "firewall", "\nconfig defaults\n", time.Now().Add(time.Hour))
	p.Trigger()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not report the triggered change")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// An own write the controller saw through a fresh hello (an apply's
// redial) leaves no echo behind: the router later pausing and resuming a
// section back to Perch's exact bytes is a router edit both times (lab,
// 2026-09-23: sqm enabled 0 then 1 was reported as origin perch, unread).
func TestWatchOwnEchoAbsorbedByHello(t *testing.T) {
	root, p, _, clk, in := watchSetup(t)
	p.Step(in.notify)
	written := "\nconfig interface 'lan'\n\toption proto 'static'\n"
	edit(t, root, "network", written, clk.now().Add(time.Hour))
	h, _ := p.files.Hash("network")
	p.RecordOwn("network", h, "g3-a42")
	// The apply drops the session; the fresh hello carries the new hash.
	p.Hello(context.Background(), "")
	p.Configure(Configure{Mode: ModeObserve, WatchSeconds: seconds(10), DebounceSeconds: seconds(5)})
	paused := "\nconfig interface 'lan'\n\toption proto 'static'\n\toption disabled '1'\n"
	for i, body := range []string{paused, written} {
		edit(t, root, "network", body, clk.now().Add(time.Duration(2+i)*time.Hour))
		p.Trigger()
		p.Step(in.notify)
		clk.add(5 * time.Second)
		p.Step(in.notify)
		if len(in.got) != i+1 || in.got[i].Origin != OriginRouter {
			t.Fatalf("edit %d: %+v", i, in.got)
		}
	}

	// Without a hello in between, a router edit on top of an own write
	// that was never reported still drops the echo.
	edit(t, root, "firewall", "\nconfig defaults\n", clk.now().Add(5*time.Hour))
	hf, _ := p.files.Hash("firewall")
	p.RecordOwn("firewall", hf, "g3-a43")
	edit(t, root, "firewall", "\nconfig defaults\n\toption input 'DROP'\n", clk.now().Add(6*time.Hour))
	p.Trigger()
	p.Step(in.notify)
	edit(t, root, "firewall", "\nconfig defaults\n", clk.now().Add(7*time.Hour))
	p.Trigger()
	p.Step(in.notify)
	clk.add(5 * time.Second)
	p.Step(in.notify)
	last := in.got[len(in.got)-1]
	if last.Origin != OriginRouter || !reflect.DeepEqual(last.Changed, []string{"firewall"}) {
		t.Fatalf("%+v", in.got)
	}
}
