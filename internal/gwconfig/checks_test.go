package gwconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Apply checks (gateway-sync protocol 1) on the fake clock: the router's
// answers (netifd status, routes, ping, TCP, DNS) are set per step.

// A router with an uplink: wan (dhcp) on wan0 with its device section.
const fixNetworkWAN = fixNetwork + `
config device 'wan0dev'
	option name 'wan0'
	option macaddr '02:00:00:00:00:01'

config interface 'wan'
	option device 'wan0'
	option proto 'dhcp'
	option metric '1'
`

const (
	wanUp      = `{"up":true,"l3_device":"wan0","device":"wan0","ipv4-address":[{"address":"203.0.113.10","mask":24}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"203.0.113.1"}]}`
	wanDown    = `{"up":false,"device":"wan0","errors":[{"code":"NO_DEVICE"}]}`
	wanRoute4  = "default via 203.0.113.1 dev wan0 proto static src 203.0.113.10 metric 1\n"
	netDumpWAN = `{"interface":[{"interface":"lan","up":true,"l3_device":"br-lan","device":"br-lan","proto":"static"},` +
		`{"interface":"guest","up":true,"l3_device":"br-guest","device":"br-guest","proto":"static"},` +
		`{"interface":"wan","up":true,"l3_device":"wan0","device":"wan0","proto":"dhcp","route":[{"target":"0.0.0.0","mask":0,"nexthop":"203.0.113.1"}]}]}`
)

// netState is what the network answers, switched between steps.
type netState struct {
	mu      sync.Mutex
	dns     bool
	tcpOpen map[string]bool
}

func (n *netState) resolve(_ context.Context, _, host string) ([]net.IP, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.dns {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host}
	}
	return []net.IP{net.ParseIP("192.0.2.80")}, nil
}

func (n *netState) dial(_ context.Context, _, addr, _ string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.tcpOpen[addr] {
		return nil
	}
	return errors.New("dial tcp " + addr + ": connect: connection refused")
}

func (n *netState) set(dns bool, open ...string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dns = dns
	n.tcpOpen = map[string]bool{}
	for _, a := range open {
		n.tcpOpen[a] = true
	}
}

// newWANEnv is an env whose router has an uplink that is up and reaches
// the internet.
func newWANEnv(t *testing.T, opts ...envOpt) (*env, *netState) {
	t.Helper()
	ns := &netState{}
	ns.set(true)
	opts = append([]envOpt{func(o *Options) { o.CheckResolve = ns.resolve; o.CheckDial = ns.dial }}, opts...)
	e := newEnv(t, opts...)
	put(t, e.root, "etc/config/network", fixNetworkWAN)
	e.router.set(func(r *fakeRouter) {
		r.netDump = netDumpWAN
		r.ifStatus = map[string]string{"wan": wanUp}
		r.route4 = wanRoute4
		r.pingOK = map[string]bool{"203.0.113.1": true, "1.1.1.1": true, "8.8.8.8": true}
	})
	return e, ns
}

func wanUplinkDown(e *env, ns *netState) {
	e.router.set(func(r *fakeRouter) {
		r.ifStatus = map[string]string{"wan": wanDown}
		r.route4 = ""
		r.pingOK = map[string]bool{}
	})
	ns.set(false)
}

const wanChecks = `{"v":1,"timeoutSeconds":60,"items":[
     {"id":"up:wan","kind":"interface_up","network":"wan","family":4,"mustPass":true},
     {"id":"route4","kind":"default_route","family":4},
     {"id":"reach4","kind":"reach","family":4,"targets":["$gateway:wan","1.1.1.1","8.8.8.8"],"tcpPort":443},
     {"id":"dns","kind":"resolve","name":"example.com"}]}`

// wanJob changes the WAN's metric to 2, with the given checks ("" = none).
func wanJob(e *env, id, checks string) string { return wanJobMetric(e, id, checks, "2") }

func wanJobMetric(e *env, id, checks, metric string) string {
	c := ""
	if checks != "" {
		c = `,"checks":` + checks
	}
	return fmt.Sprintf(`{"applyId":%q,"confirmTimeoutSeconds":300,"base":%s,"ops":[
	  {"op":"adopt","config":"network","section":"wan","perchId":"w1","domain":"wan"},
	  {"op":"put","config":"network","section":"wan","type":"interface","options":{"device":"wan0","proto":"dhcp","metric":%q}}]%s}`,
		id, mustJSON(e.base("network")), metric, c)
}

func itemStates(items []CheckItemResult) string {
	var out []string
	for _, i := range items {
		out = append(out, i.ID+"="+i.State)
	}
	return strings.Join(out, " ")
}

func pendingOnDisk(t *testing.T, e *env) *pendingRecord {
	t.Helper()
	rec, err := store{root: e.root}.readPending()
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestChecksPassThenConfirm(t *testing.T) {
	e, _ := newWANEnv(t)
	res, err := e.apply(wanJob(e, "c1", wanChecks))
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StatePendingConfirm || res.ConfirmTimeoutSeconds != 300 || res.Checks == nil || res.Checks.State != CheckPending ||
		res.Checks.TimeoutSeconds != 60 || res.Checks.AgentAdded || itemStates(res.Checks.Baseline) != "up:wan=passed route4=passed reach4=passed dns=passed" {
		t.Fatalf("%+v %+v", res, res.Checks)
	}
	if d := *res.Checks.Baseline[0].Detail; d != "up, 203.0.113.10/24" {
		t.Fatal(d)
	}
	// The pending record carries the checks for a restart.
	if rec := pendingOnDisk(t, e); rec.Checks == nil || len(rec.Checks.Items) != 4 || rec.CheckState == nil || rec.CheckState.State != CheckPending {
		t.Fatalf("%+v", rec)
	}
	// Before the reload settled nothing runs, and the confirm waits.
	e.waitReconnect()
	h := e.p.Hello(context.Background(), "c2")
	if h.Apply.Checks == nil || h.Apply.Checks.State != CheckRunning || h.Apply.Checks.StartedAt != "2026-09-23T10:00:00Z" {
		t.Fatalf("%+v", h.Apply.Checks)
	}
	_, err = e.p.Confirm("c1", SessionRef{Gen: 2})
	if code(err) != CodeChecksPending || data(err)["checks"].(*ChecksView).State != CheckRunning {
		t.Fatalf("%v %v", err, data(err))
	}
	// One round: everything passes.
	e.clock.Advance(0)
	st := e.p.ApplyState()
	if st.Checks.State != CheckPassed || itemStates(st.Checks.Items) != "up:wan=passed route4=passed reach4=passed dns=passed" || st.Checks.AllSkipped {
		t.Fatalf("%+v", st.Checks)
	}
	if d := *st.Checks.Items[0].Detail; d != "up after 0.0 s, 203.0.113.10/24" {
		t.Fatal(d)
	}
	if d := *st.Checks.Items[2].Detail; !strings.HasSuffix(d, "answered (icmp)") {
		t.Fatal(d)
	}
	if d := *st.Checks.Items[3].Detail; d != "example.com → 192.0.2.80" {
		t.Fatal(d)
	}
	notes := e.sentNotes()
	if len(notes) != 2 || notes[0].State != CheckRunning || notes[1].State != CheckPassed || notes[1].ApplyID != "c1" {
		t.Fatalf("%+v", notes)
	}
	if rec := pendingOnDisk(t, e); rec.CheckState.State != CheckPassed {
		t.Fatalf("%+v", rec.CheckState)
	}
	out, err := e.p.Confirm("c1", SessionRef{Gen: 2})
	if err != nil || out["state"] != StateConfirmed {
		t.Fatalf("%v %v", out, err)
	}
	if e.exists("etc/perch-collector/rollback/pending.json") || e.clock.active() != 0 {
		t.Fatalf("confirm leaves nothing behind (%d timers)", e.clock.active())
	}
	e.clock.Advance(10 * time.Minute)
	if len(e.sentResults()) != 0 {
		t.Fatal("a confirmed apply is never rolled back")
	}
}

func TestChecksFailRollBackBeforeTheDeadline(t *testing.T) {
	e, ns := newWANEnv(t)
	before := e.file("network")
	if _, err := e.apply(wanJob(e, "c2", wanChecks)); err != nil {
		t.Fatal(err)
	}
	// The job took the uplink down.
	wanUplinkDown(e, ns)
	e.waitReconnect()
	e.clock.Advance(0)
	st := e.p.ApplyState().Checks
	if st.State != CheckRunning || itemStates(st.Items) != "up:wan=running route4=running reach4=running dns=running" {
		t.Fatalf("%+v", st)
	}
	if d := *st.Items[0].Detail; d != "wan is down (NO_DEVICE)" {
		t.Fatal(d)
	}
	if d := *st.Items[2].Detail; d != "no answer from 2 targets; tcp 443 refused; $gateway:wan unknown" {
		t.Fatal(d)
	}
	for i := 0; i < 19; i++ {
		e.clock.Advance(checkRetry)
	}
	if e.p.ApplyState().State != StatePendingConfirm {
		t.Fatal("rolled back before the budget ended")
	}
	e.clock.Advance(checkRetry) // 60 s: the budget is over
	sent := e.sentResults()
	if len(sent) != 1 || sent[0].Reason != ReasonChecksFailed || sent[0].Outcome != OutcomeRolledBack || sent[0].At != "2026-09-23T10:01:00Z" ||
		sent[0].Checks == nil || sent[0].Checks.State != CheckFailed ||
		itemStates(sent[0].Checks.Items) != "up:wan=failed route4=failed reach4=failed dns=failed" ||
		!strings.HasPrefix(sent[0].Detail, "up:wan: wan is down (NO_DEVICE); route4: no IPv4 default route; reach4: no answer") {
		t.Fatalf("%+v", sent)
	}
	if e.file("network") != before || e.exists("etc/perch-collector/rollback/pending.json") || e.p.ApplyState().State != StateIdle {
		t.Fatal("not restored")
	}
	// Long before the 300 s deadline; nothing else fires later.
	e.clock.Advance(10 * time.Minute)
	if len(e.sentResults()) != 1 || e.clock.active() != 0 {
		t.Fatalf("%d results, %d timers", len(e.sentResults()), e.clock.active())
	}
	if _, err := e.p.Confirm("c2", SessionRef{Gen: 2}); code(err) != CodeDeadlinePassed {
		t.Fatal(err)
	}
	// Notifications: running at the start, at most one every 5 s while
	// running, failed at the end.
	notes := e.sentNotes()
	if notes[0].State != CheckRunning || notes[len(notes)-1].State != CheckFailed || len(notes) > 2+60/5 {
		t.Fatalf("%d notes: %+v", len(notes), notes)
	}
	for i := 1; i < len(notes)-1; i++ {
		if notes[i].ElapsedSeconds-notes[i-1].ElapsedSeconds < 5 && i > 1 {
			t.Fatalf("notes closer than 5 s: %+v", notes)
		}
	}
}

func TestChecksBaselineSkipsWhatFailedBefore(t *testing.T) {
	e, ns := newWANEnv(t)
	// The ISP is down before the job; the uplink itself is down too, and
	// the job must bring it up (mustPass).
	wanUplinkDown(e, ns)
	res, err := e.apply(wanJob(e, "c3", wanChecks))
	if err != nil {
		t.Fatal(err)
	}
	if itemStates(res.Checks.Baseline) != "up:wan=failed route4=skipped reach4=skipped dns=skipped" {
		t.Fatalf("%+v", res.Checks.Baseline)
	}
	e.waitReconnect()
	e.clock.Advance(0)
	st := e.p.ApplyState().Checks
	if st.State != CheckRunning || itemStates(st.Items) != "up:wan=running route4=skipped reach4=skipped dns=skipped" ||
		!strings.HasPrefix(*st.Items[1].Detail, "failed before the job: ") {
		t.Fatalf("%+v", st)
	}
	// The uplink comes up (the ISP is still out): the mustPass item passes,
	// the rest stays skipped.
	e.router.set(func(r *fakeRouter) { r.ifStatus = map[string]string{"wan": wanUp} })
	e.clock.Advance(checkRetry)
	st = e.p.ApplyState().Checks
	if st.State != CheckPassed || !st.AllSkipped || itemStates(st.Items) != "up:wan=passed route4=skipped reach4=skipped dns=skipped" ||
		*st.Items[0].Detail != "up after 3.0 s, 203.0.113.10/24" {
		t.Fatalf("%+v", st)
	}
	if _, err := e.p.Confirm("c3", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}

	// No mustPass and everything skipped: passed at once, no round runs.
	e2, ns2 := newWANEnv(t)
	wanUplinkDown(e2, ns2)
	if _, err := e2.apply(wanJob(e2, "c4", `{"v":1,"timeoutSeconds":30,"items":[{"id":"route4","kind":"default_route"},{"id":"dns","kind":"resolve","name":"example.com"}]}`)); err != nil {
		t.Fatal(err)
	}
	e2.waitReconnect()
	if st := e2.p.ApplyState().Checks; st.State != CheckPassed || !st.AllSkipped || e2.clock.active() != 1 {
		t.Fatalf("%+v, %d timers", st, e2.clock.active())
	}
	if _, err := e2.p.Confirm("c4", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}
}

func TestChecksOverride(t *testing.T) {
	e, ns := newWANEnv(t)
	if _, err := e.apply(wanJob(e, "c5", wanChecks)); err != nil {
		t.Fatal(err)
	}
	wanUplinkDown(e, ns)
	e.waitReconnect()
	e.clock.Advance(0)
	e.clock.Advance(checkRetry)
	if _, err := e.p.ConfirmWith("c5", false, SessionRef{Gen: 2}); code(err) != CodeChecksPending {
		t.Fatal(err)
	}
	// The override still needs the fresh session.
	if _, err := e.p.ConfirmWith("c5", true, SessionRef{Gen: 1}); code(err) != CodeNotReconnected {
		t.Fatal(err)
	}
	out, err := e.p.ConfirmWith("c5", true, SessionRef{Gen: 2})
	if err != nil || out["state"] != StateConfirmed {
		t.Fatalf("%v %v", out, err)
	}
	e.clock.Advance(10 * time.Minute)
	if len(e.sentResults()) != 0 || e.clock.active() != 0 || e.exists("etc/perch-collector/rollback/pending.json") {
		t.Fatal("an overridden apply stays, and its checks stop")
	}
	// Through the wire: overrideChecks in the confirm params.
	e2, ns2 := newWANEnv(t)
	if _, err := e2.apply(wanJob(e2, "c6", wanChecks)); err != nil {
		t.Fatal(err)
	}
	wanUplinkDown(e2, ns2)
	e2.waitReconnect()
	e2.clock.Advance(0)
	if _, err := e2.p.ServeWrite(context.Background(), MethodConfirm, json.RawMessage(`{"applyId":"c6"}`), SessionRef{Gen: 2}); code(err) != CodeChecksPending {
		t.Fatal(err)
	}
	if _, err := e2.p.ServeWrite(context.Background(), MethodConfirm, json.RawMessage(`{"applyId":"c6","overrideChecks":true}`), SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}
}

// A daemon restart during the checks: what passed stays passed, the rest
// runs again with what is left of the budget (never counted as a pass).
func TestChecksRestartMidChecks(t *testing.T) {
	e, ns := newWANEnv(t)
	if _, err := e.apply(wanJob(e, "c7", wanChecks)); err != nil {
		t.Fatal(err)
	}
	// Up and routed, but the internet does not answer yet.
	e.router.set(func(r *fakeRouter) { r.pingOK = map[string]bool{} })
	ns.set(true)
	e.waitReconnect()
	e.clock.Advance(0)
	e.clock.Advance(checkRetry) // 3 s
	if st := e.p.ApplyState().Checks; itemStates(st.Items) != "up:wan=passed route4=passed reach4=running dns=passed" {
		t.Fatalf("%+v", st)
	}
	if rec := pendingOnDisk(t, e); itemStates(rec.CheckState.Items) != "up:wan=passed route4=passed reach4=running dns=passed" ||
		rec.CheckState.StartedAt == nil || !rec.CheckState.StartedAt.Equal(e.clock.Now().Add(-3*time.Second)) {
		t.Fatalf("%+v", rec.CheckState)
	}
	// The daemon dies: its timers are gone with it.
	kill := func(p *Plane) {
		p.ap.mu.Lock()
		if p.ap.stop != nil {
			p.ap.stop()
		}
		p.ap.mu.Unlock()
		p.chk.mu.Lock()
		if p.chk.run != nil {
			p.stopRunLocked(p.chk.run)
		}
		p.chk.mu.Unlock()
	}
	kill(e.p)
	e.clock.Advance(20 * time.Second) // 23 s
	n := &env{t: t, root: e.root, clock: e.clock, be: e.be, router: e.router, reconCh: make(chan string, 16)}
	n.p = New(e.p.o)
	n.p.Configure(Configure{Mode: ModeManaged})
	n.hook()
	n.p.Start()
	st := n.p.ApplyState()
	if st.State != StatePendingConfirm || st.Checks.State != CheckRunning || itemStates(st.Checks.Items) != "up:wan=passed route4=passed reach4=pending dns=passed" {
		t.Fatalf("%+v %+v", st, st.Checks)
	}
	if _, err := n.p.Confirm("c7", SessionRef{Gen: 1}); code(err) != CodeChecksPending {
		t.Fatalf("a restart never counts as a pass: %v", err)
	}
	n.clock.Advance(0)
	if st := n.p.ApplyState().Checks; st.State != CheckRunning || itemStates(st.Items) != "up:wan=passed route4=passed reach4=running dns=passed" {
		t.Fatalf("%+v", st)
	}
	e.router.set(func(r *fakeRouter) { r.pingOK = map[string]bool{"1.1.1.1": true} })
	n.clock.Advance(checkRetry)
	if st := n.p.ApplyState().Checks; st.State != CheckPassed {
		t.Fatalf("%+v", st)
	}
	if _, err := n.p.Confirm("c7", SessionRef{Gen: 1}); err != nil {
		t.Fatal(err)
	}

	// Restarted after the budget ran out: failed, rolled back at once.
	e2, _ := newWANEnv(t)
	before := e2.file("network")
	if _, err := e2.apply(wanJob(e2, "c8", wanChecks)); err != nil {
		t.Fatal(err)
	}
	e2.router.set(func(r *fakeRouter) { r.pingOK = map[string]bool{} })
	e2.waitReconnect()
	e2.clock.Advance(0)
	kill(e2.p)
	e2.clock.Advance(90 * time.Second)
	n2 := New(e2.p.o)
	var got []Result
	n2.SetHooks(Hooks{Result: func(r Result) bool { got = append(got, r); return true }})
	n2.Start() // no round runs: the budget is over
	if len(got) != 1 || got[0].Reason != ReasonChecksFailed || e2.file("network") != before || n2.ApplyState().State != StateIdle ||
		itemStates(got[0].Checks.Items) != "up:wan=passed route4=passed reach4=failed dns=passed" {
		t.Fatalf("%+v", got)
	}

	// Died between failing and restoring: restored at start.
	e3, _ := newWANEnv(t)
	before3 := e3.file("network")
	if _, err := e3.apply(wanJob(e3, "c9", wanChecks)); err != nil {
		t.Fatal(err)
	}
	e3.waitReconnect()
	kill(e3.p)
	rec := pendingOnDisk(t, e3)
	rec.CheckState.State = CheckFailed
	store{root: e3.root}.writePending(rec)
	n3 := New(e3.p.o)
	n3.Start()
	if r := n3.Results(); len(r) != 1 || r[0].Reason != ReasonChecksFailed || e3.file("network") != before3 {
		t.Fatalf("%+v", r)
	}
}

// An older binary reads the new pending record and ignores the checks.
func TestPendingRecordWithChecksStaysReadable(t *testing.T) {
	e, _ := newWANEnv(t)
	if _, err := e.apply(wanJob(e, "c10", wanChecks)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(e.root, "etc/perch-collector/rollback/pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		ApplyID   string    `json:"applyId"`
		Deadline  time.Time `json:"deadline"`
		Committed bool      `json:"committed"`
		Configs   []string  `json:"configs"`
	}
	if err := json.Unmarshal(data, &old); err != nil || old.ApplyID != "c10" || !old.Committed || old.Deadline.IsZero() {
		t.Fatalf("%+v %v", old, err)
	}
	if !strings.Contains(string(data), `"checks"`) || !strings.Contains(string(data), `"checkState"`) {
		t.Fatal(string(data))
	}
}

// The agent's own net: a job without checks that changes an uplink gets a
// default-route check; an explicit empty list means none.
func TestAgentNet(t *testing.T) {
	e, _ := newWANEnv(t)
	res, err := e.apply(wanJob(e, "n1", ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Checks == nil || !res.Checks.AgentAdded || res.Checks.TimeoutSeconds != agentChecksSeconds || itemStates(res.Checks.Baseline) != "agent:route4=passed" {
		t.Fatalf("%+v", res.Checks)
	}
	e.waitReconnect()
	if _, err := e.p.Confirm("n1", SessionRef{Gen: 2}); code(err) != CodeChecksPending {
		t.Fatal(err)
	}
	e.clock.Advance(0)
	if _, err := e.p.Confirm("n1", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}

	// The controller says "no checks": none.
	res, err = e.apply(wanJobMetric(e, "n2", `{"v":1,"items":[]}`, "3"))
	if err != nil || res.Checks != nil {
		t.Fatalf("%+v %v", res, err)
	}
	e.waitReconnect()
	if _, err := e.p.Confirm("n2", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}

	// Not an uplink (a static LAN without a default route): none.
	res, err = e.apply(fmt.Sprintf(`{"applyId":"n3","base":%s,"ops":[
	  {"op":"adopt","config":"network","section":"guest","perchId":"g1"},
	  {"op":"put","config":"network","section":"guest","type":"interface","options":{"device":"br-guest","proto":"static","ipaddr":"192.168.3.1","netmask":"255.255.255.0"}}]}`,
		mustJSON(e.base("network"))))
	if err != nil || res.Checks != nil {
		t.Fatalf("%+v %v", res, err)
	}
	e.waitReconnect()
	if _, err := e.p.Confirm("n3", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}

	// A static interface holding the default route now, and the uplink's
	// device section (its MAC): the net.
	e.router.set(func(r *fakeRouter) {
		r.netDump = strings.Replace(netDumpWAN, `"interface":"guest","up":true,"l3_device":"br-guest","device":"br-guest","proto":"static"`,
			`"interface":"guest","up":true,"l3_device":"br-guest","device":"br-guest","proto":"static","route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.168.3.254"}]`, 1)
	})
	res, err = e.apply(fmt.Sprintf(`{"applyId":"n4","base":%s,"ops":[
	  {"op":"put","config":"network","section":"guest","type":"interface","options":{"device":"br-guest","proto":"static","ipaddr":"192.168.4.1","netmask":"255.255.255.0"}}]}`,
		mustJSON(e.base("network"))))
	if err != nil || res.Checks == nil || !res.Checks.AgentAdded {
		t.Fatalf("%+v %v", res, err)
	}
	e.waitReconnect()
	e.clock.Advance(0)
	if _, err := e.p.Confirm("n4", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}
	res, err = e.apply(fmt.Sprintf(`{"applyId":"n5","base":%s,"ops":[
	  {"op":"adopt","config":"network","section":"wan0dev","perchId":"d1"},
	  {"op":"put","config":"network","section":"wan0dev","type":"device","options":{"name":"wan0","macaddr":"02:00:00:00:00:02"}}]}`,
		mustJSON(e.base("network"))))
	if err != nil || res.Checks == nil || !res.Checks.AgentAdded {
		t.Fatalf("%+v %v", res, err)
	}
	e.waitReconnect()
	e.clock.Advance(0)
	if _, err := e.p.Confirm("n5", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}

	// An older controller (no checks) whose job kills the default route:
	// the confirm keeps being refused and the net rolls back.
	before := e.file("network")
	if _, err := e.apply(wanJobMetric(e, "n6", "", "4")); err != nil {
		t.Fatal(err)
	}
	e.router.set(func(r *fakeRouter) { r.route4 = "" })
	e.waitReconnect()
	for i := 0; i < 40 && e.p.ApplyState().State == StatePendingConfirm; i++ {
		if _, err := e.p.Confirm("n6", SessionRef{Gen: 2}); code(err) != CodeChecksPending {
			t.Fatal(err)
		}
		e.clock.Advance(checkRetry)
	}
	sent := e.sentResults()
	if len(sent) != 1 || sent[0].ApplyID != "n6" || sent[0].Reason != ReasonChecksFailed || e.file("network") != before {
		t.Fatalf("%+v", sent)
	}
	// 90 s budget in a 300 s window.
	if sent[0].At != e.clock.Now().UTC().Format(time.RFC3339) || e.clock.Now().Sub(time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)) > 2*time.Minute {
		t.Fatalf("rolled back at %s", sent[0].At)
	}
}

// The budget is clamped to the window minus 20 s, and ends before the
// deadline whatever the controller asked for.
func TestChecksBudgetClamp(t *testing.T) {
	e, _ := newWANEnv(t)
	res, err := e.apply(fmt.Sprintf(`{"applyId":"b1","confirmTimeoutSeconds":60,"base":%s,"ops":[
	  {"op":"adopt","config":"network","section":"wan","perchId":"w1"},
	  {"op":"put","config":"network","section":"wan","type":"interface","options":{"device":"wan0","proto":"dhcp","metric":"5"}}],
	  "checks":{"v":1,"timeoutSeconds":900,"items":[{"id":"r","kind":"reach","targets":["192.0.2.99"]}]}}`, mustJSON(e.base("network"))))
	if err != nil || res.ConfirmTimeoutSeconds != 60 || res.Checks.TimeoutSeconds != 40 {
		t.Fatalf("%+v %v", res, err)
	}
	// 192.0.2.99 answered before (baseline passed) but not after.
	if itemStates(res.Checks.Baseline) != "r=skipped" {
		t.Fatalf("%+v", res.Checks.Baseline)
	}
}

func TestProbes(t *testing.T) {
	e, ns := newWANEnv(t)
	ctx := context.Background()
	probe := func(js string) (bool, string) {
		t.Helper()
		it := mustItem(t, js)
		if err := validateChecks(&Checks{V: 1, TimeoutSeconds: 60, Items: []CheckItem{it}}); err != nil {
			t.Fatal(err)
		}
		return e.p.probe(ctx, it, time.Time{})
	}
	e.router.set(func(r *fakeRouter) {
		r.ifStatus["wan6"] = `{"up":true,"l3_device":"wan0","ipv6-prefix":[{"address":"2001:db8:10::","mask":56}],"route":[{"target":"::","mask":0,"nexthop":"fe80::1"}]}`
		r.ifStatus["wg0"] = `{"up":true,"l3_device":"wg0"}`
		r.route6 = "default from 2001:db8:10::/56 via fe80::1 dev wan0 proto static metric 512 pref medium\n"
		r.pingOK = map[string]bool{}
		r.wgHS = map[string]string{"wg0": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t" + fmt.Sprint(e.clock.Now().Unix()-40) +
			"\nTrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=\t0\n"}
	})
	cases := []struct {
		item string
		ok   bool
		want string
	}{
		{`{"id":"a","kind":"interface_up","network":"wan6","family":6}`, true, "up, prefix 2001:db8:10::/56"},
		{`{"id":"a","kind":"interface_up","network":"wan"}`, true, "up, 203.0.113.10/24"},
		{`{"id":"a","kind":"interface_up","network":"wan","family":6}`, false, "wan is up without an IPv6 address"},
		{`{"id":"a","kind":"interface_up","network":"nope"}`, false, "nope: no such interface"},
		{`{"id":"a","kind":"default_route","network":"wan"}`, true, "default via 203.0.113.1 dev wan0 proto static src 203.0.113.10 metric 1"},
		{`{"id":"a","kind":"default_route","family":6}`, true, "default from 2001:db8:10::/56 via fe80::1 dev wan0 proto static metric 512 pref medium"},
		{`{"id":"a","kind":"default_route","network":"wg0"}`, false, "no IPv4 default route through wg0"},
		{`{"id":"a","kind":"reach","targets":["$gateway:wan"]}`, false, "no answer from 1 target"},
		{`{"id":"a","kind":"reach","targets":["$gateway:wg0"]}`, false, "no target ($gateway:wg0 unknown)"},
		{`{"id":"a","kind":"reach","targets":["192.0.2.7"],"tcpPort":443}`, false, "no answer from 1 target; tcp 443 refused"},
		{`{"id":"a","kind":"reach","targets":["192.0.2.7"],"tcpPort":443,"via":"nope"}`, false, "via nope: no device"},
		{`{"id":"a","kind":"wg_handshake","network":"wg0","withinSeconds":60}`, true, "handshake 40 s ago"},
		{`{"id":"a","kind":"wg_handshake","network":"wg0","withinSeconds":30}`, false, "no handshake within 30 s"},
		{`{"id":"a","kind":"wg_handshake","network":"wg0","publicKey":"TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=","withinSeconds":600}`, false, "no handshake within 600 s"},
		{`{"id":"a","kind":"wg_handshake","network":"wg0","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","withinSeconds":600}`, false, "peer not configured on wg0"},
		{`{"id":"a","kind":"wg_handshake","network":"wg9","withinSeconds":600}`, false, "wg9: no WireGuard interface"},
		{`{"id":"a","kind":"resolve","name":"example.com","family":6}`, true, "example.com → 192.0.2.80"},
	}
	for _, c := range cases {
		ok, d := probe(c.item)
		if ok != c.ok || d != c.want {
			t.Errorf("%s: %v %q, want %v %q", c.item, ok, d, c.ok, c.want)
		}
	}
	// TCP answers; via pings through the device.
	ns.set(true, "192.0.2.7:443")
	if ok, d := probe(`{"id":"a","kind":"reach","targets":["192.0.2.7"],"tcpPort":443,"via":"wan"}`); !ok || d != "192.0.2.7:443 connected (tcp)" {
		t.Fatalf("%v %q", ok, d)
	}
	e.router.set(func(r *fakeRouter) { r.pingOK = map[string]bool{"fe80::1": true} })
	if ok, d := probe(`{"id":"a","kind":"reach","family":6,"targets":["$gateway:wan6","2001:db8::1"]}`); !ok || d != "fe80::1 answered (icmp)" {
		t.Fatalf("%v %q", ok, d)
	}
	ns.set(false)
	if ok, d := probe(`{"id":"a","kind":"resolve","name":"example.com"}`); ok || d != "example.com: server misbehaving" {
		t.Fatalf("%v %q", ok, d)
	}
	var sawVia, sawLinkLocal, sawSecret bool
	for _, c := range e.router.log() {
		if strings.HasPrefix(c, "ping -c 1 -W 2 -I wan0 192.0.2.7") {
			sawVia = true
		}
		if c == "ping -c 1 -W 2 -I wan0 fe80::1" {
			sawLinkLocal = true
		}
		if strings.HasPrefix(c, "wg ") && !strings.HasSuffix(c, " latest-handshakes") {
			sawSecret = true
		}
	}
	if !sawVia || !sawLinkLocal || sawSecret {
		t.Fatalf("ping via %v, link-local on its device %v, a wg command that prints keys %v: %v", sawVia, sawLinkLocal, sawSecret, e.router.log())
	}
	if clip(strings.Repeat("é", 150)) == strings.Repeat("é", 150) || len(clip(strings.Repeat("é", 150))) > checkDetailMax {
		t.Fatal("clip")
	}
}

// WireGuard peers on the management path are protected (gateway-sync
// domains 4): every peer of a path interface, and a peer whose routed
// allowed_ips cover the controller.
func TestWireGuardPeersOnTheManagementPath(t *testing.T) {
	cfg := func(body string) *uci.Config {
		c, err := uci.Parse("network", []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	network := cfg(fixNetwork + `
config interface 'wg0'
	option proto 'wireguard'
	list addresses '192.168.9.1/24'

config wireguard_wg0 'peer_a'
	option public_key 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg='
	list allowed_ips '192.168.9.2/32'

config interface 'wgc'
	option proto 'wireguard'

config wireguard_wgc 'peer_all'
	option route_allowed_ips '1'
	list allowed_ips '0.0.0.0/0'

config wireguard_wgc 'peer_off'
	option route_allowed_ips '0'
	list allowed_ips '0.0.0.0/0'

config wireguard_wgc 'peer_other'
	option route_allowed_ips '1'
	list allowed_ips '10.99.0.0/16'
`)
	name := "wg0"
	// The path runs over wg0 (a remote controller dialled over WireGuard).
	prot := protectedSections(map[string]*uci.Config{"network": network}, &ManagementPath{Network: &name, Device: "wg0", ControllerAddress: "192.168.9.5"})
	want := map[string]bool{"wg0": true, "peer_a": true, "peer_all": true}
	if len(prot["network"]) != len(want) {
		t.Fatalf("%v", prot["network"])
	}
	for s := range prot["network"] {
		if !want[s] {
			t.Fatalf("%v", prot["network"])
		}
	}
	// The path runs over the LAN: only the peer routing everything.
	lan := "lan"
	prot = protectedSections(map[string]*uci.Config{"network": network}, &ManagementPath{Network: &lan, Device: "br-lan", ControllerAddress: "192.168.1.5"})
	if !prot["network"]["peer_all"] || prot["network"]["peer_a"] || prot["network"]["peer_off"] || prot["network"]["peer_other"] || !prot["network"]["lan"] {
		t.Fatalf("%v", prot["network"])
	}
	// An apply that adds such a peer gets the protected window.
	e := newEnv(t)
	res, err := e.apply(fmt.Sprintf(`{"applyId":"p1","confirmTimeoutSeconds":90,"base":%s,"ops":[
	  {"op":"put","config":"network","section":"perch_wgp1","type":"wireguard_wgc","options":{"route_allowed_ips":"1","allowed_ips":["192.168.0.0/16"]}}]}`,
		mustJSON(e.base("network"))))
	if err != nil || !res.Protected || res.ConfirmTimeoutSeconds != ProtectedConfirmSeconds {
		t.Fatalf("%+v %v", res, err)
	}
}
