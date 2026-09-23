package gwconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// A DHCP reservation, the first managed domain: a new section under a
// Perch name, registered in the ledger.
func reservationJSON(e *env, id string) string {
	return fmt.Sprintf(`{"applyId":%q,"kind":"apply","confirmTimeoutSeconds":90,"base":%s,
	 "ops":[{"op":"put","config":"dhcp","section":"perch_h1","type":"host",
	         "options":{"name":"camera","mac":"02:00:00:00:00:20","ip":"192.168.1.20"}}],
	 "ledger":{"set":[{"perchId":"h1","config":"dhcp","section":"perch_h1","domain":"dhcp_hosts"}]}}`,
		id, mustJSON(e.base("dhcp")))
}

func TestApplyConfirmOnAFreshSession(t *testing.T) {
	e := newEnv(t)

	before := e.file("dhcp")
	res, err := e.apply(reservationJSON(e, "a1"))
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StatePendingConfirm || res.ConfirmTimeoutSeconds != 90 || res.Protected ||
		res.Deadline != "2026-09-23T10:01:30Z" || res.Hashes["dhcp"] != e.hash("dhcp") || res.Hashes[LedgerConfig] != e.hash(LedgerConfig) {
		t.Fatalf("%+v", res)
	}
	host := e.load("dhcp").Section("perch_h1")
	if host == nil || host.Type != "host" || mustJSON(host.Values()) != `{"ip":"192.168.1.20","mac":"02:00:00:00:00:20","name":"camera"}` {
		t.Fatalf("committed %s", e.file("dhcp"))
	}
	if !strings.Contains(e.file(LedgerConfig), "config synced 'h1'\n\toption config 'dhcp'\n\toption section 'perch_h1'\n\toption domain 'dhcp_hosts'\n") {
		t.Fatalf("ledger %q", e.file(LedgerConfig))
	}
	// The fallback's reload ran for the config, not the ledger.
	if got := e.be.reloadLog(); !reflect.DeepEqual(got, [][]string{{"dhcp"}}) {
		t.Fatalf("reloads %v", got)
	}
	// Snapshot on flash, marker on tmpfs, pending record.
	if !e.exists("etc/perch-collector/rollback/a1/before/dhcp") || !e.exists("etc/perch-collector/rollback/pending.json") ||
		!e.exists("var/run/perch-collector/apply-a1") || e.exists("etc/perch-collector/rollback/a1/before/"+LedgerConfig) {
		t.Fatal("snapshot, record or marker missing")
	}
	snap, _ := os.ReadFile(filepath.Join(e.root, "etc/perch-collector/rollback/a1/before/dhcp"))
	if string(snap) != before {
		t.Fatal("snapshot is not the file before the apply")
	}
	// The session is dropped once the reload settled.
	if r := e.waitReconnect(); !strings.Contains(r, "a1") {
		t.Fatal(r)
	}
	if st := e.p.ApplyState(); st.State != StatePendingConfirm || st.ApplyID != "a1" || st.Kind != KindApply || st.Deadline != res.Deadline {
		t.Fatalf("%+v", st)
	}
	if h := e.p.Hello(context.Background(), "c2"); h.Apply.State != StatePendingConfirm || len(h.Results) != 0 {
		t.Fatalf("%+v", h)
	}
	if !e.p.RedialFast() {
		t.Fatal("the loop must redial fast while the apply waits")
	}
	// A second apply meanwhile is busy; the same one again is the same reply.
	if _, err := e.apply(reservationJSON(e, "a2")); code(err) != CodeBusy || data(err)["reason"] != "apply_pending" {
		t.Fatalf("%v", err)
	}
	again, err := e.apply(reservationJSON(e, "a1"))
	if err != nil || again.State != StatePendingConfirm || again.Deadline != res.Deadline {
		t.Fatalf("%+v %v", again, err)
	}
	// Confirm on the session the apply came on: refused.
	if _, err := e.p.Confirm("a1", SessionRef{Gen: 1}); code(err) != CodeNotReconnected {
		t.Fatalf("%v", err)
	}
	if _, err := e.p.Confirm("zz", SessionRef{Gen: 2}); code(err) != CodeUnknownApply {
		t.Fatalf("%v", err)
	}
	e.clock.Advance(80 * time.Second)
	out, err := e.p.Confirm("a1", SessionRef{Gen: 2})
	if err != nil || out["state"] != StateConfirmed || out["hashes"].(map[string]string)["dhcp"] != e.hash("dhcp") {
		t.Fatalf("%v %v", out, err)
	}
	if e.exists("etc/perch-collector/rollback/a1") || e.exists("etc/perch-collector/rollback/pending.json") || e.exists("var/run/perch-collector/apply-a1") {
		t.Fatal("confirm must drop the snapshot, the record and the marker")
	}
	// Idempotent, and the deadline no longer matters.
	if out, err := e.p.Confirm("a1", SessionRef{Gen: 3}); err != nil || out["state"] != StateConfirmed {
		t.Fatalf("%v %v", out, err)
	}
	e.clock.Advance(time.Hour)
	if e.load("dhcp").Section("perch_h1") == nil || len(e.sentResults()) != 0 || e.clock.active() != 0 {
		t.Fatal("a confirmed apply stays")
	}
	if st := e.p.ApplyState(); st.State != StateIdle || e.p.RedialFast() {
		t.Fatalf("%+v", st)
	}
	// The fresh session's hello carried the committed hashes: the commit
	// needs no echo (the watcher reports nothing), and none is left behind
	// to mislabel a later router edit (TestWatchOwnEchoAbsorbedByHello).
	if notes := e.drainNotes(e.p.Hashes()); len(notes) != 0 {
		t.Fatalf("%+v", notes)
	}
	if len(e.p.w.own) != 0 {
		t.Fatalf("echo left behind: %+v", e.p.w.own)
	}
}

// drainNotes runs the watcher: a forced scan, then a report after the
// debounce.
func (e *env) drainNotes(baseline map[string]string) []Changed {
	e.p.mu.Lock()
	e.p.w.rebase(baseline)
	e.p.w.force = true
	e.p.mu.Unlock()
	var notes []Changed
	e.p.Step(func(c Changed) bool { notes = append(notes, c); return true })
	e.clock.Advance(10 * time.Second)
	e.p.Step(func(c Changed) bool { notes = append(notes, c); return true })
	return notes
}

func TestDeadlineRestoresTheSnapshot(t *testing.T) {
	e := newEnv(t)
	before := e.file("dhcp")
	res, err := e.apply(reservationJSON(e, "a1"))
	if err != nil {
		t.Fatal(err)
	}
	e.waitReconnect()
	e.clock.Advance(89 * time.Second)
	if e.p.ApplyState().State != StatePendingConfirm {
		t.Fatal("rolled back early")
	}
	e.clock.Advance(time.Second)
	if e.file("dhcp") != before || e.exists("etc/config/"+LedgerConfig) {
		t.Fatalf("not restored: %s", e.file("dhcp"))
	}
	if got := e.be.reloadLog(); !reflect.DeepEqual(got, [][]string{{"dhcp"}, {"dhcp"}}) {
		t.Fatalf("the restored config must be reloaded: %v", got)
	}
	sent := e.sentResults()
	if len(sent) != 1 || sent[0].ApplyID != "a1" || sent[0].Outcome != OutcomeRolledBack || sent[0].Reason != ReasonConfirmTimeout ||
		sent[0].At != "2026-09-23T10:01:30Z" || sent[0].Hashes["dhcp"] != e.hash("dhcp") || sent[0].Discarded != nil {
		t.Fatalf("%+v", sent)
	}
	if e.exists("etc/perch-collector/rollback/a1") || e.exists("etc/perch-collector/rollback/pending.json") {
		t.Fatal("rollback leaves the snapshot behind")
	}
	// Kept for the hello until acked; confirm is too late now.
	h := e.p.Hello(context.Background(), "c2")
	if h.Apply.State != StateIdle || len(h.Results) != 1 || h.Results[0].ApplyID != "a1" {
		t.Fatalf("%+v", h)
	}
	if _, err := e.p.Confirm("a1", SessionRef{Gen: 2}); code(err) != CodeDeadlinePassed {
		t.Fatalf("%v", err)
	}
	if !e.p.RedialFast() {
		t.Fatal("redial fast after a rollback, so the controller hears it")
	}
	if out, _ := e.p.Ack([]string{"a1", "nope"}); out["acked"] != 1 || len(e.p.Results()) != 0 {
		t.Fatalf("%v", out)
	}
	if res.ApplyID != "a1" {
		t.Fatal(res.ApplyID)
	}
	// The slot is free again.
	if r, err := e.apply(reservationJSON(e, "a3")); err != nil || r.State != StatePendingConfirm {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestRollbackKeepsRouterEditsAsDiscarded(t *testing.T) {
	e := newEnv(t)
	before := e.file("dhcp")
	if _, err := e.apply(reservationJSON(e, "a1")); err != nil {
		t.Fatal(err)
	}
	// Someone edits the router during the window (LuCI, ssh).
	c := e.load("dhcp")
	c.Section("lan").Set("leasetime", uci.String("1h"))
	c.Sections = append(c.Sections, &uci.Section{Name: "extra", Type: "host", Options: []uci.Option{{Name: "name", Value: uci.String("tv")}, {Name: "key", Value: uci.String("s3cret")}}})
	var gone *uci.Section
	for _, s := range c.Sections {
		if s.Name == "nas" {
			gone = s
		}
	}
	kept := c.Sections[:0]
	for _, s := range c.Sections {
		if s != gone {
			kept = append(kept, s)
		}
	}
	c.Sections = kept
	os.WriteFile(filepath.Join(e.root, "etc/config/dhcp"), uci.Render(c), 0o644)
	e.clock.Advance(90 * time.Second)
	if e.file("dhcp") != before {
		t.Fatal("not restored")
	}
	r := e.sentResults()[0]
	d := r.Discarded["dhcp"]
	got := map[string]string{}
	for _, s := range d {
		got[s.Name] = s.Change
	}
	if !reflect.DeepEqual(got, map[string]string{"lan": "changed", "extra": "added", "nas": "removed"}) {
		t.Fatalf("%s", mustJSON(r.Discarded))
	}
	for _, s := range d {
		if s.Name == "extra" && (s.Options["key"].Items != nil || !strings.HasPrefix(s.Secrets["key"], "hmac:")) {
			t.Fatalf("discarded secrets must be redacted: %s", mustJSON(s))
		}
	}
}

func TestAdminRollback(t *testing.T) {
	e := newEnv(t)
	before := e.file("dhcp")
	if _, err := e.apply(reservationJSON(e, "a1")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.RollbackNow("other"); code(err) != CodeUnknownApply {
		t.Fatal(err)
	}
	out, err := e.p.RollbackNow("a1")
	if err != nil || out["state"] != StateRollingBack {
		t.Fatalf("%v %v", out, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for e.p.ApplyState().State != StateIdle && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.file("dhcp") != before || e.sentResults()[0].Reason != ReasonAdmin || e.clock.active() != 0 {
		t.Fatal("admin rollback")
	}
	// A repeat reports the outcome.
	if out, err := e.p.RollbackNow("a1"); err != nil || out["state"] != OutcomeRolledBack {
		t.Fatalf("%v %v", out, err)
	}
}

func TestRefusals(t *testing.T) {
	e := newEnv(t)
	// Stale base.
	js := reservationJSON(e, "a1")
	os.WriteFile(filepath.Join(e.root, "etc/config/dhcp"), []byte(fixDHCP+"\nconfig host 'late'\n\toption name 'x'\n"), 0o644)
	_, err := e.apply(js)
	if code(err) != CodeStaleBase || !reflect.DeepEqual(data(err)["configs"], []string{"dhcp"}) || data(err)["hashes"].(map[string]string)["dhcp"] != e.hash("dhcp") {
		t.Fatalf("%v %v", err, data(err))
	}
	// Missing base.
	if _, err := e.apply(`{"applyId":"a2","base":{},"ops":[{"op":"delete","config":"dhcp","section":"nas"}]}`); code(err) != CodeBadParams {
		t.Fatal(err)
	}
	// Config not allowed, denylisted, the ledger itself.
	for _, cfg := range []string{"system", "rpcd", "perch-collector", LedgerConfig} {
		_, err := e.apply(fmt.Sprintf(`{"applyId":"a3","base":{%q:""},"ops":[{"op":"put","config":%q,"section":"x","type":"t","options":{}}]}`, cfg, cfg))
		if code(err) != ErrConfigNotAllowed.Error() {
			t.Fatalf("%s: %v", cfg, err)
		}
	}
	// LuCI apply pending.
	put(t, e.root, "var/run/rpcd/snapshot-files/network", "x")
	if _, err := e.apply(reservationJSON(e, "a4")); code(err) != CodeBusy || data(err)["reason"] != "luci_pending" {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(e.root, "var/run/rpcd"))
	// Foreign staged network deltas (uci set without commit).
	put(t, e.root, "tmp/.uci/network", "network.guest.ipaddr='192.168.3.1'\nnetwork.wg0.private_key='abc'\n")
	netJS := fmt.Sprintf(`{"applyId":"a5","base":%s,"ops":[{"op":"adopt","config":"network","section":"guest","perchId":"n2"},
	  {"op":"put","config":"network","section":"guest","type":"interface","options":{"device":"br-guest","proto":"static","ipaddr":"192.168.9.1","netmask":"255.255.255.0"}}]}`,
		mustJSON(e.base("network")))
	_, err = e.apply(netJS)
	if code(err) != "foreign_staged" || strings.Join(data(err)["changes"].([]string), "|") != "network.guest.ipaddr='192.168.3.1'|network.wg0.private_key=<redacted>" {
		t.Fatalf("%v %v", err, data(err))
	}
	os.Remove(filepath.Join(e.root, "tmp/.uci/network"))
	// Not managed by the controller.
	e.p.Configure(Configure{Mode: ModeObserve})
	if _, err := e.apply(reservationJSON(e, "a6")); code(err) != ErrNotManaged.Error() {
		t.Fatal(err)
	}
	e.p.Configure(Configure{Mode: ModeManaged})
	// Bad ids and kinds.
	for _, js := range []string{`{"applyId":"../x","base":{},"ops":[]}`, `{"applyId":"a7","kind":"nuke","base":{},"ops":[]}`,
		`{"applyId":"a8","base":` + mustJSON(e.base("dhcp")) + `,"ops":[{"op":"frob","config":"dhcp","section":"x"}]}`} {
		var a ApplyParams
		json.Unmarshal([]byte(js), &a)
		if _, err := e.p.Apply(context.Background(), &a, SessionRef{Gen: 1}, true); code(err) != CodeBadParams {
			t.Fatalf("%s: %v", js, err)
		}
	}
	// Every refusal released the slot.
	if r, err := e.apply(reservationJSON(e, "ok")); err != nil || r.State != StatePendingConfirm {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestOwnership(t *testing.T) {
	e := newEnv(t)
	b := mustJSON(e.base("dhcp"))
	cases := []struct {
		ops, ledger, want string
	}{
		// A router section is not Perch's until adopted.
		{`[{"op":"put","config":"dhcp","section":"nas","type":"host","options":{"name":"x"}}]`, `{}`, CodeNotOwned},
		{`[{"op":"delete","config":"dhcp","section":"nas"}]`, `{}`, CodeNotOwned},
		{`[{"op":"order","config":"dhcp","type":"host","sections":["nas"]}]`, `{}`, CodeNotOwned},
		// Anonymous sections are adopted under a new name only.
		{`[{"op":"adopt","config":"dhcp","section":"%[3]s","perchId":"h9"}]`, `{}`, CodeBadParams},
		{`[{"op":"adopt","config":"dhcp","section":"%[3]s","perchId":"h9","renameTo":"nas"}]`, `{}`, CodeNameTaken},
		{`[{"op":"adopt","config":"dhcp","section":"nope","perchId":"h9"}]`, `{}`, CodeNoSection},
		{`[{"op":"adopt","config":"dhcp","section":"nas","perchId":"bad-id!"}]`, `{}`, CodeBadParams},
		// The ledger never takes a router section as a side effect.
		{`[]`, `{"set":[{"perchId":"h9","config":"dhcp","section":"nas"}]}`, CodeNotOwned},
		{`[]`, `{"set":[{"perchId":"h9","config":"dhcp","section":"%[3]s"}]}`, CodeBadParams},
		{`[]`, `{"set":[{"perchId":"h9","config":"dhcp","section":"ghost"}]}`, CodeNoSection},
		// Values.
		{`[{"op":"put","config":"dhcp","section":"perch_x","type":"host","options":{"name":"a\nb"}}]`, `{}`, CodeBadParams},
		{`[{"op":"put","config":"dhcp","section":"perch_x","type":"host","options":{"na-me":"a"}}]`, `{}`, CodeBadParams},
		{`[{"op":"put","config":"dhcp","section":"perch x","type":"host","options":{}}]`, `{}`, CodeBadParams},
		{`[{"op":"put","config":"dhcp","section":"perch_x","type":"host","options":{"k":{"$secret":"nope"}}}]`, `{}`, CodeBadParams},
	}
	for i, c := range cases {
		anon := uci.AnonymousName(3, "host")
		ops := strings.ReplaceAll(c.ops, "%[3]s", anon)
		led := strings.ReplaceAll(c.ledger, "%[3]s", anon)
		js := fmt.Sprintf(`{"applyId":"o%d","base":%s,"ops":%s,"ledger":%s}`, i, b, ops, led)
		if _, err := e.apply(js); code(err) != c.want {
			t.Errorf("case %d %s: got %v, want %s", i, c.ops, err, c.want)
		}
	}
	if e.p.ApplyState().State != StateIdle {
		t.Fatal("slot not released")
	}
}

func TestAdoptNamedSectionNeedsNoWindow(t *testing.T) {
	e := newEnv(t)
	dhcp := e.file("dhcp")
	res, err := e.apply(fmt.Sprintf(`{"applyId":"ad1","kind":"adopt","base":%s,
	  "ops":[{"op":"adopt","config":"dhcp","section":"nas","perchId":"h2","domain":"dhcp_hosts"}]}`, mustJSON(e.base("dhcp"))))
	if err != nil || res.State != StateApplied || res.Hashes[LedgerConfig] == "" {
		t.Fatalf("%+v %v", res, err)
	}
	if e.file("dhcp") != dhcp || !strings.Contains(e.file(LedgerConfig), "config synced 'h2'") || len(e.be.reloadLog()) != 0 {
		t.Fatal("adopt-only must touch the ledger only")
	}
	select {
	case r := <-e.reconCh:
		t.Fatalf("adopt-only must not reconnect: %s", r)
	case <-time.After(100 * time.Millisecond):
	}
	// Re-link: the same perch id adopting another section overwrites the
	// entry (the controller's re-link by identity keys).
	c := e.load("dhcp")
	c.Section("nas").Name = "nas2"
	os.WriteFile(filepath.Join(e.root, "etc/config/dhcp"), uci.Render(c), 0o644)
	res, err = e.apply(fmt.Sprintf(`{"applyId":"ad2","kind":"adopt","base":%s,
	  "ops":[{"op":"adopt","config":"dhcp","section":"nas2","perchId":"h2"}]}`, mustJSON(e.base("dhcp"))))
	if err != nil || res.State != StateApplied {
		t.Fatalf("%+v %v", res, err)
	}
	led, _ := e.p.readLedger()
	if mustJSON(led) != `[{"perchId":"h2","config":"dhcp","section":"nas2","domain":"dhcp_hosts"}]` {
		t.Fatal(mustJSON(led))
	}
	// Another perch id cannot take a ledgered section.
	if _, err := e.apply(fmt.Sprintf(`{"applyId":"ad3","base":%s,"ops":[{"op":"adopt","config":"dhcp","section":"nas2","perchId":"h3"}]}`,
		mustJSON(e.base("dhcp")))); code(err) != CodeNotOwned {
		t.Fatal(err)
	}
	// Nothing to do at all: noop.
	res, err = e.apply(fmt.Sprintf(`{"applyId":"ad4","base":%s,"ops":[{"op":"adopt","config":"dhcp","section":"nas2","perchId":"h2"}]}`, mustJSON(e.base("dhcp"))))
	if err != nil || res.State != StateNoop {
		t.Fatalf("%+v %v", res, err)
	}
	// Ledger removal alone.
	res, err = e.apply(`{"applyId":"ad5","base":{},"ops":[],"ledger":{"remove":["h2"]}}`)
	if err != nil || res.State != StateApplied || strings.Contains(e.file(LedgerConfig), "h2") {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestAdoptRenamesAnonymousThroughTheWindow(t *testing.T) {
	e := newEnv(t)
	c := e.load("dhcp")
	printer := c.Sections[2]
	if !printer.Anonymous {
		t.Fatal("fixture")
	}
	content := uci.Canonical(printer, nil)
	res, err := e.apply(fmt.Sprintf(`{"applyId":"r1","kind":"apply","base":%s,
	  "ops":[{"op":"adopt","config":"dhcp","section":%q,"perchId":"h7","renameTo":"perch_h7","domain":"dhcp_hosts"}]}`,
		mustJSON(e.base("dhcp")), printer.Name))
	if err != nil || res.State != StatePendingConfirm {
		t.Fatalf("%+v %v", res, err)
	}
	after := e.load("dhcp")
	s := after.Section("perch_h7")
	if s == nil || s.Anonymous || s.Index != 2 || string(uci.Canonical(s, nil)) != string(content) {
		t.Fatalf("%s", e.file("dhcp"))
	}
	if !strings.Contains(e.file(LedgerConfig), "config synced 'h7'\n\toption config 'dhcp'\n\toption section 'perch_h7'") {
		t.Fatal(e.file(LedgerConfig))
	}
	// And a timeout restores the anonymous section and removes the ledger.
	e.clock.Advance(90 * time.Second)
	if e.load("dhcp").Sections[2].Name != printer.Name || e.exists("etc/config/"+LedgerConfig) {
		t.Fatal("rename not rolled back")
	}
}

func TestPutSemantics(t *testing.T) {
	e := newEnv(t)
	// Adopt the lan pool and the rules first (named: no window).
	if _, err := e.apply(fmt.Sprintf(`{"applyId":"p0","base":%s,"ops":[
	  {"op":"adopt","config":"dhcp","section":"lan","perchId":"pool1"},
	  {"op":"adopt","config":"firewall","section":"r1","perchId":"r1"},
	  {"op":"adopt","config":"firewall","section":"r2","perchId":"r2"}]}`, mustJSON(e.base("dhcp", "firewall")))); err != nil {
		t.Fatal(err)
	}
	res, err := e.apply(fmt.Sprintf(`{"applyId":"p1","base":%s,"confirmTimeoutSeconds":5,"ops":[
	  {"op":"put","config":"dhcp","section":"lan","type":"dhcp","options":{"interface":"lan","start":"50","leasetime":{"$keep":true},"dhcp_option":["3,192.168.1.1","6,192.168.1.2"]}},
	  {"op":"put","config":"dhcp","section":"perch_h1","type":"host","options":{"name":"cam","mac":"02:00:00:00:00:20","tag":[]},"position":{"after":"lan"}},
	  {"op":"put","config":"firewall","section":"r2","type":"redirect","options":{"name":"Fwd","src":"wan","dest_port":"8080"}},
	  {"op":"put","config":"firewall","section":"perch_r4","type":"rule","options":{"name":"New","target":"REJECT"}},
	  {"op":"order","config":"firewall","type":"","sections":["r2","perch_r4","r1"]}],
	  "ledger":{"set":[{"perchId":"h1","config":"dhcp","section":"perch_h1"},{"perchId":"r4","config":"firewall","section":"perch_r4"}]}}`,
		mustJSON(e.base("dhcp", "firewall"))))
	if err != nil {
		t.Fatal(err)
	}
	// The window is clamped up to the minimum.
	if res.ConfirmTimeoutSeconds != MinConfirmSeconds {
		t.Fatal(res.ConfirmTimeoutSeconds)
	}
	d := e.load("dhcp")
	lan := d.Section("lan")
	// limit (unlisted) is gone, leasetime kept, start set in place, the list appended.
	if mustJSON(lan.Values()) != `{"dhcp_option":["3,192.168.1.1","6,192.168.1.2"],"interface":"lan","leasetime":"12h","start":"50"}` {
		t.Fatal(mustJSON(lan.Values()))
	}
	var names []string
	for _, s := range d.Sections {
		names = append(names, s.Name)
	}
	if names[1] != "lan" || names[2] != "perch_h1" {
		t.Fatalf("position after: %v", names)
	}
	if _, ok := d.Section("perch_h1").Get("tag"); ok {
		t.Fatal("an empty list is no option")
	}
	f := e.load("firewall")
	names = nil
	for _, s := range f.Sections {
		names = append(names, s.Name+":"+s.Type)
	}
	// r2 changed type in place; the Perch sections take the slots they held
	// together (r1, r2 and the appended perch_r4), in the listed order; r3
	// (the router's) keeps its position between them.
	if !reflect.DeepEqual(names[2:], []string{"r2:redirect", "perch_r4:rule", "r3:rule", "r1:rule"}) {
		t.Fatalf("%v", names)
	}
	// The ledger has the new entries.
	led, _ := e.p.readLedger()
	if len(led) != 5 {
		t.Fatal(mustJSON(led))
	}
}

func TestSecretsNeedVerifiedTLS(t *testing.T) {
	e := newEnv(t)
	js := fmt.Sprintf(`{"applyId":"s1","base":%s,"ops":[{"op":"put","config":"network","section":"wg0","type":"interface",
	  "options":{"proto":"wireguard","private_key":{"$secret":"k1"}}}],"secrets":{"k1":"c2VjcmV0"},
	  "ledger":{"set":[{"perchId":"w1","config":"network","section":"wg0"}]}}`, mustJSON(e.base("network")))
	var a ApplyParams
	json.Unmarshal([]byte(js), &a)
	if _, err := e.p.Apply(context.Background(), &a, SessionRef{Gen: 1}, false); code(err) != ErrInsecure.Error() {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(js), &a)
	res, err := e.p.Apply(context.Background(), &a, SessionRef{Gen: 1}, true)
	if err != nil || res.State != StatePendingConfirm {
		t.Fatalf("%+v %v", res, err)
	}
	if v, _ := e.load("network").Section("wg0").Get("private_key"); v.Str() != "c2VjcmV0" {
		t.Fatal("secret not written")
	}
}

func TestNoopAndDryRun(t *testing.T) {
	e := newEnv(t)
	if _, err := e.apply(reservationJSON(e, "a1")); err != nil {
		t.Fatal(err)
	}
	e.waitReconnect()
	if _, err := e.p.Confirm("a1", SessionRef{Gen: 2}); err != nil {
		t.Fatal(err)
	}
	// The same put again changes nothing.
	res, err := e.apply(reservationJSON(e, "a2"))
	if err != nil || res.State != StateNoop {
		t.Fatalf("%+v %v", res, err)
	}
	dhcp := e.file("dhcp")
	res, err = e.apply(fmt.Sprintf(`{"applyId":"d1","dryRun":true,"base":%s,"ops":[
	  {"op":"put","config":"dhcp","section":"perch_h1","type":"host","options":{"name":"cam2","mac":"02:00:00:00:00:20","ip":"192.168.1.20"}},
	  {"op":"delete","config":"dhcp","section":"perch_h1"}]}`, mustJSON(e.base("dhcp"))))
	if err != nil || res.State != StateDryRun || len(res.Changes) != 2 || res.Changes[0].Op != "set" || res.Changes[0].Value != "cam2" ||
		res.Changes[1].Op != "remove" {
		t.Fatalf("%+v %v", res, err)
	}
	if e.file("dhcp") != dhcp || e.p.ApplyState().State != StateIdle || e.exists("etc/perch-collector/rollback/d1") {
		t.Fatal("a dry run changes nothing")
	}
}

func TestCommitFailures(t *testing.T) {
	e := newEnv(t)
	b := e.base("dhcp", "firewall")
	two := fmt.Sprintf(`{"applyId":"%%s","base":%s,"ops":[
	  {"op":"put","config":"dhcp","section":"perch_h1","type":"host","options":{"name":"a"}},
	  {"op":"put","config":"firewall","section":"perch_r1","type":"rule","options":{"name":"b"}}]}`, mustJSON(b))
	dhcp, fw := e.file("dhcp"), e.file("firewall")
	// The first commit (apply order: dhcp before firewall) fails: nothing landed.
	e.be.failOn["dhcp"] = fmt.Errorf("disk full")
	if _, err := e.apply(fmt.Sprintf(two, "c1")); code(err) != CodeApplyFailed {
		t.Fatal(err)
	}
	if e.file("dhcp") != dhcp || e.exists("etc/perch-collector/rollback/pending.json") || e.exists("etc/perch-collector/rollback/c1") || len(e.sentResults()) != 0 {
		t.Fatal("first commit failure")
	}
	// The second fails: the first is rolled back, outcome commit_failed.
	e.be.failOn = map[string]error{"firewall": fmt.Errorf("disk full")}
	_, err := e.apply(fmt.Sprintf(two, "c2"))
	if code(err) != CodeApplyFailed || data(err)["rolledBack"] != true {
		t.Fatal(err)
	}
	if e.file("dhcp") != dhcp || e.file("firewall") != fw || e.sentResults()[0].Reason != ReasonCommitFailed || e.p.ApplyState().State != StateIdle {
		t.Fatal("partial commit not rolled back")
	}
	// A commit that does not write what was staged: the verification notices.
	e.be.failOn = map[string]error{}
	e.be.dropSets = true
	if _, err := e.apply(fmt.Sprintf(`{"applyId":"c3","base":%s,"ops":[{"op":"adopt","config":"dhcp","section":"lan","perchId":"p1"},
	  {"op":"put","config":"dhcp","section":"lan","type":"dhcp","options":{"interface":"lan","start":"7","limit":"150","leasetime":"12h"}}]}`,
		mustJSON(e.base("dhcp")))); code(err) != CodeApplyFailed || !strings.Contains(err.Error(), "differs") {
		t.Fatal(err)
	}
	if e.file("dhcp") != dhcp || e.exists(LedgerConfig) {
		t.Fatal("verification failure not rolled back")
	}
	// A staging error: nothing committed.
	e.be.dropSets = false
	e.be.stageErr = fmt.Errorf("%w (dhcp)", uci.ErrForeignChanges)
	if _, err := e.apply(reservationJSON(e, "c4")); code(err) != CodeBusy || data(err)["reason"] != "uncommitted" {
		t.Fatal(err)
	}
	if e.p.ApplyState().State != StateIdle || e.exists("etc/perch-collector/rollback/c4") {
		t.Fatal("staging failure")
	}
}

func TestManagementPathIsProtected(t *testing.T) {
	e := newEnv(t)
	m := e.p.ManagementPath(context.Background())
	if m == nil || m.Device != "br-lan" || m.NetworkName() != "lan" || m.ControllerAddress != "192.168.1.5" {
		t.Fatalf("%+v", m)
	}
	prot := protectedSections(map[string]*uci.Config{"network": e.load("network"), "firewall": e.load("firewall")}, m)
	got := []string{}
	for c, secs := range prot {
		for s := range secs {
			got = append(got, c+"."+s)
		}
	}
	want := map[string]bool{"network.lan": true, "network.cfg020f15": true, "firewall.cfg01e63d": true, "firewall.cfg02dc81": true}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("%v", got)
		}
	}
	// A change to the lan interface: protected, the window is at least 300 s.
	res, err := e.apply(fmt.Sprintf(`{"applyId":"m1","base":%s,"confirmTimeoutSeconds":90,"ops":[
	  {"op":"adopt","config":"network","section":"lan","perchId":"n1"},
	  {"op":"put","config":"network","section":"lan","type":"interface","options":{"device":"br-lan","proto":"static","ipaddr":"192.168.1.1","netmask":"255.255.0.0"}}]}`,
		mustJSON(e.base("network"))))
	if err != nil || !res.Protected || res.ConfirmTimeoutSeconds != ProtectedConfirmSeconds {
		t.Fatalf("%+v %v", res, err)
	}
	e.clock.Advance(300 * time.Second)
	if e.p.ApplyState().State != StateIdle {
		t.Fatal("protected window")
	}
	// The guest network is not on the path.
	res, err = e.apply(fmt.Sprintf(`{"applyId":"m2","base":%s,"confirmTimeoutSeconds":90,"ops":[
	  {"op":"adopt","config":"network","section":"guest","perchId":"n2"},
	  {"op":"put","config":"network","section":"guest","type":"interface","options":{"device":"br-guest","proto":"static","ipaddr":"192.168.2.1","netmask":"255.255.0.0"}}]}`,
		mustJSON(e.base("network"))))
	if err != nil || res.Protected || res.ConfirmTimeoutSeconds != 90 {
		t.Fatalf("%+v %v", res, err)
	}
	e.clock.Advance(90 * time.Second)
	// A job the controller flagged is protected whatever the agent sees, and
	// config_confirm_max caps the window.
	e2 := newEnv(t, func(o *Options) { o.ConfirmMax = 120 })
	res, err = e2.apply(fmt.Sprintf(`{"applyId":"m3","protected":true,"base":%s,"ops":[{"op":"put","config":"dhcp","section":"perch_x","type":"host","options":{"name":"x"}}]}`,
		mustJSON(e2.base("dhcp"))))
	if err != nil || !res.Protected || res.ConfirmTimeoutSeconds != 120 {
		t.Fatalf("%+v %v", res, err)
	}
	// No route to the controller: nothing is protected.
	e.router.routeDev = ""
	if e.p.ManagementPath(context.Background()) != nil {
		t.Fatal("no route")
	}
	if routeDevice("local 127.0.0.1 dev lo table local src 127.0.0.1 uid 0") != "lo" || parentDevice("br-lan.10") != "br-lan" {
		t.Fatal("parsing")
	}
}

func TestApplyOrderAndReload(t *testing.T) {
	if got := sortApplyOrder([]string{"zeta", "firewall", "opennds", "dhcp", "network", "sqm", "alpha", "system", "pbr", "perch-qos", "mwan3"}); !reflect.DeepEqual(got,
		[]string{"system", "network", "dhcp", "firewall", "sqm", "perch-qos", "opennds", "mwan3", "pbr", "alpha", "zeta"}) {
		t.Fatal(got)
	}
	e := newEnv(t)
	if _, err := e.apply(fmt.Sprintf(`{"applyId":"o1","base":%s,"ops":[
	  {"op":"put","config":"firewall","section":"perch_r","type":"rule","options":{"name":"a"}},
	  {"op":"put","config":"dhcp","section":"perch_h","type":"host","options":{"name":"b"}},
	  {"op":"put","config":"network","section":"perch_n","type":"route","options":{"target":"192.168.7.0/24"}}]}`, mustJSON(e.base("network", "dhcp", "firewall")))); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.be.commits, []string{"network", "dhcp", "firewall"}) || !reflect.DeepEqual(e.be.reloadLog(), [][]string{{"network", "dhcp", "firewall"}}) {
		t.Fatalf("%v %v", e.be.commits, e.be.reloadLog())
	}
	e.clock.Advance(90 * time.Second)
	if got := e.be.reloadLog(); !reflect.DeepEqual(got[1], []string{"network", "dhcp", "firewall"}) {
		t.Fatalf("rollback reload order %v", got)
	}
}

// A daemon restart during the window resumes it; any session of the new
// process may confirm.
func TestRestartResumes(t *testing.T) {
	e := newEnv(t)
	if _, err := e.apply(reservationJSON(e, "a1")); err != nil {
		t.Fatal(err)
	}
	e.waitReconnect()
	restarted := func() *env {
		n := &env{t: t, root: e.root, clock: e.clock, be: e.be, router: e.router, reconCh: make(chan string, 16)}
		n.p = New(e.p.o)
		n.p.Configure(Configure{Mode: ModeManaged})
		n.hook()
		n.p.Start()
		return n
	}
	e.clock.Advance(30 * time.Second)
	n := restarted()
	if st := n.p.ApplyState(); st.State != StatePendingConfirm || st.ApplyID != "a1" {
		t.Fatalf("%+v", st)
	}
	if _, err := n.p.Confirm("a1", SessionRef{Gen: 1}); err != nil {
		t.Fatalf("any session of the new process confirms: %v", err)
	}
	// Restart after the deadline (this process's timer never fired): restored at start.
	e3 := newEnv(t)
	before3 := e3.file("dhcp")
	if _, err := e3.apply(reservationJSON(e3, "b3")); err != nil {
		t.Fatal(err)
	}
	e3.p.ap.mu.Lock()
	if e3.p.ap.stop != nil {
		e3.p.ap.stop()
	}
	e3.p.ap.mu.Unlock()
	e3.clock.Advance(120 * time.Second)
	n3 := New(e3.p.o)
	var got []Result
	n3.SetHooks(Hooks{Result: func(r Result) bool { got = append(got, r); return false }})
	n3.Start()
	if e3.file("dhcp") != before3 || len(got) != 1 || got[0].Reason != ReasonConfirmTimeout || n3.ApplyState().State != StateIdle {
		t.Fatalf("%+v", got)
	}
	// Interrupted while committing: never confirmable, restored at start.
	e4 := newEnv(t)
	before4 := e4.file("dhcp")
	st := store{root: e4.root}
	rec := &pendingRecord{ApplyID: "c1", Kind: KindApply, Deadline: e4.clock.Now().Add(time.Minute), Configs: []string{"dhcp"}}
	h, _ := st.snapshot("c1", "before", rec.Configs)
	rec.HashesBefore = h
	st.writePending(rec)
	st.setMarker("c1")
	os.WriteFile(filepath.Join(e4.root, "etc/config/dhcp"), []byte("\nconfig half 'written'\n"), 0o644)
	n4 := New(e4.p.o)
	n4.Start()
	if e4.file("dhcp") != before4 || n4.Results()[0].Reason != ReasonCommitFailed {
		t.Fatal("interrupted commit")
	}
}

func TestBootGuard(t *testing.T) {
	e := newEnv(t)
	before := e.file("dhcp")
	if _, err := e.apply(reservationJSON(e, "a1")); err != nil {
		t.Fatal(err)
	}
	// While the daemon runs (marker present) the guard leaves it alone.
	if r, err := Guard(e.root, e.router.run, e.clock.Now(), uci.Redactor{}); err != nil || r != nil {
		t.Fatalf("%v %v", r, err)
	}
	// Reboot: tmpfs is empty.
	os.RemoveAll(filepath.Join(e.root, "var/run/perch-collector"))
	r, err := Guard(e.root, e.router.run, e.clock.Now(), uci.Redactor{Key: []byte("k")})
	if err != nil || r == nil || r.Outcome != OutcomeRolledBack || r.Reason != ReasonReboot || r.Hashes["dhcp"] != e.hash("dhcp") {
		t.Fatalf("%+v %v", r, err)
	}
	if e.file("dhcp") != before || e.exists("etc/config/"+LedgerConfig) || e.exists("etc/perch-collector/rollback/pending.json") {
		t.Fatal("guard did not restore")
	}
	for _, c := range e.router.log() {
		if strings.HasPrefix(c, "ubus") && strings.Contains(c, "service") {
			t.Fatal("the guard reloads nothing")
		}
	}
	// The next daemon start reports it in the hello; nothing pending.
	n := New(e.p.o)
	n.Start()
	h := n.Hello(context.Background(), "")
	if h.Apply.State != StateIdle || len(h.Results) != 1 || h.Results[0].Reason != ReasonReboot {
		t.Fatalf("%+v", h)
	}
	// Nothing pending: nothing to do.
	if r, err := Guard(e.root, nil, e.clock.Now(), uci.Redactor{}); err != nil || r != nil {
		t.Fatal(r, err)
	}
	// The daemon at start does the same when the guard is not installed.
	e2 := newEnv(t)
	before2 := e2.file("dhcp")
	if _, err := e2.apply(reservationJSON(e2, "b1")); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(e2.root, "var/run/perch-collector"))
	n2 := New(e2.p.o)
	n2.Start()
	if e2.file("dhcp") != before2 || n2.Results()[0].Reason != ReasonReboot {
		t.Fatal("start without guard")
	}
}

func TestResultsAreBounded(t *testing.T) {
	st := store{root: t.TempDir()}
	for i := 0; i < MaxResults+5; i++ {
		st.addResult(Result{ApplyID: fmt.Sprintf("r%d", i), Outcome: OutcomeRolledBack})
	}
	list := st.readResults()
	if len(list) != MaxResults || list[0].ApplyID != "r5" {
		t.Fatal(len(list), list[0].ApplyID)
	}
	if n, _ := st.ack([]string{"r5", "r6"}); n != 2 || len(st.readResults()) != MaxResults-2 {
		t.Fatal(n)
	}
}

func TestFileStagerRefusesAConcurrentEdit(t *testing.T) {
	root := t.TempDir()
	put(t, root, "etc/config/dhcp", fixDHCP)
	s := newFileStager(filepath.Join(root, "etc/config"), []string{"dhcp"})
	ctx := context.Background()
	if _, err := s.Add(ctx, "dhcp", "host", "perch_x", []uci.Option{{Name: "name", Value: uci.String("x")}}); err != nil {
		t.Fatal(err)
	}
	put(t, root, "etc/config/dhcp", fixDHCP+"\nconfig host 'y'\n")
	if err := s.Commit(ctx, "dhcp"); err == nil || !strings.Contains(err.Error(), "changed on the router") {
		t.Fatal(err)
	}
	if _, err := s.Add(ctx, "network", "x", "y", nil); err == nil {
		t.Fatal("config outside the stager")
	}
	if redactDelta("network.wg0.private_key='abc'") != "network.wg0.private_key=<redacted>" || redactDelta("+network.lan.dns='1'") != "+network.lan.dns='1'" {
		t.Fatal(redactDelta("network.wg0.private_key='abc'"))
	}
}
