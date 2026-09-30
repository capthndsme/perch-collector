package gwconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Wire types of gateway-sync (docs: gateway-sync protocol 1-5): old params
// decode as before, new fields round-trip, unbuilt features are refused.

// sameJSON compares two JSON documents semantically.
func sameJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("want: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// The apply params of ARCHITECTURE.md, as an older controller sends them.
const oldApplyParams = `{"applyId":"g3-a41","kind":"apply","protected":false,"confirmTimeoutSeconds":90,"dryRun":false,
 "base":{"network":"3f9a","dhcp":"77c0"},
 "ops":[
  {"op":"adopt","config":"dhcp","section":"cfg03a1b2","perchId":"h9","renameTo":"perch_h9","domain":"dhcp_hosts"},
  {"op":"put","config":"dhcp","section":"perch_h1","type":"host",
   "options":{"name":"camera","mac":"02:00:00:00:00:20","ip":"192.168.1.20","tag":["x","y"],"leasetime":{"$keep":true}},
   "position":{"after":"lan"}},
  {"op":"put","config":"network","section":"wg0","type":"interface","options":{"private_key":{"$secret":"s7"}}},
  {"op":"delete","config":"dhcp","section":"perch_h3"},
  {"op":"order","config":"firewall","type":"rule","sections":["perch_r40","perch_r41"]}],
 "ledger":{"set":[{"perchId":"h1","config":"dhcp","section":"perch_h1","domain":"dhcp_hosts"}],"remove":["h3"]},
 "secrets":{"s7":"<value>"},
 "someFutureField":{"x":1}}`

func TestOldApplyParamsDecodeUnchanged(t *testing.T) {
	var a ApplyParams
	if err := json.Unmarshal([]byte(oldApplyParams), &a); err != nil {
		t.Fatal(err)
	}
	if a.Checks != nil || a.ApplyID != "g3-a41" || len(a.Ops) != 5 || a.Secrets["s7"] != "<value>" || *a.ConfirmTimeoutSeconds != 90 {
		t.Fatalf("%+v", a)
	}
	put := a.Ops[1].Options
	if !put["leasetime"].Keep || put["leasetime"].Generate != "" || !put["tag"].Value.IsList || put["name"].Value.Str() != "camera" {
		t.Fatalf("%+v", put)
	}
	if a.Ops[2].Options["private_key"].Secret != "s7" || a.Ops[2].Options["private_key"].Generate != "" {
		t.Fatalf("%+v", a.Ops[2])
	}
	if a.Ops[0].Name != "" || a.Ops[0].Enabled != nil || a.Ops[0].Running != nil {
		t.Fatalf("%+v", a.Ops[0])
	}
	if err := checkUnsupported(&a); err != nil {
		t.Fatal(err)
	}
	// A value object stays strict: an unknown or mixed form is refused.
	for _, bad := range []string{`{"$keep":true,"x":1}`, `{"$keep":false}`, `{"$secret":""}`, `{"$generate":""}`,
		`{"$generate":"wg_private_key","$keep":true}`, `{"$secret":"a","$generate":"wg_private_key"}`, `{}`} {
		var w WireValue
		if err := json.Unmarshal([]byte(bad), &w); err == nil {
			t.Fatalf("%s accepted: %+v", bad, w)
		}
	}
	// The pre-C0 marshalling of ops is unchanged.
	b, _ := json.Marshal(a.Ops[3])
	if string(b) != `{"op":"delete","config":"dhcp","section":"perch_h3"}` {
		t.Fatal(string(b))
	}
	var c ConfirmParams
	if err := json.Unmarshal([]byte(`{"applyId":"a1"}`), &c); err != nil || c.ApplyID != "a1" || c.OverrideChecks {
		t.Fatalf("%+v %v", c, err)
	}
}

// protocol.md 1.1's example.
const checksApplyParams = `{"applyId":"g1-5c0ffee00001","kind":"apply","protected":false,"confirmTimeoutSeconds":300,
 "base":{"network":"3f9a","dhcp":"77c0"},
 "ops":[{"op":"put","config":"network","section":"wan","type":"interface",
         "options":{"proto":"dhcp","device":"wan0","metric":"2","peerdns":"0","dns":["192.0.2.53"]}}],
 "ledger":{"set":[],"remove":[]},
 "checks":{
   "v":1,
   "timeoutSeconds":60,
   "items":[
     {"id":"up:wan","kind":"interface_up","network":"wan","family":4,"mustPass":true},
     {"id":"route4","kind":"default_route","family":4},
     {"id":"reach4","kind":"reach","family":4,"targets":["$gateway:wan","1.1.1.1","8.8.8.8"],"tcpPort":443},
     {"id":"dns","kind":"resolve","name":"example.com"}
   ]}}`

func TestNewWireFieldsRoundTrip(t *testing.T) {
	var a ApplyParams
	if err := json.Unmarshal([]byte(checksApplyParams), &a); err != nil {
		t.Fatal(err)
	}
	if err := validateChecks(a.Checks); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(a.Checks)
	sameJSON(t, b, `{"v":1,"timeoutSeconds":60,"items":[
	  {"id":"up:wan","kind":"interface_up","network":"wan","family":4,"mustPass":true},
	  {"id":"route4","kind":"default_route","family":4},
	  {"id":"reach4","kind":"reach","family":4,"targets":["$gateway:wan","1.1.1.1","8.8.8.8"],"tcpPort":443},
	  {"id":"dns","kind":"resolve","name":"example.com"}]}`)
	// The controller's explicit "no checks".
	var none ApplyParams
	json.Unmarshal([]byte(`{"applyId":"x","checks":{"v":1,"items":[]}}`), &none)
	if none.Checks == nil || len(none.Checks.Items) != 0 || validateChecks(none.Checks) != nil {
		t.Fatalf("%+v", none.Checks)
	}
	// wg_handshake and via.
	var wg Checks
	if err := json.Unmarshal([]byte(`{"v":1,"timeoutSeconds":120,"items":[
	  {"id":"wg","kind":"wg_handshake","network":"wg0","publicKey":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","withinSeconds":180},
	  {"id":"r6","kind":"reach","family":6,"targets":["2001:db8::1"],"via":"wan6"}]}`), &wg); err != nil || validateChecks(&wg) != nil {
		t.Fatalf("%+v %v", wg, validateChecks(&wg))
	}
	b, _ = json.Marshal(wg)
	sameJSON(t, b, `{"v":1,"timeoutSeconds":120,"items":[
	  {"id":"wg","kind":"wg_handshake","network":"wg0","publicKey":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","withinSeconds":180},
	  {"id":"r6","kind":"reach","family":6,"targets":["2001:db8::1"],"via":"wan6"}]}`)

	// $generate and the service op.
	var g ApplyParams
	if err := json.Unmarshal([]byte(`{"applyId":"g","ops":[
	  {"op":"put","config":"network","section":"wg0","type":"interface",
	   "options":{"proto":"wireguard","private_key":{"$generate":"wg_private_key"},"listen_port":"51820","addresses":["192.168.9.1/24"]}},
	  {"op":"service","name":"mwan3","enabled":true,"running":false}]}`), &g); err != nil {
		t.Fatal(err)
	}
	if g.Ops[0].Options["private_key"].Generate != GenerateWGPrivateKey || g.Ops[1].Name != "mwan3" || !*g.Ops[1].Enabled || *g.Ops[1].Running {
		t.Fatalf("%+v", g.Ops)
	}
	b, _ = json.Marshal(g.Ops[0].Options["private_key"])
	if string(b) != `{"$generate":"wg_private_key"}` {
		t.Fatal(string(b))
	}
	b, _ = json.Marshal(g.Ops[1])
	sameJSON(t, b, `{"op":"service","config":"","name":"mwan3","enabled":true,"running":false}`)

	var c ConfirmParams
	if err := json.Unmarshal([]byte(`{"applyId":"g1-5c0ffee00001","overrideChecks":true}`), &c); err != nil || !c.OverrideChecks {
		t.Fatalf("%+v %v", c, err)
	}

	// Replies, results, the hello's apply block and the notification.
	detail, at := "up after 4.1 s, 203.0.113.10/24", "2026-10-02T10:00:07Z"
	st := ApplyState{State: StatePendingConfirm, ApplyID: "g1-5c0ffee00001", Kind: KindApply, Deadline: "2026-10-02T10:05:00Z",
		Checks: &ChecksView{State: CheckRunning, StartedAt: "2026-10-02T10:00:03Z", TimeoutSeconds: 60, Items: []CheckItemResult{
			{ID: "up:wan", State: CheckPassed, Detail: &detail, At: &at}, {ID: "reach4", State: CheckRunning}}}}
	b, _ = json.Marshal(st)
	sameJSON(t, b, `{"state":"pending_confirm","applyId":"g1-5c0ffee00001","kind":"apply","deadline":"2026-10-02T10:05:00Z",
	  "checks":{"state":"running","startedAt":"2026-10-02T10:00:03Z","timeoutSeconds":60,
	            "items":[{"id":"up:wan","state":"passed","detail":"up after 4.1 s, 203.0.113.10/24","at":"2026-10-02T10:00:07Z"},
	                     {"id":"reach4","state":"running","detail":null,"at":null}]}}`)
	var back ApplyState
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, st) {
		t.Fatalf("%+v %v", back, err)
	}
	b, _ = json.Marshal(ApplyState{State: StateIdle})
	if string(b) != `{"state":"idle"}` {
		t.Fatal(string(b))
	}
	b, _ = json.Marshal(ChecksNote{ApplyID: "a", State: CheckFailed, StartedAt: "2026-10-02T10:00:03Z", ElapsedSeconds: 61.5, AllSkipped: true,
		Items: []CheckItemResult{{ID: "x", State: CheckSkipped}}})
	sameJSON(t, b, `{"applyId":"a","state":"failed","startedAt":"2026-10-02T10:00:03Z","elapsedSeconds":61.5,"allSkipped":true,
	  "items":[{"id":"x","state":"skipped","detail":null,"at":null}]}`)
	res := ApplyResult{State: StatePendingConfirm, ApplyID: "g1", Hashes: map[string]string{"network": "h"},
		Checks:    &ChecksReply{State: CheckPending, TimeoutSeconds: 60, Baseline: []CheckItemResult{{ID: "x", State: CheckPassed}}},
		Generated: []Generated{{Config: "network", Section: "wg0", Option: "private_key", PublicKey: "k"}}}
	b, _ = json.Marshal(res)
	sameJSON(t, b, `{"state":"pending_confirm","applyId":"g1","hashes":{"network":"h"},
	  "checks":{"state":"pending","timeoutSeconds":60,"baseline":[{"id":"x","state":"passed","detail":null,"at":null}]},
	  "generated":[{"config":"network","section":"wg0","option":"private_key","publicKey":"k"}]}`)
	r := Result{ApplyID: "g1", Kind: KindApply, Outcome: OutcomeRolledBack, Reason: ReasonChecksFailed, At: "t", Hashes: map[string]string{},
		Detail: "reach4: no answer", Checks: &ChecksView{State: CheckFailed, Items: []CheckItemResult{}}}
	b, _ = json.Marshal(r)
	sameJSON(t, b, `{"applyId":"g1","kind":"apply","outcome":"rolled_back","reason":"checks_failed","at":"t","hashes":{},
	  "detail":"reach4: no answer","checks":{"state":"failed","items":[]}}`)
	// A result without checks keeps its old shape.
	b, _ = json.Marshal(Result{ApplyID: "g1", Outcome: OutcomeConfirmed, At: "t", Hashes: map[string]string{}})
	if strings.Contains(string(b), "checks") {
		t.Fatal(string(b))
	}
}

func TestValidateChecks(t *testing.T) {
	item := func(js string) *Checks {
		return &Checks{V: 1, TimeoutSeconds: 60, Items: []CheckItem{mustItem(t, js)}}
	}
	bad := map[string]*Checks{
		"checks version 2 is not supported": {V: 2, Items: []CheckItem{{ID: "a", Kind: CheckDefaultRoute}}},
		"timeoutSeconds":                    {V: 1, TimeoutSeconds: 5, Items: []CheckItem{{ID: "a", Kind: CheckDefaultRoute}}},
		"timeoutSeconds ":                   {V: 1, TimeoutSeconds: 901, Items: []CheckItem{{ID: "a", Kind: CheckDefaultRoute}}},
		"twice":                             {V: 1, TimeoutSeconds: 60, Items: []CheckItem{{ID: "a", Kind: CheckDefaultRoute}, {ID: "a", Kind: CheckDefaultRoute}}},
		"invalid id":                        item(`{"id":"UP","kind":"default_route"}`),
		"invalid id ":                       item(`{"id":"` + strings.Repeat("a", 33) + `","kind":"default_route"}`),
		"unknown kind":                      item(`{"id":"a","kind":"speedtest"}`),
		"family":                            item(`{"id":"a","kind":"default_route","family":5}`),
		"invalid network":                   item(`{"id":"a","kind":"interface_up"}`),
		"invalid network ":                  item(`{"id":"a","kind":"default_route","network":"wan 1"}`),
		"targets":                           item(`{"id":"a","kind":"reach","targets":[]}`),
		"not an IP address":                 item(`{"id":"a","kind":"reach","targets":["example.com"]}`),
		"invalid network  ":                 item(`{"id":"a","kind":"reach","targets":["$gateway:"]}`),
		"tcpPort":                           item(`{"id":"a","kind":"reach","targets":["1.1.1.1"],"tcpPort":70000}`),
		"invalid name":                      item(`{"id":"a","kind":"resolve","name":"-bad-.example.com"}`),
		"invalid name ":                     item(`{"id":"a","kind":"resolve","name":""}`),
		// 235 characters: no room for the probe's fresh label (19).
		"invalid name  ": item(`{"id":"a","kind":"resolve","name":"` + strings.Repeat("a.", 116) + `com"}`),
		"withinSeconds":  item(`{"id":"a","kind":"wg_handshake","network":"wg0","withinSeconds":10}`),
		"publicKey":      item(`{"id":"a","kind":"wg_handshake","network":"wg0","publicKey":"short","withinSeconds":60}`),
	}
	many := &Checks{V: 1, TimeoutSeconds: 60}
	for i := 0; i < 17; i++ {
		many.Items = append(many.Items, CheckItem{ID: "r" + strings.Repeat("x", i), Kind: CheckDefaultRoute})
	}
	bad["at most 16 items"] = many
	for want, c := range bad {
		err := validateChecks(c)
		if code(err) != CodeBadParams || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("%q: %v", want, err)
		}
	}
	if err := validateChecks(item(`{"id":"agent:route4","kind":"default_route","family":4}`)); err != nil {
		t.Fatal(err)
	}
	if err := validateChecks(item(`{"id":"dns.v6","kind":"resolve","name":"example.com.","family":6}`)); err != nil {
		t.Fatal(err)
	}
	// 234 characters (and a final dot): a fresh label still fits in 253.
	if err := validateChecks(item(`{"id":"dns","kind":"resolve","name":"` + strings.Repeat("a.", 116) + `co."}`)); err != nil {
		t.Fatal(err)
	}
}

func mustItem(t *testing.T, js string) CheckItem {
	t.Helper()
	var it CheckItem
	dec := json.NewDecoder(bytes.NewReader([]byte(js)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&it); err != nil {
		t.Fatal(err)
	}
	return it
}

// What this build does not implement yet is refused with `unsupported`,
// never half done; bad checks are bad_params before anything is read.
func TestUnbuiltFeaturesAreRefused(t *testing.T) {
	e := newEnv(t)
	before := e.file("network")
	_, err := e.apply(`{"applyId":"s1","base":{},"ops":[{"op":"service","name":"mwan3","enabled":true}]}`)
	if code(err) != CodeUnsupported {
		t.Fatal(err)
	}
	_, err = e.apply(`{"applyId":"s3","base":{},"ops":[],"checks":{"v":2,"items":[]}}`)
	if code(err) != CodeBadParams || !strings.Contains(err.Error(), "checks version 2 is not supported") {
		t.Fatal(err)
	}
	if e.file("network") != before || e.p.ApplyState().State != StateIdle {
		t.Fatal("a refusal must leave nothing behind")
	}
}

func TestFeaturesWritableAndRedaction(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Features = []string{FeatureUPnPDelete, "", FeatureUPnPDelete} })
	caps := e.p.Capabilities(context.Background(), "c")
	want := append(append([]string(nil), builtFeatures...), FeatureUPnPDelete)
	if !uci.IsSecret("public_key") {
		want = append(want, FeaturePlainPublicKey)
	}
	if !sameSet(caps.Features, want) {
		t.Fatalf("features %v, want %v", caps.Features, want)
	}
	if !reflect.DeepEqual(caps.WritableConfigs, []string{"dhcp", "firewall", "network"}) {
		t.Fatalf("%v", caps.WritableConfigs)
	}
	b, _ := json.Marshal(caps)
	if !strings.Contains(string(b), `"features":[`) || !strings.Contains(string(b), `"writableConfigs":["dhcp","firewall","network"]`) {
		t.Fatal(string(b))
	}
	// A mobile WAN's SIM codes never leave the router.
	put(t, e.root, "etc/config/network", fixNetwork+"\nconfig interface 'wwan'\n\toption proto 'qmi'\n\toption device '/dev/cdc-wdm0'\n\toption apn 'internet'\n\toption pincode '1234'\n\toption pukcode '12345678'\n")
	res, err := e.p.Read([]string{"network"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Configs[0].Sections {
		if s.Name != "wwan" {
			continue
		}
		if _, ok := s.Options["pincode"]; ok || s.Secrets["pincode"] == "" || s.Secrets["pukcode"] == "" || s.Options["apn"].Str() != "internet" {
			t.Fatalf("%+v", s)
		}
		for name, v := range s.Options {
			if v.Str() == "1234" || v.Str() == "12345678" {
				t.Fatalf("SIM code in option %s", name)
			}
		}
		return
	}
	t.Fatal("no wwan section")
}

func sameSet(a, b []string) bool {
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return len(a) == len(b)
}
