package gwconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

const fixSQM = "config queue 'eth1'\n\toption enabled '1'\n\toption interface 'eth1'\n\toption download '85000'\n\toption upload '10000'\n"

// sqmPutJSON writes a WAN queue (what the controller's sqm domain sends).
func sqmPutJSON(e *env, id string) string {
	return fmt.Sprintf(`{"applyId":%q,"kind":"apply","confirmTimeoutSeconds":90,"base":%s,
	 "ops":[{"op":"adopt","config":"sqm","section":"eth1","perchId":"q1","domain":"sqm"},
	        {"op":"put","config":"sqm","section":"eth1","type":"queue",
	         "options":{"enabled":"1","interface":"eth1","download":"50000","upload":"10000"}}]}`,
		id, mustJSON(e.base("sqm")))
}

func siblingByConfig(t *testing.T, list []SiblingConfig, config string) SiblingConfig {
	t.Helper()
	for _, s := range list {
		if s.Config == config {
			return s
		}
	}
	t.Fatalf("no sibling %s in %+v", config, list)
	return SiblingConfig{}
}

func TestSiblingsJoinTheAllowlistWhenInstalled(t *testing.T) {
	e := newEnv(t)
	put(t, e.root, "etc/config/sqm", fixSQM)
	if got := e.p.Allowed(); !reflect.DeepEqual(got, []string{"dhcp", "firewall", "network"}) {
		t.Fatalf("before: %v", got)
	}
	if s := siblingByConfig(t, e.p.SiblingConfigs(), "sqm"); s.Allowed || s.Installed || s.Reason != SiblingNotInstalled {
		t.Fatalf("%+v", s)
	}
	// Not allowed: the write is refused, and the read does not cover it.
	if _, err := e.apply(sqmPutJSON(e, "a1")); code(err) != ErrConfigNotAllowed.Error() {
		t.Fatal(err)
	}
	if _, ok := e.p.Hashes()["sqm"]; ok {
		t.Fatal("sqm read before its package is installed")
	}

	// sqm-scripts and perch-qos installed (by hand): within the cache's TTL.
	e.router.writeInstalled(map[string]bool{"base-files": true, "dnsmasq": true, "firewall4": true, "sqm-scripts": true, "perch-qos": true})
	e.clock.Advance(siblingTTL + time.Second)
	if got := e.p.Allowed(); !reflect.DeepEqual(got, []string{"dhcp", "firewall", "network", "perch-qos", "sqm"}) {
		t.Fatalf("after: %v", got)
	}
	caps := e.p.Capabilities(context.Background(), "c")
	if !reflect.DeepEqual(caps.AllowedConfigs, []string{"dhcp", "firewall", "network", "perch-qos", "sqm"}) {
		t.Fatalf("%v", caps.AllowedConfigs)
	}
	if _, ok := caps.Packages["perch-qos"]; !ok {
		t.Fatalf("perch-qos not in the reported packages: %v", caps.Packages)
	}
	if s := siblingByConfig(t, caps.SiblingConfigs, "sqm"); !s.Allowed || !s.Installed || s.Reason != SiblingInstalled || s.Package != "sqm-scripts" {
		t.Fatalf("%+v", s)
	}
	if _, ok := e.p.Hashes()["sqm"]; !ok {
		t.Fatal("sqm not readable")
	}
	res, err := e.apply(sqmPutJSON(e, "a2"))
	if err != nil || res.State != StatePendingConfirm {
		t.Fatalf("%+v %v", res, err)
	}
	if v, _ := e.load("sqm").Section("eth1").Get("download"); v.Str() != "50000" {
		t.Fatal(e.file("sqm"))
	}
}

func TestSiblingsOptOut(t *testing.T) {
	installed := func(e *env) {
		e.router.writeInstalled(map[string]bool{"base-files": true, "sqm-scripts": true, "perch-qos": true})
		e.p.refreshSiblings()
	}
	// managed_config_auto '0': none join.
	e := newEnv(t, func(o *Options) { o.SiblingsOff = true })
	installed(e)
	if got := e.p.Allowed(); !reflect.DeepEqual(got, []string{"dhcp", "firewall", "network"}) {
		t.Fatalf("%v", got)
	}
	if s := siblingByConfig(t, e.p.SiblingConfigs(), "perch-qos"); s.Allowed || !s.Installed || s.Reason != SiblingOptedOut {
		t.Fatalf("%+v", s)
	}
	// list managed_config_exclude 'sqm': only perch-qos joins.
	e = newEnv(t, func(o *Options) { o.SiblingExclude = []string{"sqm"} })
	installed(e)
	if got := e.p.Allowed(); !reflect.DeepEqual(got, []string{"dhcp", "firewall", "network", "perch-qos"}) {
		t.Fatalf("%v", got)
	}
	// Listed in managed_config: allowed whatever is installed (and never twice).
	e = newEnv(t, func(o *Options) { o.Allowlist = []string{"network", "sqm"}; o.SiblingsOff = true })
	if got := e.p.Allowed(); !reflect.DeepEqual(got, []string{"network", "sqm"}) {
		t.Fatalf("%v", got)
	}
	if s := siblingByConfig(t, e.p.SiblingConfigs(), "sqm"); !s.Allowed || s.Reason != SiblingListed {
		t.Fatalf("%+v", s)
	}
	e = newEnv(t, func(o *Options) { o.Allowlist = []string{"network", "sqm"} })
	installed(e)
	if got := e.p.Allowed(); !reflect.DeepEqual(got, []string{"network", "perch-qos", "sqm"}) {
		t.Fatalf("%v", got)
	}
}

func TestSiblingJoinsRightAfterItsInstallJob(t *testing.T) {
	e := newEnv(t)
	e.router.pkgSize = map[string]int64{"sqm-scripts": 20000}
	if _, err := e.install("p1", "sqm-scripts"); err != nil {
		t.Fatal(err)
	}
	// No TTL wait: the install job refreshed the view.
	if s := siblingByConfig(t, e.p.SiblingConfigs(), "sqm"); !s.Allowed || s.Reason != SiblingInstalled {
		t.Fatalf("%+v", s)
	}
	// Rolled back at the deadline: the package is gone, and so is its config.
	e.waitReconnect()
	e.clock.Advance(90 * time.Second)
	if e.router.installed()["sqm-scripts"] {
		t.Fatal("not rolled back")
	}
	if s := siblingByConfig(t, e.p.SiblingConfigs(), "sqm"); s.Allowed || s.Reason != SiblingNotInstalled {
		t.Fatalf("%+v", s)
	}
}

const fixMwan3 = "config globals 'globals'\n\toption mmx_mask '0x3F00'\n\nconfig interface 'wan'\n\toption enabled '1'\n\tlist track_ip '192.0.2.1'\n"
const fixUpnpd = "config upnpd 'config'\n\toption enabled '1'\n\toption secure_mode '1'\n"

// mwan3PutJSON writes an mwan3 section (what a multi-WAN domain would send).
func mwan3PutJSON(e *env, id string) string {
	return fmt.Sprintf(`{"applyId":%q,"base":%s,"ops":[{"op":"put","config":"mwan3","section":"perch_m1","type":"member",
	  "options":{"interface":"wan","metric":"1","weight":"1"}}]}`, id, mustJSON(e.base("mwan3")))
}

// gateway-sync protocol 5 (decision D11): upnpd and ddns join writable once
// installed; mwan3 and pbr join readable only, unless listed.
func TestReadOnlySiblings(t *testing.T) {
	e := newEnv(t)
	put(t, e.root, "etc/config/mwan3", fixMwan3)
	put(t, e.root, "etc/config/upnpd", fixUpnpd)
	e.router.writeInstalled(map[string]bool{"base-files": true, "mwan3": true, "miniupnpd-nftables": true})
	e.p.refreshSiblings()

	if got := e.p.Allowed(); !reflect.DeepEqual(got, []string{"dhcp", "firewall", "mwan3", "network", "upnpd"}) {
		t.Fatalf("readable: %v", got)
	}
	if got := e.p.WritableConfigs(); !reflect.DeepEqual(got, []string{"dhcp", "firewall", "network", "upnpd"}) {
		t.Fatalf("writable: %v", got)
	}
	caps := e.p.Capabilities(context.Background(), "c")
	want := map[string]SiblingConfig{
		"sqm":       {Config: "sqm", Package: "sqm-scripts", Reason: SiblingNotInstalled},
		"perch-qos": {Config: "perch-qos", Package: "perch-qos", Reason: SiblingNotInstalled},
		"upnpd":     {Config: "upnpd", Package: "miniupnpd-nftables", Installed: true, Allowed: true, Reason: SiblingInstalled},
		"ddns":      {Config: "ddns", Package: "ddns-scripts", Reason: SiblingNotInstalled},
		"mwan3":     {Config: "mwan3", Package: "mwan3", Installed: true, Allowed: true, ReadOnly: true, Reason: SiblingInstalledReadOnly},
		"pbr":       {Config: "pbr", Package: "pbr", ReadOnly: true, Reason: SiblingNotInstalled},
	}
	if len(caps.SiblingConfigs) != len(want) {
		t.Fatalf("%+v", caps.SiblingConfigs)
	}
	for _, s := range caps.SiblingConfigs {
		if s != want[s.Config] {
			t.Fatalf("%+v, want %+v", s, want[s.Config])
		}
	}
	if !reflect.DeepEqual(caps.WritableConfigs, []string{"dhcp", "firewall", "network", "upnpd"}) ||
		!reflect.DeepEqual(caps.AllowedConfigs, []string{"dhcp", "firewall", "mwan3", "network", "upnpd"}) {
		t.Fatalf("%v %v", caps.AllowedConfigs, caps.WritableConfigs)
	}
	if caps.Packages["mwan3"] == "" || caps.Packages["miniupnpd-nftables"] == "" {
		t.Fatalf("sibling packages are watched: %v", caps.Packages)
	}
	b, _ := json.Marshal(want["mwan3"])
	if string(b) != `{"config":"mwan3","package":"mwan3","installed":true,"allowed":true,"readOnly":true,"reason":"installed_read_only"}` {
		t.Fatal(string(b))
	}

	// Readable: in the hashes and the read, watched for changes.
	if _, ok := e.p.Hashes()["mwan3"]; !ok {
		t.Fatal("mwan3 not readable")
	}
	if res, err := e.p.Read([]string{"mwan3"}); err != nil || len(res.Configs) != 1 || len(res.Configs[0].Sections) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// Never written: config_not_allowed, and nothing staged or snapshotted.
	before := e.file("mwan3")
	_, err := e.apply(mwan3PutJSON(e, "m1"))
	if code(err) != ErrConfigNotAllowed.Error() || !reflect.DeepEqual(data(err)["configs"], []string{"mwan3"}) {
		t.Fatalf("%v %v", err, data(err))
	}
	if e.file("mwan3") != before || e.exists("etc/perch-collector/rollback/m1") || e.p.ApplyState().State != StateIdle {
		t.Fatal("a refused write left something behind")
	}
	// upnpd is writable once installed.
	res, err := e.apply(fmt.Sprintf(`{"applyId":"u1","base":%s,"ops":[
	  {"op":"adopt","config":"upnpd","section":"config","perchId":"u1","domain":"upnp"},
	  {"op":"put","config":"upnpd","section":"config","type":"upnpd","options":{"enabled":"1","secure_mode":"1","enable_natpmp":"1"}}]}`,
		mustJSON(e.base("upnpd"))))
	if err != nil || res.State != StatePendingConfirm {
		t.Fatalf("%+v %v", res, err)
	}
	e.waitReconnect()
	e.clock.Advance(90 * time.Second)

	// The router's owner lists mwan3: writable, reason listed.
	e2 := newEnv(t, func(o *Options) { o.Allowlist = []string{"network", "dhcp", "firewall", "mwan3"} })
	put(t, e2.root, "etc/config/mwan3", fixMwan3)
	e2.router.writeInstalled(map[string]bool{"base-files": true, "mwan3": true})
	e2.p.refreshSiblings()
	if s := siblingByConfig(t, e2.p.SiblingConfigs(), "mwan3"); !s.Allowed || s.ReadOnly || s.Reason != SiblingListed {
		t.Fatalf("%+v", s)
	}
	if res, err := e2.apply(mwan3PutJSON(e2, "m2")); err != nil || res.State != StatePendingConfirm {
		t.Fatalf("%+v %v", res, err)
	}

	// Opted out: neither readable nor writable; miniupnpd (not -nftables)
	// brings upnpd too.
	e3 := newEnv(t, func(o *Options) { o.SiblingExclude = []string{"mwan3"} })
	e3.router.writeInstalled(map[string]bool{"base-files": true, "mwan3": true, "miniupnpd": true, "ddns-scripts": true})
	e3.p.refreshSiblings()
	if got := e3.p.Allowed(); !reflect.DeepEqual(got, []string{"ddns", "dhcp", "firewall", "network", "upnpd"}) {
		t.Fatalf("%v", got)
	}
	if s := siblingByConfig(t, e3.p.SiblingConfigs(), "mwan3"); s.Allowed || s.Reason != SiblingOptedOut || !s.ReadOnly {
		t.Fatalf("%+v", s)
	}
	if s := siblingByConfig(t, e3.p.SiblingConfigs(), "upnpd"); s.Package != "miniupnpd" || s.Reason != SiblingInstalled {
		t.Fatalf("%+v", s)
	}
}

func TestInstallAllowlistGatewaySync(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range InstallAllowlist {
		if seen[n] {
			t.Fatalf("%s listed twice", n)
		}
		seen[n] = true
	}
	for _, n := range []string{"miniupnpd-nftables", "luci-app-upnp", "ddns-scripts", "ddns-scripts-services", "ddns-scripts-cloudflare",
		"luci-app-ddns", "ca-bundle", "wireguard-tools", "kmod-wireguard", "luci-proto-wireguard", "luci-app-mwan3", "luci-app-pbr", "sqm-scripts"} {
		if !seen[n] {
			t.Fatalf("%s not on the install allowlist", n)
		}
	}
}
