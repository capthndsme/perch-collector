package gwconfig

import (
	"context"
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
