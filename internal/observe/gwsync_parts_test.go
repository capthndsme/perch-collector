package observe

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The parts of gateway-sync protocol 6.1: wireguard, ddns, the interfaces'
// IPv6 prefixes and upnp's secureMode. The byte-for-byte tests compare
// with the protocol's examples, placeholders filled with the fixtures'
// values.

const (
	fixIfKey   = "parWe9vI6HIbi/K1cSi+T4QoJ1h6hGZddixadNTq6UI="
	fixPeerKey = "gOfqWazSdGuRFxc3JgwDl1c5VSDMWqgEn37hewWbwhY="
	// Secrets of the fixtures: they must never appear in any output.
	fixIfPrivate = "IKTRYYo3faMCh5xRWnOZ44SwQyEibYdDKmOrPS5bT38="
	fixPSK       = "U9OX5Ao2njHPS5azWQJW0dMASTbBHRh3DNSbZkAvI2Y="
	fixDDNSPass  = "fixture-ddns-password-0001"
)

// wgRouter answers `wg show all <field>` from files and uci from a fixture,
// records every command, and would print secrets for the commands the
// reader must never run.
type wgRouter struct {
	dir  string
	uci  []byte
	mu   sync.Mutex
	runs []string
	// noWG: the wg tool is missing.
	noWG bool
}

func (r *wgRouter) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	r.runs = append(r.runs, cmd)
	switch {
	case name == "uci" && cmd == "uci -q show network":
		return r.uci, nil
	case name != "wg":
		return nil, errors.New("unexpected " + cmd)
	case r.noWG:
		return nil, errors.New(`exec: "wg": executable file not found in $PATH`)
	case len(args) == 3 && args[0] == "show" && args[1] == "all":
		switch args[2] {
		case "dump":
			return []byte("wg0\t" + fixIfPrivate + "\t" + fixIfKey + "\t51820\toff\nwg0\t" + fixPeerKey + "\t" + fixPSK + "\t203.0.113.7:40211\t192.168.9.2/32\t1790000000\t123456\t654321\t25\n"), nil
		case "private-key":
			return []byte("wg0\t" + fixIfPrivate + "\n"), nil
		case "preshared-keys":
			return []byte("wg0\t" + fixPeerKey + "\t" + fixPSK + "\n"), nil
		}
		b, err := readFixture(filepath.Join(r.dir, args[2]+".txt"))
		if err != nil {
			return []byte{}, nil
		}
		return b, nil
	}
	return []byte(fixIfPrivate + "\n"), nil
}

func readFixture(p string) ([]byte, error) {
	return os.ReadFile(p)
}

func TestWireGuardPartMatchesTheProtocol(t *testing.T) {
	r := &wgRouter{dir: filepath.Join("testdata", "wg-show-all"), uci: fixture(t, "uci-show-network-wg.txt")}
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{"etc/config/network": []byte("x")})
	w := (&WireGuardReader{Env: &Env{Root: root, Run: r.run}}).Read()
	b, _ := json.Marshal(w)
	// protocol.md 6.1, with the fixture's keys and 192.168.x.2 → 192.168.9.2.
	want := `{"interfaces":[{"name":"wg0","network":"wg0","publicKey":"<base64>","listenPort":51820,
  "peers":[{"publicKey":"<base64>","description":"phone","endpoint":"203.0.113.7:40211",
            "allowedIps":["192.168.x.2/32"],"latestHandshake":1790000000,"rxBytes":123456,"txBytes":654321,
            "keepalive":25}]}]}`
	want = oneLine(want)
	want = strings.Replace(want, "<base64>", fixIfKey, 1)
	want = strings.Replace(want, "<base64>", fixPeerKey, 1)
	want = strings.Replace(want, "192.168.x.2", "192.168.9.2", 1)
	if string(b) != want {
		t.Fatalf("wireguard part\n got %s\nwant %s", b, want)
	}
	// Only the eight secret-free fields were asked for; the part holds no
	// private or preshared key (the UCI fixture has both, dump would print
	// them).
	for _, cmd := range r.runs {
		if strings.HasPrefix(cmd, "wg ") {
			f := strings.Fields(cmd)
			if len(f) != 4 || f[1] != "show" || f[2] != "all" || !contains(wgFields, f[3]) {
				t.Fatalf("ran %q", cmd)
			}
		}
		if strings.Contains(cmd, "dump") || strings.Contains(cmd, "private-key") || strings.Contains(cmd, "preshared") {
			t.Fatalf("ran %q", cmd)
		}
	}
	for _, secret := range []string{fixIfPrivate, fixPSK} {
		if strings.Contains(string(b), secret) {
			t.Fatal("a secret in the part")
		}
	}
}

// oneLine joins the protocol's multi-line JSON examples.
func oneLine(s string) string { return regexp.MustCompile(`\n\s*`).ReplaceAllString(s, "") }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestWireGuardPartEdges(t *testing.T) {
	k2 := "zV2QA/HJZR2sJZWZBB9tw76KyX8AfD4M5LCz0aKx2wI="
	out := map[string][]byte{
		"public-key":           []byte("wg1\t(none)\nwg0\t" + fixIfKey + "\n"),
		"listen-port":          []byte("wg1\t0\nwg0\t51820\n"),
		"peers":                []byte("wg0\t" + fixPeerKey + "\nwg0\t" + k2 + "\nwg0\tnot-a-key\n"),
		"endpoints":            []byte("wg0\t" + fixPeerKey + "\t[2001:db8::7]:51820\nwg0\t" + k2 + "\t(none)\n"),
		"allowed-ips":          []byte("wg0\t" + fixPeerKey + "\t192.168.9.2/32 fd00:9::2/128\nwg0\t" + k2 + "\t(none)\n"),
		"latest-handshakes":    []byte("wg0\t" + fixPeerKey + "\t1790000000\nwg0\t" + k2 + "\t0\n"),
		"transfer":             []byte("wg0\t" + fixPeerKey + "\t1\t2\nwg0\t" + k2 + "\t0\t0\n"),
		"persistent-keepalive": []byte("wg0\t" + fixPeerKey + "\toff\nwg0\t" + k2 + "\t25\n"),
	}
	w := ParseWireGuard(out, map[string]string{"wg0": "wg0"}, map[string]string{"wg0\t" + k2: "laptop", "wg9\t" + fixPeerKey: "elsewhere"})
	b, _ := json.Marshal(w)
	want := `{"interfaces":[` +
		`{"name":"wg0","network":"wg0","publicKey":"` + fixIfKey + `","listenPort":51820,"peers":[` +
		`{"publicKey":"` + fixPeerKey + `","description":null,"endpoint":"[2001:db8::7]:51820","allowedIps":["192.168.9.2/32","fd00:9::2/128"],"latestHandshake":1790000000,"rxBytes":1,"txBytes":2,"keepalive":null},` +
		`{"publicKey":"` + k2 + `","description":"laptop","endpoint":null,"allowedIps":[],"latestHandshake":0,"rxBytes":0,"txBytes":0,"keepalive":25}]},` +
		`{"name":"wg1","network":null,"publicKey":null,"listenPort":0,"peers":[]}]}`
	if string(b) != want {
		t.Fatalf("\n got %s\nwant %s", b, want)
	}
	// Byte counters tick without a resend; a handshake is a change.
	fp := Fingerprint(wgStable(w))
	w.Interfaces[0].Peers[0].RxBytes += 1000
	if Fingerprint(wgStable(w)) != fp {
		t.Fatal("rx bytes changed the fingerprint")
	}
	w.Interfaces[0].Peers[1].LatestHandshake = 1790000100
	if Fingerprint(wgStable(w)) == fp {
		t.Fatal("a handshake must change the fingerprint")
	}
	if w.Interfaces[0].Peers[0].RxBytes != 1001 {
		t.Fatal("wgStable must not touch the part")
	}
}

func TestWireGuardReaderWithoutWG(t *testing.T) {
	r := &wgRouter{noWG: true}
	o := NewObserver(&Env{Root: t.TempDir(), Run: r.run}, map[Part]bool{PartWireGuard: true}, "")
	if _, ok := o.Read(PartWireGuard, true); ok {
		t.Fatal("no wg: the part must be absent")
	}
	if caps := o.Parts(); len(caps) != 1 || caps[0].Capability() != "observe.wireguard" {
		t.Fatalf("%v", caps)
	}
	// wg without interfaces: one call, an empty list.
	r = &wgRouter{dir: t.TempDir()}
	w := (&WireGuardReader{Env: &Env{Root: t.TempDir(), Run: r.run}}).Read()
	if b, _ := json.Marshal(w); string(b) != `{"interfaces":[]}` {
		t.Fatalf("%s", b)
	}
	n := 0
	for _, c := range r.runs {
		if strings.HasPrefix(c, "wg ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("runs %v", r.runs)
	}
}

// ddnsTree is a router with ddns-scripts and the protocol example's state.
func ddnsTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{
		"etc/config/ddns":                               []byte("x"),
		"usr/lib/ddns/dynamic_dns_updater.sh":           []byte("#!/bin/sh\n"),
		"etc/rc.d/S95ddns":                              []byte(""),
		"usr/share/ddns/default/cloudflare.com-v4.json": []byte("{}"),
		"usr/share/ddns/default/duckdns.org.json":       []byte("{}"),
		"usr/share/ddns/default/no-ip.com.json":         []byte("{}"),
		"var/run/ddns/home.ip":                          []byte("203.0.113.10\n"),
		// ddns-scripts writes the uptime of the update, not the clock.
		"var/run/ddns/home.update": []byte("12345\n"),
		"var/run/ddns/home.pid":    []byte("4242\n"),
		"proc/4242/cmdline":        []byte("/bin/sh\x00/usr/lib/ddns/dynamic_dns_updater.sh\x00-v\x000\x00-S\x00home\x00--\x00start\x00"),
		"proc/uptime":              []byte("20000.12 39000.50\n"),
		"var/log/ddns/home.log":    fixture(t, "ddns-home.log"),
	})
	return root
}

// now makes boot = 1790007655 − 20000.12 ≈ 1789987655, so the update at
// uptime 12345 was at 1790000000.
var ddnsNow = time.Unix(1790007655, 0)

func TestDDNSPartMatchesTheProtocol(t *testing.T) {
	root := ddnsTree(t)
	var runs []string
	env := &Env{Root: root, Now: func() time.Time { return ddnsNow }, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		runs = append(runs, name+" "+strings.Join(args, " "))
		if name+" "+strings.Join(args, " ") == "uci -q -X show ddns" {
			return fixture(t, "uci-show-ddns.txt"), nil
		}
		return nil, errors.New("not found")
	}}
	d := (&DDNSReader{Env: env}).Read()
	b, _ := json.Marshal(d)
	want := `{"installed":true,"serviceEnabled":true,
  "providers":["cloudflare.com-v4","duckdns.org","no-ip.com"],
  "services":[{"name":"home","enabled":true,"domain":"home.example.com","registeredIp":"203.0.113.10",
               "lastUpdate":1790000000,"running":true,"lastError":null}]}`
	want = oneLine(want)
	if string(b) != want {
		t.Fatalf("ddns part\n got %s\nwant %s", b, want)
	}
	if strings.Contains(string(b), fixDDNSPass) || strings.Contains(string(b), "Bearer") {
		t.Fatal("the part carries the service's credentials")
	}
	if len(runs) != 1 {
		t.Fatalf("runs %v", runs)
	}
}

func TestDDNSPartStates(t *testing.T) {
	root := ddnsTree(t)
	writeTree(t, root, map[string][]byte{
		// A service whose last update failed, a stale pid, an update file
		// from before a reboot, and a failed lookup.
		"var/log/ddns/cfg02b4c1.log":             []byte(" 100100  info : Update successful - IP '203.0.113.10' send\n 100200 ERROR : IP update not accepted by DDNS Provider\n 100201       : Waiting 60 seconds (Retry Interval)\n"),
		"var/run/ddns/cfg02b4c1.pid":             []byte("4343\n"),
		"proc/4343/cmdline":                      []byte("/usr/sbin/dnsmasq\x00"),
		"var/run/ddns/cfg02b4c1.update":          []byte("99999\n"),
		"var/run/ddns/cfg02b4c1.ip":              []byte("\n"),
		"usr/share/ddns/custom/my-provider.json": []byte("{}"),
		"usr/share/ddns/custom/duckdns.org.json": []byte("{}"),
	})
	uciOut := string(fixture(t, "uci-show-ddns.txt")) +
		"ddns.cfg02b4c1=service\nddns.cfg02b4c1.enabled='0'\nddns.cfg02b4c1.domain='other.example.com'\nddns.cfg02b4c1.password='x'\n" +
		"ddns.weird=service\nddns.weird.enabled='1'\n"
	env := &Env{Root: root, Now: func() time.Time { return ddnsNow }, Run: cannedRun(map[string][]byte{"uci -q -X show ddns": []byte(uciOut)})}
	d := (&DDNSReader{Env: env}).Read()
	if len(d.Services) != 3 || strings.Join(d.Providers, ",") != "cloudflare.com-v4,duckdns.org,my-provider,no-ip.com" {
		t.Fatalf("%+v", d)
	}
	s := d.Services[1]
	if s.Name != "cfg02b4c1" || s.Enabled || s.Domain == nil || *s.Domain != "other.example.com" || s.RegisteredIP != nil ||
		s.LastUpdate != nil || s.Running || s.LastError == nil || !strings.Contains(*s.LastError, "IP update not accepted") {
		t.Fatalf("%s", mustJSONText(s))
	}
	w := d.Services[2]
	if w.Name != "weird" || !w.Enabled || w.Domain != nil || w.LastError != nil || w.Running || w.LastUpdate != nil {
		t.Fatalf("%s", mustJSONText(w))
	}
	// Not installed: absent.
	o := NewObserver(&Env{Root: t.TempDir(), Run: cannedRun(nil)}, map[Part]bool{PartDDNS: true}, "")
	if _, ok := o.Read(PartDDNS, true); ok {
		t.Fatal("no ddns-scripts: the part must be absent")
	}
}

func TestDDNSLastError(t *testing.T) {
	long := " 100200 ERROR : " + strings.Repeat("é", 150)
	if got := ddnsLastError([]byte(long + "\n")); len(got) > 200 || !strings.HasPrefix(got, "100200 ERROR") {
		t.Fatalf("%q (%d bytes)", got, len(got))
	}
	// The cause, not the generic line ddns-scripts writes after it.
	run := " 110106 ERROR : No or private or invalid IP '192.168.1.2' given! Please check your configuration\n" +
		" 110106 ERROR : No update send to DDNS Provider\n 110106       : Waiting 600 seconds (Check Interval)\n"
	if got := ddnsLastError([]byte(run)); !strings.Contains(got, "private or invalid IP") {
		t.Errorf("cause: %q", got)
	}
	if got := ddnsLastError([]byte(" 1  WARN : Transfer failed - retry 1/5 in 60 seconds\n")); !strings.Contains(got, "Transfer failed") {
		t.Errorf("a generic line alone still shows: %q", got)
	}
	if got := ddnsLastError([]byte(" 1  WARN : x\n 2  info : Forced update successful - IP: '203.0.113.10' send\n")); got != "" {
		t.Fatalf("%q", got)
	}
}

func mustJSONText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestInterfacesIPv6Prefixes(t *testing.T) {
	dump := `{"interface":[
	 {"interface":"wan6","up":true,"uptime":10,"l3_device":"wan0","device":"wan0","proto":"dhcpv6",
	  "ipv6-address":[{"address":"2001:db8:0:1::2","mask":64}],
	  "ipv6-prefix":[{"address":"2001:db8:10::","mask":56,"preferred":3600,"valid":7200,"class":"wan6","assigned":{"lan":{"address":"2001:db8:10:1::","mask":64}}},
	                 {"address":"2001:db8:20::","mask":48,"class":"wan6","assigned":{}}],
	  "ipv6-prefix-assignment":[],"route":[{"target":"::","mask":0,"nexthop":"fe80::1"}]},
	 {"interface":"lan","up":true,"uptime":10,"l3_device":"br-lan","device":"br-lan","proto":"static",
	  "ipv4-address":[{"address":"192.168.1.1","mask":24}],
	  "ipv6-prefix-assignment":[{"address":"2001:db8:10:1::","mask":64,"preferred":3600,"valid":7200,"local-address":{"address":"2001:db8:10:1::1","mask":64}}]}]}`
	list, ok := ParseInterfaceDumpAt([]byte(dump), time.Unix(1790000000, 0))
	if !ok || len(list) != 2 {
		t.Fatalf("%+v", list)
	}
	b, _ := json.Marshal(list)
	// protocol.md 6.1's example fields.
	for _, want := range []string{
		`"network":"wan6","device":"wan0",`,
		`"ipv6Prefixes":[{"prefix":"2001:db8:10::/56","preferredUntil":1790003600,"validUntil":1790007200},{"prefix":"2001:db8:20::/48","preferredUntil":null,"validUntil":null}],"ipv6Assigned":[]}`,
		`"ipv6Prefixes":[],"ipv6Assigned":["2001:db8:10:1::/64"]}`,
	} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("interfaces %s\nlack %s", b, want)
		}
	}
	// The lifetimes wobble between reads: not part of the fingerprint.
	o := &Observer{Interfaces: &InterfaceReader{Env: &Env{}}}
	o.Interfaces.last, o.Interfaces.ok, o.Interfaces.at = list, true, time.Now()
	item, _ := o.Read(PartInterfaces, true)
	later, _ := ParseInterfaceDumpAt([]byte(dump), time.Unix(1790000001, 0))
	o.Interfaces.last = later
	item2, _ := o.Read(PartInterfaces, true)
	if item.FP != item2.FP {
		t.Fatal("a lifetime second changed the fingerprint")
	}
}

func TestUPnPSecureMode(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{"etc/config/upnpd": []byte("x"), "usr/sbin/miniupnpd": []byte("")})
	env := &Env{Root: root, Run: cannedRun(map[string][]byte{"uci -q show upnpd": []byte("upnpd.config=upnpd\nupnpd.config.enabled='1'\nupnpd.config.secure_mode='0'\n")})}
	u := (&UPnPReader{Env: env}).Read()
	b, _ := json.Marshal(u)
	if string(b) != `{"installed":true,"enabled":true,"running":false,"secureMode":false,"mappings":[]}` {
		t.Fatalf("%s", b)
	}
}
