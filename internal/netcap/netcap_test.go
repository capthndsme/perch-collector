package netcap

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/hoststat"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/observe"
)

// fakeSys is /sys/class/net as a map.
type fakeSys struct {
	devs   map[string]string   // device → MAC
	master map[string]string   // port → bridge
	uppers map[string][]string // device → its VLAN devices
}

func (f fakeSys) Exists(dev string) bool   { _, ok := f.devs[dev]; return ok }
func (f fakeSys) Master(dev string) string { return f.master[dev] }
func (f fakeSys) Uppers(dev string) []string {
	return f.uppers[dev]
}
func (f fakeSys) MAC(dev string) (net.HardwareAddr, bool) {
	m, err := net.ParseMAC(f.devs[dev])
	return m, err == nil
}

func labSys() fakeSys {
	return fakeSys{
		devs: map[string]string{
			"br-lan": "02:00:00:00:10:01", "br-guest": "02:00:00:00:20:01", "br-iot": "02:00:00:00:30:01",
			"br-trunk": "02:00:00:00:99:01", "br-trunk.110": "02:00:00:00:99:01", "br-trunk.120": "02:00:00:00:99:01",
			"lan4": "02:00:00:00:00:44", "wan": "02:00:00:00:00:01", "wan2": "02:00:00:00:00:02", "wan3": "02:00:00:00:00:03",
			"eth9": "02:00:00:00:00:99",
		},
		master: map[string]string{"lan4": "br-lan"},
		uppers: map[string][]string{"br-trunk": {"br-trunk.110", "br-trunk.120"}},
	}
}

func labDiscovery(t *testing.T) Discovery {
	t.Helper()
	b, err := os.ReadFile("testdata/netifd-multi.json")
	if err != nil {
		t.Fatal(err)
	}
	list, ok := observe.ParseInterfaceDump(b)
	if !ok {
		t.Fatal("dump did not parse")
	}
	return Discovery{OK: true, Netifd: true, Interfaces: list, Masq: map[string]bool{"wan3": true}}
}

func targetsOf(p Plan) []string {
	var out []string
	for _, t := range p.Targets {
		out = append(out, t.Network+"@"+t.Device)
	}
	return out
}

func TestMakePlanAuto(t *testing.T) {
	p := MakePlan(labDiscovery(t), Selection{Networks: []string{Auto}}, labSys())
	want := []string{"guest@br-guest", "iot@br-iot", "lan@br-lan", "vlan110@br-trunk.110", "vlan120@br-trunk.120"}
	if got := targetsOf(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("targets %v, want %v", got, want)
	}
	// lan and its alias share br-lan: one engine, attributed to lan (IPv4).
	for _, tg := range p.Targets {
		if tg.Device == "br-lan" && !reflect.DeepEqual(tg.Networks, []string{"lan", "lan6"}) {
			t.Errorf("br-lan networks %v", tg.Networks)
		}
	}
	reasons := map[string]string{}
	for _, s := range p.Skipped {
		reasons[s.Network] = s.Reason
	}
	if !strings.Contains(reasons["trunk"], "br-trunk.110, br-trunk.120") || !strings.Contains(reasons["trunk"], "auto captures those") {
		t.Errorf("trunk: %q (the VLAN-filtering bridge must not be captured with its VLANs)", reasons["trunk"])
	}
	if !strings.Contains(reasons["port4"], "port of br-lan") {
		t.Errorf("port4: %q (a bridge port is never captured)", reasons["port4"])
	}
	for _, n := range []string{"wan", "wan2", "wan3", "office", "loopback"} {
		if _, ok := reasons[n]; ok {
			t.Errorf("%s reported as skipped; auto never selects it", n)
		}
	}
	// LAN side = everything but loopback and the three WANs (default route
	// ×2, masquerading zone ×1).
	var lan []string
	for _, i := range p.LAN {
		lan = append(lan, i.Network)
	}
	if want := []string{"guest", "iot", "lan", "lan6", "office", "port4", "trunk", "vlan110", "vlan120"}; !reflect.DeepEqual(lan, want) {
		t.Errorf("LAN %v, want %v", lan, want)
	}
	var prefixes []string
	for _, n := range p.LANPrefixes {
		prefixes = append(prefixes, n.String())
	}
	sort.Strings(prefixes)
	wantP := []string{"192.168.1.0/24", "192.168.110.0/24", "192.168.120.0/24", "192.168.20.0/24", "192.168.30.0/24",
		"2001:db8:0:10::/64", "fd00:1::/64", "fd00:2::/64"}
	if !reflect.DeepEqual(prefixes, wantP) {
		t.Errorf("prefixes %v, want %v", prefixes, wantP)
	}
	var macs []string
	for _, m := range p.GatewayMACs {
		macs = append(macs, m.String())
	}
	wantM := []string{"02:00:00:00:00:44", "02:00:00:00:10:01", "02:00:00:00:20:01", "02:00:00:00:30:01", "02:00:00:00:99:01"}
	if !reflect.DeepEqual(macs, wantM) {
		t.Errorf("gateway MACs %v, want %v (no WAN MAC)", macs, wantM)
	}
}

func TestMakePlanSelection(t *testing.T) {
	d := labDiscovery(t)
	cases := []struct {
		name string
		sel  Selection
		want []string
		skip map[string]string
	}{
		{"exclude by network", Selection{Networks: []string{Auto}, Exclude: []string{"guest", "vlan120"}},
			[]string{"iot@br-iot", "lan@br-lan", "vlan110@br-trunk.110"}, nil},
		{"exclude by device", Selection{Networks: []string{Auto}, Exclude: []string{"br-iot"}},
			[]string{"guest@br-guest", "lan@br-lan", "vlan110@br-trunk.110", "vlan120@br-trunk.120"}, nil},
		{"explicit names", Selection{Networks: []string{"lan", "iot"}},
			[]string{"iot@br-iot", "lan@br-lan"}, nil},
		{"explicit trunk alone is fine", Selection{Networks: []string{"trunk"}},
			[]string{"trunk@br-trunk"}, nil},
		{"trunk with its VLANs is refused", Selection{Networks: []string{"trunk", "vlan110"}},
			[]string{"vlan110@br-trunk.110"}, map[string]string{"trunk": "captured on their own"}},
		{"a WAN is refused", Selection{Networks: []string{"lan", "wan", "wan3"}},
			[]string{"lan@br-lan"}, map[string]string{"wan": "WAN", "wan3": "WAN"}},
		{"configured WAN is excluded from auto", Selection{Networks: []string{Auto}, WAN: []string{"guest"}},
			[]string{"iot@br-iot", "lan@br-lan", "vlan110@br-trunk.110", "vlan120@br-trunk.120"}, nil},
		{"down network", Selection{Networks: []string{"office"}}, nil, map[string]string{"office": "down"}},
		{"device name without a network", Selection{Networks: []string{"eth9"}}, []string{"eth9@eth9"}, nil},
		{"device name of a network", Selection{Networks: []string{"br-guest"}}, []string{"br-guest@br-guest"}, nil},
		{"unknown", Selection{Networks: []string{"nope"}}, nil, map[string]string{"nope": "no such"}},
		{"auto plus explicit", Selection{Networks: []string{"eth9", Auto}, Exclude: []string{"guest", "iot", "vlan110", "vlan120"}},
			[]string{"eth9@eth9", "lan@br-lan"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := MakePlan(d, tc.sel, labSys())
			if got := targetsOf(p); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("targets %v, want %v", got, tc.want)
			}
			for n, reason := range tc.skip {
				found := false
				for _, s := range p.Skipped {
					if s.Network == n && strings.Contains(s.Reason, reason) {
						found = true
					}
				}
				if !found {
					t.Errorf("%s not skipped with %q: %+v", n, reason, p.Skipped)
				}
			}
		})
	}
}

func TestMasqNetworks(t *testing.T) {
	secs := observe.ParseUCIShow("firewall", []byte(`firewall.lan=zone
firewall.lan.name='lan'
firewall.lan.network='lan'
firewall.wan=zone
firewall.wan.name='wan'
firewall.wan.network='wan' 'wan2'
firewall.wan.masq='1'
firewall.@rule[0]=rule
firewall.@rule[0].masq='1'
`))
	got := MasqNetworks(secs)
	if !reflect.DeepEqual(got, map[string]bool{"wan": true, "wan2": true}) {
		t.Errorf("masq %v", got)
	}
}

// fakeEngine records its life.
type fakeEngine struct {
	t       Target
	mu      sync.Mutex
	ran     bool
	stopped bool
}

func (e *fakeEngine) Run()  { e.mu.Lock(); e.ran = true; e.mu.Unlock() }
func (e *fakeEngine) Stop() { e.mu.Lock(); e.stopped = true; e.mu.Unlock() }

// netifd is a changeable fake of the router.
type netifd struct {
	mu   sync.Mutex
	d    Discovery
	fail bool
}

func (n *netifd) discover() Discovery {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail {
		return Discovery{}
	}
	d := n.d
	d.Interfaces = append([]observe.Interface(nil), n.d.Interfaces...)
	return d
}

func (n *netifd) set(f func(*Discovery)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	f(&n.d)
}

func TestReconcilerHotAddRemove(t *testing.T) {
	fake := &netifd{d: labDiscovery(t)}
	sys := labSys()
	var opened []*fakeEngine
	var shares []int
	var applied []Plan
	failDev := ""
	r := &Reconciler{
		Discover:  fake.discover,
		Selection: Selection{Networks: []string{Auto}},
		Sys:       sys,
		Open: func(tg Target, n int) (Engine, error) {
			if tg.Device == failDev {
				return nil, errors.New("permission denied")
			}
			e := &fakeEngine{t: tg}
			opened = append(opened, e)
			shares = append(shares, n)
			return e, nil
		},
		Apply: func(p Plan) { applied = append(applied, p) },
		Logf:  func(string, ...any) {},
	}
	started, stopped := r.Reconcile()
	if len(started) != 5 || len(stopped) != 0 || len(applied) != 1 {
		t.Fatalf("first round: started %v stopped %v", started, stopped)
	}
	if shares[0] != 5 {
		t.Errorf("share count %d, want 5", shares[0])
	}
	// Nothing changed: nothing happens.
	if started, stopped = r.Reconcile(); len(started)+len(stopped) != 0 {
		t.Fatalf("idle round: started %v stopped %v", started, stopped)
	}

	// A new VLAN network appears (uci add + ifup): only it starts.
	sys.devs["br-trunk.130"] = "02:00:00:00:99:01"
	sys.uppers["br-trunk"] = append(sys.uppers["br-trunk"], "br-trunk.130")
	fake.set(func(d *Discovery) {
		d.Interfaces = append(d.Interfaces, observe.Interface{Network: "vlan130", Device: "br-trunk.130", Proto: "static", Up: true,
			IPv4: []string{"192.168.130.1/24"}})
	})
	started, stopped = r.Reconcile()
	if !reflect.DeepEqual(started, []string{"br-trunk.130"}) || len(stopped) != 0 {
		t.Fatalf("add: started %v stopped %v", started, stopped)
	}
	last := applied[len(applied)-1]
	found := false
	for _, n := range last.LANPrefixes {
		found = found || n.String() == "192.168.130.0/24"
	}
	if !found {
		t.Errorf("the new network's prefix is not local")
	}
	if got := r.Captured()["br-trunk.130"]; got != "vlan130" {
		t.Errorf("captured %v", r.Captured())
	}

	// guest goes down: its engine stops, the others keep running.
	fake.set(func(d *Discovery) {
		for i := range d.Interfaces {
			if d.Interfaces[i].Network == "guest" {
				d.Interfaces[i].Up = false
			}
		}
	})
	started, stopped = r.Reconcile()
	if len(started) != 0 || !reflect.DeepEqual(stopped, []string{"br-guest"}) {
		t.Fatalf("down: started %v stopped %v", started, stopped)
	}
	for _, e := range opened {
		if e.t.Device == "br-guest" && !e.stopped {
			t.Errorf("guest engine still running")
		}
		if e.t.Device == "br-lan" && e.stopped {
			t.Errorf("lan engine stopped by an unrelated change")
		}
	}

	// netifd hiccup: nothing stops.
	fake.mu.Lock()
	fake.fail = true
	fake.mu.Unlock()
	if started, stopped = r.Reconcile(); len(started)+len(stopped) != 0 {
		t.Fatalf("hiccup: started %v stopped %v", started, stopped)
	}
	fake.mu.Lock()
	fake.fail = false
	fake.mu.Unlock()

	// A network moves to another device (br-iot → br-iot.1): restart.
	sys.devs["br-iot.1"] = "02:00:00:00:30:01"
	fake.set(func(d *Discovery) {
		for i := range d.Interfaces {
			if d.Interfaces[i].Network == "iot" {
				d.Interfaces[i].Device = "br-iot.1"
			}
		}
	})
	started, stopped = r.Reconcile()
	if !reflect.DeepEqual(started, []string{"br-iot.1"}) || !reflect.DeepEqual(stopped, []string{"br-iot"}) {
		t.Fatalf("move: started %v stopped %v", started, stopped)
	}

	// An engine that cannot open is retried every round.
	failDev = "br-guest"
	fake.set(func(d *Discovery) {
		for i := range d.Interfaces {
			if d.Interfaces[i].Network == "guest" {
				d.Interfaces[i].Up = true
			}
		}
	})
	if started, _ = r.Reconcile(); len(started) != 0 {
		t.Fatalf("a failing open started %v", started)
	}
	failDev = ""
	if started, _ = r.Reconcile(); !reflect.DeepEqual(started, []string{"br-guest"}) {
		t.Fatalf("retry started %v", started)
	}

	r.Close()
	for _, e := range opened {
		e.mu.Lock()
		stoppedE := e.stopped
		e.mu.Unlock()
		if !stoppedE {
			t.Errorf("%s not stopped by Close", e.t.Device)
		}
	}
	if started, _ = r.Reconcile(); len(started) != 0 {
		t.Errorf("Reconcile after Close started %v", started)
	}
}

func TestFitInterfaceList(t *testing.T) {
	list := "br-lan,br-guest,br-iot,br-trunk.110,br-trunk.120,mgmt,br-extra1,br-extra2"
	got := FitInterfaceList(list, 64)
	if len(got) > 64 || !strings.HasSuffix(got, ",+1") && !strings.HasSuffix(got, ",+2") {
		t.Errorf("fit %q (%d)", got, len(got))
	}
	if FitInterfaceList("br-lan", 64) != "br-lan" {
		t.Errorf("short list changed")
	}
}

func writeNetDev(t *testing.T, root string, rows map[string][2]uint64) {
	t.Helper()
	var b strings.Builder
	b.WriteString("Inter-|   Receive                                                |  Transmit\n")
	b.WriteString(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n")
	names := make([]string, 0, len(rows))
	for n := range rows {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := rows[n]
		b.WriteString(n + ": " + u(r[0]) + " 0 0 0 0 0 0 0 " + u(r[1]) + " 0 0 0 0 0 0 0\n")
	}
	if err := os.MkdirAll(filepath.Join(root, "proc/net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/net/dev"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func u(v uint64) string { return itoa(int(v)) }

func TestReporter(t *testing.T) {
	root := t.TempDir()
	writeNetDev(t, root, map[string][2]uint64{"br-lan": {1000, 5000}, "br-iot": {10, 20}, "wan": {1, 2}})
	agg := aggregator.New([]net.HardwareAddr{mustMAC("02:00:00:00:10:01")}, nil, 50, 50)
	agg.SetRoutedLAN(true, nil)
	agg.RecordPacket(mustMAC("02:00:00:00:10:11"), mustMAC("02:00:00:00:10:01"), net.ParseIP("192.168.1.100"),
		net.ParseIP("203.0.113.9"), 700, aggregator.FlowInfo{Network: "lan", ToServer: true})
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	d := labDiscovery(t)
	r := &Reporter{
		Discover: func() Discovery { return d },
		Sys:      labSys(),
		Captured: func() map[string]string { return map[string]string{"br-lan": "lan"} },
		Agg:      agg,
		FS:       hoststat.FS{Root: root},
		Scope:    func() string { return "routed" },
		Drops:    func() map[string]uint64 { return map[string]uint64{"br-lan": 7} },
		Now:      func() time.Time { return now },
	}
	first := *r.Read()
	byName := map[string]int{}
	for i, n := range first {
		byName[n.Name] = i
	}
	if _, ok := byName["wan"]; ok {
		t.Fatalf("a WAN in the networks report")
	}
	lan := first[byName["lan"]]
	if !lan.Captured || lan.Device != "br-lan" || *lan.RxBytes != 1000 || *lan.TxBytes != 5000 || lan.RxRate != nil {
		t.Errorf("lan first read %+v", lan)
	}
	if lan.Devices != 1 || lan.ActiveDevices != 1 || lan.Capture == nil || lan.Capture.BytesOutWAN != 700 || lan.Capture.Scope != "routed" {
		t.Errorf("lan capture %+v %+v", lan, lan.Capture)
	}
	if lan.Capture.KernelDrops == nil || *lan.Capture.KernelDrops != 7 {
		t.Errorf("lan kernel drops %v", lan.Capture.KernelDrops)
	}
	if !reflect.DeepEqual(lan.IPv6, []string{"fd00:1::1/64", "2001:db8:0:10::/64"}) {
		t.Errorf("lan ipv6 %v", lan.IPv6)
	}
	lan6 := first[byName["lan6"]]
	if !lan6.Captured || lan6.Capture != nil || lan6.Devices != 0 {
		t.Errorf("alias lan6 %+v", lan6)
	}
	iot := first[byName["iot"]]
	if iot.Captured || iot.Capture != nil || *iot.RxBytes != 10 {
		t.Errorf("iot %+v", iot)
	}
	office := first[byName["office"]]
	if office.Up || office.RxBytes != nil || office.Device != "br-office" {
		t.Errorf("office %+v", office)
	}

	// 10 s later: rates.
	now = now.Add(10 * time.Second)
	writeNetDev(t, root, map[string][2]uint64{"br-lan": {3000, 105000}, "br-iot": {5, 5}})
	second := *r.Read()
	lan = second[byName["lan"]]
	if lan.RxRate == nil || *lan.RxRate != 200 || *lan.TxRate != 10000 {
		t.Errorf("lan rates %v %v", lan.RxRate, lan.TxRate)
	}
	if second[byName["lan6"]].RxRate == nil {
		t.Errorf("the alias shares its device's rate")
	}
	// iot's counters went backwards (recreated): no rate.
	if second[byName["iot"]].RxRate != nil {
		t.Errorf("rate across a counter reset")
	}
	// netifd down: not reported.
	d.OK = false
	if r.Read() != nil {
		t.Errorf("reported without netifd")
	}
}

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestSysFS(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "sys/class/net")
	for _, d := range []string{"br-trunk", "br-trunk.110", "lan1", "tun0"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(base, "br-trunk/address"), []byte("02:00:00:00:99:01\n"), 0o644)
	os.WriteFile(filepath.Join(base, "tun0/address"), []byte("00:00:00:00:00:00\n"), 0o644)
	os.Symlink("../br-trunk.110", filepath.Join(base, "br-trunk/upper_br-trunk.110"))
	os.Symlink("../br-trunk", filepath.Join(base, "lan1/master"))
	s := SysFS{Root: root}
	if !s.Exists("br-trunk") || s.Exists("nope") || s.Exists("../x") {
		t.Errorf("Exists")
	}
	if s.Master("lan1") != "br-trunk" || s.Master("br-trunk") != "" {
		t.Errorf("Master")
	}
	if !reflect.DeepEqual(s.Uppers("br-trunk"), []string{"br-trunk.110"}) {
		t.Errorf("Uppers %v", s.Uppers("br-trunk"))
	}
	if m, ok := s.MAC("br-trunk"); !ok || m.String() != "02:00:00:00:99:01" {
		t.Errorf("MAC %v", m)
	}
	if _, ok := s.MAC("tun0"); ok {
		t.Errorf("an all-zero MAC is no pivot")
	}
}

func TestNetworkOfDevice(t *testing.T) {
	p := MakePlan(labDiscovery(t), Selection{}, labSys())
	if got := NetworkOfDevice("br-lan", p.LAN); got != "lan" {
		t.Errorf("br-lan → %q", got)
	}
	if got := NetworkOfDevice("wan", p.LAN); got != "" {
		t.Errorf("wan → %q", got)
	}
	if len(p.Targets) != 0 {
		t.Errorf("an empty selection captures nothing: %v", p.Targets)
	}
}
