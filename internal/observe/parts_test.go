package observe

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

func TestParseOdhcpdStateFile(t *testing.T) {
	v4, v6 := ParseOdhcpdStateFile(fixture(t, "odhcpd-state.txt"))
	if len(v6) != 2 {
		t.Fatalf("v6 = %+v (the expired lease must be skipped)", v6)
	}
	if l := v6[0]; l.DUID != "00030001020000001061" || l.Hostname != "phone" || l.ValidUntil != 1790003600 ||
		!reflect.DeepEqual(l.Addresses, []string{"fd00::61", "fd00::62"}) || l.Device != "br-lan" || l.IAID == nil || *l.IAID != 1 {
		t.Errorf("phone = %+v", l)
	}
	if l := v6[1]; l.Hostname != "" || l.ValidUntil != 0 {
		t.Errorf("infinite, unnamed = %+v", l)
	}
	if len(v4) != 1 || v4[0].MAC != "02:00:00:00:10:65" || v4[0].IP != "192.168.1.65" || v4[0].Hostname != "laptop4" || v4[0].Source != SourceOdhcpd {
		t.Errorf("v4 = %+v", v4)
	}
}

func TestReaderOdhcpdStateFileFallback(t *testing.T) {
	f := newFakeRouter(t)
	f.uci = fixture(t, "uci-show-dhcp.txt")
	f.write(t, "etc/config/dhcp", []byte("x"))
	f.write(t, "tmp/hosts/odhcpd", fixture(t, "odhcpd-state.txt"))
	// No ubus answers: the state file stands in.
	r := &Reader{Root: f.root, Run: f.run}
	d, _ := r.Read()
	n := 0
	for _, l := range d.Leases6 {
		if l.Source == SourceOdhcpd {
			n++
		}
	}
	if n != 2 {
		t.Errorf("odhcpd leases from the state file = %d: %+v", n, d.Leases6)
	}
}

func TestPoolsAndLeaseNetworks(t *testing.T) {
	f := newFakeRouter(t)
	f.uci = append(fixture(t, "uci-show-dhcp.txt"), []byte("dhcp.guest=dhcp\ndhcp.guest.interface='guest'\ndhcp.guest.leasetime='2m'\ndhcp.guest.start='100'\ndhcp.guest.limit='50'\ndhcp.wan=dhcp\ndhcp.wan.interface='wan'\ndhcp.wan.ignore='1'\n")...)
	f.write(t, "etc/config/dhcp", []byte("x"))
	f.write(t, "tmp/dhcp.leases", []byte("1790000000 02:00:00:00:10:21 192.168.1.21 laptop *\n1790000000 02:00:00:00:20:21 192.168.20.21 guest1 *\n1790000000 02:00:00:00:30:21 10.9.9.9 elsewhere *\n"))
	ifaces, _ := ParseInterfaceDump(fixture(t, "ubus-interface-dump.json"))
	r := &Reader{Root: f.root, Run: f.run, Networks: func() []Subnet { return Subnets(ifaces) }}
	d, _ := r.Read()
	want := []Pool{
		{Network: "lan", LeaseTime: 12 * 3600, Section: "lan"},
		{Network: "guest", LeaseTime: 120, Start: 100, Limit: 50, Section: "guest"},
		{Network: "wan", Ignore: true, LeaseTime: DefaultLeaseTime, Section: "wan"},
	}
	if !reflect.DeepEqual(d.Pools, want) {
		t.Errorf("pools =\n%+v\nwant\n%+v", d.Pools, want)
	}
	nets := map[string]string{}
	for _, l := range d.Leases4 {
		nets[l.Hostname] = l.Network
	}
	if nets["laptop"] != "lan" || nets["guest1"] != "guest" || nets["elsewhere"] != "" {
		t.Errorf("lease networks = %v", nets)
	}
}

func TestParseLeaseTime(t *testing.T) {
	cases := map[string]int64{"12h": 43200, "720m": 43200, "3600": 3600, "90s": 90, "1d": 86400, "2w": 1209600, "infinite": 0}
	for in, want := range cases {
		if got, ok := ParseLeaseTime(in); !ok || got != want {
			t.Errorf("ParseLeaseTime(%q) = %d %v, want %d", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "h", "-1h", "12x", "0"} {
		if _, ok := ParseLeaseTime(bad); ok {
			t.Errorf("ParseLeaseTime(%q) accepted", bad)
		}
	}
}

func TestParseInterfaceDump(t *testing.T) {
	list, ok := ParseInterfaceDump(fixture(t, "ubus-interface-dump.json"))
	if !ok {
		t.Fatal("not parsed")
	}
	by := map[string]Interface{}
	for _, i := range list {
		by[i.Network] = i
	}
	if _, ok := by["loopback"]; ok {
		t.Error("loopback must be left out")
	}
	if len(list) != 5 {
		t.Errorf("got %d interfaces: %+v", len(list), list)
	}
	lan := by["lan"]
	if lan.Device != "br-lan" || !reflect.DeepEqual(lan.IPv4, []string{"192.168.1.1/24"}) || !reflect.DeepEqual(lan.IPv6, []string{"fd00::1/64"}) ||
		lan.DefaultRoute || lan.Metric != nil || lan.UptimeSeconds != 14437 {
		t.Errorf("lan = %+v", lan)
	}
	wan := by["wan"]
	if !wan.DefaultRoute || wan.Metric == nil || *wan.Metric != 1 || wan.Gateway4 != "203.0.113.1" ||
		!reflect.DeepEqual(wan.DNSServers, []string{"203.0.113.53"}) || wan.Proto != "dhcp" || wan.Device != "wan0" {
		t.Errorf("wan = %+v", wan)
	}
	if w2 := by["wan2"]; w2.Metric == nil || *w2.Metric != 2 || !w2.DefaultRoute {
		t.Errorf("wan2 = %+v", w2)
	}
	if w6 := by["wan6"]; w6.Up || w6.UptimeSeconds != 0 || w6.Error != "NO_DEVICE" || w6.IPv4 == nil {
		t.Errorf("wan6 = %+v", w6)
	}
	if _, ok := ParseInterfaceDump([]byte("nope")); ok {
		t.Error("garbage parsed")
	}
}

func TestNetworkOf(t *testing.T) {
	ifaces, _ := ParseInterfaceDump(fixture(t, "ubus-interface-dump.json"))
	nets := Subnets(ifaces)
	for ip, want := range map[string]string{"192.168.1.50": "lan", "fd00::50": "lan", "192.168.20.9": "guest", "203.0.113.77": "wan", "8.8.8.8": "", "bad": ""} {
		if got := networkOf(nets, ip); got != want {
			t.Errorf("networkOf(%s) = %q, want %q", ip, got, want)
		}
	}
}

// neighMsg builds one RTM_NEWNEIGH message.
func neighMsg(t *testing.T, ifindex int32, state uint16, ip net.IP, mac net.HardwareAddr) netlink.Message {
	t.Helper()
	hdr := make([]byte, ndmsgLen)
	if ip.To4() != nil {
		hdr[0] = 2
		ip = ip.To4()
	} else {
		hdr[0] = 10
	}
	binary.NativeEndian.PutUint32(hdr[4:8], uint32(ifindex))
	binary.NativeEndian.PutUint16(hdr[8:10], state)
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(ndaDst, ip)
	if mac != nil {
		ae.Bytes(ndaLLAddr, mac)
	}
	attrs, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return netlink.Message{Header: netlink.Header{Type: rtmNewNeigh}, Data: append(hdr, attrs...)}
}

func TestParseNeighMessages(t *testing.T) {
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	msgs := []netlink.Message{
		neighMsg(t, 3, nudReachable, net.ParseIP("192.168.1.21"), mac("02:00:00:00:10:21")),
		neighMsg(t, 3, nudStale, net.ParseIP("192.168.1.22"), mac("02:00:00:00:10:22")),
		neighMsg(t, 3, nudDelay, net.ParseIP("fd00::21"), mac("02:00:00:00:10:21")),
		neighMsg(t, 3, nudPermanent, net.ParseIP("192.168.1.30"), mac("02:00:00:00:10:30")),
		neighMsg(t, 3, nudFailed, net.ParseIP("192.168.1.40"), mac("02:00:00:00:10:40")),
		neighMsg(t, 3, nudIncomplete, net.ParseIP("192.168.1.41"), nil),
		neighMsg(t, 3, nudReachable, net.ParseIP("fe80::1"), mac("02:00:00:00:10:21")),
		neighMsg(t, 3, nudNoARP, net.ParseIP("224.0.0.1"), mac("01:00:5e:00:00:01")),
		neighMsg(t, 3, nudReachable, net.ParseIP("192.168.1.50"), mac("00:00:00:00:00:00")),
		{Header: netlink.Header{Type: 3}, Data: []byte{1, 2}},
	}
	got := ParseNeighMessages(msgs, func(i int) string {
		if i == 3 {
			return "br-lan"
		}
		return ""
	})
	want := []Neighbor{
		{IP: "192.168.1.21", MAC: "02:00:00:00:10:21", Device: "br-lan", Reachable: true, State: "reachable"},
		{IP: "192.168.1.22", MAC: "02:00:00:00:10:22", Device: "br-lan", State: "stale"},
		{IP: "fd00::21", MAC: "02:00:00:00:10:21", Device: "br-lan", Reachable: true, State: "delay"},
		{IP: "192.168.1.30", MAC: "02:00:00:00:10:30", Device: "br-lan", State: "permanent"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("neighbors =\n%+v\nwant\n%+v", got, want)
	}
}

func TestNeighborReaderFallsBackToProcARP(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{"proc/net/arp": fixture(t, "proc-net-arp.txt")})
	ifaces, _ := ParseInterfaceDump(fixture(t, "ubus-interface-dump.json"))
	r := &NeighborReader{Env: &Env{Root: root}, Networks: func() []Subnet { return Subnets(ifaces) },
		dump: func() ([]netlink.Message, error) { return nil, errors.New("no netlink") }}
	list, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	want := []Neighbor{
		{IP: "192.168.1.21", MAC: "02:00:00:00:10:21", Device: "br-lan", Network: "lan", State: "stale"},
		{IP: "192.168.1.30", MAC: "02:00:00:00:10:30", Device: "br-lan", Network: "lan", State: "permanent"},
		{IP: "203.0.113.1", MAC: "02:00:00:00:99:01", Device: "wan0", Network: "wan", State: "stale"},
	}
	if !reflect.DeepEqual(list, want) {
		t.Errorf("arp =\n%+v\nwant\n%+v", list, want)
	}
	r.Env.Root = filepath.Join(root, "nothing")
	if _, err := r.Read(); err == nil {
		t.Error("no netlink and no /proc/net/arp must be an error (part not reported)")
	}
}

func TestParseUPnPLeases(t *testing.T) {
	got := ParseUPnPLeases(fixture(t, "miniupnpd.leases"))
	want := []UPnPMapping{
		{Proto: "TCP", ExtPort: 51413, IntIP: "192.168.1.21", IntPort: 51413, Expires: 1790003600, Description: "Transmission at 51413"},
		{Proto: "UDP", ExtPort: 3074, IntIP: "192.168.1.30", IntPort: 3074, Expires: 1790001234, Description: "Xbox: Live"},
		{Proto: "UDP", ExtPort: 51413, IntIP: "192.168.1.21", IntPort: 51413, Description: "Transmission at 51413"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mappings =\n%+v\nwant\n%+v", got, want)
	}
	old := ParseUPnPLeases(fixture(t, "miniupnpd-v1.leases"))
	if len(old) != 2 || old[0].Description != "old client" || old[1].Description != "with:colons" || old[0].Expires != 0 {
		t.Errorf("1.x format = %+v", old)
	}
	long := ParseUPnPLeases([]byte("TCP:1:192.168.1.2:1:0:" + strings.Repeat("é", 100) + "\n"))
	if len(long) != 1 || len(long[0].Description) > MaxDescription || !strings.HasPrefix(long[0].Description, "é") ||
		strings.ContainsRune(long[0].Description, '�') {
		t.Errorf("long description = %q", long[0].Description)
	}
}

// ── fixture router trees ──────────────────────────────────────────────────

func writeTree(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	for p, data := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// process adds /proc/<pid>/comm and fd symlinks to socket inodes.
func process(t *testing.T, root, pid, comm string, inodes ...string) {
	t.Helper()
	writeTree(t, root, map[string][]byte{"proc/" + pid + "/comm": []byte(comm + "\n")})
	fd := filepath.Join(root, "proc", pid, "fd")
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink("/dev/null", filepath.Join(fd, "0"))
	for i, ino := range inodes {
		if err := os.Symlink("socket:["+ino+"]", filepath.Join(fd, string(rune('3'+i)))); err != nil {
			t.Fatal(err)
		}
	}
}

// cannedRun answers uci and ubus from a map keyed by the full command line.
func cannedRun(answers map[string][]byte) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		if b, ok := answers[name+" "+strings.Join(args, " ")]; ok {
			return b, nil
		}
		return nil, errors.New("not found")
	}
}

func TestUPnPReader(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{
		"etc/config/upnpd":         []byte("x"),
		"usr/sbin/miniupnpd":       []byte(""),
		"var/run/miniupnpd.leases": fixture(t, "miniupnpd.leases"),
	})
	process(t, root, "700", "miniupnpd")
	env := &Env{Root: root, Run: cannedRun(map[string][]byte{"uci -q show upnpd": fixture(t, "uci-show-upnpd.txt")})}
	u := (&UPnPReader{Env: env}).Read()
	if !u.Installed || !u.Enabled || !u.Running || !u.SecureMode || len(u.Mappings) != 3 {
		t.Errorf("upnp = %+v", u)
	}
	// Not installed: reported as such, with no mappings.
	u = (&UPnPReader{Env: &Env{Root: t.TempDir(), Run: cannedRun(nil)}}).Read()
	b, _ := json.Marshal(u)
	if string(b) != `{"installed":false,"enabled":false,"running":false,"secureMode":false,"mappings":[]}` {
		t.Errorf("no miniupnpd = %s", b)
	}
}

func TestMWAN3(t *testing.T) {
	ifaces, pol, ok := ParseMWAN3Status(fixture(t, "ubus-mwan3-active.json"))
	if !ok || len(ifaces) != 2 {
		t.Fatalf("active = %+v", ifaces)
	}
	if w := ifaces[0]; w.Name != "wan" || w.Status != "online" || w.Tracking != "active" || w.UptimeSeconds != 86400 ||
		!reflect.DeepEqual(w.TrackIPs, []MWAN3TrackIP{{IP: "203.0.113.1", Up: true}, {IP: "198.51.100.9"}}) {
		t.Errorf("wan = %+v", w)
	}
	if b := ifaces[1]; b.Name != "wanb" || b.Status != "offline" || b.Tracking != "paused" {
		t.Errorf("wanb = %+v", b)
	}
	wantPol := map[string][]MWAN3PolicyMember{
		"balanced": {{Interface: "wan", Percent: 50}, {Interface: "wanb", Percent: 50}},
		"wan_only": {{Interface: "wan", Percent: 100}},
	}
	if !reflect.DeepEqual(pol, wantPol) {
		t.Errorf("policies = %+v (an identical IPv6 twin is dropped)", pol)
	}

	// The live gateway's case: config present, service disabled, metric
	// failover. Config and service state are reported separately.
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{"etc/config/mwan3": []byte("x"), "etc/init.d/mwan3": []byte("")})
	env := &Env{Root: root, Run: cannedRun(map[string][]byte{
		"uci -q show mwan3":      fixture(t, "uci-show-mwan3.txt"),
		"ubus call mwan3 status": fixture(t, "ubus-mwan3-disabled.json"),
	})}
	m := (&MWAN3Reader{Env: env}).Read()
	if m == nil || m.ServiceEnabled || m.Running || len(m.Interfaces) != 3 || m.Interfaces[0].Status != "notracking" ||
		m.Interfaces[0].Tracking != "none" || len(m.Policies) != 0 {
		t.Fatalf("disabled mwan3 = %+v", m)
	}
	wantCfg := []MWAN3ConfigInterface{
		{Name: "wan", Enabled: true, Family: "ipv4", TrackIPs: []string{"203.0.113.1", "198.51.100.9"}},
		{Name: "wanb", Family: "ipv4", TrackIPs: []string{"192.0.2.1"}},
	}
	if !reflect.DeepEqual(m.ConfigInterfaces, wantCfg) || !reflect.DeepEqual(m.ConfigPolicies, map[string][]string{"balanced": {"wan_m1", "wanb_m1"}}) {
		t.Errorf("config = %+v %+v", m.ConfigInterfaces, m.ConfigPolicies)
	}
	// Enabled at boot and tracking.
	writeTree(t, root, map[string][]byte{"etc/rc.d/S19mwan3": []byte("")})
	process(t, root, "812", "mwan3track")
	m = (&MWAN3Reader{Env: env}).Read()
	if !m.ServiceEnabled || !m.Running {
		t.Errorf("enabled mwan3 = %+v", m)
	}
	// Not installed: nothing.
	if m := (&MWAN3Reader{Env: &Env{Root: t.TempDir(), Run: cannedRun(nil)}}).Read(); m != nil {
		t.Errorf("no mwan3 = %+v", m)
	}
}

func TestProcNetListeners(t *testing.T) {
	if got := ProcNetListeners(fixture(t, "proc-net-udp.txt"), 53, false); !reflect.DeepEqual(got, []uint64{5001}) {
		t.Errorf("udp :53 = %v (a connected socket is not a listener)", got)
	}
	if got := ProcNetListeners(fixture(t, "proc-net-udp.txt"), 54, false); !reflect.DeepEqual(got, []uint64{5002}) {
		t.Errorf("udp :54 = %v", got)
	}
	if got := ProcNetListeners(fixture(t, "proc-net-tcp.txt"), 53, true); !reflect.DeepEqual(got, []uint64{5004}) {
		t.Errorf("tcp :53 = %v", got)
	}
}

func TestResolverAdGuardInFront(t *testing.T) {
	// AdGuard Home on :53, dnsmasq on :54 (a real setup).
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{
		"etc/config/dhcp": []byte("x"),
		"proc/net/udp":    fixture(t, "proc-net-udp.txt"),
		"proc/net/tcp":    fixture(t, "proc-net-tcp.txt"),
	})
	process(t, root, "100", "AdGuardHome", "5001", "5004")
	process(t, root, "200", "dnsmasq", "5002", "5005")
	env := &Env{Root: root, Run: cannedRun(map[string][]byte{"uci -q show dhcp": fixture(t, "uci-show-dhcp.txt")})}
	r := &ResolverReader{Env: env, ControllerHost: "perch.example.com",
		Lookup: func(_ context.Context, host string) ([]string, error) {
			if host != "perch.example.com" {
				t.Errorf("looked up %q", host)
			}
			return []string{"192.168.1.10", "fd00::10"}, nil
		}}
	res := r.Read()
	b, _ := json.Marshal(res)
	want := `{"dnsmasqPort":54,"port53Process":"AdGuardHome","port53Processes":["AdGuardHome"],"controllerHost":{"name":"perch.example.com","addresses":["192.168.1.10","fd00::10"]}}`
	if string(b) != want {
		t.Errorf("resolver = %s\nwant %s", b, want)
	}
	// A name that does not resolve, and a controller given by address.
	r.Lookup = func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "perch.example.com", IsNotFound: true}
	}
	if h := r.Read().ControllerHost; h.Error != "not_found" || len(h.Addresses) != 0 {
		t.Errorf("unresolved = %+v", h)
	}
	r.ControllerHost = "192.168.1.10"
	if h := r.Read().ControllerHost; !reflect.DeepEqual(h.Addresses, []string{"192.168.1.10"}) {
		t.Errorf("literal = %+v", h)
	}
	// dnsmasq without a port option answers on 53; nothing on :53 at all.
	root2 := t.TempDir()
	writeTree(t, root2, map[string][]byte{"etc/config/dhcp": []byte("x")})
	r2 := &ResolverReader{Env: &Env{Root: root2, Run: cannedRun(map[string][]byte{"uci -q show dhcp": []byte("dhcp.@dnsmasq[0]=dnsmasq\n")})}}
	b, _ = json.Marshal(r2.Read())
	if string(b) != `{"dnsmasqPort":53,"port53Process":null,"port53Processes":[],"controllerHost":null}` {
		t.Errorf("plain = %s", b)
	}
}

func TestSystemReader(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{"etc/config/system": []byte("x"), "etc/config/firewall": []byte("x")})
	env := &Env{Root: root, Run: cannedRun(map[string][]byte{
		"ubus call system board": fixture(t, "ubus-system-board.json"),
		"ubus call system info":  fixture(t, "ubus-system-info.json"),
		"uci -q show firewall":   fixture(t, "uci-show-firewall.txt"),
	})}
	s := (&SystemReader{Env: env}).Read()
	want := &System{Hostname: "gateway", Release: "OpenWrt 24.10.2 r28739-d9340319c6", Version: "24.10.2", Revision: "r28739-d9340319c6",
		Board: "x86/64", BoardName: "example,router", Model: "Example Router", Kernel: "6.6.100", UptimeSeconds: 123456,
		FlowOffloading: true, FlowOffloadingHw: true}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("system =\n%+v\nwant\n%+v", s, want)
	}
	if s := (&SystemReader{Env: &Env{Root: t.TempDir(), Run: cannedRun(nil)}}).Read(); s != nil {
		t.Errorf("no ubus = %+v", s)
	}
}

// fixtureRouter is a whole router: every part answers.
func fixtureRouter(t *testing.T) (*Env, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, map[string][]byte{
		"etc/config/dhcp":          []byte("x"),
		"etc/config/upnpd":         []byte("x"),
		"etc/config/mwan3":         []byte("x"),
		"etc/config/system":        []byte("x"),
		"etc/config/firewall":      []byte("x"),
		"etc/init.d/mwan3":         []byte(""),
		"usr/sbin/miniupnpd":       []byte(""),
		"tmp/dhcp.leases":          fixture(t, "dhcp.leases"),
		"var/run/miniupnpd.leases": fixture(t, "miniupnpd.leases"),
		"proc/net/udp":             fixture(t, "proc-net-udp.txt"),
		"proc/net/arp":             fixture(t, "proc-net-arp.txt"),
	})
	process(t, root, "100", "AdGuardHome", "5001")
	answers := map[string][]byte{
		"uci -q show dhcp":                 fixture(t, "uci-show-dhcp.txt"),
		"uci -q show upnpd":                fixture(t, "uci-show-upnpd.txt"),
		"uci -q show mwan3":                fixture(t, "uci-show-mwan3.txt"),
		"uci -q show firewall":             fixture(t, "uci-show-firewall.txt"),
		"ubus call network.interface dump": fixture(t, "ubus-interface-dump.json"),
		"ubus call mwan3 status":           fixture(t, "ubus-mwan3-disabled.json"),
		"ubus call system board":           fixture(t, "ubus-system-board.json"),
		"ubus call system info":            fixture(t, "ubus-system-info.json"),
		"ubus call dhcp ipv6leases":        fixture(t, "ubus-ipv6leases.json"),
	}
	return &Env{Root: root, Run: cannedRun(answers)}, answers
}

func allParts() map[Part]bool {
	m := map[Part]bool{}
	for _, p := range AllParts {
		m[p] = true
	}
	return m
}

func TestObserverSection(t *testing.T) {
	env, answers := fixtureRouter(t)
	now := time.Unix(1790000000, 0)
	env.Now = func() time.Time { return now }
	o := NewObserver(env, allParts(), "")
	o.Now = env.Now
	o.Neighbors.dump = func() ([]netlink.Message, error) { return nil, errors.New("no netlink here") }
	if got := o.Parts(); !reflect.DeepEqual(got, AllParts) {
		t.Fatalf("parts = %v", got)
	}
	s := o.Section(nil, true)
	if !s.Full || s.DHCP == nil || s.Neighbors == nil || s.Interfaces == nil || s.UPnP == nil || s.MWAN3 == nil || s.Resolver == nil || s.System == nil {
		t.Fatalf("section = %+v", s)
	}
	// Leases and neighbours carry their network.
	for _, l := range s.DHCP.Leases4 {
		if l.IP == "192.168.1.21" && l.Network != "lan" {
			t.Errorf("lease network = %+v", l)
		}
	}
	if (*s.Neighbors)[0].Network != "lan" {
		t.Errorf("neighbor network = %+v", (*s.Neighbors)[0])
	}
	if *s.Resolver.Port53Process != "AdGuardHome" || *s.Resolver.DNSMasqPort != 54 {
		t.Errorf("resolver = %+v", s.Resolver)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"dhcp":`, `"neighbors":`, `"interfaces":`, `"upnp":`, `"mwan3":`, `"resolver":`, `"system":`, `"full":true`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("section lacks %s: %s", key, b)
		}
	}

	// Only some parts asked for: not full.
	if s := o.Section([]Part{PartSystem}, true); s.Full || s.System == nil || s.DHCP != nil {
		t.Errorf("one part = %+v", s)
	}

	// Uptimes are not part of a fingerprint.
	sys1, _ := o.Read(PartSystem, true)
	answers["ubus call system info"] = []byte(`{"uptime": 999999}`)
	sys2, _ := o.Read(PartSystem, true)
	if sys1.FP != sys2.FP || sys2.Value.(*System).UptimeSeconds != 999999 {
		t.Errorf("uptime changed the fingerprint or was not read: %v %v", sys1.FP != sys2.FP, sys2.Value)
	}
	if1, _ := o.Read(PartInterfaces, true)
	answers["ubus call network.interface dump"] = []byte(strings.Replace(string(answers["ubus call network.interface dump"]), `"uptime": 14437`, `"uptime": 14442`, 1))
	o.Interfaces.at = time.Time{}
	if2, _ := o.Read(PartInterfaces, true)
	if if1.FP != if2.FP {
		t.Error("interface uptime changed the fingerprint")
	}

	// The re-read interval: neighbours are read at most every 60 s.
	calls := 0
	o.Neighbors.dump = func() ([]netlink.Message, error) { calls++; return nil, errors.New("x") }
	o.Read(PartNeighbors, false)
	o.Read(PartNeighbors, false)
	if calls != 0 {
		t.Errorf("neighbours re-read within their interval: %d", calls)
	}
	now = now.Add(61 * time.Second)
	o.Read(PartNeighbors, false)
	if calls != 1 {
		t.Errorf("neighbours not re-read after their interval: %d", calls)
	}

	// A part that has nothing to report is left out and does not count
	// against "full": no mwan3.
	delete(answers, "ubus call mwan3 status")
	_ = os.Remove(filepath.Join(env.Root, "etc/init.d/mwan3"))
	_ = os.Remove(filepath.Join(env.Root, "etc/config/mwan3"))
	if s := o.Section(nil, true); s.MWAN3 != nil || !s.Full {
		t.Errorf("no mwan3: %+v full=%v", s.MWAN3, s.Full)
	}
}

func TestPacer(t *testing.T) {
	p := &Pacer{Refresh: 10 * time.Minute, RefreshOf: map[Part]time.Duration{PartDHCP: time.Hour}}
	t0 := time.Unix(1790000000, 0)
	// First of a session.
	if !p.Due(1, PartSystem, "a", t0) {
		t.Fatal("first push must carry the part")
	}
	p.Sent(1, PartSystem, "a", t0)
	if p.Due(1, PartSystem, "a", t0.Add(time.Minute)) {
		t.Error("unchanged part resent")
	}
	if !p.Due(1, PartSystem, "b", t0.Add(5*time.Second)) {
		t.Error("changed part held back")
	}
	if !p.Due(1, PartSystem, "a", t0.Add(10*time.Minute)) {
		t.Error("refresh not due")
	}
	if !p.Due(2, PartSystem, "a", t0.Add(time.Second)) {
		t.Error("a new session must resend")
	}
	// Per-part refresh.
	p.Sent(1, PartDHCP, "d", t0)
	if p.Due(1, PartDHCP, "d", t0.Add(30*time.Minute)) || !p.Due(1, PartDHCP, "d", t0.Add(time.Hour)) {
		t.Error("dhcp refresh must follow RefreshOf")
	}
	// Neighbours: a change waits for the 60 s gap.
	p.Sent(1, PartNeighbors, "n1", t0)
	if p.Due(1, PartNeighbors, "n2", t0.Add(30*time.Second)) {
		t.Error("changed neighbours sent within 60 s")
	}
	if !p.Due(1, PartNeighbors, "n2", t0.Add(60*time.Second)) {
		t.Error("changed neighbours held back after 60 s")
	}
}
