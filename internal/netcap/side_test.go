package netcap

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/capthndsme/perch-collector/internal/observe"
)

// The side rule on a multi-WAN gateway (placeholders only): three uplinks
// (wan, lan2 = WAN 2 despite its name, wan3 = WAN 3, down), their IPv6
// companions, two aliases on uplinks (wanaddr in a masquerading zone,
// wan3_mgmt in none: the modem's management subnet, the shape that used to
// count as a LAN), a masqueraded side network (sidenet), a WireGuard client
// in a masquerading zone (wgc), and one LAN.

func gatewaySyncFixture(t *testing.T) (*observe.Env, []byte) {
	t.Helper()
	dump, err := os.ReadFile("testdata/gateway-sync/netifd.json")
	if err != nil {
		t.Fatal(err)
	}
	network, err := os.ReadFile("testdata/gateway-sync/network.uci")
	if err != nil {
		t.Fatal(err)
	}
	firewall, err := os.ReadFile("testdata/gateway-sync/firewall.uci")
	if err != nil {
		t.Fatal(err)
	}
	env := &observe.Env{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		switch call {
		case "ubus call network.interface dump":
			return dump, nil
		case "uci -q show network":
			return network, nil
		case "uci -q show firewall":
			return firewall, nil
		}
		return nil, errors.New("unexpected " + call)
	}}
	return env, firewall
}

func gatewaySyncSys() fakeSys {
	return fakeSys{devs: map[string]string{
		"lan0": "02:00:00:00:10:01", "wan0": "02:00:00:00:00:01", "wan2": "02:00:00:00:00:02",
		"wan3": "02:00:00:00:00:03", "eth0": "02:00:00:00:00:04", "wgc": "00:00:00:00:00:00",
	}}
}

func sidesString(m map[string]Side) string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+string(v))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func TestSideRuleOnTheGatewaySyncTopology(t *testing.T) {
	env, _ := gatewaySyncFixture(t)
	d := (&Discoverer{Env: env}).Discover(true)
	if !d.OK || !d.Netifd || len(d.Interfaces) != 10 || len(d.Masq) == 0 {
		t.Fatalf("%+v", d)
	}
	if d.ConfDevice["wan3v6"] != "@wan3" || d.ConfDevice["wan3_mgmt"] != "wan3" || d.Gateway["lan"] {
		t.Fatalf("UCI network: %v %v", d.ConfDevice, d.Gateway)
	}
	want := map[string]Side{
		"wan": SideWAN, "wan6": SideWAN, "lan2": SideWAN, "wan3": SideWAN, "wan3v6": SideWAN,
		"wanaddr": SideWAN, "sidenet": SideWAN, "wan3_mgmt": SideWAN,
		"wgc": SideVPN, "lan": SideLAN,
	}
	got := Sides(d, Selection{})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sides\n got %s\nwant %s", sidesString(got), sidesString(want))
	}

	// What capture and the networks report see: the LAN alone.
	p := MakePlan(d, Selection{Networks: []string{Auto}}, gatewaySyncSys())
	if got := targetsOf(p); !reflect.DeepEqual(got, []string{"lan@lan0"}) {
		t.Fatalf("targets %v", got)
	}
	if len(p.LAN) != 1 || p.LAN[0].Network != "lan" {
		t.Fatalf("LAN %+v", p.LAN)
	}
	var prefixes []string
	for _, n := range p.LANPrefixes {
		prefixes = append(prefixes, n.String())
	}
	if !reflect.DeepEqual(prefixes, []string{"192.168.1.0/24"}) {
		t.Fatalf("local prefixes %v: the modem subnet (192.168.254.0/24) and the tunnel's are not local", prefixes)
	}
	if len(p.GatewayMACs) != 1 || p.GatewayMACs[0].String() != "02:00:00:00:10:01" {
		t.Fatalf("gateway MACs %v", p.GatewayMACs)
	}
	// Named explicitly: refused by side, never captured as a bare device.
	p = MakePlan(d, Selection{Networks: []string{"lan", "wan3_mgmt", "wan3", "wgc", "wan0"}}, gatewaySyncSys())
	if got := targetsOf(p); !reflect.DeepEqual(got, []string{"lan@lan0"}) {
		t.Fatalf("targets %v", got)
	}
	reasons := map[string]string{}
	for _, s := range p.Skipped {
		reasons[s.Network] = s.Reason
	}
	if reasons["wan3_mgmt"] != "a WAN is never captured" || reasons["wan3"] != "a WAN is never captured" ||
		reasons["wgc"] != "a VPN tunnel is never captured" || reasons["wan0"] != "a WAN is never captured" {
		t.Fatalf("%v", reasons)
	}
}

// wan3_mgmt is WAN because it sits on an uplink's device, not because of a
// firewall zone: with no zones and no UCI at all (netifd alone) the aliases
// wanaddr and wan3_mgmt are still WAN (rule 4); only sidenet, which nothing
// but its masquerading zone makes an uplink, turns LAN.
func TestSideRuleAliasWithoutZones(t *testing.T) {
	env, _ := gatewaySyncFixture(t)
	d := (&Discoverer{Env: env}).Discover(true)
	d.Masq, d.Gateway, d.ConfDevice = nil, nil, nil
	got := Sides(d, Selection{})
	want := map[string]Side{
		"wan": SideWAN, "wan6": SideWAN, "lan2": SideWAN, "wan3": SideWAN, "wan3v6": SideWAN,
		"wanaddr": SideWAN, "wan3_mgmt": SideWAN, "sidenet": SideLAN,
		"wgc": SideVPN, "lan": SideLAN,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sides\n got %s\nwant %s", sidesString(got), sidesString(want))
	}
	// The pre-rule classification (default route, masq zone, configured WAN)
	// called wan3_mgmt LAN: it is static, has no route and no zone.
	var gf observe.Interface
	for _, i := range d.Interfaces {
		if i.Network == "wan3_mgmt" {
			gf = i
		}
	}
	if gf.DefaultRoute || gf.Proto != "static" {
		t.Fatalf("fixture: %+v", gf)
	}
	if !IsWAN(gf, d, Selection{}) {
		t.Fatal("wan3_mgmt is an alias on WAN 3's device")
	}
}

func iface(network, proto, device string, up bool, v4 ...string) observe.Interface {
	return observe.Interface{Network: network, Proto: proto, Device: device, Up: up, IPv4: v4, IPv6: []string{}}
}

func TestSideRuleCases(t *testing.T) {
	cases := []struct {
		name string
		d    Discovery
		sel  Selection
		want map[string]Side
	}{
		{"pppoe: the alias sits on the UCI device under pppoe-wan",
			Discovery{Interfaces: []observe.Interface{
				iface("wan", "pppoe", "pppoe-wan", true, "203.0.113.10/32"),
				iface("modem", "static", "eth1", true, "192.168.254.2/24"),
				iface("lan", "static", "br-lan", true, "192.168.1.1/24")},
				ConfDevice: map[string]string{"wan": "eth1", "modem": "eth1", "lan": "br-lan"}},
			Selection{}, map[string]Side{"wan": SideWAN, "modem": SideWAN, "lan": SideLAN}},
		{"@wan alias, down, known only by its UCI device",
			Discovery{Interfaces: []observe.Interface{
				iface("wan", "dhcp", "eth1", true, "203.0.113.10/24"),
				iface("wan_alias", "static", "", false),
				iface("lan", "static", "br-lan", true, "192.168.1.1/24")},
				ConfDevice: map[string]string{"wan_alias": "@wan"}},
			Selection{}, map[string]Side{"wan": SideWAN, "wan_alias": SideWAN, "lan": SideLAN}},
		{"a static uplink known by its UCI gateway while down",
			Discovery{Interfaces: []observe.Interface{
				iface("wanb", "static", "eth2", false),
				iface("lan", "static", "br-lan", true, "192.168.1.1/24")},
				Gateway: map[string]bool{"wanb": true}},
			Selection{}, map[string]Side{"wanb": SideWAN, "lan": SideLAN}},
		{"configured WAN by device, and its alias",
			Discovery{Interfaces: []observe.Interface{
				iface("up", "static", "eth3", true, "198.51.100.2/24"),
				iface("up_mgmt", "none", "eth3", true),
				iface("lan", "static", "br-lan", true, "192.168.1.1/24")}},
			Selection{WAN: []string{"eth3"}}, map[string]Side{"up": SideWAN, "up_mgmt": SideWAN, "lan": SideLAN}},
		{"LAN aliases and tunnels in no zone",
			Discovery{Interfaces: []observe.Interface{
				iface("lan", "static", "br-lan", true, "192.168.1.1/24"),
				iface("lan_b", "static", "br-lan", true, "192.168.2.1/24"),
				iface("vpn", "openvpn", "tun0", true, "10.8.0.1/24"),
				iface("gre", "gre", "gre4-gre", true),
				iface("lo2", "static", "lo", true)}},
			Selection{}, map[string]Side{"lan": SideLAN, "lan_b": SideLAN, "vpn": SideVPN, "gre": SideVPN, "lo2": SideLoopback}},
		{"a DHCP client on its own device is an uplink, not an alias host for the LAN",
			Discovery{Interfaces: []observe.Interface{
				iface("wwan", "qmi", "wwan0", true, "203.0.113.50/30"),
				iface("lan", "static", "br-lan", true, "192.168.1.1/24")}},
			Selection{}, map[string]Side{"wwan": SideWAN, "lan": SideLAN}},
	}
	for _, c := range cases {
		if got := Sides(c.d, c.sel); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s\n got %s\nwant %s", c.name, sidesString(got), sidesString(c.want))
		}
	}
	// A tunnel is never captured by auto, even with an Ethernet-looking device.
	d := Discovery{OK: true, Netifd: true, Interfaces: []observe.Interface{
		iface("lan", "static", "br-lan", true, "192.168.1.1/24"),
		iface("wg0", "wireguard", "wg0", true, "192.168.9.1/24")}}
	sys := fakeSys{devs: map[string]string{"br-lan": "02:00:00:00:10:01", "wg0": "02:00:00:00:10:09"}}
	p := MakePlan(d, Selection{Networks: []string{Auto}}, sys)
	if got := targetsOf(p); !reflect.DeepEqual(got, []string{"lan@br-lan"}) || len(p.LAN) != 1 || len(p.LANPrefixes) != 1 {
		t.Fatalf("%v %+v %v", got, p.LAN, p.LANPrefixes)
	}
	if !IsWANProto("dhcpv6") || IsWANProto("static") || !IsTunnelProto("wireguard") || IsTunnelProto("dhcp") {
		t.Fatal("proto lists")
	}
}

func TestNetworkUCI(t *testing.T) {
	secs := observe.ParseUCIShow("network", []byte("network.a=interface\nnetwork.a.ifname='eth0 eth1'\nnetwork.a.gateway='192.168.1.254'\n"+
		"network.b=interface\nnetwork.b.device='@a'\nnetwork.@device[0]=device\nnetwork.@device[0].name='x'\n"+
		"network.lan=interface\nnetwork.lan.type='bridge'\nnetwork.lan.ifname='eth0.1 eth0.3'\n"))
	gw, dev := NetworkUCI(secs)
	if !reflect.DeepEqual(gw, map[string]bool{"a": true}) || !reflect.DeepEqual(dev, map[string]string{"a": "eth0", "b": "@a", "lan": "br-lan"}) {
		t.Fatalf("%v %v", gw, dev)
	}
}
