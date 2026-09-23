package aggregator

import (
	"net"
	"testing"
	"time"
)

// The router of these tests: lan 192.168.1.0/24 (router .1, MAC gwLAN) and
// iot 192.168.30.0/24 (router .1, MAC gwIoT), both captured; an IPv6 ULA
// on lan. c1 is on lan, i1 on iot.
const (
	gwLANMAC = "02:00:00:00:10:01"
	gwIoTMAC = "02:00:00:00:30:01"
	c1MAC    = "02:00:00:00:10:11"
	c2MAC    = "02:00:00:00:10:12"
	i1MAC    = "02:00:00:00:30:11"
)

func scopeAgg(t *testing.T, routed bool) *Aggregator {
	t.Helper()
	lan := mustSubnets(t, "192.168.1.0/24", "192.168.30.0/24", "fd00:1::/64")
	agg := New([]net.HardwareAddr{mustMAC(t, gwLANMAC), mustMAC(t, gwIoTMAC)}, lan, 50, 50)
	agg.SetRoutedLAN(routed, lan)
	return agg
}

type scopeWant struct {
	mac                        string
	inWAN, outWAN, inLAN, outL uint64
	wanPeers, lanPeers         []string
	network                    string
}

func checkScope(t *testing.T, agg *Aggregator, w scopeWant) {
	t.Helper()
	d := findDevice(agg.Snapshot(time.Time{}), w.mac)
	if d == nil {
		t.Fatalf("%s: no device row", w.mac)
	}
	if d.BytesInWAN != w.inWAN || d.BytesOutWAN != w.outWAN || d.BytesInLAN != w.inLAN || d.BytesOutLAN != w.outL {
		t.Errorf("%s: wan in/out %d/%d lan in/out %d/%d, want %d/%d %d/%d", w.mac,
			d.BytesInWAN, d.BytesOutWAN, d.BytesInLAN, d.BytesOutLAN, w.inWAN, w.outWAN, w.inLAN, w.outL)
	}
	if d.BytesIn != d.BytesInWAN+d.BytesInLAN || d.BytesOut != d.BytesOutWAN+d.BytesOutLAN {
		t.Errorf("%s: totals do not add up", w.mac)
	}
	peers := func(ps []PeerStats) []string {
		out := []string{}
		for _, p := range ps {
			out = append(out, p.IP)
		}
		return out
	}
	if got := peers(d.TopPeers); !sameStrings(got, w.wanPeers) {
		t.Errorf("%s: WAN peers %v, want %v", w.mac, got, w.wanPeers)
	}
	if got := peers(d.TopLANPeers); !sameStrings(got, w.lanPeers) {
		t.Errorf("%s: LAN peers %v, want %v", w.mac, got, w.lanPeers)
	}
	if d.Network != w.network {
		t.Errorf("%s: network %q, want %q", w.mac, d.Network, w.network)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// frame is one captured frame: on which capture network, MACs, IPs, size.
type frame struct {
	network           string
	srcMAC, dstMAC    string
	srcIP, dstIP      string
	size              int
	toServer          bool
	serverName, proto string
}

func (f frame) record(t *testing.T, agg *Aggregator) {
	agg.RecordPacket(mustMAC(t, f.srcMAC), mustMAC(t, f.dstMAC), net.ParseIP(f.srcIP), net.ParseIP(f.dstIP), f.size,
		FlowInfo{Protocol: f.proto, ServerName: f.serverName, ToServer: f.toServer, Network: f.network})
}

func TestScopeRuleTable(t *testing.T) {
	cases := []struct {
		name   string
		routed bool
		frames []frame
		want   []scopeWant
	}{
		{
			name:   "internet upload and download stay WAN",
			routed: true,
			frames: []frame{
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "203.0.113.5", size: 1000, toServer: true},
				{network: "lan", srcMAC: gwLANMAC, dstMAC: c1MAC, srcIP: "203.0.113.5", dstIP: "192.168.1.100", size: 3000},
			},
			want: []scopeWant{{mac: c1MAC, inWAN: 3000, outWAN: 1000, wanPeers: []string{"203.0.113.5"}, lanPeers: []string{}, network: "lan"}},
		},
		{
			name:   "router's own LAN address (DNS) is LAN",
			routed: true,
			frames: []frame{
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "192.168.1.1", size: 80, toServer: true, proto: "dns"},
				{network: "lan", srcMAC: gwLANMAC, dstMAC: c1MAC, srcIP: "192.168.1.1", dstIP: "192.168.1.100", size: 120, proto: "dns"},
			},
			want: []scopeWant{{mac: c1MAC, inLAN: 120, outL: 80, wanPeers: []string{}, lanPeers: []string{"192.168.1.1"}, network: "lan"}},
		},
		{
			name:   "router's own LAN address, legacy rule: WAN without a peer",
			routed: false,
			frames: []frame{
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "192.168.1.1", size: 80, toServer: true},
				{network: "lan", srcMAC: gwLANMAC, dstMAC: c1MAC, srcIP: "192.168.1.1", dstIP: "192.168.1.100", size: 120},
			},
			want: []scopeWant{{mac: c1MAC, inWAN: 120, outWAN: 80, wanPeers: []string{}, lanPeers: []string{}, network: "lan"}},
		},
		{
			name:   "inter-VLAN routed flow: once per side, LAN on both",
			routed: true,
			frames: []frame{
				// c1 → i1 seen on lan (to the router) and on iot (from it).
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "192.168.30.50", size: 1500, toServer: true},
				{network: "iot", srcMAC: gwIoTMAC, dstMAC: i1MAC, srcIP: "192.168.1.100", dstIP: "192.168.30.50", size: 1500, toServer: true},
				// the reply
				{network: "iot", srcMAC: i1MAC, dstMAC: gwIoTMAC, srcIP: "192.168.30.50", dstIP: "192.168.1.100", size: 60},
				{network: "lan", srcMAC: gwLANMAC, dstMAC: c1MAC, srcIP: "192.168.30.50", dstIP: "192.168.1.100", size: 60},
			},
			want: []scopeWant{
				{mac: c1MAC, inLAN: 60, outL: 1500, wanPeers: []string{}, lanPeers: []string{"192.168.30.50"}, network: "lan"},
				{mac: i1MAC, inLAN: 1500, outL: 60, wanPeers: []string{}, lanPeers: []string{"192.168.1.100"}, network: "iot"},
			},
		},
		{
			name:   "inter-VLAN routed flow, legacy rule: WAN on both sides",
			routed: false,
			frames: []frame{
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "192.168.30.50", size: 1500, toServer: true},
				{network: "iot", srcMAC: gwIoTMAC, dstMAC: i1MAC, srcIP: "192.168.1.100", dstIP: "192.168.30.50", size: 1500, toServer: true},
			},
			want: []scopeWant{
				{mac: c1MAC, outWAN: 1500, wanPeers: []string{}, lanPeers: []string{}, network: "lan"},
				{mac: i1MAC, inWAN: 1500, wanPeers: []string{}, lanPeers: []string{}, network: "iot"},
			},
		},
		{
			name:   "switched LAN-to-LAN is unchanged",
			routed: true,
			frames: []frame{
				{network: "lan", srcMAC: c2MAC, dstMAC: c1MAC, srcIP: "192.168.1.101", dstIP: "192.168.1.100", size: 700},
			},
			want: []scopeWant{
				{mac: c1MAC, inLAN: 700, wanPeers: []string{}, lanPeers: []string{"192.168.1.101"}, network: "lan"},
				{mac: c2MAC, outL: 700, wanPeers: []string{}, lanPeers: []string{"192.168.1.100"}, network: "lan"},
			},
		},
		{
			name:   "IPv6 link-local and ULA to the router are LAN",
			routed: true,
			frames: []frame{
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "fe80::10", dstIP: "fe80::1", size: 100},
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "fd00:1::10", dstIP: "fd00:1::1", size: 200},
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "fd00:1::10", dstIP: "2001:db8::1", size: 400, toServer: true},
			},
			want: []scopeWant{{mac: c1MAC, outL: 300, outWAN: 400, wanPeers: []string{"2001:db8::1"}, lanPeers: []string{"fd00:1::1", "fe80::1"}, network: "lan"}},
		},
		{
			name:   "a WAN-side private address is still WAN",
			routed: true,
			frames: []frame{
				{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "10.0.0.1", size: 90, toServer: true},
			},
			want: []scopeWant{{mac: c1MAC, outWAN: 90, wanPeers: []string{"10.0.0.1"}, lanPeers: []string{}, network: "lan"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agg := scopeAgg(t, tc.routed)
			for _, f := range tc.frames {
				f.record(t, agg)
			}
			for _, w := range tc.want {
				checkScope(t, agg, w)
			}
			if got := len(agg.Snapshot(time.Time{})); got != len(tc.want) {
				t.Errorf("%d device rows, want %d (the router must never get one)", got, len(tc.want))
			}
		})
	}
}

// The per-network capture counters count a routed frame once per network
// and an intra-network frame once each way; summed over the networks a
// routed flow is never counted twice in one direction.
func TestNetworkCountersNoDoubleCounting(t *testing.T) {
	agg := scopeAgg(t, true)
	for _, f := range []frame{
		{network: "lan", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "192.168.30.50", size: 1500, toServer: true},
		{network: "iot", srcMAC: gwIoTMAC, dstMAC: i1MAC, srcIP: "192.168.1.100", dstIP: "192.168.30.50", size: 1500, toServer: true},
		{network: "lan", srcMAC: c2MAC, dstMAC: c1MAC, srcIP: "192.168.1.101", dstIP: "192.168.1.100", size: 700},
		{network: "lan", srcMAC: gwLANMAC, dstMAC: c1MAC, srcIP: "203.0.113.5", dstIP: "192.168.1.100", size: 5000},
		{network: "iot", srcMAC: gwIoTMAC, dstMAC: gwLANMAC, srcIP: "192.168.30.1", dstIP: "192.168.1.1", size: 99},
	} {
		f.record(t, agg)
	}
	nets := agg.NetworkTraffic()
	lan, iot := nets["lan"], nets["iot"]
	if lan.BytesOutLAN != 1500+700 || lan.BytesInLAN != 700 || lan.BytesInWAN != 5000 || lan.BytesOutWAN != 0 {
		t.Errorf("lan counters %+v", lan)
	}
	if iot.BytesInLAN != 1500 || iot.BytesOutLAN != 0 || iot.BytesInWAN != 0 {
		t.Errorf("iot counters %+v", iot)
	}
	if lan.PacketsOutLAN != 2 || iot.PacketsInLAN != 1 {
		t.Errorf("packets lan %+v iot %+v", lan, iot)
	}
	counts := agg.NetworkDeviceCounts(time.Minute)
	if counts["lan"].Devices != 2 || counts["iot"].Devices != 1 || counts["lan"].ActiveDevices != 2 {
		t.Errorf("device counts %+v", counts)
	}
	agg.Reset()
	if len(agg.NetworkTraffic()) != 0 {
		t.Errorf("Reset kept the network counters")
	}
}

func TestDeviceNetworksSeenSet(t *testing.T) {
	agg := scopeAgg(t, true)
	for i := 0; i < MaxDeviceNetworks+3; i++ {
		name := string(rune('a' + i))
		frame{network: name, srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "203.0.113.5", size: 10}.record(t, agg)
	}
	frame{network: "b", srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "203.0.113.5", size: 10}.record(t, agg)
	d := findDevice(agg.Snapshot(time.Time{}), c1MAC)
	if d.Network != "b" {
		t.Errorf("network %q, want the last one, b", d.Network)
	}
	if len(d.Networks) != MaxDeviceNetworks || d.Networks[0] != "a" {
		t.Errorf("networks %v", d.Networks)
	}
	// No network known: the fields stay absent, as before.
	plain := New([]net.HardwareAddr{mustMAC(t, gwLANMAC)}, nil, 50, 50)
	frame{srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "203.0.113.5", size: 10}.record(t, plain)
	d = findDevice(plain.Snapshot(time.Time{}), c1MAC)
	if d.Network != "" || len(d.Networks) != 0 {
		t.Errorf("unexpected attribution %q %v", d.Network, d.Networks)
	}
	if len(plain.NetworkTraffic()) != 0 {
		t.Errorf("counters without a network")
	}
}

func TestSetGatewayMACsAtRuntime(t *testing.T) {
	agg := New(nil, nil, 50, 50)
	frame{srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "203.0.113.5", size: 10}.record(t, agg)
	if len(agg.Snapshot(time.Time{})) != 2 {
		t.Fatalf("without pivots both ends are devices")
	}
	agg.Reset()
	agg.SetGatewayMACs([]net.HardwareAddr{mustMAC(t, gwLANMAC)})
	frame{srcMAC: c1MAC, dstMAC: gwLANMAC, srcIP: "192.168.1.100", dstIP: "203.0.113.5", size: 10}.record(t, agg)
	if devs := agg.Snapshot(time.Time{}); len(devs) != 1 || devs[0].BytesOutWAN != 10 {
		t.Fatalf("after SetGatewayMACs: %+v", devs)
	}
	if got := agg.GatewayMACs(); len(got) != 1 || got[0] != gwLANMAC {
		t.Errorf("GatewayMACs %v", got)
	}
}
