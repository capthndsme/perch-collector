package aggregator

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/capthndsme/perch-collector/internal/netutil"
)

// --- helpers ---------------------------------------------------------------

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("parse MAC %q: %v", s, err)
	}
	return m
}

func mustSubnets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	out, err := netutil.ParseCIDRs(cidrs)
	if err != nil {
		t.Fatalf("parse CIDRs %v: %v", cidrs, err)
	}
	return out
}

func ipOf(s string) net.IP { return net.ParseIP(s) }

func findDevice(devs []DeviceStats, mac string) *DeviceStats {
	want, err := net.ParseMAC(mac)
	if err != nil {
		return nil
	}
	for i := range devs {
		if devs[i].MAC == want.String() {
			return &devs[i]
		}
	}
	return nil
}

// --- tests -----------------------------------------------------------------

func TestRecordOutboundLANtoWAN(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	// LAN device sends 1500 bytes to 8.8.8.8 via gateway.
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 1500, "")

	devs := agg.Snapshot(time.Time{})
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	d := devs[0]
	if d.MAC != local.String() {
		t.Errorf("MAC: got %s, want %s", d.MAC, local.String())
	}
	if d.BytesOut != 1500 || d.PacketsOut != 1 {
		t.Errorf("counters: out=%d/%d, want 1500/1", d.BytesOut, d.PacketsOut)
	}
	if d.BytesOutWAN != 1500 || d.PacketsOutWAN != 1 {
		t.Errorf("WAN-out counters: %d/%d, want 1500/1", d.BytesOutWAN, d.PacketsOutWAN)
	}
	if d.BytesOutLAN != 0 || d.PacketsOutLAN != 0 {
		t.Errorf("LAN-out counters must stay zero on a WAN flow, got %d/%d", d.BytesOutLAN, d.PacketsOutLAN)
	}
	if d.BytesIn != 0 || d.PacketsIn != 0 {
		t.Errorf("counters: in=%d/%d, want 0/0", d.BytesIn, d.PacketsIn)
	}
	if len(d.IPs) != 1 || d.IPs[0] != "192.168.1.100" {
		t.Errorf("IPs: got %v, want [192.168.1.100]", d.IPs)
	}
	if len(d.TopPeers) != 1 {
		t.Fatalf("peers: got %d, want 1", len(d.TopPeers))
	}
	p := d.TopPeers[0]
	if p.IP != "8.8.8.8" || p.BytesOut != 1500 || p.BytesIn != 0 {
		t.Errorf("peer: %+v, want {8.8.8.8 in=0 out=1500}", p)
	}
}

func TestRecordInboundWANtoLAN(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(gw, local, ipOf("8.8.8.8"), ipOf("192.168.1.100"), 800, "")

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("expected device, got nil")
	}
	if d.BytesIn != 800 || d.PacketsIn != 1 {
		t.Errorf("counters: in=%d/%d, want 800/1", d.BytesIn, d.PacketsIn)
	}
	if d.BytesOut != 0 {
		t.Errorf("BytesOut: got %d, want 0", d.BytesOut)
	}
	if len(d.TopPeers) != 1 {
		t.Fatalf("peers: got %d, want 1", len(d.TopPeers))
	}
	p := d.TopPeers[0]
	if p.IP != "8.8.8.8" || p.BytesIn != 800 || p.BytesOut != 0 {
		t.Errorf("peer: %+v, want {8.8.8.8 in=800 out=0}", p)
	}
}

func TestRecordLANtoLANNoWANPeers(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	a := mustMAC(t, "02:aa:aa:aa:aa:aa")
	b := mustMAC(t, "02:bb:bb:bb:bb:bb")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(a, b, ipOf("192.168.1.10"), ipOf("192.168.1.20"), 500, "")

	devs := agg.Snapshot(time.Time{})
	if len(devs) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devs))
	}
	for _, d := range devs {
		if len(d.TopPeers) != 0 {
			t.Errorf("LAN-to-LAN should yield no WAN peers, got %v for %s", d.TopPeers, d.MAC)
		}
	}

	da := findDevice(devs, a.String())
	db := findDevice(devs, b.String())
	if da == nil || db == nil {
		t.Fatalf("missing devices: a=%v b=%v", da, db)
	}
	if da.BytesOut != 500 || db.BytesIn != 500 {
		t.Errorf("counters: a.out=%d (want 500) b.in=%d (want 500)", da.BytesOut, db.BytesIn)
	}
}

func TestWANLANSplitInvariant(t *testing.T) {
	// The WAN+LAN split fields must always sum to the totals, even when a
	// device is busy on both scopes simultaneously (Plex over LAN while the
	// browser is downloading from the internet, etc.).
	gw := mustMAC(t, "02:00:00:00:00:01")
	host := mustMAC(t, "02:aa:bb:cc:dd:ee")
	nas := mustMAC(t, "02:bb:bb:bb:bb:bb")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	// 5000 B of LAN ingress (NAS -> host) and 1200 B of WAN ingress on host.
	agg.Record(nas, host, ipOf("192.168.1.20"), ipOf("192.168.1.100"), 5000, "")
	agg.Record(gw, host, ipOf("8.8.8.8"), ipOf("192.168.1.100"), 1200, "")
	// 800 B of WAN egress and 300 B of LAN egress on host.
	agg.Record(host, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 800, "")
	agg.Record(host, nas, ipOf("192.168.1.100"), ipOf("192.168.1.20"), 300, "")

	d := agg.GetDevice(host.String())
	if d == nil {
		t.Fatal("device missing")
	}
	if d.BytesIn != d.BytesInWAN+d.BytesInLAN {
		t.Errorf("BytesIn invariant: %d != %d (wan) + %d (lan)", d.BytesIn, d.BytesInWAN, d.BytesInLAN)
	}
	if d.BytesOut != d.BytesOutWAN+d.BytesOutLAN {
		t.Errorf("BytesOut invariant: %d != %d (wan) + %d (lan)", d.BytesOut, d.BytesOutWAN, d.BytesOutLAN)
	}
	if d.BytesInWAN != 1200 || d.BytesInLAN != 5000 {
		t.Errorf("WAN/LAN-in split: got %d/%d, want 1200/5000", d.BytesInWAN, d.BytesInLAN)
	}
	if d.BytesOutWAN != 800 || d.BytesOutLAN != 300 {
		t.Errorf("WAN/LAN-out split: got %d/%d, want 800/300", d.BytesOutWAN, d.BytesOutLAN)
	}
	if d.PacketsIn != d.PacketsInWAN+d.PacketsInLAN {
		t.Errorf("PacketsIn invariant: %d != %d + %d", d.PacketsIn, d.PacketsInWAN, d.PacketsInLAN)
	}
	if d.PacketsOut != d.PacketsOutWAN+d.PacketsOutLAN {
		t.Errorf("PacketsOut invariant: %d != %d + %d", d.PacketsOut, d.PacketsOutWAN, d.PacketsOutLAN)
	}
}

func TestRecordLANPeersBothSides(t *testing.T) {
	// LAN-to-LAN frames must record each side as the other's LAN peer with
	// directional bytes: the sender sees the receiver as a peer it sent
	// bytes_out to; the receiver sees the sender as a peer it got bytes_in
	// from. WAN peers stay empty.
	gw := mustMAC(t, "02:00:00:00:00:01")
	a := mustMAC(t, "02:aa:aa:aa:aa:aa")
	b := mustMAC(t, "02:bb:bb:bb:bb:bb")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	// SMB-style read: NAS (a) sends file bytes to host (b), 1500 bytes per
	// frame, 10 frames.
	for i := 0; i < 10; i++ {
		agg.Record(a, b, ipOf("192.168.1.10"), ipOf("192.168.1.20"), 1500, "")
	}

	devs := agg.Snapshot(time.Time{})
	da := findDevice(devs, a.String())
	db := findDevice(devs, b.String())
	if da == nil || db == nil {
		t.Fatalf("missing devices: a=%v b=%v", da, db)
	}

	if len(da.TopPeers) != 0 || len(db.TopPeers) != 0 {
		t.Errorf("WAN TopPeers must stay empty for LAN-to-LAN; a=%v b=%v", da.TopPeers, db.TopPeers)
	}

	if len(da.TopLANPeers) != 1 {
		t.Fatalf("a.TopLANPeers: got %d, want 1: %+v", len(da.TopLANPeers), da.TopLANPeers)
	}
	pa := da.TopLANPeers[0]
	if pa.IP != "192.168.1.20" || pa.BytesOut != 15000 || pa.BytesIn != 0 {
		t.Errorf("a's LAN peer: got %+v, want {ip=192.168.1.20 in=0 out=15000}", pa)
	}

	if len(db.TopLANPeers) != 1 {
		t.Fatalf("b.TopLANPeers: got %d, want 1: %+v", len(db.TopLANPeers), db.TopLANPeers)
	}
	pb := db.TopLANPeers[0]
	if pb.IP != "192.168.1.10" || pb.BytesIn != 15000 || pb.BytesOut != 0 {
		t.Errorf("b's LAN peer: got %+v, want {ip=192.168.1.10 in=15000 out=0}", pb)
	}
}

func TestLANPeerEvictionIndependentOfWAN(t *testing.T) {
	// Heavy WAN traffic must not push out LAN peers (and vice versa). We
	// configure a tiny LAN cap of 2 and verify that flooding the WAN heap
	// past its own cap of 3 leaves the LAN entries untouched.
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	other := mustMAC(t, "02:cc:cc:cc:cc:cc")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 3, 2)

	// 1) Establish two LAN peers for `local`: one inbound from `other`'s IP,
	//    one outbound from another LAN address `other` later assumes.
	agg.Record(other, local, ipOf("192.168.1.50"), ipOf("192.168.1.100"), 700, "") // local <- 192.168.1.50 (LAN)
	agg.Record(local, other, ipOf("192.168.1.100"), ipOf("192.168.1.51"), 200, "") // local -> 192.168.1.51 (LAN)

	// 2) Flood the WAN peer heap with 10 distinct outbound peers, each
	//    heavier than the LAN ones. If the heaps were shared, the LAN
	//    entries would be evicted.
	for i := 0; i < 10; i++ {
		dst := net.IPv4(8, 8, 0, byte(i+1))
		agg.Record(local, gw, ipOf("192.168.1.100"), dst, 100000, "")
	}

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("device missing")
	}

	if len(d.TopPeers) != 3 {
		t.Errorf("WAN heap should be capped at 3, got %d", len(d.TopPeers))
	}
	if len(d.TopLANPeers) != 2 {
		t.Errorf("LAN heap should still hold both LAN peers, got %d: %+v", len(d.TopLANPeers), d.TopLANPeers)
	}

	have := make(map[string]PeerStats, 2)
	for _, p := range d.TopLANPeers {
		have[p.IP] = p
	}
	if p, ok := have["192.168.1.50"]; !ok || p.BytesIn != 700 {
		t.Errorf("192.168.1.50 LAN peer missing or wrong bytes_in: %+v", have)
	}
	if p, ok := have["192.168.1.51"]; !ok || p.BytesOut != 200 {
		t.Errorf("192.168.1.51 LAN peer missing or wrong bytes_out: %+v", have)
	}
}

func TestLANPeersDisabledByNegativeCap(t *testing.T) {
	// A negative LAN cap turns LAN peer tracking off without affecting
	// WAN peer tracking or device counters.
	gw := mustMAC(t, "02:00:00:00:00:01")
	a := mustMAC(t, "02:aa:aa:aa:aa:aa")
	b := mustMAC(t, "02:bb:bb:bb:bb:bb")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, -1)

	agg.Record(a, b, ipOf("192.168.1.10"), ipOf("192.168.1.20"), 500, "")
	agg.Record(a, gw, ipOf("192.168.1.10"), ipOf("8.8.8.8"), 1000, "")

	da := agg.GetDevice(a.String())
	if da == nil {
		t.Fatal("device a missing")
	}
	if len(da.TopLANPeers) != 0 {
		t.Errorf("LAN peer tracking should be disabled, got %+v", da.TopLANPeers)
	}
	if len(da.TopPeers) != 1 || da.TopPeers[0].IP != "8.8.8.8" {
		t.Errorf("WAN peers must still be recorded, got %+v", da.TopPeers)
	}
	if da.BytesOut != 1500 {
		t.Errorf("BytesOut should still sum across LAN+WAN, got %d", da.BytesOut)
	}
}

func TestRecordDropsBroadcastAndMulticast(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	bcast := mustMAC(t, "ff:ff:ff:ff:ff:ff")
	v4mcast := mustMAC(t, "01:00:5e:00:00:fb") // mDNS
	v6mcast := mustMAC(t, "33:33:00:00:00:01") // IPv6 all-nodes
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(local, bcast, ipOf("192.168.1.100"), ipOf("192.168.1.255"), 200, "")
	agg.Record(local, v4mcast, ipOf("192.168.1.100"), ipOf("224.0.0.251"), 200, "")
	agg.Record(local, v6mcast, ipOf("fe80::dead"), ipOf("ff02::1"), 200, "")
	// Source multicast (illegal but defensive):
	agg.Record(v4mcast, local, ipOf("224.0.0.251"), ipOf("192.168.1.100"), 200, "")

	devs := agg.Snapshot(time.Time{})
	if len(devs) != 0 {
		t.Errorf("expected 0 devices (all dropped), got %d", len(devs))
	}
}

func TestRecordDropsGatewayToGateway(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	agg := New([]net.HardwareAddr{gw}, nil, 50, 50)

	agg.Record(gw, gw, ipOf("1.1.1.1"), ipOf("2.2.2.2"), 500, "")

	if devs := agg.Snapshot(time.Time{}); len(devs) != 0 {
		t.Errorf("expected 0 devices, got %d", len(devs))
	}
}

func TestDualStackConsolidation(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24", "fe80::/64")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	// Same physical device, two address families, outbound:
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 1000, "")
	agg.Record(local, gw, ipOf("fe80::dead:beef"), ipOf("2001:4860:4860::8888"), 500, "")
	// And one inbound on each family:
	agg.Record(gw, local, ipOf("8.8.8.8"), ipOf("192.168.1.100"), 200, "")
	agg.Record(gw, local, ipOf("2001:4860:4860::8888"), ipOf("fe80::dead:beef"), 100, "")

	devs := agg.Snapshot(time.Time{})
	if len(devs) != 1 {
		t.Fatalf("expected exactly 1 device (dual-stack consolidation), got %d", len(devs))
	}
	d := devs[0]
	if d.BytesOut != 1500 {
		t.Errorf("BytesOut: got %d, want 1500", d.BytesOut)
	}
	if d.BytesIn != 300 {
		t.Errorf("BytesIn: got %d, want 300", d.BytesIn)
	}
	if d.PacketsOut != 2 || d.PacketsIn != 2 {
		t.Errorf("Packets: out=%d in=%d, want 2/2", d.PacketsOut, d.PacketsIn)
	}
	if len(d.IPs) != 2 {
		t.Fatalf("IPs: got %v, want both v4 and v6", d.IPs)
	}
	// IPs are sorted by string; just verify both families are present.
	haveV4, haveV6 := false, false
	for _, ip := range d.IPs {
		if ip == "192.168.1.100" {
			haveV4 = true
		}
		if ip == "fe80::dead:beef" {
			haveV6 = true
		}
	}
	if !haveV4 || !haveV6 {
		t.Errorf("expected both v4 and v6 IPs, got %v", d.IPs)
	}
	// Two distinct WAN peers expected.
	if len(d.TopPeers) != 2 {
		t.Errorf("peers: got %d, want 2", len(d.TopPeers))
	}
}

func TestTopPeersEviction(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	const topN = 5
	agg := New([]net.HardwareAddr{gw}, subnets, topN, 50)

	// Send to topN+10 unique remote IPs with increasing byte counts so the
	// smallest are evicted in order.
	const total = topN + 10
	for i := 0; i < total; i++ {
		dst := net.IPv4(8, 8, 0, byte(i+1))
		agg.Record(local, gw, ipOf("192.168.1.100"), dst, (i+1)*100, "")
	}

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("device missing")
	}
	if len(d.TopPeers) != topN {
		t.Fatalf("expected exactly %d peers, got %d", topN, len(d.TopPeers))
	}
	// The kept peers must be the heaviest: i = total-1 .. total-topN.
	// TopPeers is sorted descending by total bytes.
	for rank, p := range d.TopPeers {
		// rank 0 == largest, which was i = total-1, bytes = total*100.
		wantBytes := uint64((total - rank) * 100)
		if p.BytesOut != wantBytes {
			t.Errorf("peer[%d]=%s out=%d, want %d", rank, p.IP, p.BytesOut, wantBytes)
		}
	}

	// Device-level counters must still sum every packet (the heap only bounds
	// peer detail, not the device totals).
	wantTotal := uint64(0)
	for i := 0; i < total; i++ {
		wantTotal += uint64((i + 1) * 100)
	}
	if d.BytesOut != wantTotal {
		t.Errorf("device BytesOut=%d, want %d", d.BytesOut, wantTotal)
	}
}

func TestTopPeersExistingPeerUpdateMovesInHeap(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	const topN = 3
	agg := New([]net.HardwareAddr{gw}, subnets, topN, 50)

	// Fill heap.
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.0.1"), 100, "")
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.0.2"), 200, "")
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.0.3"), 300, "")
	// Add more to the smallest (8.8.0.1) so it becomes the largest.
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.0.1"), 1000, "")
	// Try inserting a peer (250) that should fail because all current peers now
	// score >= 250 (the old min was 100 + 1000 = 1100; remaining mins are 200 and 300).
	// Actually the heap of three peers has scores {1100, 200, 300} -> min is 200.
	// New peer 250 > 200 should evict the 200.
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.0.99"), 250, "")

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("device missing")
	}
	if len(d.TopPeers) != topN {
		t.Fatalf("expected %d peers, got %d", topN, len(d.TopPeers))
	}
	have := make(map[string]uint64, topN)
	for _, p := range d.TopPeers {
		have[p.IP] = p.BytesOut
	}
	if have["8.8.0.1"] != 1100 {
		t.Errorf("8.8.0.1 should still be present with 1100 bytes, got %d", have["8.8.0.1"])
	}
	if _, ok := have["8.8.0.2"]; ok {
		t.Errorf("8.8.0.2 (smallest at 200) should have been evicted: %v", have)
	}
	if have["8.8.0.99"] != 250 {
		t.Errorf("new peer 8.8.0.99 should be present with 250 bytes: %v", have)
	}
}

func TestPeerNotAddedForLocalDestination(t *testing.T) {
	// Defensive: if a packet routes through the gateway but its "remote" IP is
	// inside our local subnets, don't pollute peers.
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("192.168.1.250"), 400, "")

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("device missing")
	}
	if len(d.TopPeers) != 0 {
		t.Errorf("expected no peers for local destination, got %v", d.TopPeers)
	}
	if d.BytesOut != 400 {
		t.Errorf("BytesOut should still be counted: got %d, want 400", d.BytesOut)
	}
}

func TestSnapshotSinceFilter(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 100, "")

	future := time.Now().Add(1 * time.Hour)
	if devs := agg.Snapshot(future); len(devs) != 0 {
		t.Errorf("expected 0 devices with future since, got %d", len(devs))
	}
	if devs := agg.Snapshot(time.Time{}); len(devs) != 1 {
		t.Errorf("expected 1 device with zero since, got %d", len(devs))
	}
}

func TestGetDeviceFormatTolerance(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "aa:bb:cc:dd:ee:ff")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 100, "")

	for _, form := range []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"aabb.ccdd.eeff",
	} {
		if d := agg.GetDevice(form); d == nil {
			t.Errorf("GetDevice(%q) returned nil", form)
		}
	}
	if d := agg.GetDevice("not-a-mac"); d != nil {
		t.Error("GetDevice(invalid) should return nil")
	}
}

func TestReset(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 1000, "")
	agg.Reset()

	if devs := agg.Snapshot(time.Time{}); len(devs) != 0 {
		t.Errorf("expected 0 devices after Reset, got %d", len(devs))
	}
}

func TestGetSummary(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	a := mustMAC(t, "02:aa:aa:aa:aa:aa")
	b := mustMAC(t, "02:bb:bb:bb:bb:bb")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(a, gw, ipOf("192.168.1.10"), ipOf("8.8.8.8"), 1000, "")
	agg.Record(b, gw, ipOf("192.168.1.20"), ipOf("8.8.8.8"), 500, "")

	s := agg.GetSummary()
	if s.TotalDevices != 2 {
		t.Errorf("TotalDevices: got %d, want 2", s.TotalDevices)
	}
	if s.TotalBytes != 1500 {
		t.Errorf("TotalBytes: got %d, want 1500", s.TotalBytes)
	}
	if s.TotalPackets != 2 {
		t.Errorf("TotalPackets: got %d, want 2", s.TotalPackets)
	}
}

func TestConcurrentAccess(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 1, "https")
			}
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				agg.Snapshot(time.Time{})
				agg.GetSummary()
				agg.GetDevice(local.String())
			}
		}()
	}
	wg.Wait()

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("expected device after concurrent writes")
	}
	if d.BytesOut != 50_000 {
		t.Errorf("BytesOut: got %d, want 50000", d.BytesOut)
	}
	if d.PacketsOut != 50_000 {
		t.Errorf("PacketsOut: got %d, want 50000", d.PacketsOut)
	}
}

func TestNoGatewayConfiguredTreatsAllAsLAN(t *testing.T) {
	// When gateway MAC is unknown, every packet falls into the LAN-to-LAN
	// branch: both sides counted, no WAN peer entries, but LAN peers
	// populated on each side (the only signal of who talked to whom).
	a := mustMAC(t, "02:aa:aa:aa:aa:aa")
	b := mustMAC(t, "02:bb:bb:bb:bb:bb")
	agg := New(nil, nil, 50, 50)

	agg.Record(a, b, ipOf("10.0.0.1"), ipOf("10.0.0.2"), 700, "")
	devs := agg.Snapshot(time.Time{})
	if len(devs) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devs))
	}
	for _, d := range devs {
		if len(d.TopPeers) != 0 {
			t.Errorf("no-gateway mode should produce no WAN peers: %v", d.TopPeers)
		}
		if len(d.TopLANPeers) != 1 {
			t.Errorf("no-gateway mode should still record LAN peers, got %d: %+v", len(d.TopLANPeers), d.TopLANPeers)
		}
	}
}

func TestMultiGatewayPivot(t *testing.T) {
	// Two upstream gateways (e.g. primary OpenWrt + secondary WAN container).
	// A frame pivoted by either gateway must classify as WAN for the device
	// on the other side.
	gw1 := mustMAC(t, "02:00:00:00:00:01")
	gw2 := mustMAC(t, "02:00:00:00:00:02")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw1, gw2}, subnets, 50, 50)

	// Outbound via gw1.
	agg.Record(local, gw1, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 1000, "")
	// Outbound via gw2 (e.g. policy-routed second WAN).
	agg.Record(local, gw2, ipOf("192.168.1.100"), ipOf("1.1.1.1"), 500, "")
	// Inbound via gw2.
	agg.Record(gw2, local, ipOf("1.1.1.1"), ipOf("192.168.1.100"), 200, "")

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("device missing")
	}
	if d.BytesOut != 1500 {
		t.Errorf("BytesOut: got %d, want 1500 (1000 via gw1 + 500 via gw2)", d.BytesOut)
	}
	if d.BytesIn != 200 {
		t.Errorf("BytesIn: got %d, want 200 (via gw2)", d.BytesIn)
	}
	if len(d.TopPeers) != 2 {
		t.Fatalf("expected 2 distinct WAN peers, got %d: %+v", len(d.TopPeers), d.TopPeers)
	}
	have := make(map[string]bool, 2)
	for _, p := range d.TopPeers {
		have[p.IP] = true
	}
	if !have["8.8.8.8"] || !have["1.1.1.1"] {
		t.Errorf("expected both 8.8.8.8 and 1.1.1.1 in peers, got %v", have)
	}

	// Neither gateway should appear as its own device.
	if dev := agg.GetDevice(gw1.String()); dev != nil {
		t.Errorf("gw1 must not appear as a device, got %+v", dev)
	}
	if dev := agg.GetDevice(gw2.String()); dev != nil {
		t.Errorf("gw2 must not appear as a device, got %+v", dev)
	}
}

func TestInterGatewayRelayFramesDropped(t *testing.T) {
	// A frame whose src AND dst are both registered gateway MACs (typical of
	// inter-router relay traffic, e.g. OpenWrt -> the second WAN router on the way to wan0)
	// must be dropped so neither side is double-counted.
	gw1 := mustMAC(t, "02:00:00:00:00:01")
	gw2 := mustMAC(t, "02:00:00:00:00:02")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw1, gw2}, subnets, 50, 50)

	// Inter-gateway frame: should be dropped entirely.
	agg.Record(gw1, gw2, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 5000, "")
	// Real outbound from the phone via gw1: should be counted normally.
	agg.Record(local, gw1, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 1000, "")

	devs := agg.Snapshot(time.Time{})
	if len(devs) != 1 {
		t.Fatalf("expected exactly 1 device (only the phone, not either gateway), got %d", len(devs))
	}
	d := devs[0]
	if d.MAC != local.String() {
		t.Errorf("expected only the phone device, got %s", d.MAC)
	}
	if d.BytesOut != 1000 {
		t.Errorf("BytesOut: got %d, want 1000 (inter-gateway 5000-byte frame should be dropped, not counted)", d.BytesOut)
	}
}

// --- Protocol classification tests -----------------------------------------

func TestProtocolCountersWAN(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	// Outbound HTTPS traffic.
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 1500, "https")
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 500, "https")
	// Inbound HTTPS reply.
	agg.Record(gw, local, ipOf("8.8.8.8"), ipOf("192.168.1.100"), 3000, "https")
	// Outbound DNS.
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 64, "dns")

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("device missing")
	}

	if len(d.Protocols) != 2 {
		t.Fatalf("expected 2 protocols, got %d: %+v", len(d.Protocols), d.Protocols)
	}

	// Protocols are sorted by total bytes descending.
	// HTTPS: in=3000, out=2000 → total=5000
	// DNS:   in=0, out=64     → total=64
	httpsProto := d.Protocols[0]
	dnsProto := d.Protocols[1]

	if httpsProto.Protocol != "https" {
		t.Errorf("expected first protocol to be 'https', got %q", httpsProto.Protocol)
	}
	if httpsProto.BytesIn != 3000 {
		t.Errorf("https BytesIn: got %d, want 3000", httpsProto.BytesIn)
	}
	if httpsProto.BytesOut != 2000 {
		t.Errorf("https BytesOut: got %d, want 2000", httpsProto.BytesOut)
	}
	if httpsProto.PacketsIn != 1 {
		t.Errorf("https PacketsIn: got %d, want 1", httpsProto.PacketsIn)
	}
	if httpsProto.PacketsOut != 2 {
		t.Errorf("https PacketsOut: got %d, want 2", httpsProto.PacketsOut)
	}

	if dnsProto.Protocol != "dns" {
		t.Errorf("expected second protocol to be 'dns', got %q", dnsProto.Protocol)
	}
	if dnsProto.BytesOut != 64 {
		t.Errorf("dns BytesOut: got %d, want 64", dnsProto.BytesOut)
	}
}

func TestProtocolCountersLANToLAN(t *testing.T) {
	// LAN-to-LAN: both devices should get protocol counters.
	gw := mustMAC(t, "02:00:00:00:00:01")
	a := mustMAC(t, "02:aa:aa:aa:aa:aa")
	b := mustMAC(t, "02:bb:bb:bb:bb:bb")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(a, b, ipOf("192.168.1.10"), ipOf("192.168.1.20"), 5000, "smb")

	da := agg.GetDevice(a.String())
	db := agg.GetDevice(b.String())
	if da == nil || db == nil {
		t.Fatalf("missing devices: a=%v b=%v", da, db)
	}

	// Device a (sender): protocol should show bytes_out=5000
	if len(da.Protocols) != 1 || da.Protocols[0].Protocol != "smb" {
		t.Fatalf("a.Protocols: got %+v, want [{smb ...}]", da.Protocols)
	}
	if da.Protocols[0].BytesOut != 5000 || da.Protocols[0].BytesIn != 0 {
		t.Errorf("a.smb: in=%d out=%d, want in=0 out=5000",
			da.Protocols[0].BytesIn, da.Protocols[0].BytesOut)
	}

	// Device b (receiver): protocol should show bytes_in=5000
	if len(db.Protocols) != 1 || db.Protocols[0].Protocol != "smb" {
		t.Fatalf("b.Protocols: got %+v, want [{smb ...}]", db.Protocols)
	}
	if db.Protocols[0].BytesIn != 5000 || db.Protocols[0].BytesOut != 0 {
		t.Errorf("b.smb: in=%d out=%d, want in=5000 out=0",
			db.Protocols[0].BytesIn, db.Protocols[0].BytesOut)
	}
}

func TestProtocolStatsSnapshotSorted(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	// Send traffic with varying sizes: dns < ntp < https
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 100, "dns")
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 200, "ntp")
	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 5000, "https")

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("device missing")
	}

	if len(d.Protocols) != 3 {
		t.Fatalf("expected 3 protocols, got %d", len(d.Protocols))
	}

	// Sorted descending by total bytes: https(5000) > ntp(200) > dns(100)
	if d.Protocols[0].Protocol != "https" {
		t.Errorf("expected first protocol to be 'https', got %q", d.Protocols[0].Protocol)
	}
	if d.Protocols[1].Protocol != "ntp" {
		t.Errorf("expected second protocol to be 'ntp', got %q", d.Protocols[1].Protocol)
	}
	if d.Protocols[2].Protocol != "dns" {
		t.Errorf("expected third protocol to be 'dns', got %q", d.Protocols[2].Protocol)
	}
}

func TestEmptyProtocolIsIgnored(t *testing.T) {
	// Record with empty protocol should not create a protocol entry.
	gw := mustMAC(t, "02:00:00:00:00:01")
	local := mustMAC(t, "02:aa:bb:cc:dd:ee")
	subnets := mustSubnets(t, "192.168.1.0/24")
	agg := New([]net.HardwareAddr{gw}, subnets, 50, 50)

	agg.Record(local, gw, ipOf("192.168.1.100"), ipOf("8.8.8.8"), 1000, "")

	d := agg.GetDevice(local.String())
	if d == nil {
		t.Fatal("device missing")
	}
	if len(d.Protocols) != 0 {
		t.Errorf("empty protocol should not produce entries, got %+v", d.Protocols)
	}
	// Device-level counters should still be incremented.
	if d.BytesOut != 1000 {
		t.Errorf("BytesOut: got %d, want 1000", d.BytesOut)
	}
}
