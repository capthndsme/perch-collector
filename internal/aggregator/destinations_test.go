package aggregator

import (
	"net"
	"testing"
	"time"
)

// Destination accounting: bytes land on the *client-side* device only, keyed
// by the name it asked for, split into in (downloaded) and out (uploaded).

func findDestination(devs []DeviceStats, mac, name, proto string) *DestinationStats {
	d := findDevice(devs, mac)
	if d == nil {
		return nil
	}
	for i := range d.Destinations {
		if d.Destinations[i].ServerName == name && d.Destinations[i].Protocol == proto {
			return &d.Destinations[i]
		}
	}
	return nil
}

func TestDestinationAccountingWANClient(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	laptop := mustMAC(t, "aa:aa:aa:aa:aa:01")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)

	yt := FlowInfo{Protocol: "youtube", ServerName: "youtube.com", Category: "streaming", ToServer: true}
	ytBack := yt
	ytBack.ToServer = false

	// Laptop → YouTube (request bytes): uploaded.
	a.RecordPacket(laptop, gw, ipOf("192.168.2.50"), ipOf("142.250.1.1"), 900, yt)
	// YouTube → laptop (video bytes): downloaded.
	a.RecordPacket(gw, laptop, ipOf("142.250.1.1"), ipOf("192.168.2.50"), 90000, ytBack)
	a.RecordPacket(gw, laptop, ipOf("142.250.1.1"), ipOf("192.168.2.50"), 60000, ytBack)

	devs := a.Snapshot(time.Time{})
	d := findDestination(devs, "aa:aa:aa:aa:aa:01", "youtube.com", "youtube")
	if d == nil {
		t.Fatalf("expected a youtube.com destination row on the client")
	}
	if d.BytesIn != 150000 || d.BytesOut != 900 {
		t.Fatalf("in/out = %d/%d, want 150000/900", d.BytesIn, d.BytesOut)
	}
	if d.PacketsIn != 2 || d.PacketsOut != 1 {
		t.Fatalf("packets in/out = %d/%d, want 2/1", d.PacketsIn, d.PacketsOut)
	}
	if d.Category != "streaming" {
		t.Fatalf("category = %q, want streaming", d.Category)
	}
	// The client is not serving anything: no service row.
	if dev := findDevice(devs, "aa:aa:aa:aa:aa:01"); len(dev.Services) != 0 {
		t.Fatalf("client-side flow must not create a service row, got %d", len(dev.Services))
	}
}

func TestDestinationAccountingServerSideNeverRecordsOne(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	srv := mustMAC(t, "aa:aa:aa:aa:aa:02")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)

	// WAN client → our server, then our server replies: a service row, no
	// destination row (the *client* is the remote end, not a local device).
	a.RecordFlow(gw, srv, ipOf("203.0.113.9"), ipOf("192.168.2.100"), 300, "https", "photos.example", true)
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 5000, "https", "photos.example", false)

	devs := a.Snapshot(time.Time{})
	dev := findDevice(devs, "aa:aa:aa:aa:aa:02")
	if dev == nil {
		t.Fatalf("server device missing")
	}
	if len(dev.Destinations) != 0 {
		t.Fatalf("server-side flow must not create a destination row, got %+v", dev.Destinations)
	}
	if len(dev.Services) != 1 {
		t.Fatalf("expected the service row to still be recorded, got %d", len(dev.Services))
	}
}

func TestDestinationUnnamedFlowsPoolPerProtocol(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	tv := mustMAC(t, "aa:aa:aa:aa:aa:03")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)

	// nDPI recognised Netflix from IP ranges but never saw an SNI: the bytes
	// still count, under server_name "" for the "netflix" label.
	nf := FlowInfo{Protocol: "netflix", Category: "streaming", ToServer: false}
	a.RecordPacket(gw, tv, ipOf("198.51.100.7"), ipOf("192.168.2.60"), 40000, nf)
	a.RecordPacket(gw, tv, ipOf("198.51.100.8"), ipOf("192.168.2.60"), 20000, nf)
	// A named flow of the same protocol is a separate row.
	named := FlowInfo{Protocol: "netflix", ServerName: "nflxvideo.net", Category: "streaming", ToServer: false}
	a.RecordPacket(gw, tv, ipOf("198.51.100.9"), ipOf("192.168.2.60"), 10000, named)

	devs := a.Snapshot(time.Time{})
	pooled := findDestination(devs, "aa:aa:aa:aa:aa:03", "", "netflix")
	if pooled == nil || pooled.BytesIn != 60000 {
		t.Fatalf("expected pooled unnamed netflix row with 60000 in, got %+v", pooled)
	}
	if n := findDestination(devs, "aa:aa:aa:aa:aa:03", "nflxvideo.net", "netflix"); n == nil || n.BytesIn != 10000 {
		t.Fatalf("expected named row with 10000 in, got %+v", n)
	}
	if dev := findDevice(devs, "aa:aa:aa:aa:aa:03"); dev.Destinations[0].BytesIn != 60000 {
		t.Fatalf("rows must be sorted by total bytes desc, got %+v", dev.Destinations)
	}
}

func TestDestinationLANFlowsAndLocalPeersAreIgnored(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	pc := mustMAC(t, "aa:aa:aa:aa:aa:04")
	nas := mustMAC(t, "aa:aa:aa:aa:aa:05")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)

	smb := FlowInfo{Protocol: "smb", ServerName: "nas.home", Category: "data-transfer", ToServer: true}
	// LAN-to-LAN: neither side is the gateway.
	a.RecordPacket(pc, nas, ipOf("192.168.2.10"), ipOf("192.168.2.20"), 1500, smb)
	// Through the gateway but the far IP is still local (hairpin / VLAN
	// routing): the peer list skips it and so does the destination row.
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("192.168.9.1"), 1500, smb)

	devs := a.Snapshot(time.Time{})
	for _, mac := range []string{"aa:aa:aa:aa:aa:04", "aa:aa:aa:aa:aa:05"} {
		if dev := findDevice(devs, mac); dev != nil && len(dev.Destinations) != 0 {
			t.Fatalf("%s: LAN flow must not create a destination row, got %+v", mac, dev.Destinations)
		}
	}
}

func TestDestinationCapAndDisable(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	pc := mustMAC(t, "aa:aa:aa:aa:aa:06")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)
	a.SetTopDestinationsCount(2)

	for _, name := range []string{"a.example", "b.example", "c.example"} {
		a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("203.0.113.1"), 100,
			FlowInfo{Protocol: "https", ServerName: name, ToServer: true})
	}
	devs := a.Snapshot(time.Time{})
	dev := findDevice(devs, "aa:aa:aa:aa:aa:06")
	if len(dev.Destinations) != 2 {
		t.Fatalf("cap of 2 not honoured, got %d rows", len(dev.Destinations))
	}
	if findDestination(devs, "aa:aa:aa:aa:aa:06", "c.example", "https") != nil {
		t.Fatalf("rows past the cap must be dropped, not evict existing ones")
	}
	// Existing rows keep accumulating past the cap.
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("203.0.113.1"), 50,
		FlowInfo{Protocol: "https", ServerName: "a.example", ToServer: true})
	if d := findDestination(a.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:06", "a.example", "https"); d == nil || d.BytesOut != 150 {
		t.Fatalf("existing row must keep counting, got %+v", d)
	}

	a.SetTopDestinationsCount(-1)
	other := mustMAC(t, "aa:aa:aa:aa:aa:07")
	a.RecordPacket(other, gw, ipOf("192.168.2.11"), ipOf("203.0.113.1"), 100,
		FlowInfo{Protocol: "https", ServerName: "z.example", ToServer: true})
	if dev := findDevice(a.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:07"); len(dev.Destinations) != 0 {
		t.Fatalf("negative cap must disable destination accounting, got %+v", dev.Destinations)
	}
	if dev := findDevice(a.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:07"); dev.BytesOut != 100 {
		t.Fatalf("device totals must still count, got %d", dev.BytesOut)
	}
}

func TestDestinationCategoryFollowsLatestPacket(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	pc := mustMAC(t, "aa:aa:aa:aa:aa:08")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)

	// First packets arrive from the tentative port-based label (no category),
	// later ones from nDPI's final answer.
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("203.0.113.1"), 100,
		FlowInfo{Protocol: "https", ServerName: "ads.example", ToServer: true})
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("203.0.113.1"), 100,
		FlowInfo{Protocol: "https", ServerName: "ads.example", Category: "advertisement", ToServer: true})
	d := findDestination(a.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:08", "ads.example", "https")
	if d == nil || d.Category != "advertisement" || d.BytesOut != 200 {
		t.Fatalf("expected category to settle on the classified value with both packets counted, got %+v", d)
	}
}

func TestDestinationUnnamedNameableFlowsKeyByPeerAddress(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	pc := mustMAC(t, "aa:aa:aa:aa:aa:09")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)

	// TLS without a captured hello: keyed by the peer address.
	tls := FlowInfo{Protocol: "https", Category: "web", ToServer: true, NameExpected: true}
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("142.250.1.1"), 1000, tls)
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("104.16.1.1"), 500, tls)
	back := tls
	back.ToServer = false
	a.RecordPacket(gw, pc, ipOf("142.250.1.1"), ipOf("192.168.2.10"), 9000, back)
	// BitTorrent never carries a name: pooled, no address.
	bt := FlowInfo{Protocol: "bittorrent", Category: "download", ToServer: true}
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("203.0.113.5"), 700, bt)
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("203.0.113.6"), 300, bt)

	devs := a.Snapshot(time.Time{})
	dev := findDevice(devs, "aa:aa:aa:aa:aa:09")
	if dev == nil {
		t.Fatalf("device missing")
	}
	byPeer := map[string]DestinationStats{}
	for _, d := range dev.Destinations {
		byPeer[d.PeerIP+"|"+d.Protocol] = d
	}
	g := byPeer["142.250.1.1|https"]
	if g.BytesOut != 1000 || g.BytesIn != 9000 || g.ServerName != "" {
		t.Fatalf("google peer row = %+v, want 1000 out / 9000 in, unnamed", g)
	}
	if cf := byPeer["104.16.1.1|https"]; cf.BytesOut != 500 {
		t.Fatalf("cloudflare peer row = %+v, want 500 out", cf)
	}
	pool := byPeer["|bittorrent"]
	if pool.BytesOut != 1000 || pool.PeerIP != "" {
		t.Fatalf("bittorrent must pool without an address, got %+v", pool)
	}
	if len(dev.Destinations) != 3 {
		t.Fatalf("expected 3 rows (2 addressed https + 1 pooled bittorrent), got %d", len(dev.Destinations))
	}
}

func TestDestinationUnnamedCapFallsBackToPool(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	pc := mustMAC(t, "aa:aa:aa:aa:aa:0a")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)
	a.SetTopUnnamedDestinationsCount(2)

	tls := FlowInfo{Protocol: "https", ToServer: true, NameExpected: true}
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf(ip), 100*(i+1), tls)
	}
	// A named flow is unaffected by the unnamed cap.
	named := FlowInfo{Protocol: "https", ServerName: "photos.example", ToServer: true, NameExpected: true}
	a.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("198.51.100.9"), 50, named)

	dev := findDevice(a.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:0a")
	addressed, pooled, namedRows := 0, uint64(0), 0
	for _, d := range dev.Destinations {
		switch {
		case d.ServerName != "":
			namedRows++
		case d.PeerIP != "":
			addressed++
		default:
			pooled += d.BytesOut
		}
	}
	if addressed != 2 || pooled != 700 || namedRows != 1 {
		t.Fatalf("addressed=%d pooled=%d named=%d, want 2 / 700 (300+400) / 1: %+v", addressed, pooled, namedRows, dev.Destinations)
	}

	// Disabled: everything unnamed pools, even the first one.
	b := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)
	b.SetTopUnnamedDestinationsCount(-1)
	b.RecordPacket(pc, gw, ipOf("192.168.2.10"), ipOf("198.51.100.1"), 100, tls)
	if d := findDevice(b.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:0a"); d.Destinations[0].PeerIP != "" {
		t.Fatalf("negative cap must never key by address, got %+v", d.Destinations)
	}
}
