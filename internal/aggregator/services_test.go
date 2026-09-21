package aggregator

import (
	"net"
	"testing"
	"time"
)

// Service accounting: bytes land on the *server-side* device only, split
// into served (server → client) and received (client → server).

func findService(devs []DeviceStats, mac, name, proto string) *ServiceStats {
	d := findDevice(devs, mac)
	if d == nil {
		return nil
	}
	for i := range d.Services {
		if d.Services[i].ServerName == name && d.Services[i].Protocol == proto {
			return &d.Services[i]
		}
	}
	return nil
}

func TestServiceAccountingWANServer(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	srv := mustMAC(t, "aa:aa:aa:aa:aa:01")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)

	// WAN client → our server (request bytes): received.
	a.RecordFlow(gw, srv, ipOf("203.0.113.9"), ipOf("192.168.2.100"), 300, "https", "photos.example", true)
	// Our server → WAN client (response bytes): served.
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 5000, "https", "photos.example", false)
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 7000, "https", "photos.example", false)
	// Our device as a *client* of a remote server: never a service row.
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("142.250.1.1"), 900, "https", "youtube.com", true)
	a.RecordFlow(gw, srv, ipOf("142.250.1.1"), ipOf("192.168.2.100"), 90000, "https", "youtube.com", false)
	// No name learned yet: nothing recorded.
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 100, "https", "", false)

	devs := a.Snapshot(time.Time{})
	s := findService(devs, "aa:aa:aa:aa:aa:01", "photos.example", "https")
	if s == nil {
		t.Fatalf("expected a photos.example service row on the server")
	}
	if s.BytesServed != 12000 || s.BytesReceived != 300 {
		t.Fatalf("served/received = %d/%d, want 12000/300", s.BytesServed, s.BytesReceived)
	}
	if s.PacketsServed != 2 || s.PacketsReceived != 1 {
		t.Fatalf("packets served/received = %d/%d, want 2/1", s.PacketsServed, s.PacketsReceived)
	}
	if got := findService(devs, "aa:aa:aa:aa:aa:01", "youtube.com", "https"); got != nil {
		t.Fatalf("client-side flow must not create a service row, got %+v", *got)
	}
	if d := findDevice(devs, "aa:aa:aa:aa:aa:01"); len(d.Services) != 1 {
		t.Fatalf("expected exactly one service row, got %d", len(d.Services))
	}
}

func TestServiceAccountingLANServer(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	client := mustMAC(t, "aa:aa:aa:aa:aa:02")
	nas := mustMAC(t, "aa:aa:aa:aa:aa:03")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)

	a.RecordFlow(client, nas, ipOf("192.168.5.1"), ipOf("192.168.2.101"), 200, "https", "cloud.home", true)
	a.RecordFlow(nas, client, ipOf("192.168.2.101"), ipOf("192.168.5.1"), 4000, "https", "cloud.home", false)

	devs := a.Snapshot(time.Time{})
	s := findService(devs, "aa:aa:aa:aa:aa:03", "cloud.home", "https")
	if s == nil || s.BytesServed != 4000 || s.BytesReceived != 200 {
		t.Fatalf("nas service row = %+v, want served 4000 / received 200", s)
	}
	if c := findDevice(devs, "aa:aa:aa:aa:aa:02"); len(c.Services) != 0 {
		t.Fatalf("LAN client must not get a service row, got %+v", c.Services)
	}
}

func TestServiceCapAndDisable(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	srv := mustMAC(t, "aa:aa:aa:aa:aa:04")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)
	a.SetTopServicesCount(1)

	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 10, "https", "first.example", false)
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 10, "https", "second.example", false)
	// Existing rows keep accumulating even at the cap.
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 10, "https", "first.example", false)

	d := findDevice(a.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:04")
	if len(d.Services) != 1 || d.Services[0].ServerName != "first.example" || d.Services[0].BytesServed != 20 {
		t.Fatalf("cap=1 should keep only first.example (20 B), got %+v", d.Services)
	}

	a.SetTopServicesCount(-1)
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 10, "https", "first.example", false)
	d = findDevice(a.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:04")
	if d.Services[0].BytesServed != 20 {
		t.Fatalf("disabled accounting must stop counting, got %d", d.Services[0].BytesServed)
	}
}

func TestServicesSortedByTotalDesc(t *testing.T) {
	gw := mustMAC(t, "02:00:00:00:00:01")
	srv := mustMAC(t, "aa:aa:aa:aa:aa:05")
	a := New([]net.HardwareAddr{gw}, mustSubnets(t, "192.168.0.0/16"), 0, 0)
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 10, "https", "small.example", false)
	a.RecordFlow(srv, gw, ipOf("192.168.2.100"), ipOf("203.0.113.9"), 999, "quic", "big.example", false)

	d := findDevice(a.Snapshot(time.Time{}), "aa:aa:aa:aa:aa:05")
	if len(d.Services) != 2 || d.Services[0].ServerName != "big.example" || d.Services[0].Protocol != "quic" {
		t.Fatalf("services not sorted by total desc: %+v", d.Services)
	}
}
