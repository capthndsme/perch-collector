package classifier

import "testing"

func TestPortClassifierHTTPS(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	// Client → server: dstPort 443, TCP → https
	r := c.Classify(nil, nil, 54321, 443, ProtoTCP, nil)
	if r.Protocol != "https" {
		t.Errorf("TCP dst=443: got %q, want %q", r.Protocol, "https")
	}
}

func TestPortClassifierHTTPSReply(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	// Server → client reply: srcPort 443, TCP → https
	r := c.Classify(nil, nil, 443, 54321, ProtoTCP, nil)
	if r.Protocol != "https" {
		t.Errorf("TCP src=443: got %q, want %q", r.Protocol, "https")
	}
}

func TestPortClassifierQUIC(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	// UDP on port 443 → quic (not https)
	r := c.Classify(nil, nil, 54321, 443, ProtoUDP, nil)
	if r.Protocol != "quic" {
		t.Errorf("UDP dst=443: got %q, want %q", r.Protocol, "quic")
	}

	// Reply direction: srcPort=443, dstPort=ephemeral, UDP → quic
	r = c.Classify(nil, nil, 443, 54321, ProtoUDP, nil)
	if r.Protocol != "quic" {
		t.Errorf("UDP src=443 reply: got %q, want %q", r.Protocol, "quic")
	}
}

func TestPortClassifierDNS(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	r := c.Classify(nil, nil, 54321, 53, ProtoUDP, nil)
	if r.Protocol != "dns" {
		t.Errorf("UDP dst=53: got %q, want %q", r.Protocol, "dns")
	}

	r = c.Classify(nil, nil, 54321, 53, ProtoTCP, nil)
	if r.Protocol != "dns" {
		t.Errorf("TCP dst=53: got %q, want %q", r.Protocol, "dns")
	}
}

func TestPortClassifierSSH(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	r := c.Classify(nil, nil, 54321, 22, ProtoTCP, nil)
	if r.Protocol != "ssh" {
		t.Errorf("TCP dst=22: got %q, want %q", r.Protocol, "ssh")
	}
}

func TestPortClassifierSMB(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	r := c.Classify(nil, nil, 54321, 445, ProtoTCP, nil)
	if r.Protocol != "smb" {
		t.Errorf("TCP dst=445: got %q, want %q", r.Protocol, "smb")
	}
}

func TestPortClassifierBitTorrentRange(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	for port := uint16(6881); port <= 6889; port++ {
		r := c.Classify(nil, nil, 54321, port, ProtoTCP, nil)
		if r.Protocol != "bittorrent" {
			t.Errorf("TCP dst=%d: got %q, want %q", port, r.Protocol, "bittorrent")
		}
	}
}

func TestPortClassifierSteamRange(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	for port := uint16(27015); port <= 27050; port++ {
		r := c.Classify(nil, nil, 54321, port, ProtoUDP, nil)
		if r.Protocol != "steam" {
			t.Errorf("UDP dst=%d: got %q, want %q", port, r.Protocol, "steam")
		}
	}
}

func TestPortClassifierFallbackTCPOther(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	r := c.Classify(nil, nil, 54321, 54322, ProtoTCP, nil)
	if r.Protocol != "tcp-other" {
		t.Errorf("TCP unknown ports: got %q, want %q", r.Protocol, "tcp-other")
	}
}

func TestPortClassifierFallbackUDPOther(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	r := c.Classify(nil, nil, 54321, 54322, ProtoUDP, nil)
	if r.Protocol != "udp-other" {
		t.Errorf("UDP unknown ports: got %q, want %q", r.Protocol, "udp-other")
	}
}

func TestPortClassifierNoTransportLayer(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	// ICMP (proto 1) → "other"
	r := c.Classify(nil, nil, 0, 0, 1, nil)
	if r.Protocol != "other" {
		t.Errorf("ICMP: got %q, want %q", r.Protocol, "other")
	}

	// No transport (proto 0) → "other"
	r = c.Classify(nil, nil, 0, 0, 0, nil)
	if r.Protocol != "other" {
		t.Errorf("proto=0: got %q, want %q", r.Protocol, "other")
	}
}

func TestPortClassifierPlex(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	r := c.Classify(nil, nil, 54321, 32400, ProtoTCP, nil)
	if r.Protocol != "plex" {
		t.Errorf("TCP dst=32400: got %q, want %q", r.Protocol, "plex")
	}
}

func TestPortClassifierWireguard(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	r := c.Classify(nil, nil, 54321, 51820, ProtoUDP, nil)
	if r.Protocol != "wireguard" {
		t.Errorf("UDP dst=51820: got %q, want %q", r.Protocol, "wireguard")
	}
}

func TestPortClassifierVNCRange(t *testing.T) {
	c := NewPortClassifier()
	defer c.Close()

	for port := uint16(5900); port <= 5903; port++ {
		r := c.Classify(nil, nil, 54321, port, ProtoTCP, nil)
		if r.Protocol != "vnc" {
			t.Errorf("TCP dst=%d: got %q, want %q", port, r.Protocol, "vnc")
		}
	}
}

func TestServerSideIsDstHeuristic(t *testing.T) {
	cases := []struct {
		src, dst uint16
		want     bool
	}{
		{51000, 443, true},    // known destination port → dst is the server
		{443, 51000, false},   // known source port → src is the server
		{50000, 60000, false}, // neither known → lower port is the service
		{60000, 50000, true},
	}
	for _, c := range cases {
		if got := ServerSideIsDst(c.src, c.dst); got != c.want {
			t.Errorf("ServerSideIsDst(%d,%d)=%v want %v", c.src, c.dst, got, c.want)
		}
	}
	r := NewPortClassifier().Classify(nil, nil, 51000, 443, ProtoTCP, nil)
	if !r.ToServer || r.Protocol != "https" || r.ServerName != "" {
		t.Errorf("port classifier result = %+v", r)
	}
}

func TestNameExpectedForPorts(t *testing.T) {
	cases := []struct {
		name     string
		src, dst uint16
		proto    uint8
		want     bool
	}{
		{"tcp client to 443", 50000, 443, ProtoTCP, true},
		{"tcp reply from 443", 443, 50000, ProtoTCP, true},
		{"tcp 80", 50000, 80, ProtoTCP, true},
		{"tcp 8443", 8443, 50000, ProtoTCP, true},
		{"udp 443 is quic", 50000, 443, ProtoUDP, true},
		{"udp 80 is not", 50000, 80, ProtoUDP, false},
		{"tcp 22", 50000, 22, ProtoTCP, false},
		{"bittorrent-ish", 51413, 6881, ProtoTCP, false},
		{"icmp", 0, 0, 1, false},
	}
	for _, tc := range cases {
		if got := NameExpectedForPorts(tc.src, tc.dst, tc.proto); got != tc.want {
			t.Errorf("%s: NameExpectedForPorts(%d, %d, %d) = %v, want %v", tc.name, tc.src, tc.dst, tc.proto, got, tc.want)
		}
	}
}
