//go:build ndpi
// +build ndpi

package classifier

import (
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// pqClientHello reads the TLS ClientHello (the first TCP payload) from a
// fixture pcap. The fixtures are lab captures of curl 8.22 (OpenSSL 3.5)
// and headless Chromium offering X25519MLKEM768, rewritten to placeholder
// addresses; see internal/capture's test for their provenance.
func pqClientHello(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, _, err := rd.ReadPacketData()
		if err != nil {
			t.Fatalf("%s: no ClientHello: %v", name, err)
		}
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && len(tcp.Payload) > 0 {
			return append([]byte(nil), tcp.Payload...)
		}
	}
}

// A post-quantum ClientHello is 1.5-2 KB: more than one TCP segment on the
// wire, one coalesced packet above the MTU at the capture. nDPI 5 reassembles
// it either way as long as it is handed whole packets; a capture cut at a
// frame-sized snap length (the pre-fix OpenWrt default of 1500) loses the
// SNI, which is why the capture takes whole packets in nDPI mode.
func TestNDPIPostQuantumClientHelloSNI(t *testing.T) {
	client, server := []byte{192, 168, 1, 10}, []byte{203, 0, 113, 10}
	const sport, dport = 40000, 443
	const mss = 1388 // what the lab's ClientHellos were split at on the wire

	for _, fixture := range []string{"tls-clienthello-pq-curl.pcap", "tls-clienthello-pq-chromium.pcap"} {
		hello := pqClientHello(t, fixture)
		if len(hello) <= mss {
			t.Fatalf("%s: hello is %d bytes, want one that spans segments", fixture, len(hello))
		}
		feeds := map[string][][]byte{
			"coalesced": {ipv4TCP(client, server, sport, dport, tcpPSH|tcpACK, 1001, hello)},
			"segments": {
				ipv4TCP(client, server, sport, dport, tcpACK, 1001, hello[:mss]),
				ipv4TCP(client, server, sport, dport, tcpPSH|tcpACK, 1001+mss, hello[mss:]),
			},
		}
		for mode, packets := range feeds {
			t.Run(fixture+"/"+mode, func(t *testing.T) {
				c := newTestNDPI(t)
				c.Classify(client, server, sport, dport, ProtoTCP, ipv4TCP(client, server, sport, dport, tcpSYN, 1000, nil))
				c.Classify(server, client, dport, sport, ProtoTCP, ipv4TCP(server, client, dport, sport, tcpSYN|tcpACK, 5000, nil))
				c.Classify(client, server, sport, dport, ProtoTCP, ipv4TCP(client, server, sport, dport, tcpACK, 1001, nil))
				var r Result
				for _, p := range packets {
					r = c.Classify(client, server, sport, dport, ProtoTCP, p)
				}
				if r.Protocol != "https" || r.ServerName != "www.example.com" {
					t.Fatalf("got %q/%q, want https/www.example.com", r.Protocol, r.ServerName)
				}
				if !r.ToServer || !r.NameExpected {
					t.Errorf("ToServer=%v NameExpected=%v, want both true", r.ToServer, r.NameExpected)
				}
			})
		}
		t.Run(fixture+"/truncated-at-1500", func(t *testing.T) {
			// What a 1500-byte snap length leaves of the coalesced packet
			// (14 bytes of Ethernet header come off the top). Logged, not
			// asserted: it documents the failure the full-packet capture
			// avoids, and a later nDPI may cope differently.
			c := newTestNDPI(t)
			whole := ipv4TCP(client, server, sport, dport, tcpPSH|tcpACK, 1001, hello)
			r := c.Classify(client, server, sport, dport, ProtoTCP, whole[:1500-14])
			t.Logf("truncated hello -> %q/%q", r.Protocol, r.ServerName)
		})
	}
}
