package capture

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/classifier"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestSnapLen(t *testing.T) {
	cases := []struct {
		configured int32
		inspect    bool
		want       int32
	}{
		{96, false, 96},
		{1500, false, 1500},
		{96, true, FullPacketSnapLen},
		// The OpenWrt package's default: one byte short of every full-size
		// frame, and far short of a coalesced post-quantum ClientHello.
		{1500, true, FullPacketSnapLen},
		{65535, true, 65535},
		{262144, true, 262144},
	}
	for _, c := range cases {
		if got := SnapLen(c.configured, c.inspect); got != c.want {
			t.Errorf("SnapLen(%d, %v) = %d, want %d", c.configured, c.inspect, got, c.want)
		}
	}
}

func TestNetworkBytesReslicesAdjacent(t *testing.T) {
	buf := []byte{0x45, 1, 2, 3, 4, 5, 6, 7}
	got := networkBytes(buf[:3], buf[3:6])
	if !bytes.Equal(got, buf[:6]) {
		t.Fatalf("got %v, want %v", got, buf[:6])
	}
	if &got[0] != &buf[0] {
		t.Error("adjacent header and payload were copied, want a re-slice")
	}
}

func TestNetworkBytesCopiesApart(t *testing.T) {
	h, p := []byte{0x45, 1, 2}, []byte{7, 8}
	got := networkBytes(h, p)
	if !bytes.Equal(got, []byte{0x45, 1, 2, 7, 8}) {
		t.Fatalf("got %v", got)
	}
	if networkBytes(nil, p) != nil {
		t.Error("no header: want nil")
	}
	if got := networkBytes(h, nil); !bytes.Equal(got, h) {
		t.Errorf("no payload: got %v, want the header", got)
	}
}

// recorder is a Classifier that keeps a copy of every IP packet handed to it.
type recorder struct{ packets [][]byte }

func (r *recorder) Classify(_, _ []byte, _, _ uint16, _ uint8, ipPacket []byte) classifier.Result {
	r.packets = append(r.packets, append([]byte(nil), ipPacket...))
	return classifier.Result{Protocol: "https"}
}
func (r *recorder) Close() {}

// The ClientHello fixtures were captured in the lab on a router's LAN
// interface (curl 8.22 / OpenSSL 3.5 and headless Chromium, both offering
// X25519MLKEM768, to www.example.com) and rewritten to placeholder
// addresses. The hello arrives as one packet larger than the MTU, as the
// capture sees it behind GSO/GRO. The classifier must get it whole.
func TestProcessPacketHandsOverWholePQClientHello(t *testing.T) {
	for _, name := range []string{"tls-clienthello-pq-curl.pcap", "tls-clienthello-pq-chromium.pcap"} {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open("../classifier/testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			rd, err := pcapgo.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			rec := &recorder{}
			e := &Engine{agg: aggregator.New(nil, nil, 10, 10), classifier: rec}
			for {
				data, _, err := rd.ReadPacketData()
				if err != nil {
					break
				}
				e.processPacket(gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy))
			}
			if len(rec.packets) != 4 {
				t.Fatalf("classifier saw %d packets, want 4 (handshake + hello)", len(rec.packets))
			}
			hello := rec.packets[3]
			total := int(binary.BigEndian.Uint16(hello[2:4]))
			if total <= 1500 {
				t.Fatalf("fixture hello is %d bytes, want a post-quantum one above the MTU", total)
			}
			if len(hello) != total {
				t.Fatalf("classifier got %d of the hello's %d IP bytes", len(hello), total)
			}
			if !bytes.Contains(hello, []byte("www.example.com")) {
				t.Error("hello does not carry its SNI")
			}
			if !net.IP(hello[16:20]).Equal(net.IP{203, 0, 113, 10}) {
				t.Errorf("unexpected destination %v", net.IP(hello[16:20]))
			}
		})
	}
}
