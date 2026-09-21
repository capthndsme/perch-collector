//go:build ndpi
// +build ndpi

package classifier

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/capthndsme/perch-collector/internal/flow"
)

// Runs only with `-tags ndpi`. These tests pin the behaviour of the nDPI
// 5 binding on hand-built packets: the label table's ids against the
// header, SNI availability from the first ClientHello, the partial ->
// final label lifecycle, and giveup guessing by port.

func newTestNDPI(t *testing.T) *NDPIClassifier {
	t.Helper()
	c, err := NewNDPIClassifier(1000, 60)
	if err != nil {
		t.Skipf("nDPI unavailable: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestNDPIProtocolIDsMatchLibrary(t *testing.T) {
	ours := map[string]uint16{
		"NDPI_PROTOCOL_UNKNOWN":         ndpiProtocolUnknown,
		"NDPI_PROTOCOL_FTP_CONTROL":     ndpiProtocolFTPControl,
		"NDPI_PROTOCOL_MAIL_POP":        ndpiProtocolMail_POP,
		"NDPI_PROTOCOL_MAIL_SMTP":       ndpiProtocolMail_SMTP,
		"NDPI_PROTOCOL_MAIL_IMAP":       ndpiProtocolMail_IMAP,
		"NDPI_PROTOCOL_DNS":             ndpiProtocolDNS,
		"NDPI_PROTOCOL_HTTP":            ndpiProtocolHTTP,
		"NDPI_PROTOCOL_MDNS":            ndpiProtocolMDNS,
		"NDPI_PROTOCOL_NTP":             ndpiProtocolNTP,
		"NDPI_PROTOCOL_NETBIOS":         ndpiProtocolNetBIOS,
		"NDPI_PROTOCOL_NFS":             ndpiProtocolNFS,
		"NDPI_PROTOCOL_SSDP":            ndpiProtocolSSDP,
		"NDPI_PROTOCOL_BGP":             ndpiProtocolBGP,
		"NDPI_PROTOCOL_SNMP":            ndpiProtocolSNMP,
		"NDPI_PROTOCOL_XDMCP":           ndpiProtocolXDMCP,
		"NDPI_PROTOCOL_SMBV1":           ndpiProtocolSMBv1,
		"NDPI_PROTOCOL_SYSLOG":          ndpiProtocolSyslog,
		"NDPI_PROTOCOL_DHCP":            ndpiProtocolDHCP,
		"NDPI_PROTOCOL_MAIL_POPS":       ndpiProtocolMail_POPS,
		"NDPI_PROTOCOL_NATS":            ndpiProtocolNATS,
		"NDPI_PROTOCOL_FTP_DATA":        ndpiProtocolFTPData,
		"NDPI_PROTOCOL_BITTORRENT":      ndpiProtocolBitTorrent,
		"NDPI_PROTOCOL_SIGNAL":          ndpiProtocolSignal,
		"NDPI_PROTOCOL_TIKTOK":          ndpiProtocolTikTok,
		"NDPI_PROTOCOL_DISCORD":         ndpiProtocolDiscord,
		"NDPI_PROTOCOL_MAIL_SMTPS":      ndpiProtocolMail_SMTPS,
		"NDPI_PROTOCOL_MAIL_IMAPS":      ndpiProtocolMail_IMAPS,
		"NDPI_PROTOCOL_STEAM":           ndpiProtocolSteam,
		"NDPI_PROTOCOL_TELNET":          ndpiProtocolTelnet,
		"NDPI_PROTOCOL_RDP":             ndpiProtocolRDP,
		"NDPI_PROTOCOL_VNC":             ndpiProtocolVNC,
		"NDPI_PROTOCOL_TLS":             ndpiProtocolTLS,
		"NDPI_PROTOCOL_SSH":             ndpiProtocolSSH,
		"NDPI_PROTOCOL_USENET":          ndpiProtocolUSENET,
		"NDPI_PROTOCOL_FACEBOOK":        ndpiProtocolFacebook,
		"NDPI_PROTOCOL_YOUTUBE":         ndpiProtocolYouTube,
		"NDPI_PROTOCOL_GOOGLE":          ndpiProtocolGoogle,
		"NDPI_PROTOCOL_NETFLIX":         ndpiProtocolNetflix,
		"NDPI_PROTOCOL_APPLE":           ndpiProtocolApple,
		"NDPI_PROTOCOL_WHATSAPP":        ndpiProtocolWhatsApp,
		"NDPI_PROTOCOL_WINDOWS_UPDATE":  ndpiProtocolWindowsUpdate,
		"NDPI_PROTOCOL_SPOTIFY":         ndpiProtocolSpotify,
		"NDPI_PROTOCOL_OPENVPN":         ndpiProtocolOpenVPN,
		"NDPI_PROTOCOL_TOR":             ndpiProtocolTor,
		"NDPI_PROTOCOL_QUIC":            ndpiProtocolQUIC,
		"NDPI_PROTOCOL_ZOOM":            ndpiProtocolZoom,
		"NDPI_PROTOCOL_TWITCH":          ndpiProtocolTwitch,
		"NDPI_PROTOCOL_WIREGUARD":       ndpiProtocolWireGuard,
		"NDPI_PROTOCOL_MICROSOFT":       ndpiProtocolMicrosoft,
		"NDPI_PROTOCOL_MICROSOFT_365":   ndpiProtocolMicrosoft365,
		"NDPI_PROTOCOL_MQTT":            ndpiProtocolMQTT,
		"NDPI_PROTOCOL_GIT":             ndpiProtocolGit,
		"NDPI_PROTOCOL_APPLE_ICLOUD":    ndpiProtocolAppleiCloud,
		"NDPI_PROTOCOL_APPLE_ITUNES":    ndpiProtocolAppleiTunes,
		"NDPI_PROTOCOL_GOOGLE_SERVICES": ndpiProtocolGoogleServices,
		"NDPI_PROTOCOL_INSTAGRAM":       ndpiProtocolInstagram,
	}
	if len(ours) != len(ndpiHeaderProtocolIDs) {
		t.Errorf("pin tables differ in size: test has %d ids, ndpi_ids.go has %d", len(ours), len(ndpiHeaderProtocolIDs))
	}
	for name, want := range ndpiHeaderProtocolIDs {
		got, ok := ours[name]
		if !ok {
			t.Errorf("%s: in ndpi_ids.go but not pinned here", name)
			continue
		}
		if got != want {
			t.Errorf("%s: ndpi_labels.go says %d, ndpi_protocol_ids.h says %d", name, got, want)
		}
	}
	for name := range ours {
		if _, ok := ndpiHeaderProtocolIDs[name]; !ok {
			t.Errorf("%s: pinned here but missing from ndpi_ids.go", name)
		}
	}
}

func TestNDPIVersionIsFive(t *testing.T) {
	v := NDPIVersion()
	if !strings.HasPrefix(v, "5.") {
		t.Fatalf("linked libndpi reports %q, want a 5.x release", v)
	}
	if NDPIAPIVersion() <= 0 {
		t.Fatalf("api version = %d", NDPIAPIVersion())
	}
	t.Logf("libndpi %s, api %d", v, NDPIAPIVersion())
}

// A TLS ClientHello with an SNI for a Netflix host: nDPI names the app
// from the SNI on that very packet, and the binding surfaces label + server
// name at once (partial state), then holds them once the flow is final.
func TestNDPIClassifyTLSClientHelloSNI(t *testing.T) {
	c := newTestNDPI(t)
	client, server := []byte{192, 168, 1, 10}, []byte{52, 20, 30, 40}
	const sport, dport = 51234, 443

	hello := ipv4TCP(client, server, sport, dport, tcpPSH|tcpACK, 1000, tlsClientHello("www.netflix.com"))
	r := c.Classify(client, server, sport, dport, ProtoTCP, hello)
	if r.Protocol != "netflix" {
		t.Fatalf("ClientHello: protocol = %q, want netflix (%+v)", r.Protocol, r)
	}
	if r.ServerName != "www.netflix.com" {
		t.Errorf("ClientHello: server name = %q, want www.netflix.com", r.ServerName)
	}
	if !r.ToServer || !r.NameExpected {
		t.Errorf("ClientHello: ToServer=%v NameExpected=%v, want both true", r.ToServer, r.NameExpected)
	}
	if r.Category == "" {
		t.Errorf("ClientHello: category empty, want nDPI's category for Netflix")
	}
	if n := c.FlowCount(); n != 1 {
		t.Errorf("flow count = %d, want 1", n)
	}
	t.Logf("ClientHello -> %+v", r)
	// nDPI leaves a TLS flow PARTIAL after the ClientHello (it wants the
	// ServerHello etc.); the binding keeps the native state for exactly
	// ndpiPartialExtraPackets more packets, then finalises and frees it.
	key := flow.MakeKey(client, server, sport, dport, ProtoTCP)
	if done, native := c.flowState(key); done || !native {
		t.Fatalf("after ClientHello: done=%v native=%v, want inspecting with native state", done, native)
	}

	// Keep the flow alive with data-less segments in both directions until
	// the inspection budget is spent and ndpi_detection_giveup settles it;
	// every packet in between must already be attributed to netflix.
	for i := 1; i <= ndpiMaxPacketsPerFlow+2; i++ {
		var rr Result
		if i%2 == 0 {
			rr = c.Classify(client, server, sport, dport, ProtoTCP, ipv4TCP(client, server, sport, dport, tcpACK, 2000+uint32(i), nil))
			if !rr.ToServer {
				t.Errorf("packet %d: client->server marked as ToServer=false", i)
			}
		} else {
			rr = c.Classify(server, client, dport, sport, ProtoTCP, ipv4TCP(server, client, dport, sport, tcpACK, 5000+uint32(i), nil))
			if rr.ToServer {
				t.Errorf("packet %d: server->client marked as ToServer=true", i)
			}
		}
		if rr.Protocol != "netflix" || rr.ServerName != "www.netflix.com" {
			t.Fatalf("packet %d: got %q/%q, want netflix/www.netflix.com", i, rr.Protocol, rr.ServerName)
		}
		if !rr.NameExpected {
			t.Errorf("packet %d: NameExpected=false", i)
		}
		done, native := c.flowState(key)
		if wantDone := uint32(i) >= ndpiPartialExtraPackets.Load(); done != wantDone || native == wantDone {
			t.Fatalf("after %d extra packets: done=%v native=%v, want done=%v (partial_extra_packets=%d)", i, done, native, wantDone, ndpiPartialExtraPackets.Load())
		}
	}
	if c.evictedFlows.Load() != 0 {
		t.Errorf("evictedFlows = %d, want 0 (the flow finalised on its own)", c.evictedFlows.Load())
	}
}

// flowState reports, under c.mu, whether the flow is finalised and
// whether native nDPI state is still attached to it.
func (c *NDPIClassifier) flowState(key flow.Key) (done, native bool) {
	e, created := c.table.GetOrCreate(key)
	if created {
		panic("flowState: unknown flow")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return e.Done, e.UserData != nil
}

// Idle and cap evictions run on the table's sweeper goroutine and race
// with Classify on the capture goroutine(s). With a millisecond sweep
// interval and idle timeout, both eviction paths run repeatedly while two
// goroutines keep creating flows that never finalise on their own (a
// ClientHello, still PARTIAL; a bare SYN, still INSPECTING), so the
// evicted-after-lookup window, giveup-on-evict and the lock discipline
// are all exercised. Run with -race.
func TestNDPISweeperFreesUnfinalisedFlows(t *testing.T) {
	c, err := newNDPIClassifier(64, 20*time.Millisecond, 2*time.Millisecond)
	if err != nil {
		t.Skipf("nDPI unavailable: %v", err)
	}
	t.Cleanup(c.Close)
	client, server := []byte{192, 168, 1, 20}, []byte{52, 20, 30, 41}

	var wg sync.WaitGroup
	stop := make(chan struct{}) // closed, so every generator sees it
	time.AfterFunc(250*time.Millisecond, func() { close(stop) })
	packets := func(kind string, base uint16) {
		defer wg.Done()
		for i := uint16(0); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			sport := base + i%20000
			var pkt []byte
			if kind == "hello" {
				pkt = ipv4TCP(client, server, sport, 443, tcpPSH|tcpACK, 1, tlsClientHello("www.netflix.com"))
			} else {
				pkt = ipv4TCP(client, server, sport, 443, tcpSYN, 1, nil)
			}
			r := c.Classify(client, server, sport, 443, ProtoTCP, pkt)
			if kind == "hello" && r.Protocol != "netflix" {
				t.Errorf("ClientHello on port %d: protocol = %q", sport, r.Protocol)
				return
			}
			// Revisit a recent flow too, so lookups race with its eviction.
			if i > 0 {
				c.Classify(client, server, sport-1, 443, ProtoTCP, ipv4TCP(client, server, sport-1, 443, tcpACK, 2, nil))
			}
		}
	}
	wg.Add(2)
	go packets("hello", 10000)
	go packets("syn", 40000)
	wg.Wait()

	if n := c.FlowCount(); n > 64 {
		t.Fatalf("flow count %d exceeds the cap of 64", n)
	}
	capEvictions := c.evictedFlows.Load()
	if capEvictions == 0 {
		t.Fatal("no flow was evicted under the cap")
	}
	// Traffic stopped; the sweeper alone must now drain the table.
	deadline := time.Now().Add(3 * time.Second)
	for c.FlowCount() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := c.FlowCount(); n != 0 {
		t.Fatalf("sweeper left %d flows after idle timeout", n)
	}
	t.Logf("evicted flows: %d under the cap, %d more by the idle sweep", capEvictions, c.evictedFlows.Load()-capEvictions)
}

// A bare DNS query is labelled from the first packet; the query name must
// not leak into ServerName (that field is for TLS/HTTP/QUIC servers only).
func TestNDPIClassifyDNSQuery(t *testing.T) {
	c := newTestNDPI(t)
	client, resolver := []byte{192, 168, 1, 10}, []byte{1, 1, 1, 1}
	const sport, dport = 40000, 53

	r := c.Classify(client, resolver, sport, dport, ProtoUDP, ipv4UDP(client, resolver, sport, dport, dnsQuery("example.com")))
	if r.Protocol != "dns" {
		t.Fatalf("DNS query: protocol = %q, want dns (%+v)", r.Protocol, r)
	}
	if r.ServerName != "" {
		t.Errorf("DNS query: server name = %q, want empty", r.ServerName)
	}
	if r.NameExpected {
		t.Errorf("DNS query: NameExpected = true, want false")
	}
	if r.Category != "network" {
		t.Errorf("DNS query: category = %q, want network", r.Category)
	}
	if !r.ToServer {
		t.Errorf("DNS query: ToServer = false, want true")
	}
}

// Payload no dissector recognises, on a port our own table does not know
// but nDPI does (PostgreSQL, 5432): while inspecting, the packet falls
// back to the port label ("tcp-other"); once nDPI gives up it guesses
// by port (dpi.guess_on_giveup is on by default) and the flow settles on
// the library's own name for that protocol.
func TestNDPIGiveupGuessesByPort(t *testing.T) {
	c := newTestNDPI(t)
	client, server := []byte{192, 168, 1, 10}, []byte{10, 0, 0, 5}
	const sport, dport = 40001, 5432

	junk := bytes.Repeat([]byte("go-collector test payload, nothing to see here 0123456789\n"), 4)
	first := c.Classify(client, server, sport, dport, ProtoTCP, ipv4TCP(client, server, sport, dport, tcpPSH|tcpACK, 1, junk))
	if first.Protocol != "tcp-other" && first.Protocol != "postgresql" {
		t.Fatalf("first packet: protocol = %q, want tcp-other (inspecting) or postgresql (already guessed)", first.Protocol)
	}
	var r Result
	for i := 1; i <= ndpiMaxPacketsPerFlow; i++ {
		r = c.Classify(client, server, sport, dport, ProtoTCP, ipv4TCP(client, server, sport, dport, tcpPSH|tcpACK, uint32(1+i*len(junk)), junk))
	}
	if r.Protocol != "postgresql" {
		t.Fatalf("after giveup: protocol = %q, want postgresql (guessed by port); first was %q", r.Protocol, first.Protocol)
	}
	if r.ServerName != "" || r.NameExpected {
		t.Errorf("after giveup: server name %q / NameExpected %v, want empty / false", r.ServerName, r.NameExpected)
	}
	// Finalised flows answer from the cache without libndpi state.
	again := c.Classify(client, server, sport, dport, ProtoTCP, ipv4TCP(client, server, sport, dport, tcpACK, 999999, nil))
	if again.Protocol != "postgresql" {
		t.Errorf("cached: protocol = %q, want postgresql", again.Protocol)
	}
	t.Logf("first=%q final=%q category=%q", first.Protocol, r.Protocol, r.Category)
}

// ---- packet builders --------------------------------------------------

const (
	tcpSYN = 0x02
	tcpACK = 0x10
	tcpPSH = 0x08
)

// ipv4TCP builds an IPv4 packet (header onwards, no link layer) carrying
// a TCP segment. Checksums stay zero; nDPI does not verify them.
func ipv4TCP(src, dst []byte, sport, dport uint16, flags byte, seq uint32, payload []byte) []byte {
	total := 20 + 20 + len(payload)
	p := make([]byte, total)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(total))
	binary.BigEndian.PutUint16(p[4:], 0x1234)
	p[6] = 0x40 // DF
	p[8] = 64
	p[9] = ProtoTCP
	copy(p[12:16], src)
	copy(p[16:20], dst)
	tcp := p[20:]
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], 1)
	tcp[12] = 5 << 4 // data offset: 5 words, no options
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	copy(tcp[20:], payload)
	return p
}

// ipv4UDP builds an IPv4 packet carrying a UDP datagram.
func ipv4UDP(src, dst []byte, sport, dport uint16, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	p := make([]byte, total)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(total))
	binary.BigEndian.PutUint16(p[4:], 0x4321)
	p[8] = 64
	p[9] = ProtoUDP
	copy(p[12:16], src)
	copy(p[16:20], dst)
	udp := p[20:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	copy(udp[8:], payload)
	return p
}

func be16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// tlsClientHello is a minimal but well-formed TLS 1.2 ClientHello record
// carrying a server_name extension for name, plus the few extensions a
// modern client always sends.
func tlsClientHello(name string) []byte {
	var ext []byte
	sni := []byte{0x00, 0x00} // server_name
	sni = be16(sni, uint16(5+len(name)))
	sni = be16(sni, uint16(3+len(name)))
	sni = append(sni, 0x00) // host_name
	sni = be16(sni, uint16(len(name)))
	sni = append(sni, name...)
	ext = append(ext, sni...)
	ext = append(ext, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d)             // supported_groups: x25519
	ext = append(ext, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04) // signature_algorithms
	alpnProtos := []byte{0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	alpn := []byte{0x00, 0x10} // application_layer_protocol_negotiation
	alpn = be16(alpn, uint16(2+len(alpnProtos)))
	alpn = be16(alpn, uint16(len(alpnProtos)))
	ext = append(ext, append(alpn, alpnProtos...)...)
	ext = append(ext, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03) // supported_versions: 1.3, 1.2

	body := []byte{0x03, 0x03}
	for i := 0; i < 32; i++ { // client random
		body = append(body, byte(i*7+3))
	}
	body = append(body, 0x00)                                           // session id
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f) // cipher suites
	body = append(body, 0x01, 0x00)                                     // compression: null
	body = be16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = be16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// dnsQuery is a standard A query for name.
func dnsQuery(name string) []byte {
	q := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0x00, 0x00, 0x01, 0x00, 0x01)
}
