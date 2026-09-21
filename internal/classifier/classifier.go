// Package classifier provides protocol classification for captured packets.
// It maps transport-layer metadata (ports, protocol number) to a human-readable
// protocol label such as "https", "dns", "smb", etc.
package classifier

// Result is the classification outcome for a single packet.
type Result struct {
	Protocol string // e.g. "https", "dns", "smb", "bittorrent", "other"

	// ServerName is the name the client asked for on this flow — TLS SNI,
	// HTTP Host, or QUIC SNI — lower-cased, or "" when the classifier has
	// not (yet) learned it. Only stateful classifiers (nDPI) fill it.
	ServerName string

	// Category is the coarse application category nDPI assigns to the flow
	// ("web", "streaming", "social-network", "vpn", "advertisement", …;
	// lowercase-dash), or "" when unknown. It is flow-aware, not just a
	// property of the protocol: TLS to an ad-network domain is
	// "advertisement" even though Protocol is plain "https". Only nDPI
	// fills it.
	Category string

	// ToServer is true when this packet travels client → server. The
	// server is the endpoint that received the flow's first packet, unless
	// the ports say otherwise (see ServerSideIsDst); stateless classifiers
	// fall back to the port heuristic alone.
	ToServer bool

	// NameExpected is true when the protocol family carries a server name
	// the classifier could have learned (TLS / HTTP / QUIC). An unnamed
	// flow of such a family is worth accounting by its peer address
	// instead of pooling it: the name was simply not observed (long-lived
	// session, ClientHello outside the inspection window), not absent.
	NameExpected bool
}

// nameExpectedLabels are the port-based labels of those families.
var nameExpectedLabels = map[string]bool{"https": true, "http": true, "quic": true, "http-proxy": true}

// ProtocolCategory pairs a protocol label with the category nDPI assigns
// to that protocol by default (before any per-flow hostname refinement).
type ProtocolCategory struct {
	Protocol string `json:"protocol"`
	Category string `json:"category"`
}

// CategoryLister is implemented by classifiers that can enumerate a default
// category per protocol label (nDPI). Consumers type-assert for it so the
// stateless port classifier stays untouched.
type CategoryLister interface {
	ProtocolCategories() []ProtocolCategory
}

// ServerSideIsDst reports whether, for a packet with these ports, the
// destination looks like the server: a well-known destination port wins,
// then a well-known source port marks the source as the server, and with
// neither the lower port number is taken to be the service.
// NameExpectedForPorts reports whether a flow on these ports belongs to a
// family that normally carries a server name (TLS / HTTP / QUIC), judged by
// the well-known ports alone. It backs up the nDPI-based decision for flows
// nDPI could only guess by IP — typically a long-lived connection the
// collector joined mid-stream (after a restart) whose ClientHello it never
// saw. Such a flow still deserves to be attributed by its peer address
// rather than pooled under "<protocol> (unnamed)".
func NameExpectedForPorts(srcPort, dstPort uint16, transportProto uint8) bool {
	switch transportProto {
	case ProtoTCP:
		return isNamedTCPPort(srcPort) || isNamedTCPPort(dstPort)
	case ProtoUDP:
		return srcPort == 443 || dstPort == 443 // QUIC
	}
	return false
}

func isNamedTCPPort(port uint16) bool {
	switch port {
	case 80, 443, 8080, 8443:
		return true
	}
	return false
}

func ServerSideIsDst(srcPort, dstPort uint16) bool {
	if isKnownPort(dstPort) {
		return true
	}
	if isKnownPort(srcPort) {
		return false
	}
	return dstPort < srcPort
}

// Classifier assigns a protocol label to a packet.
type Classifier interface {
	// Classify returns a protocol label for the given packet metadata.
	//
	//   - For port-based: only the ports + transport proto are used;
	//     `ipPacket` is ignored and may be nil.
	//   - For nDPI: `ipPacket` must point at the IP header onwards (no
	//     link-layer bytes). The library inspects payload to recognise
	//     encrypted apps via TLS SNI, QUIC, BitTorrent handshakes, etc.
	//
	// The slice is borrowed for the duration of the call; callers must
	// not retain it.
	Classify(srcIP, dstIP []byte, srcPort, dstPort uint16, transportProto uint8, ipPacket []byte) Result

	// Close releases any resources (nDPI context, flow table, etc.)
	Close()
}

// Transport protocol numbers.
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// PortClassifier is a stateless, port-based protocol classifier. It maps
// well-known destination (or source) ports to protocol labels using a static
// lookup table. This is the default classifier — always available, no
// external dependencies.
type PortClassifier struct{}

// NewPortClassifier returns a new port-based classifier.
func NewPortClassifier() *PortClassifier {
	return &PortClassifier{}
}

// Classify returns a protocol label based on the transport ports.
//
// Logic (the "service port" heuristic from the spec):
//  1. Special-case: port 443 over UDP → "quic"
//  2. Try destination port in the lookup table (most common: client→server)
//  3. Try source port in the lookup table (reply packets: server→client)
//  4. Fall back to "tcp-other", "udp-other", or "other"
func (c *PortClassifier) Classify(_ /* srcIP */, _ /* dstIP */ []byte, srcPort, dstPort uint16, transportProto uint8, _ /* ipPacket */ []byte) Result {
	// No transport layer (ICMP, GRE, etc.)
	if transportProto != ProtoTCP && transportProto != ProtoUDP {
		return Result{Protocol: "other"}
	}
	toServer := ServerSideIsDst(srcPort, dstPort)

	// Special case: QUIC is UDP on port 443.
	if transportProto == ProtoUDP && (dstPort == 443 || (srcPort == 443 && !isKnownPort(dstPort))) {
		return Result{Protocol: "quic", ToServer: toServer, NameExpected: true}
	}

	// Try destination port first (client → server).
	if label, ok := portTable[dstPort]; ok {
		return Result{Protocol: label, ToServer: toServer, NameExpected: nameExpectedLabels[label]}
	}

	// Try source port (server → client reply).
	if label, ok := portTable[srcPort]; ok {
		return Result{Protocol: label, ToServer: toServer, NameExpected: nameExpectedLabels[label]}
	}

	// Fallback by transport.
	if transportProto == ProtoTCP {
		return Result{Protocol: "tcp-other", ToServer: toServer}
	}
	return Result{Protocol: "udp-other", ToServer: toServer}
}

// isKnownPort returns true when the port appears in the static lookup table.
func isKnownPort(port uint16) bool {
	_, ok := portTable[port]
	return ok
}

// Close is a no-op for the stateless port-based classifier.
func (c *PortClassifier) Close() {}
