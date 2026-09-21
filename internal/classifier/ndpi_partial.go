package classifier

import "sync/atomic"

// ndpiPartialExtraPackets bounds how long a flow keeps its native
// inspection state after nDPI has produced a usable partial label (for
// TLS / HTTP / QUIC: label plus server name). nDPI 5 leaves such a flow
// in PARTIAL and wants more packets to refine it, twelve after the
// ClientHello for TLS over TCP (ServerHello, certificate, JA3S, risks),
// none of which the collector reports. Meanwhile the flow struct plus
// dissector metadata is ~3.3 KB per TLS flow, ~157 MB at
// ndpi_max_flows=50000 if every flow stayed until CLASSIFIED or idle.
// After this many further packets the flow is finalised with
// ndpi_detection_giveup (which keeps the partial label) and its native
// state freed. Trade-off: a larger value lets nDPI refine STUN into the
// call app behind it and TLS into a by-certificate label; 0 reproduces
// the 4.x binding (finalise on the first label).
var ndpiPartialExtraPackets = func() *atomic.Uint32 {
	v := new(atomic.Uint32)
	v.Store(4)
	return v
}()

// SetNDPIPartialExtraPackets sets how many packets a flow keeps its native
// nDPI state after its first usable label before it is finalised. Call it
// before NewNDPIClassifier; 0 finalises on the first label (the 4.x
// behaviour), larger values let nDPI refine labels at the cost of memory.
//
// Carve-out: TLS/HTTP/QUIC flows that never yield a server name (ECH,
// resumption, direct-to-IP TLS, flows joined mid-stream) do not start the
// allowance on the bare label; they keep native state until nDPI settles
// them itself (13 packets for TCP TLS) or the 24-packet cap. The knob bounds
// the common case, not that one.
func SetNDPIPartialExtraPackets(n int) {
	if n < 0 {
		n = 0
	}
	ndpiPartialExtraPackets.Store(uint32(n))
}
