// Package aggregator maintains thread-safe per-device (per-MAC) traffic
// counters, with a bounded list of top external peers per device.
package aggregator

import (
	"container/heap"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/capthndsme/perch-collector/internal/netutil"
)

// PeerStats is the JSON-serializable view of a remote external peer that a
// local device has talked to via the gateway.
type PeerStats struct {
	IP       string `json:"ip"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

// ServiceStats holds per-(server name, protocol) counters for JSON
// serialization. A row exists only on the device that was the *server* of
// the flow: `bytes_served` is what it pushed to clients, `bytes_received` is
// what clients sent to it. Names are TLS SNI / HTTP Host / QUIC SNI as
// learned by the classifier, so a reverse proxy terminating many vhosts
// shows one row per vhost.
type ServiceStats struct {
	ServerName      string `json:"server_name"`
	Protocol        string `json:"protocol"`
	BytesServed     uint64 `json:"bytes_served"`
	BytesReceived   uint64 `json:"bytes_received"`
	PacketsServed   uint64 `json:"packets_served"`
	PacketsReceived uint64 `json:"packets_received"`
}

// DestinationStats is the JSON view of one remote (WAN) destination a local
// device talked to *as a client*: the name it asked for (TLS SNI / HTTP Host
// / QUIC SNI) plus the protocol label. Flows without a name pool under
// server_name "" per protocol, so an app-level label such as "youtube" still
// accounts for every byte. Bytes are from the device's point of view:
// bytes_in were downloaded from the destination, bytes_out uploaded to it.
// Category is nDPI's application category for the flow ("streaming",
// "advertisement", …) or "" when unknown. This is the "where is the traffic
// going" row: the peer IP list answers *which address*, this answers *which
// site / app*.
type DestinationStats struct {
	ServerName string `json:"server_name"`
	// PeerIP is set only on unnamed rows of a name-carrying family (TLS /
	// HTTP / QUIC): the flow *should* have had a name, so the peer address
	// stands in for it and a consumer can attribute it by ASN. Named rows
	// and the per-protocol pool leave it "".
	PeerIP     string `json:"peer_ip"`
	Protocol   string `json:"protocol"`
	Category   string `json:"category"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`
}

// FlowInfo is the per-packet context a classifier attaches to a frame.
type FlowInfo struct {
	Protocol   string
	ServerName string
	Category   string
	// ToServer is true when the packet travels client → server.
	ToServer bool
	// NameExpected: the protocol family carries a server name, so an
	// unnamed flow is accounted by peer address (see DestinationStats).
	NameExpected bool
}

// ProtocolStats holds per-protocol byte/packet counters for JSON serialization.
type ProtocolStats struct {
	Protocol   string `json:"protocol"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`
}

// DeviceStats is the JSON-serializable view of a single LAN device, keyed by
// its Ethernet MAC address. Counters and peer lists are point-in-time copies.
//
// TopPeers and TopLANPeers are two independently-bounded heaps:
//   - TopPeers    is populated only when traffic pivots through a configured
//     gateway MAC (i.e. WAN-scope flows).
//   - TopLANPeers is populated for LAN-to-LAN frames (neither side is a
//     gateway), so a NAS feeding a Jellyfin host over SMB shows up here even
//     though it never crosses the WAN.
//
// Both lists use identical eviction semantics. Splitting them prevents a
// chatty WAN swarm from pushing out the one critical LAN peer (and vice
// versa), and keeps the JSON shape useful without any client-side filtering.
//
// BytesIn / BytesOut / PacketsIn / PacketsOut are TOTALS (WAN + LAN combined)
// preserved verbatim from the original schema so anything still consuming
// those fields keeps working. BytesIn{WAN,LAN} / BytesOut{WAN,LAN} (and
// their packet equivalents) split the totals along the same WAN/LAN seam
// the peer heaps use, so a dashboard can render "WAN-only Mbps" without
// any heuristic on top of the totals. Invariant:
//
//	BytesIn  == BytesInWAN  + BytesInLAN
//	BytesOut == BytesOutWAN + BytesOutLAN
//	(same for packet counters)
type DeviceStats struct {
	MAC           string             `json:"mac"`
	IPs           []string           `json:"ips"`
	BytesIn       uint64             `json:"bytes_in"`
	BytesOut      uint64             `json:"bytes_out"`
	PacketsIn     uint64             `json:"packets_in"`
	PacketsOut    uint64             `json:"packets_out"`
	BytesInWAN    uint64             `json:"bytes_in_wan"`
	BytesOutWAN   uint64             `json:"bytes_out_wan"`
	PacketsInWAN  uint64             `json:"packets_in_wan"`
	PacketsOutWAN uint64             `json:"packets_out_wan"`
	BytesInLAN    uint64             `json:"bytes_in_lan"`
	BytesOutLAN   uint64             `json:"bytes_out_lan"`
	PacketsInLAN  uint64             `json:"packets_in_lan"`
	PacketsOutLAN uint64             `json:"packets_out_lan"`
	FirstSeen     time.Time          `json:"first_seen"`
	LastSeen      time.Time          `json:"last_seen"`
	TopPeers      []PeerStats        `json:"top_peers"`
	TopLANPeers   []PeerStats        `json:"top_lan_peers"`
	Protocols     []ProtocolStats    `json:"protocols"`
	Services      []ServiceStats     `json:"services"`
	Destinations  []DestinationStats `json:"destinations"`
}

// Summary is the JSON-serializable aggregate view across all devices.
type Summary struct {
	TotalDevices int           `json:"total_devices"`
	TotalBytes   uint64        `json:"total_bytes"`
	TotalPackets uint64        `json:"total_packets"`
	Uptime       time.Duration `json:"uptime_ns"`
	UptimeSecs   float64       `json:"uptime_seconds"`
	StartedAt    time.Time     `json:"started_at"`
}

// peerEntry is the internal mutable record kept in a device's peer set and
// min-heap. heapIdx is maintained by Swap so heap.Fix can locate the entry
// after an in-place counter update.
type peerEntry struct {
	ip       string
	bytesIn  uint64
	bytesOut uint64
	heapIdx  int
}

func (p *peerEntry) score() uint64 { return p.bytesIn + p.bytesOut }

// peerMinHeap is a min-heap of *peerEntry ordered by score (lowest first), so
// the root is always the cheapest peer to evict when the heap is full.
type peerMinHeap []*peerEntry

func (h peerMinHeap) Len() int           { return len(h) }
func (h peerMinHeap) Less(i, j int) bool { return h[i].score() < h[j].score() }
func (h peerMinHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIdx = i
	h[j].heapIdx = j
}
func (h *peerMinHeap) Push(x any) {
	p := x.(*peerEntry)
	p.heapIdx = len(*h)
	*h = append(*h, p)
}
func (h *peerMinHeap) Pop() any {
	old := *h
	n := len(old)
	p := old[n-1]
	old[n-1] = nil
	p.heapIdx = -1
	*h = old[:n-1]
	return p
}

// device is the internal mutable record for one MAC.
//
// Two parallel peer sets are kept per device:
//   - peers / peerHeap     — WAN remotes (set only when a gateway MAC pivots).
//   - lanPeers / lanPeerHeap — LAN neighbours (set only on LAN-to-LAN frames).
//
// Each set is its own bounded min-heap so that eviction in one cannot affect
// the other.
//
// bytes/packets counters carry both a roll-up (`bytesIn`, `bytesOut`,
// `packetsIn`, `packetsOut`) and per-scope splits (`*WAN`, `*LAN`). The
// roll-up is the simple sum of the two splits; we keep all three writes
// in lockstep inside Record so the invariant always holds.
// protocolCounters is the internal mutable record for per-protocol traffic.
type protocolCounters struct {
	bytesIn    uint64
	bytesOut   uint64
	packetsIn  uint64
	packetsOut uint64
}

// serviceKey identifies one served name per protocol label (the same SNI
// over TLS and over QUIC are two rows).
type serviceKey struct {
	name     string
	protocol string
}

// serviceCounters is the internal mutable record behind ServiceStats.
type serviceCounters struct {
	bytesServed     uint64
	bytesReceived   uint64
	packetsServed   uint64
	packetsReceived uint64
}

// destinationKey identifies one destination row: a name, or for unnamed
// flows of a name-carrying family the peer address, or neither (the
// per-protocol pool).
type destinationKey struct {
	name     string
	peerIP   string
	protocol string
}

// destinationCounters is the internal mutable record behind
// DestinationStats. category is refreshed on every packet that carries one,
// so a flow reclassified mid-way settles on the latest answer.
type destinationCounters struct {
	category   string
	bytesIn    uint64
	bytesOut   uint64
	packetsIn  uint64
	packetsOut uint64
}

type device struct {
	mac           string
	ipSet         map[string]struct{}
	bytesIn       uint64
	bytesOut      uint64
	packetsIn     uint64
	packetsOut    uint64
	bytesInWAN    uint64
	bytesOutWAN   uint64
	packetsInWAN  uint64
	packetsOutWAN uint64
	bytesInLAN    uint64
	bytesOutLAN   uint64
	packetsInLAN  uint64
	packetsOutLAN uint64
	firstSeen     time.Time
	lastSeen      time.Time
	peers         map[string]*peerEntry
	peerHeap      peerMinHeap
	lanPeers      map[string]*peerEntry
	lanPeerHeap   peerMinHeap
	protocols     map[string]*protocolCounters // keyed by protocol label
	services      map[serviceKey]*serviceCounters
	destinations  map[destinationKey]*destinationCounters
	// unnamedDestinations counts the peer-address-keyed rows so they get
	// their own cap and cannot starve named rows.
	unnamedDestinations int
}

// Aggregator maintains thread-safe per-device traffic counters indexed by MAC.
type Aggregator struct {
	mu               sync.RWMutex
	devices          map[string]*device
	started          time.Time
	gatewayMACs      map[string]struct{} // canonical lowercase form; empty disables WAN pivot.
	localSubnets     []*net.IPNet
	topPeersCount    int
	topLANPeersCount int
	// topServicesCount caps distinct (name, protocol) pairs per device;
	// negative disables service accounting entirely.
	topServicesCount int
	// topDestinationsCount caps distinct (name, protocol) destination rows
	// per device; negative disables destination accounting entirely.
	topDestinationsCount int
	// topUnnamedDestinationsCount caps the peer-address-keyed rows per
	// device (unnamed TLS/HTTP/QUIC); past it those flows join the pool.
	topUnnamedDestinationsCount int
}

const (
	defaultTopPeersCount        = 50
	maxTopPeersCount            = 1000
	defaultTopServicesCount     = 500
	maxTopServicesCount         = 10000
	defaultTopDestinationsCount = 500
	maxTopDestinationsCount     = 10000
	// Unnamed rows are keyed by address, which churns more than names do.
	defaultTopUnnamedDestinationsCount = 100
	maxTopUnnamedDestinationsCount     = 5000
)

// New creates a new Aggregator. gatewayMACs may be nil or empty (no WAN
// pivot — every packet is treated as LAN-to-LAN). When multiple MACs are
// provided, any of them acts as a pivot, and frames where BOTH sides are
// gateway MACs (e.g. inter-router relay frames) are dropped to avoid double
// counting. localSubnets restricts which IPs are associated with a device's
// IP set; if empty, every IP is accepted. topPeersCount caps the per-device
// WAN peer list and topLANPeersCount caps the per-device LAN peer list;
// non-positive values for either use the default of 50. Pass 0 to keep the
// default; pass a negative value to disable that list entirely.
func New(gatewayMACs []net.HardwareAddr, localSubnets []*net.IPNet, topPeersCount, topLANPeersCount int) *Aggregator {
	gws := make(map[string]struct{}, len(gatewayMACs))
	for _, m := range gatewayMACs {
		if len(m) == 0 {
			continue
		}
		gws[m.String()] = struct{}{}
	}
	return &Aggregator{
		devices:                     make(map[string]*device),
		started:                     time.Now(),
		gatewayMACs:                 gws,
		localSubnets:                localSubnets,
		topPeersCount:               normalizePeerCount(topPeersCount),
		topLANPeersCount:            normalizePeerCount(topLANPeersCount),
		topServicesCount:            defaultTopServicesCount,
		topDestinationsCount:        defaultTopDestinationsCount,
		topUnnamedDestinationsCount: defaultTopUnnamedDestinationsCount,
	}
}

// normalizePeerCount applies the shared clamp policy used for both WAN and
// LAN peer caps: 0 becomes the default; positives are clamped to the hard
// maximum; negatives are passed through and disable the list (the heap path
// short-circuits on <= 0).
func normalizePeerCount(n int) int {
	if n == 0 {
		return defaultTopPeersCount
	}
	if n > maxTopPeersCount {
		return maxTopPeersCount
	}
	return n
}

// isGateway returns true when mac is one of the configured upstream-gateway
// pivots. Hot path: O(1) map lookup, called twice per packet.
func (a *Aggregator) isGateway(mac string) bool {
	if len(a.gatewayMACs) == 0 {
		return false
	}
	_, ok := a.gatewayMACs[mac]
	return ok
}

// Record registers a single packet observed on the capture interface.
// Broadcast/multicast frames are dropped. The gateway MAC, if configured,
// pivots a packet into "WAN inbound" or "WAN outbound" relative to the local
// device on the other end. Frames where neither MAC is the gateway are
// counted as LAN-to-LAN on both devices and do not contribute peer entries.
func (a *Aggregator) Record(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, packetLen int, protocol string) {
	a.RecordPacket(srcMAC, dstMAC, srcIP, dstIP, packetLen, FlowInfo{Protocol: protocol})
}

// SetTopDestinationsCount sets the per-device cap on distinct (server name,
// protocol) destination rows. 0 selects the default, a negative value
// disables destination accounting, and values above the hard maximum are
// clamped.
func (a *Aggregator) SetTopDestinationsCount(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case n == 0:
		a.topDestinationsCount = defaultTopDestinationsCount
	case n < 0:
		a.topDestinationsCount = -1
	case n > maxTopDestinationsCount:
		a.topDestinationsCount = maxTopDestinationsCount
	default:
		a.topDestinationsCount = n
	}
}

// SetTopServicesCount sets the per-device cap on distinct (server name,
// protocol) rows. 0 selects the default, a negative value disables service
// accounting, and values above the hard maximum are clamped.
func (a *Aggregator) SetTopServicesCount(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case n == 0:
		a.topServicesCount = defaultTopServicesCount
	case n < 0:
		a.topServicesCount = -1
	case n > maxTopServicesCount:
		a.topServicesCount = maxTopServicesCount
	default:
		a.topServicesCount = n
	}
}

// SetTopUnnamedDestinationsCount sets the per-device cap on peer-address
// keyed destination rows. 0 selects the default, a negative value disables
// address keying (unnamed flows always pool), and values above the hard
// maximum are clamped.
func (a *Aggregator) SetTopUnnamedDestinationsCount(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case n == 0:
		a.topUnnamedDestinationsCount = defaultTopUnnamedDestinationsCount
	case n < 0:
		a.topUnnamedDestinationsCount = -1
	case n > maxTopUnnamedDestinationsCount:
		a.topUnnamedDestinationsCount = maxTopUnnamedDestinationsCount
	default:
		a.topUnnamedDestinationsCount = n
	}
}

// RecordFlow is Record plus the flow context a stateful classifier knows:
// the server name the client asked for (TLS SNI / HTTP Host / QUIC SNI, or
// "") and whether this packet travels client → server. Bytes are attributed
// to the *server-side* device's service row: packets toward the server count
// as received, packets from it as served. A local device acting as a client
// of a remote server never gets a service row.
func (a *Aggregator) RecordFlow(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, packetLen int, protocol, serverName string, toServer bool) {
	a.RecordPacket(srcMAC, dstMAC, srcIP, dstIP, packetLen, FlowInfo{
		Protocol:   protocol,
		ServerName: serverName,
		ToServer:   toServer,
	})
}

// RecordPacket is the full-context entry point: RecordFlow plus the flow's
// application category. Destination rows are the mirror image of service
// rows — they land on the local device that is the *client* of a WAN flow,
// keyed by the name it asked for, so "where did my bytes go" reads as sites
// and apps rather than addresses. LAN-to-LAN flows never create one (the
// LAN peer list and the server's service row already cover them).
func (a *Aggregator) RecordPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, packetLen int, info FlowInfo) {
	protocol, serverName, toServer := info.Protocol, info.ServerName, info.ToServer
	if packetLen <= 0 || len(srcMAC) == 0 || len(dstMAC) == 0 {
		return
	}
	if isBroadcastOrMulticast(srcMAC) || isBroadcastOrMulticast(dstMAC) {
		return
	}
	srcKey := srcMAC.String()
	dstKey := dstMAC.String()
	if srcKey == dstKey {
		return
	}
	srcIsGW := a.isGateway(srcKey)
	dstIsGW := a.isGateway(dstKey)

	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	bytes := uint64(packetLen)
	switch {
	case srcIsGW && dstIsGW:
		return
	case srcIsGW && !dstIsGW:
		dev := a.getOrCreate(dstKey, now)
		dev.bytesIn += bytes
		dev.packetsIn++
		dev.bytesInWAN += bytes
		dev.packetsInWAN++
		dev.lastSeen = now
		a.addIP(dev, dstIP)
		if srcIP != nil && !netutil.IsLocal(srcIP, a.localSubnets) {
			a.recordPeer(dev, srcIP.String(), bytes, 0)
			if !toServer {
				// A WAN server replying to our device: bytes it downloaded.
				a.recordDestination(dev, info, srcIP.String(), bytes, 0)
			}
		}
		a.recordProtocol(dev, protocol, bytes, 0)
		if toServer {
			// A WAN client sending to our device: our device is the server.
			a.recordService(dev, serverName, protocol, 0, bytes)
		}
	case !srcIsGW && dstIsGW:
		dev := a.getOrCreate(srcKey, now)
		dev.bytesOut += bytes
		dev.packetsOut++
		dev.bytesOutWAN += bytes
		dev.packetsOutWAN++
		dev.lastSeen = now
		a.addIP(dev, srcIP)
		if dstIP != nil && !netutil.IsLocal(dstIP, a.localSubnets) {
			a.recordPeer(dev, dstIP.String(), 0, bytes)
			if toServer {
				// Our device sending to a WAN server: bytes it uploaded.
				a.recordDestination(dev, info, dstIP.String(), 0, bytes)
			}
		}
		a.recordProtocol(dev, protocol, 0, bytes)
		if !toServer {
			// Our device replying toward a WAN client: it is the server.
			a.recordService(dev, serverName, protocol, bytes, 0)
		}
	default:
		// LAN-to-LAN (or no gateway configured): count on both sides, and
		// record each side as the other's LAN peer so callers can answer the
		// "who fed me these bytes?" question for LAN-internal flows like SMB,
		// NFS, IP-cam ↔ NVR, etc.
		src := a.getOrCreate(srcKey, now)
		src.bytesOut += bytes
		src.packetsOut++
		src.bytesOutLAN += bytes
		src.packetsOutLAN++
		src.lastSeen = now
		a.addIP(src, srcIP)
		if dstIP != nil {
			a.recordLANPeer(src, dstIP.String(), 0, bytes)
		}
		a.recordProtocol(src, protocol, 0, bytes)

		dst := a.getOrCreate(dstKey, now)
		dst.bytesIn += bytes
		dst.packetsIn++
		dst.bytesInLAN += bytes
		dst.packetsInLAN++
		dst.lastSeen = now
		a.addIP(dst, dstIP)
		if srcIP != nil {
			a.recordLANPeer(dst, srcIP.String(), bytes, 0)
		}
		a.recordProtocol(dst, protocol, bytes, 0)

		if toServer {
			a.recordService(dst, serverName, protocol, 0, bytes)
		} else {
			a.recordService(src, serverName, protocol, bytes, 0)
		}
	}
}

// getOrCreate returns the device record for mac, creating it if needed.
// Caller must hold the write lock.
func (a *Aggregator) getOrCreate(mac string, now time.Time) *device {
	if d, ok := a.devices[mac]; ok {
		return d
	}
	d := &device{
		mac:          mac,
		services:     make(map[serviceKey]*serviceCounters),
		destinations: make(map[destinationKey]*destinationCounters),
		ipSet:        make(map[string]struct{}),
		peers:        make(map[string]*peerEntry),
		lanPeers:     make(map[string]*peerEntry),
		protocols:    make(map[string]*protocolCounters),
		firstSeen:    now,
		lastSeen:     now,
	}
	a.devices[mac] = d
	return d
}

// addIP records an IP as belonging to dev, deduplicated. When local subnets
// are configured, IPs outside them are rejected so cross-pollution from a
// spoofed or unusually routed packet doesn't taint a device's identity.
func (a *Aggregator) addIP(dev *device, ip net.IP) {
	if ip == nil || ip.IsUnspecified() {
		return
	}
	if len(a.localSubnets) > 0 && !netutil.IsLocal(ip, a.localSubnets) {
		return
	}
	s := ip.String()
	if _, ok := dev.ipSet[s]; ok {
		return
	}
	dev.ipSet[s] = struct{}{}
}

// recordPeer adds or updates a WAN peer in the device's bounded top-N
// min-heap. See recordPeerInto for the eviction policy.
func (a *Aggregator) recordPeer(dev *device, ip string, bytesIn, bytesOut uint64) {
	recordPeerInto(dev.peers, &dev.peerHeap, a.topPeersCount, ip, bytesIn, bytesOut)
}

// recordLANPeer adds or updates a LAN peer in the device's bounded top-N
// min-heap. The WAN and LAN heaps are independent, so heavy WAN chatter
// cannot evict an important LAN peer (or vice versa).
func (a *Aggregator) recordLANPeer(dev *device, ip string, bytesIn, bytesOut uint64) {
	recordPeerInto(dev.lanPeers, &dev.lanPeerHeap, a.topLANPeersCount, ip, bytesIn, bytesOut)
}

// recordPeerInto is the shared implementation for both peer scopes. When the
// heap is full, only peers whose new score exceeds the current minimum are
// admitted (evicting the cheapest). capacity <= 0 disables the list entirely.
func recordPeerInto(peers map[string]*peerEntry, h *peerMinHeap, capacity int, ip string, bytesIn, bytesOut uint64) {
	if capacity <= 0 {
		return
	}
	if p, ok := peers[ip]; ok {
		p.bytesIn += bytesIn
		p.bytesOut += bytesOut
		heap.Fix(h, p.heapIdx)
		return
	}
	p := &peerEntry{ip: ip, bytesIn: bytesIn, bytesOut: bytesOut}
	if len(*h) < capacity {
		heap.Push(h, p)
		peers[ip] = p
		return
	}
	min := (*h)[0]
	if p.score() <= min.score() {
		return
	}
	evicted := heap.Pop(h).(*peerEntry)
	delete(peers, evicted.ip)
	heap.Push(h, p)
	peers[ip] = p
}

// Snapshot returns a copy of all device stats. When since is non-zero, only
// devices with LastSeen at or after since are returned.
func (a *Aggregator) Snapshot(since time.Time) []DeviceStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make([]DeviceStats, 0, len(a.devices))
	for _, d := range a.devices {
		if !since.IsZero() && d.lastSeen.Before(since) {
			continue
		}
		out = append(out, d.toStats())
	}
	// Stable ordering for clients: highest total bytes first.
	sort.Slice(out, func(i, j int) bool {
		return (out[i].BytesIn + out[i].BytesOut) > (out[j].BytesIn + out[j].BytesOut)
	})
	return out
}

// GetDevice returns a single device by MAC. Format is tolerant: "AA:BB:CC:DD:EE:FF",
// "aabbccddeeff", and "aa-bb-cc-dd-ee-ff" all match the same record.
// Returns nil if not found.
func (a *Aggregator) GetDevice(mac string) *DeviceStats {
	key := canonicalizeMAC(mac)
	if key == "" {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	d, ok := a.devices[key]
	if !ok {
		return nil
	}
	s := d.toStats()
	return &s
}

// GetSummary returns aggregate totals across all devices.
func (a *Aggregator) GetSummary() Summary {
	a.mu.RLock()
	defer a.mu.RUnlock()

	s := Summary{TotalDevices: len(a.devices), StartedAt: a.started}
	for _, d := range a.devices {
		s.TotalBytes += d.bytesIn + d.bytesOut
		s.TotalPackets += d.packetsIn + d.packetsOut
	}
	s.Uptime = time.Since(a.started)
	s.UptimeSecs = s.Uptime.Seconds()
	return s
}

// Reset clears all device counters and restarts the uptime clock.
func (a *Aggregator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.devices = make(map[string]*device)
	a.started = time.Now()
}

// toStats materializes an immutable view of the device for snapshot/JSON.
// Caller must hold at least a read lock on the aggregator.
func (d *device) toStats() DeviceStats {
	ips := make([]string, 0, len(d.ipSet))
	for ip := range d.ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	// Snapshot protocol counters, sorted by total bytes descending.
	protocols := make([]ProtocolStats, 0, len(d.protocols))
	for proto, c := range d.protocols {
		protocols = append(protocols, ProtocolStats{
			Protocol:   proto,
			BytesIn:    c.bytesIn,
			BytesOut:   c.bytesOut,
			PacketsIn:  c.packetsIn,
			PacketsOut: c.packetsOut,
		})
	}
	sort.Slice(protocols, func(i, j int) bool {
		return (protocols[i].BytesIn + protocols[i].BytesOut) >
			(protocols[j].BytesIn + protocols[j].BytesOut)
	})

	services := make([]ServiceStats, 0, len(d.services))
	for k, c := range d.services {
		services = append(services, ServiceStats{
			ServerName:      k.name,
			Protocol:        k.protocol,
			BytesServed:     c.bytesServed,
			BytesReceived:   c.bytesReceived,
			PacketsServed:   c.packetsServed,
			PacketsReceived: c.packetsReceived,
		})
	}
	sort.Slice(services, func(i, j int) bool {
		ti := services[i].BytesServed + services[i].BytesReceived
		tj := services[j].BytesServed + services[j].BytesReceived
		if ti != tj {
			return ti > tj
		}
		if services[i].ServerName != services[j].ServerName {
			return services[i].ServerName < services[j].ServerName
		}
		return services[i].Protocol < services[j].Protocol
	})

	destinations := make([]DestinationStats, 0, len(d.destinations))
	for k, c := range d.destinations {
		destinations = append(destinations, DestinationStats{
			ServerName: k.name,
			PeerIP:     k.peerIP,
			Protocol:   k.protocol,
			Category:   c.category,
			BytesIn:    c.bytesIn,
			BytesOut:   c.bytesOut,
			PacketsIn:  c.packetsIn,
			PacketsOut: c.packetsOut,
		})
	}
	sort.Slice(destinations, func(i, j int) bool {
		ti := destinations[i].BytesIn + destinations[i].BytesOut
		tj := destinations[j].BytesIn + destinations[j].BytesOut
		if ti != tj {
			return ti > tj
		}
		if destinations[i].ServerName != destinations[j].ServerName {
			return destinations[i].ServerName < destinations[j].ServerName
		}
		if destinations[i].PeerIP != destinations[j].PeerIP {
			return destinations[i].PeerIP < destinations[j].PeerIP
		}
		return destinations[i].Protocol < destinations[j].Protocol
	})

	return DeviceStats{
		MAC:           d.mac,
		IPs:           ips,
		BytesIn:       d.bytesIn,
		BytesOut:      d.bytesOut,
		PacketsIn:     d.packetsIn,
		PacketsOut:    d.packetsOut,
		BytesInWAN:    d.bytesInWAN,
		BytesOutWAN:   d.bytesOutWAN,
		PacketsInWAN:  d.packetsInWAN,
		PacketsOutWAN: d.packetsOutWAN,
		BytesInLAN:    d.bytesInLAN,
		BytesOutLAN:   d.bytesOutLAN,
		PacketsInLAN:  d.packetsInLAN,
		PacketsOutLAN: d.packetsOutLAN,
		FirstSeen:     d.firstSeen,
		LastSeen:      d.lastSeen,
		TopPeers:      snapshotHeap(d.peerHeap),
		TopLANPeers:   snapshotHeap(d.lanPeerHeap),
		Protocols:     protocols,
		Services:      services,
		Destinations:  destinations,
	}
}

// snapshotHeap copies a peer heap into a JSON-friendly slice sorted by total
// bytes descending. The empty slice (not nil) is intentional so JSON shows
// "top_peers": [] rather than "top_peers": null for devices with no peers.
func snapshotHeap(h peerMinHeap) []PeerStats {
	peers := make([]PeerStats, 0, len(h))
	for _, p := range h {
		peers = append(peers, PeerStats{
			IP:       p.ip,
			BytesIn:  p.bytesIn,
			BytesOut: p.bytesOut,
		})
	}
	sort.Slice(peers, func(i, j int) bool {
		return (peers[i].BytesIn + peers[i].BytesOut) > (peers[j].BytesIn + peers[j].BytesOut)
	})
	return peers
}

// isBroadcastOrMulticast returns true when m has the I/G (multicast) bit set
// in the first octet. The broadcast address ff:ff:ff:ff:ff:ff is also caught
// by this check because its first octet is 0xFF.
func isBroadcastOrMulticast(m net.HardwareAddr) bool {
	if len(m) == 0 {
		return false
	}
	return m[0]&0x01 == 0x01
}

// recordProtocol increments the per-protocol counters on dev. An empty
// protocol label is a no-op (graceful for legacy callers or non-IP packets).
// Caller must hold the write lock.
func (a *Aggregator) recordProtocol(dev *device, protocol string, bytesIn, bytesOut uint64) {
	if protocol == "" {
		return
	}
	p := dev.protocols[protocol]
	if p == nil {
		p = &protocolCounters{}
		dev.protocols[protocol] = p
	}
	p.bytesIn += bytesIn
	p.bytesOut += bytesOut
	if bytesIn > 0 {
		p.packetsIn++
	}
	if bytesOut > 0 {
		p.packetsOut++
	}
}

// recordService adds bytes to dev's (serverName, protocol) row. An empty
// name (classifier hasn't learned it, or the protocol carries none) is a
// no-op, as is a disabled cap. New rows past the cap are dropped rather
// than evicting an existing one, so long-lived vhosts keep their totals.
// Caller must hold the write lock.
func (a *Aggregator) recordService(dev *device, serverName, protocol string, served, received uint64) {
	if serverName == "" || a.topServicesCount < 0 {
		return
	}
	key := serviceKey{name: serverName, protocol: protocol}
	s := dev.services[key]
	if s == nil {
		if len(dev.services) >= a.topServicesCount {
			return
		}
		s = &serviceCounters{}
		dev.services[key] = s
	}
	s.bytesServed += served
	s.bytesReceived += received
	if served > 0 {
		s.packetsServed++
	}
	if received > 0 {
		s.packetsReceived++
	}
}

// recordDestination adds bytes to dev's (serverName, protocol) destination
// row. Unlike services, an empty name is kept (pooled per protocol) so the
// per-category and per-app totals stay complete; only a disabled cap is a
// no-op. New rows past the cap are dropped rather than evicting an existing
// one, so the long-lived big destinations keep their totals. Caller must
// hold the write lock.
func (a *Aggregator) recordDestination(dev *device, info FlowInfo, peerIP string, bytesIn, bytesOut uint64) {
	if a.topDestinationsCount < 0 {
		return
	}
	protocol := info.Protocol
	if protocol == "" {
		protocol = "other"
	}
	key := destinationKey{name: info.ServerName, protocol: protocol}
	// An unnamed flow that should have carried a name is keyed by its peer
	// address (its own cap); past the cap, or for families that never
	// carry a name (BitTorrent, plain UDP), it joins the per-protocol pool.
	if info.ServerName == "" && info.NameExpected && peerIP != "" && a.topUnnamedDestinationsCount > 0 {
		key.peerIP = peerIP
		if dev.destinations[key] == nil && dev.unnamedDestinations >= a.topUnnamedDestinationsCount {
			key.peerIP = ""
		}
	}
	d := dev.destinations[key]
	if d == nil {
		if len(dev.destinations) >= a.topDestinationsCount {
			return
		}
		d = &destinationCounters{}
		dev.destinations[key] = d
		if key.peerIP != "" {
			dev.unnamedDestinations++
		}
	}
	if info.Category != "" {
		d.category = info.Category
	}
	d.bytesIn += bytesIn
	d.bytesOut += bytesOut
	if bytesIn > 0 {
		d.packetsIn++
	}
	if bytesOut > 0 {
		d.packetsOut++
	}
}

// canonicalizeMAC returns the lowercase colon-separated form used as the
// internal map key, or "" if the input is not a valid MAC.
func canonicalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	h, err := net.ParseMAC(s)
	if err != nil {
		return ""
	}
	return h.String()
}
