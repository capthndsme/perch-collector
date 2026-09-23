# Architecture

## Overview

perch-collector (the Perch Network Collector) is a single-binary daemon. It
captures packet headers on a LAN interface, classifies each frame against the
configured gateway MAC(s), and maintains per-device traffic counters in
memory with two parallel bounded peer lists per device — `top_peers` for WAN
remotes and `top_lan_peers` for LAN neighbours. It hands them to the Perch
Network Controller either by pushing them over a WebSocket it dials
(`internal/controller`) or by serving them on its HTTP API to be polled; on
the router it adds the router's own health and its Ethernet ports
(`internal/gateway`), which makes it the Perch Network Gateway agent.

## Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                          main.go                              │
│  CLI → Config → resolve gateway MAC + local subnets           │
│       → wire components → signal handler                      │
└──┬───────┬───────────┬──────────────┬──────────────┬──────────┘
   │       │           │              │              │
   ▼       ▼           ▼              ▼              ▼
┌────────┐ ┌────────┐ ┌──────────┐ ┌───────────┐ ┌──────────┐
│netutil │ │Capture │ │  API     │ │  Flusher  │ │  Config  │
│gateway │ │ Engine │ │  Server  │ │           │ │  Loader  │
│subnets │ └───┬────┘ └────┬─────┘ └─────┬─────┘ └──────────┘
└────────┘     │           │             │
               ▼           ▼             ▼
       ┌──────────────────────────────────────────────────┐
       │                  Aggregator                        │
       │ sync.RWMutex + map[MAC]*device                     │
       │ each device: ipSet + two bounded min-heaps:        │
       │   - WAN peers (top_peers_count)                    │
       │   - LAN peers (top_lan_peers_count) [independent]  │
       └──────────────────────────────────────────────────┘
```

## Data Flow

```
1. STARTUP
   netutil.DetectGatewayMAC(iface)
     → reads /proc/net/route for default gateway IPv4
     → reads /proc/net/arp for that IP's MAC (pokes ARP if cache miss)
   netutil.InterfaceSubnets(iface)
     → enumerates v4 and v6 CIDRs on the capture interface
   Aggregator.New(gatewayMACs, localSubnets, topPeersCount, topLANPeersCount)

2. PACKET CAPTURE
   NIC → libpcap (BPF filter) → gopacket decoder
   Extract: Ethernet srcMAC/dstMAC, IPv4/IPv6 srcIP/dstIP, packet length
   nDPI mode opens the capture with a 65535-byte snap length whatever
   snap_len says (capture.SnapLen): offloads hand over coalesced packets
   above the MTU, and a post-quantum TLS ClientHello (1.5-2 KB) cut short
   never yields its SNI. The IP packet goes to the classifier as a
   re-slice of the capture buffer, not a copy.

3. CLASSIFICATION (Aggregator.Record)
   Drop:  broadcast (ff:ff:ff:ff:ff:ff) or any multicast MAC,
          gateway-to-gateway frames, zero-length frames.
   Case   srcMAC ∈ gatewayMACs, dstMAC ∉ gatewayMACs:
          → INBOUND to dstMAC; srcIP added to dstMAC's top_peers (BytesIn).
   Case   dstMAC ∈ gatewayMACs, srcMAC ∉ gatewayMACs:
          → OUTBOUND from srcMAC; dstIP added to srcMAC's top_peers (BytesOut).
   Else   (neither MAC is gateway):
          → LAN-to-LAN; counts on both devices.
            Each device records the *other* IP as a LAN peer:
              srcMAC: dstIP → top_lan_peers (BytesOut)
              dstMAC: srcIP → top_lan_peers (BytesIn)
   Local IP (matching local_subnets) is added to the owning device's IP set.

4. BOUNDED TOP-N PEERS (per device, per scope — WAN and LAN heaps are
   completely independent so neither can evict the other)
   Score = bytes_in + bytes_out.
   container/heap min-heap of size ≤ {top,top_lan}_peers_count:
     - existing peer  → increment + heap.Fix.
     - new peer, slot free → heap.Push.
     - new peer, heap full → only insert if newScore > minScore
       (pop min, push new; otherwise drop).

5. SERVING (parallel)
   a. HTTP API   → Aggregator.Snapshot(since) → JSON response
   b. Flusher    → Aggregator.Snapshot()       → JSON file on disk
   c. Controller → Aggregator.Snapshot() + GetSummary() + gateway.Read()
                   → collector.push over the WebSocket, on the controller's schedule
   gateway.Read() (gateway stats on) is /proc for the health and the WAN
   counters, then /sys/class/net for the ports, with the WAN list it just
   counted passed on as role "wan". GET /api/v1/summary serves the same
   report to a polling controller.
```

## Package Structure

```
perch-collector/
├── main.go                    # Entry point, `ports` subcommand, wiring, gateway/subnet resolution, transport
├── collector.example.yaml     # Configuration template (copy to collector.yaml)
├── internal/
│   ├── config/
│   │   └── config.go          # YAML + CLI + env config loading
│   ├── netutil/
│   │   ├── gateway.go         # /proc/net/route + /proc/net/arp parsers
│   │   └── subnets.go         # Interface CIDR enumeration + helpers
│   ├── capture/
│   │   └── capture.go         # libpcap capture; extracts Ethernet + IP
│   ├── aggregator/
│   │   └── aggregator.go      # Per-MAC counters + bounded peer min-heap
│   ├── api/
│   │   └── api.go             # /api/v1/devices, /summary, /reset, /healthz
│   ├── announce/
│   │   ├── announce.go        # HTTP announce (transport poll)
│   │   └── instance.go        # Stable instance id resolution
│   ├── controller/
│   │   └── controller.go      # WebSocket session to the controller (transport websocket)
│   ├── gateway/
│   │   └── gateway.go         # Router health from /proc (conntrack, TCP, load, memory, WAN) + ports from /sys
│   └── flusher/
│       └── flusher.go         # Periodic JSON file writer
├── README.md
├── ARCHITECTURE.md
└── CONFIG.md
```

## Concurrency Model

- **Capture goroutine** — single goroutine reads packets from the pcap handle
  in a blocking loop and calls `Aggregator.Record()` (acquires a write lock
  briefly).
- **API server** — `net/http` default goroutine pool. Handlers call
  `Aggregator.Snapshot()` / `GetDevice()` / `GetSummary()` (read lock).
- **Flusher goroutine** — single goroutine with a ticker. Calls
  `Aggregator.Snapshot()` on each tick (read lock).
- **Controller session** (transport websocket) — the kit's read loop, a
  pinger, the pusher (one push at a time, `Aggregator.Snapshot()` under the
  read lock) and short-lived goroutines for the controller's requests; one
  reconnect loop around them.
- **Gateway reports** — built by the pusher and by `GET /api/v1/summary`
  handlers, possibly at the same time, from copies of one `gateway.Reader`.
  They share its `gateway.Ports`: the kit's port reader and its cache,
  behind a mutex that covers setting the report's WAN list and reading (the
  kit's reader must not have its options changed during a read).
- **Main goroutine** — blocks on the OS signal channel, then orchestrates
  graceful shutdown.

The aggregator uses `sync.RWMutex` so the API server and flusher can read
concurrently with each other and only block when the capture goroutine is
writing.

## Memory Bounds

The previous IP-keyed design grew unboundedly under heavy peer-to-peer traffic
because every remote IP became a top-level entry. The MAC-keyed design has
two natural bounds:

- **Device map** — bounded by the number of physical MACs on the LAN
  (typically <100 for a household, <1000 for a small office).
- **Peers per device** — strictly bounded by `top_peers_count` (default 50,
  WAN) + `top_lan_peers_count` (default 50, LAN) via min-heap eviction. New
  peers that fail to outscore the current minimum of their scope's heap are
  dropped immediately. Worst case per device is 2 × hard_max = 2000 peer
  entries.

In aggregate this keeps RSS well below ~15 MB even when a torrent client
contacts thousands of unique IPs per minute.

## The Gateway agent's ports

With gateway stats on and `ports` not `off`, `main` gives the gateway reader
a `gateway.Ports` (the kit's `hoststat.PortReader`, which applies
docs/infrastructure-view.md section 2.1 of the controller) and logs the port
names once. Every report then carries `ports`, the router's Ethernet ports in
display order with their link state:

```
gateway.Reader.Read()
  WAN list = wan_interfaces, else the default-route interfaces (/proc/net/route, ipv6_route)
  → WAN counters from /proc/net/dev
  → Ports.Read(WAN list): one listing of /sys/class/net, cached facts per
    name + ifindex (5 min), link state read fresh; role "wan" for the WAN list,
    board.json roles for hardware ports
  → Stats.Ports: a pointer, so [] (no ports) and absent (off, or
    /sys/class/net unreadable) stay different on the wire
```

`perch-collector ports` is the first thing `main` checks: it runs the same
ports read with the default-route WAN list, prints the JSON and exits, before
logging, configuration, capture, the listener or any connection. The daemon
itself takes flags only and refuses a leftover argument before capture
starts, so a subcommand typed after a flag cannot start a second collector.

## Graceful Shutdown

```
SIGINT/SIGTERM received
  → Stop capture (close pcap handle)
  → Final flush to disk (if configured)
  → Stop announcing / close the controller socket with 1001 ("restarting")
  → Shutdown HTTP server (with timeout)
  → Exit
```

## Integration Point

The collector's counters are cumulative; the controller computes deltas per
MAC, protocol, peer, service and destination for time-bucketed storage in
MariaDB, and treats a new `summary.started_at` as a restart. Peer enrichment
(ASN, rDNS) is performed there rather than in this daemon. Two transports
carry the same data:

```
perch-collector ──wss push──→ Perch Network Controller ──write──→ MariaDB
                (collector.push every interval,        (per-MAC buckets)
                 schedule set by the controller)

perch-collector :9800 ←──poll── Perch Network Controller
                (GET /api/v1/summary + /api/v1/devices)
```

The shared protocol code (JSON-RPC, the session, the `/proc` readers and the
port reader) is the `perch-agentkit` module, which the Perch AP Daemon uses
as well: both agents report ports as the same JSON array.
