# Architecture

## Overview

perch-collector (the Perch Network Collector) is a single-binary daemon. It
captures packet headers on a LAN interface (or, on the router, on every
LAN-side network with `capture_networks`), classifies each frame against the
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
├── main.go                    # Entry point, `ports`/`dhcp` subcommands, wiring, gateway/subnet resolution, transport
├── main_capture.go            # the capture set: single engine or netcap reconciler, classifier per engine
├── main_gateway.go            # observation + runtime actions wiring, `observe`/`conntrack-flush`/`backup` subcommands
├── collector.example.yaml     # Configuration template (copy to collector.yaml)
├── internal/
│   ├── config/
│   │   └── config.go          # YAML + CLI + env config loading
│   ├── netutil/
│   │   ├── gateway.go         # /proc/net/route + /proc/net/arp parsers
│   │   └── subnets.go         # Interface CIDR enumeration + helpers
│   ├── capture/
│   │   └── capture.go         # libpcap capture of one device; extracts Ethernet + IP
│   ├── netcap/                # multi-interface capture (capture_networks)
│   │   ├── plan.go            # MakePlan: netifd + firewall + /sys → targets, local prefixes, router MACs
│   │   ├── discover.go        # netifd dump, masq zones, SysFS
│   │   ├── reconciler.go      # one engine per target, hot add/remove
│   │   └── report.go          # gateway.networks
│   ├── aggregator/
│   │   └── aggregator.go      # Per-MAC counters + bounded peer min-heap
│   ├── api/
│   │   └── api.go             # /api/v1/devices, /summary, /reset, /healthz
│   ├── announce/
│   │   ├── announce.go        # HTTP announce (transport poll)
│   │   └── instance.go        # Stable instance id resolution
│   ├── controller/
│   │   ├── controller.go      # WebSocket session to the controller (transport websocket)
│   │   ├── gateway.go         # observe section of a push, gateway.observe, net.conntrack_flush, gateway.backup
│   │   └── lastgood.go        # dialer with the last good controller address
│   ├── gateway/
│   │   └── gateway.go         # Router health from /proc (conntrack, TCP, load, memory, WAN) + ports from /sys
│   ├── observe/               # Observation channel: dhcp, neighbors, interfaces, upnp, mwan3, resolver, system
│   │   ├── observer.go        # parts, Section, per-part read intervals and fingerprints, Pacer
│   │   └── env.go, uci.go     # fixture-tree root, uci/ubus runner, `uci show` parser
│   ├── gatewayops/
│   │   ├── conntrack.go       # net.conntrack_flush over ctnetlink
│   │   └── backup.go          # gateway.backup: sysupgrade -b + redaction
│   └── flusher/
│       └── flusher.go         # Periodic JSON file writer
├── README.md
├── ARCHITECTURE.md
└── CONFIG.md
```

## Concurrency Model

- **Capture goroutines** — one per captured device reads packets from its
  pcap handle (reads time out every 250 ms so a stop is seen) and calls
  `Aggregator.RecordPacket()` (acquires the shared write lock briefly). Each
  has its own classifier, so nDPI's module and flow table are never shared
  between two captures. The gateway-MAC set is an immutable map behind an
  atomic pointer, read before the lock.
- **Reconciler** (capture_networks) — one goroutine re-reads netifd every
  `capture_rescan` seconds and on SIGHUP, starts and stops engines under its
  own mutex and updates the aggregator's router MACs, local subnets and scope
  prefixes before new engines start.
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

## Several networks

With `capture_networks` the collector on the router captures every
LAN-side network (gateway plan 1 section 8.3; settings and wire format in
CONFIG.md, "Several networks"):

```
Reconciler.Reconcile()  (start, every capture_rescan s, SIGHUP; the package
                         sends SIGHUP on every netifd interface event)
  Discoverer: ubus call network.interface dump (fresh) + uci show firewall
              (masq zones, 30 s cache)
  MakePlan (pure):
    LAN side  = not loopback, no default route, not in a masq zone, not a
                configured wan_interface
    auto      = LAN side, up, L3 device, proto static|none, carries no VLAN
                devices; minus capture_exclude; plus named networks/devices
    refused   = WANs, bridge ports (/sys/.../master), devices whose captured
                VLAN devices sit on them (/sys/.../upper_*)
    one Target per L3 device (aliases share it)
    LANPrefixes = every LAN-side prefix (v4, v6, assigned v6) → local subnets
                  and the routed-LAN scope rule
    GatewayMACs = every LAN-side L3 device's MAC → the aggregator's pivots
  stop engines whose device left the plan or changed network
  Apply(plan) → Aggregator.SetGatewayMACs / SetLocalSubnets / SetRoutedLAN
  open new ones: capture.NewForNetwork(device, network, classifier of its
                 own, ndpi_max_flows / engines, floor 4096), go Run()
```

Every frame carries its engine's network in `FlowInfo.Network`: the local
device gets `network` (last) and `networks` (seen set, cap 8), and the
per-network capture counters count it. The routed-LAN rule sits in
`Aggregator.RecordPacket` ahead of the WAN cases: a frame through a pivot MAC
whose far address is in the LAN prefixes (or link-local) is LAN scope on the
local device only, never a device row for the router. A flow routed between
two captured networks is thus seen twice, once per side, and each sighting
lands on a different device and a different network. The single-interface
mode keeps one engine and its resolution as before; `routed_lan auto` leaves
the old rule there.

The gateway report's `networks` (Reporter) re-uses the plan's LAN list
(netifd, 5 s cache), adds `/proc/net/dev` counters and rates (per device,
at least a second between two samples), the captured set and the
aggregator's per-network device counts and capture counters.

## The observation channel

On the router the collector reports runtime state that is not traffic
(gateway plan 2 section 3; wire format in CONFIG.md, "The observation
channel"). `main` builds one `observe.Observer` with a reader per part that is
on (`dhcp_leases`, `observe`, `observe_parts`); the interfaces reader is
shared, so DHCP leases and neighbours are tagged with their network.

```
push (every metricsIntervalSeconds)
  for each part the Observer has:
    Observer.Read(part)          cached per part (neighbours 60 s, interfaces 5 s,
                                 upnp/mwan3 15 s, resolver/system 60 s; dhcp watches
                                 its files); value + fingerprint without uptimes
    Pacer.Due(session, part, fp) first in the session, changed (neighbours: ≥ 60 s
                                 after the last send), or refresh due
  → observe {full?, <due parts>} in collector.push; Pacer.Sent after the write
gateway.observe {parts?}         Observer.Section(parts, fresh) + collectedAt
GET /api/v1/summary              Observer.Section(all, cached) for polled collectors
```

Readers only read: files under `Env.Root` (a fixture tree in tests), the
`uci` and `ubus` CLIs through `Env.Run`, rtnetlink for the neighbour table,
`/proc` for processes and sockets. A part that cannot be read is absent from
the push (the controller keeps its data), never an empty report.

The runtime actions sit beside it in `internal/gatewayops`: the conntrack
flush dumps the table over ctnetlink, deletes matching flows by their
original tuple and skips the collector's own controller connection (its
endpoints come from the controller dialer); the backup runs `sysupgrade -b`
into a temporary directory and rewrites the tar.gz with secrets redacted.
Both run one at a time. Capabilities, dispatch and the observe section live
in `internal/controller/gateway.go`, apart from `controller.go`, so the
config plane's hello fields and requests stay separate.

`internal/controller/lastgood.go` replaces the kit HTTP client's dial
function: it resolves the controller's name itself, dials each address, and
falls back to the address of the last accepted session when resolution
fails. The TLS server name and Host header come from the URL, so they stay
the name.

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
