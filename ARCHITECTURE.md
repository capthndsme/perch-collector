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
├── main_gateway.go            # observation + runtime actions wiring, `observe`/`conntrack-flush`/`backup` subcommands
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

## Traffic shaping (`internal/qos`, gateway plan 3 WP-E)

The shaper turns `/etc/config/perch-qos` (structure, written by the
controller's config plane) and the `qos.devices.set` entries (per MAC,
runtime) into kernel objects, following the kernel amendment of 2026-09-23.
Everything sits on the LAN side; sqm keeps the WAN root and its ifb:

```
download: WAN → ifb4<wan> [sqm CAKE] → route/de-NAT → LAN device egress (clsact)
upload:   LAN device ingress (clsact) → route/NAT → WAN egress [sqm CAKE]

clsact filters on every LAN L3 device (flower everywhere, one hook per direction):
  pref 1   arp                              pass
  pref 2   dst_mac multicast/broadcast      pass
  pref 3/4 the router's own v4/v6 addresses pass (src_ip on egress, dst_ip on ingress)
  pref 5   MACs with includeLan             skbedit priority 1:<class> | mirred → ifb
  pref 6/7 each LAN prefix, exactly (+ list exempt, fe80::/10)
                                            pass  (goto chain 1 on a network whose default shapes LAN traffic)
  pref 10  one filter per MAC (handle = the MAC's allocated handle)
                                            classify | pass (unshaped) | drop (blocked)
  pref 100 network default (flower, no keys) classify into the bucket's rest leaf
                                            or the network's overflow class
  chain 1  (only with a LAN-shaping default) pref 10: MACs with their own entry pass;
           pref 100: the default

ifb-pdn (down) and ifb-pup (up), the same tree with each direction's rates:
  htb 1: default 0 (no class = direct, never dropped) ─ 1:1 10 Gbit
    ├ 1:<b>      bucket, rate = ceil (0 = the parent's), nested ≤ 4 deep
    │ ├ 1:1<b>   rest leaf: CAKE unlimited besteffort dual-dsthost/-srchost (per_flow: fq_codel)
    │ └ 1:2xx    device leaf in the bucket: rate min_device_kbit, ceil = cap
    ├ 1:2xx      device without bucket: rate = ceil = cap
    └ 1:2xx      network overflow (n:<network>): devices of a per-device-capped
                 network without a leaf yet share one device's caps
  quantum 1514 on every class; burst = max(1600 B, rate × 1 ms);
  fq_codel limit/flows/memory_limit from globals, target = max(5 ms, 1.5 packet
  times at the ceiling), interval = 100 ms + (target − 5 ms); CAKE memlimit.
```

- **Plan** (`plan.go`, pure): config + entries + LANs (`ubus call
  network.interface dump`, less masquerading zones and default-route
  interfaces; an enabled sqm queue on a LAN device excludes it:
  `qos_conflict_sqm_on_lan`) + neighbour table + clock → the desired classes
  and filters. Class minors of devices are allocated per `d:<mac>|<parent>`,
  so moving a device to another bucket creates its new class first, repoints
  the filter (`filter replace`), then deletes the old class: no queue is
  dropped. A minor still in the kernel is never reused in the same apply.
- **Diff** (`diff.go`): the kernel is read back with one `tc -s -j -force
  -batch` (both ifbs, every LAN device's qdiscs and filters) and compared:
  rates (exact bytes/s), bursts (2 %), leaf kind and options, filter match
  and action. Only differences become commands (`class change`, `qdisc
  change`, `filter replace`, adds, deletes last); a re-parented bucket is
  deleted with its subtree and added again (the only non-hitless change).
  A kernel that matches gives an empty batch: every apply is idempotent.
- **Engine** (`engine.go`): the daemon ticks every 2 s (neighbour dump over
  rtnetlink, file stamps, interfaces every 10 s) and replans only when an
  input moved (config, sqm, firewall, TZ, device set, LANs, active schedules,
  exhausted quotas, neighbours on per-device-capped networks), plus a full
  verify every 60 s. The CLI (`perch-collector qos …`) and the hotplug/init
  scripts run the same reconcile under the same flock
  (`/tmp/perch-qos/lock`) and share `state.json`. The ifbs are created over
  rtnetlink (no `ip-full`); tc is `tc-tiny` (the spike proved it suffices).
- **Stats** (`stats.go`): one `tc -s -j -batch` per push (and every 5 s
  without pushes while quotas exist): class counters (leaf qdisc drops and
  backlog added), sqm's root qdiscs, and, for quotas, the per-MAC filters'
  action byte counters, which count a MAC on every LAN device and both hooks
  whatever class it is in. Quota deltas survive filter replacement.
- **Schedules**: POSIX TZ from `/tmp/TZ` (`tz.go`, tested against zoneinfo);
  inactive until the clock is known to be synced.
- **Safety**: kernel state outlives the daemon (a crash or restart leaves the
  tree enforcing); a broken perch-qos never tears shaping down; `qos stop`
  and `globals.enabled '0'` remove every Perch object within one tick; the
  router's own MACs are refused; router-originated and LAN↔LAN traffic
  never enters a Perch class (pref 3-7), so the collector's socket to a
  controller on the LAN is never shaped; the socket is marked DSCP CS6 for
  sqm's CAKE on the WAN.
- **Tests**: goldens render the controller planner's own output
  (`testdata/planner-*`, `testdata/golden/`); a namespace test
  (`unshare -rn`, skipped where unavailable) applies it to a real kernel,
  checks idempotence, hitless schedule switches and `stop`; the captured
  kernel read (`testdata/kernel-weekday-noon.json`) keeps the parser and the
  diff tested without a namespace.

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
