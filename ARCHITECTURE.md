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

## Guest portal

`internal/portal` is the router side of the Perch guest portal (wire contract
in CONFIG.md, "Guest portal"; controller domain in the controller repository,
`docs/gateway/portal.md`). Owner decision 27: enforcement is Perch's own
nftables, never openNDS, so several portals run side by side (one per guest
network: a plain device, a bridge, a VLAN), IPv6 is gated in the same pass,
and nothing depends on DHCP leases.

```
table inet perch_portal (collector-owned; fw4 reload/restart leave it alone)
  per portal p<id>: set p<id>_auth (MACs)  [p<id>_bind4 MAC.IPv4 when ipBinding]
                    walled garden: p<id>_wg4/_wg6 (timeout 1h, dnsmasq nftset= or resolved by
                    the collector), p<id>_wgnet4/_wgnet6 (static CIDRs); p<id>_dns (DNS meter)
  prerouting (dstnat-5):  iifname <dev> → not authorised, tcp 80, not walled → redirect :2080
  forward   (filter-5):   iifname <dev> → authorised (or walled garden) returns to fw4, else reject
  input     (filter-5):   iifname <dev> → DNS (rate-limited per MAC before auth), DHCP,
                          DHCPv6 when the network serves it, :2080, ICMP; everything else rejected
table netdev perch_portal_acct
  per portal device: ingress / egress chains at priority -500 (before any flowtable),
  router-local and multicast traffic excluded, per-MAC counter sets p<id>_up / p<id>_down
  data cut: quota q<group>_<gen> { over <bytes the group has left> } per group with a data
  quota, map p<id>_quota (MAC → quota), `quota name ether saddr|daddr map @p<id>_quota drop`
  before the counters (upload + download together, like the group's quota)
/usr/share/nftables.d/chain-pre/input/30-perch-portal.nft
  accepts the same ports in fw4's input chain on the portal devices (fw4 includes it on
  every reload; a zone with input REJECT would otherwise refuse the guest pages)
```

`Engine` (engine.go) holds the working set in Go and writes every change
through to the store; one mutex serialises the RPC handlers, the guest pages
and the tick. `applyStructuralLocked` re-renders both tables in one nft
transaction (create, delete, create) after folding the old counters into the
grants and carrying the walled garden's resolved addresses over; it runs at
start, on `portal.configure` and whenever a table is found missing. Single
grant changes are element transactions (`ElementOps`; a delete is preceded by
an idempotent add so it cannot fail on a missing element).

Tick (tick.go, every `enforceIntervalSeconds`): read both tables as JSON; a
missing table is re-applied (not a deauth); a MAC in an auth set without a
Perch grant was added outside Perch and is removed and journaled
(`external_auth`, decision 25); a Perch MAC missing from its set was removed
outside Perch and its grant ends `router_deauth`; counter deltas go to each
device's current grant (a counter below its baseline was reset); a group that
moved traffic is charged the tick's time once, on its lowest-order grant;
neighbours activate pending grants and teach addresses; exhausted groups end
every device. Ending a grant removes the MAC, flushes the device's conntrack
entries (every known address; deauth leaves established flows running
otherwise), journals `grant_ended` with the final counters and keeps its usage
for the group until the controller's `base*` includes it.

Exact data quotas (quota.go). The tick alone would overshoot a data quota by
what a device moves in one tick (30 MB at 52 Mbit/s and 5 s, lab 2026-09-23),
so the kernel cuts the device off at the byte: every group with a data quota
and a device on a counting portal has one named nft quota object seeded with
the bytes the group has left, shared by the group's devices through the
portal's MAC → quota map. The rule runs before the counters, so the quota
consumes exactly what the counters count and a dropped packet is not usage.
The map follows every grant change in the same transaction as the auth sets
(a device is cut from its first byte). The tick keeps the books: it reads
the counters and the quota objects in one dump; a group the kernel cut off is
used up (the unusable remainder under one packet, at most 256 KiB, is charged
to its current grant so the controller sees the quota used) and its grants
end like any exhausted group (deauth, conntrack flush, `grant_ended` quota);
a group whose kernel remainder drifted from the books by more than 256 KiB
(the controller moved its `base*`, another router used some of a shared
voucher) is re-seeded: a quota object's limit cannot change in place, so the
next generation is created, the MACs repointed and the old object deleted in
one transaction. Every full re-render folds the counters first and seeds the
objects with what is left, so a collector restart neither loses nor forgives
bytes. While any group is within 10 % of its quota the tick runs every
second. A kernel without `nft_quota`/`nft_objref` (probe at start,
`enforcement.quota`) falls back to the tick alone.

Store (store.go, decision 18): SQLite (mattn/go-sqlite3, the amalgamation
linked into the static cgo build, `sqlite_omit_load_extension`; a pure-Go
SQLite would add several MB and newer releases need Go > 1.22) in RAM,
snapshotted with `VACUUM INTO` + fsync + rename. Grant-class writes (grants,
groups, vouchers, journal, keys, nonces, config) are snapshotted at once;
counters every flush interval. storage.go finds what backs the path
(`/proc/mounts`: overlay → its upper layer, jffs2/ubifs/mtd = flash, mmcblk =
eMMC, sd/nvme = disk, tmpfs = RAM) and picks the default interval; a path
under /mnt, /media, /srv or /data that is not mounted, or an
`portal_storage_mount` that is not mounted (and has no marker), falls back to
the default path. Clock (clock.go): the controller's `serverNow` offset is
applied beyond 2 s; after a reboot without NTP time runs on from the last
`savedAt`.

Guest pages (fas.go): one `http.Server` with a listener per router address
(IPv4 and global IPv6) on the enforcing portals' devices, opened and closed
as portals and addresses change (configure, start, every tick; a failed bind
is retried on the next tick); nothing listens while no portal runs, and
never on the wildcard address. The portal is the
one whose device holds the connection's local address, the guest the
neighbour-table MAC of the TCP source on that device (a LAN host reaching the
address gets 403). Templates (template.go) are the controller's builtin set
(byte-identical, digest of the empty set) or a stored custom set, checked
again on arrival, rendered with escaped variables under a CSP; SVG assets get
`default-src 'none'`, template HTML is never served as an asset.

Offline redemption (guest.go): the controller's `planVoucherRedemption` on the
router (groups.go ports its group math): verifier lookup, status, device
slots (a voucher follows the newest device, the first one leaves `moved`),
time before data (a time voucher over a running data bucket swaps it into
the queue; anything else queues), a first-use wall clock started at
redemption, a `localRef` grant and an `offline_redeemed` journal entry.
Offline-queued entitlements are promoted by the router only while the
controller is away. The held list arrives in parts (part 1 replaces, later
parts of the same `serverNow` append); `firstUsedAt` decides whether
`redeemBy` still applies. A guest sign-in goes offline only when the session
is gone (no session, or it ended under the call): a live session that does
not answer within 8 s is `controller_unreachable`, because the controller may
still be answering (it refuses what it could not start within 5 s).

Paid Hotspot and click-through (hotspot*.go; controller contract in
`docs/gateway/portal.md` §14). The router runs every checkout itself, so
paid access keeps working through a controller outage:

```
guest: POST /portal/checkout {terminalId}   terminal free + online → checkout open (price table copied: locked)
terminal: session → heartbeat (sees the checkout) → coins {checkoutRef, eventId, amount}   each coin resets the idle timer
guest page polls GET /portal/checkout (checkout.js): running total, preview, seconds left
done (guest or terminal) / idle timeout (60 s default) with credit → finalise
  record (signed) → reference code = HMAC(checkoutKey, record) → local voucher (verifier)
  grant with localRef in local group c:<checkoutRef> (placed like an offline redemption:
  current, queue behind live time, swap over a data bucket) → journal checkout_finalized
idle timeout with nothing paid → expired; paid but below the smallest rate → expired + checkout_unclaimed
controller sync: the record becomes voucher v:<id> + grant; full authorize maps
  localRef → grantId and c:<ref> → v:<id> (ended usage follows), local voucher dropped
```

A terminal authenticates each request with an HMAC of its token (never sent),
a router-issued session (a replayed session request is refused by its nonce)
and a strictly increasing sequence number; coins carry the terminal's own
event id, so a retried coin counts once and a coin for a closed checkout is
journaled once as unclaimed money. A reference code the controller has not
acknowledged yet is redeemed locally (online or not) and moves the remaining
entitlement to the new MAC (the old grant ends `moved`). Click-through grants
are local groups `t:<localRef>` (→ `g:<grantId>`), limited per device by the
uses the router records. State: tables `terminals`, `checkouts` (closed ones
kept 24 h for receipts, at most 2000), `local_vouchers`, `clickthrough_uses`
(30 days) in the portal store; coins, sessions and finalisations are
grant-class writes, heartbeats counter-class.

The controller hook is `controller.Options.Portal`: the client registers the
portal.* handlers, adds the hello details, and hands the session to the engine
(`SetAgent`) while it is open. `main_portal.go` builds it (portal auto = OpenWrt
with the WebSocket transport), re-applies the held grants before any
controller is reached, and with `portal off` removes what a previous run left.

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
