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
├── main.go                    # Entry point, `ports` subcommand, wiring, gateway/subnet resolution, transport
├── main_config.go             # Config plane wiring, SIGHUP, `gateway-config` subcommand
├── collector.example.yaml     # Configuration template (copy to collector.yaml)
├── internal/
│   ├── config/
│   │   ├── config.go          # YAML + CLI + env config loading
│   │   └── config_plane.go    # config_access, managed_config, storage_path, ...
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
│   │   └── gwconfig.go        # Config plane on the socket: hello block, RPCs, notifications
│   ├── gwconfig/              # Config plane: access, read + redaction, capabilities, storage, change watch
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
- **Config plane watcher** (OpenWrt, transport websocket) — one goroutine
  for the daemon's life: stats the readable configs on the controller's
  interval, re-hashes on SIGHUP, and notifies on the current session. The
  controller's `gateway.*` requests run on the kit's request goroutines; the
  plane's state is behind one mutex, and the ubus call for the author runs
  outside it so a hello never waits for it.
- **Main goroutine** — blocks on the OS signal channel, then orchestrates
  graceful shutdown. SIGHUP has its own goroutine (the config plane's
  trigger) and no longer ends the daemon.

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

## The config plane

The router side of the managed gateway's config plane (plan 1 of the design,
promoted into the controller's `docs/gateway/`). This version is read-only:
capabilities, reads with secrets redacted, change notifications with an
author. Everything is additive on `perch-collector.v1`: an older controller
drops the unknown hello key, sends no `gatewayConfig` in `agent.configure`
(the plane then stays off) and never calls the new methods; an older
collector answers them with -32601.

Built in `main_config.go` when the collector runs on OpenWrt with transport
websocket; `internal/gwconfig` holds the logic, `internal/controller/gwconfig.go`
the wire. UCI parsing, hashing, redaction and the package database come from
the kit (`perch-agentkit/openwrt/uci`, `openwrt/pkgdb`, `openwrt/ubus`).

**Router opt-in.** `config_access` none (default) / read / write, and the
`managed_config` allowlist; see CONFIG.md. Effective access = the configured
one capped at `read` in this version. Readable = allowlist minus the denylist
(`perch-collector perch-apd rpcd uhttpd dropbear luci`) plus the ledger
`perch-managed`; nothing with access `none`.

**Hello** (`collector.hello` params): the capability `gateway_config` joins
`capabilities` whenever the plane exists, and

```json
"gatewayConfig":{"protocol":1,"access":"read","accessConfigured":"write","transportOk":false,
  "hashes":{"network":"3f9a…","firewall":"77c0…","perch-managed":"…"},
  "apply":{"state":"idle"},"results":[]}
```

`access` is effective, `accessConfigured` appears only when the router asks
for more than this version does. `transportOk` = `server_url` is https with
verification on (`announce_tls_insecure` off). `hashes` = SHA-256 of each
readable config file that exists (absent = no file; none at all with access
`none`); they are also the baseline later notifications are judged against.
`apply` and `results` are always idle/empty until applies exist.

**`agent.configure`** may carry
`"gatewayConfig":{"mode":"off"|"observe"|"managed","authoritative":bool,"watchSeconds":30,"debounceSeconds":5}`.
Mode `off`, an unknown mode, or no block at all means no watching. Seconds are
clamped to 10..600 and 1..60. A session's end turns the mode off until the next
configure.

**Requests from the controller**

| Method | Params | Result |
|---|---|---|
| `gateway.capabilities` | `{}` | `{protocol, access, accessConfigured, allowedConfigs[], transportOk, allowInsecure, confirmMaxSeconds, backend:"ubus"\|"uci-cli"\|null, openwrt:{release,revision,target,arch,board}\|null, firewall:"fw4"\|"fw3"\|null, packageManager:"opkg"\|"apk"\|null, packages:{name:version}, configs[], hashes{}, uncommitted[], luciPending, apply:{state:"idle"}, capture:{networks:[{network,device}]}, flash:{path,totalBytes,freeBytes}\|null, storage:{path,exists,mountPoint,fsType,device,medium,onRoot,readOnly,totalBytes,freeBytes}\|null}` |
| `gateway.config.read` | `{configs?:[…]}` (default: every readable config) | `{readAt, configs:[{name, hash, missing?, sections:[{name, type, anonymous, index, options:{k: string\|string[]}, secrets?:{k:"hmac:…"}, hash}]}], ledger:[{perchId, config, section, domain}], uncommitted[], luciPending}` |

- `packages` lists only the kit's watch list (`firewall4 firewall dnsmasq
  dnsmasq-full odhcpd odhcpd-ipv6only sqm-scripts kmod-sched-cake opennds mwan3
  pbr wireguard-tools luci rpcd`), read from `/usr/lib/opkg/status` or
  `/lib/apk/db/installed`.
- A read is the committed files, never staged changes. `missing: true` = an
  allowlisted config without a file (hash `""`, no sections). Sections are in
  file order with libuci's names for anonymous ones; the section `hash` is the
  SHA-256 of `["<type>",{options sorted by name, secrets as fingerprints}]`.
- Refusals are -32000 with `data.error`: `not_managed` (access `none`),
  `config_not_allowed` (+ `data.configs`, the refused names; nothing is read),
  `read_too_large` (a file over 2 MiB, or the read over 2 MiB / 2000 sections);
  `read_failed` for a file that cannot be read or parsed. Bad params are
  -32602. `gateway.config.apply`, `.confirm`, `.rollback` and `.ack` do not
  exist yet (-32601).

**Notification to the controller:** `gateway.config.changed`

```json
{"hashes":{"network":"…","firewall":"…"},"changed":["firewall"],"origin":"router",
 "author":{"kind":"luci","user":"root","via":"trigger"},"at":"2026-09-23T10:00:15Z","uncommitted":[]}
```

`hashes` = every readable config now (a deleted one is absent). `origin` is
`router`, or `perch` with `applyId` for the plane's own writes: the apply
engine records each commit's hash with `Plane.RecordOwn(config, hash,
applyID)`, and a change to exactly that hash is reported once that way (own
echoes and router edits go in separate notifications). `author.kind`:
`luci` (+ `user`) when procd's trigger saw the change and `ubus call session
list` has exactly one logged-in session, `cli` when only polling saw it,
`unknown` when the trigger saw it without a single LuCI user, `perch` for
echoes. `uncommitted` = readable configs with staged, uncommitted changes
(`/tmp/.uci`, other rpcd sessions).

**Change detection** (`gwconfig.Plane.Run`, one goroutine for the daemon's
life, started by the controller client):

```
while mode != off and access != none:
  every watchSeconds, or at once on SIGHUP (Trigger):
    stat every readable config; re-hash when size/mtime moved (all of them on SIGHUP)
    hash != last reported → dirty (since t); back to the reported hash → clean again
  when dirty and quiet for debounceSeconds:
    LuCI apply pending (/var/run/rpcd/snapshot-files non-empty) → hold (max 5 min)
    else notify on the current session; without one, stay dirty
hello → the hello's hashes become the reported baseline, dirty is cleared
```

The package's init script adds a procd reload trigger per allowlisted config
(when `config_access` is not `none`) and a `reload_service` that runs `start`
(procd restarts the instance only if its parameters changed) and sends
SIGHUP; the daemon handles SIGHUP (it used to end the process). A CLI `uci
commit` without `reload_config`, an editor or scp are caught by polling.

`perch-collector gateway-config [config...]` runs capabilities and a read
with the settings of `/etc/config/perch-collector` and prints them.

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
