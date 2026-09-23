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
├── main.go                    # Entry point, `ports`/`dhcp` subcommands, wiring, gateway/subnet resolution, transport
├── main_gateway.go            # observation + runtime actions wiring, `observe`/`conntrack-flush`/`backup` subcommands
├── main_config.go             # Config plane wiring, SIGHUP, `gateway-config` subcommand
├── main_portal.go             # Guest portal wiring (portal auto/off, held grants re-applied at start)
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
│   │   ├── gateway.go         # observe section of a push, gateway.observe, net.conntrack_flush, gateway.backup
│   │   ├── lastgood.go        # dialer with the last good controller address
│   │   └── gwconfig.go        # Config plane on the socket: hello block, RPCs, notifications
│   ├── gwconfig/              # Config plane: access, read + redaction, capabilities, storage, change watch
│   ├── gateway/
│   │   └── gateway.go         # Router health from /proc (conntrack, TCP, load, memory, WAN) + ports from /sys
│   ├── observe/               # Observation channel: dhcp, neighbors, interfaces, upnp, mwan3, resolver, system
│   │   ├── observer.go        # parts, Section, per-part read intervals and fingerprints, Pacer
│   │   └── env.go, uci.go     # fixture-tree root, uci/ubus runner, `uci show` parser
│   ├── portal/                # Guest portal: nftables enforcement, grant store, tick, guest pages
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

Guest pages (fas.go): one `http.Server` on `:portal_port`; the portal is the
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
controller is away.

The controller hook is `controller.Options.Portal`: the client registers the
portal.* handlers, adds the hello details, and hands the session to the engine
(`SetAgent`) while it is open. `main_portal.go` builds it (portal auto = OpenWrt
with the WebSocket transport), re-applies the held grants before any
controller is reached, and with `portal off` removes what a previous run left.
## The config plane

The router side of the managed gateway's config plane (plan 1 of the design,
promoted into the controller's `docs/gateway/`): capabilities, reads with
secrets redacted, change notifications with an author, and, with
`config_access write`, applies with confirm and rollback, the sync ledger, the
boot guard and package installs ("Writes" below). Everything is additive on
`perch-collector.v1`: an older controller drops the unknown hello key, sends
no `gatewayConfig` in `agent.configure` (the plane then stays off) and never
calls the new methods; an older collector answers them with -32601.

Built in `main_config.go` when the collector runs on OpenWrt with transport
websocket; `internal/gwconfig` holds the logic, `internal/controller/gwconfig.go`
the wire. UCI parsing, hashing, redaction and the package database come from
the kit (`perch-agentkit/openwrt/uci`, `openwrt/pkgdb`, `openwrt/ubus`).

**Router opt-in.** `config_access` none (default) / read / write, and the
`managed_config` allowlist; see CONFIG.md. Readable = allowlist minus the
denylist (`perch-collector perch-apd rpcd uhttpd dropbear luci`) plus the
ledger `perch-managed`; nothing with access `none`. Writable = the allowlist
minus the denylist (never the ledger, which only the agent writes).

**Hello** (`collector.hello` params): the capability `gateway_config` joins
`capabilities` whenever the plane exists, and

```json
"gatewayConfig":{"protocol":1,"access":"write","transportOk":false,
  "hashes":{"network":"3f9a…","firewall":"77c0…","perch-managed":"…"},
  "apply":{"state":"pending_confirm","applyId":"g3-a41","kind":"apply","deadline":"2026-09-23T10:01:30Z","protected":true},
  "results":[{"applyId":"g3-a40","kind":"apply","outcome":"rolled_back","reason":"reboot","at":"…","hashes":{…}}],
  "signing":{"required":true,"challenge":"<32 hex, new per session>","key":"paired","keyId":"38545dab8f16e8a2","windowSeconds":300},
  "management":{"network":"lan","device":"br-lan","controllerAddress":"192.168.1.5","reportedAt":"…"}}
```

`access` is the configured access (`accessConfigured` appears only when an
older build capped it). `transportOk` = `server_url` is https with
verification on (`announce_tls_insecure` off). `hashes` = SHA-256 of each
readable config file that exists (absent = no file; none at all with access
`none`); they are also the baseline later notifications are judged against.
`apply` is `{"state":"idle"}` or the pending job (`applying` while it
commits, `pending_confirm`, `rolling_back`); `results` are outcomes not yet
acknowledged with `gateway.config.ack`. `signing` and `management` appear with
access `write`; `signing.key` is `config_sign_key` (the router's own key is
set), `paired` with the `keyId` of the pairing's key, or `none` (no key yet:
signed writes are refused with `not_paired`). The api_key is never a signing
key.

**`agent.configure`** may carry
`"gatewayConfig":{"mode":"off"|"observe"|"managed","authoritative":bool,"watchSeconds":30,"debounceSeconds":5}`.
Mode `off`, an unknown mode, or no block at all means no watching. Seconds are
clamped to 10..600 and 1..60. A session's end turns the mode off until the next
configure.

**Requests from the controller**

| Method | Params | Result |
|---|---|---|
| `gateway.capabilities` | `{}` | `{protocol, access, accessConfigured, allowedConfigs[], transportOk, allowInsecure, confirmMaxSeconds, backend:"ubus"\|"uci-cli"\|null, openwrt:{release,revision,target,arch,board}\|null, firewall:"fw4"\|"fw3"\|null, packageManager:"opkg"\|"apk"\|null, packages:{name:version}, configs[], hashes{}, uncommitted[], luciPending, apply:{state,…}, capture:{networks:[{network,device}]}, flash:{path,totalBytes,freeBytes}\|null, storage:{path,exists,mountPoint,fsType,device,medium,onRoot,readOnly,totalBytes,freeBytes}\|null, signing?:{…}, management:{network,device,controllerAddress,reportedAt}\|null, installAllowlist[]}` |
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
  -32602. The write methods are below.

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

### Writes: apply, confirm, rollback (config_access write)

The apply engine (`internal/gwconfig/engine.go`, plan 1 section 3.4). One job
at a time: a config apply or a package install.

**Write gate** (every write method): access `write`, else `not_managed`; then
either `transportOk` (verified TLS), or the router's `config_allow_insecure
'1'` plus a signed request (below), else `insecure_transport` (no opt-in) or
`signature_required` (opt-in, unsigned; `not_paired` for a signed request
when the router has no key). Apply and package install also need
the controller's `agent.configure` mode `managed` on the session
(`not_managed`); confirm, rollback and ack do not. Secret values
(`{"$secret"}`) are refused over anything but verified TLS, signed or not.

**`gateway.config.apply`**

```json
{"applyId":"g3-a41","kind":"apply","protected":false,"confirmTimeoutSeconds":90,"dryRun":false,
 "base":{"network":"3f9a…","dhcp":"77c0…"},
 "ops":[
  {"op":"adopt","config":"dhcp","section":"cfg03a1b2","perchId":"h9","renameTo":"perch_h9","domain":"dhcp_hosts"},
  {"op":"put","config":"dhcp","section":"perch_h1","type":"host",
   "options":{"name":"camera","mac":"02:00:00:00:00:20","ip":"192.168.1.20","tag":["x","y"],"leasetime":{"$keep":true}},
   "position":{"after":"lan"}},
  {"op":"put","config":"network","section":"wg0","type":"interface","options":{"private_key":{"$secret":"s7"}}},
  {"op":"delete","config":"dhcp","section":"perch_h3"},
  {"op":"order","config":"firewall","type":"rule","sections":["perch_r40","perch_r41"]}],
 "ledger":{"set":[{"perchId":"h1","config":"dhcp","section":"perch_h1","domain":"dhcp_hosts"}],"remove":["h3"]},
 "secrets":{"s7":"<value>"}}
```

- `applyId` `^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`; `kind` `apply` | `revert` | `adopt`
  (only reported back); at most 2000 ops and 256 secrets.
- `base`: the file hash of **every config an op touches** (required; `""` =
  the file does not exist) and optionally of `perch-managed`. Any mismatch is
  `stale_base` with `data.configs` and `data.hashes` (all readable hashes now).
- `put` creates the section or fully replaces an owned one: listed options are
  set (a list replaces the whole list; `[]` = no option), unlisted ones are
  deleted, `{"$keep":true}` leaves the router's value, `{"$secret":ref}`
  resolves from `secrets`. A different `type` deletes and re-adds it in place.
  `position` `{after|before: section}` places it. An existing section must be
  owned (in the ledger, or adopted earlier in the job), else `not_owned`.
- `adopt` registers an existing section under `perchId` (overwriting that perch
  id's entry: a re-link); an anonymous section must be renamed (`renameTo`),
  a taken name is `name_taken`, a section ledgered under another id is
  `not_owned`.
- `delete` removes an owned section (absent = nothing to do) and its ledger
  entries. `order` puts owned sections of `type` into the slots they occupy
  together, in the listed order; foreign sections do not move.
- `ledger.set` may only name sections the job created or adopted, or re-link
  an existing perch id; anonymous names are refused. `ledger.remove` drops
  entries by perch id. Values: no control characters, at most 4096 bytes;
  names `^[A-Za-z0-9_]{1,64}$`; perch ids at most 24 characters.

Result:

```json
{"state":"pending_confirm","applyId":"g3-a41","deadline":"2026-09-23T10:01:30Z","confirmTimeoutSeconds":90,
 "protected":false,"hashes":{"dhcp":"…","perch-managed":"…"}}
```

`state`: `pending_confirm` (committed, window open); `applied` (only the
ledger changed: adopting named sections, ledger edits; no window, nothing
reloaded); `noop` (nothing to change; `hashes` = all readable); `dry_run`
(`changes:[{config,section,op,option?,value?}]`: rpcd's `uci changes`, secret
values `<redacted>`; nothing kept). A retried apply with the pending job's id
returns the pending reply again. The window is `confirmTimeoutSeconds`
(default 90) clamped to 30..`config_confirm_max`; a job that touches the
management path gets at least 300 s (`protected: true`, whether the controller
flagged it or the agent found it).

**Sequence** (the router's rpcd; a Go-rendered file when rpcd has no `uci`
object, because the uci CLI would also commit deltas others staged in
`/tmp/.uci`):

```
validate (gate, LuCI apply pending -> busy luci_pending, base, simulate ops,
          foreign /tmp/.uci/network deltas -> foreign_staged)
snapshot touched configs (+ ledger) -> /etc/perch-collector/rollback/<id>/before/, fsync
pending.json {applyId, kind, deadline, configs, hashesBefore, committed:false}, fsync
marker /var/run/perch-collector/apply-<id>  (tmpfs: gone after a reboot)
private rpcd session (session create + grant uci read/write on those configs, tagged perch=<id>)
stage ops -> commit per config in apply order (system network dhcp firewall sqm perch-qos opennds mwan3 pbr, rest a-z)
            rpcd's commit sends config.change; procd reloads the services
write ledger; read the files back and compare with the simulation
snapshot after/, pending.json committed:true + hashesAfter; RecordOwn (echo suppression)
reply pending_confirm
0.5 s, then wait for netifd (2 s minimum, no interface pending, 20 s max)
close the session (1000 "reconnecting after apply"); redial at once, then every 2 s
confirm on a later session -> drop snapshot, record and marker
deadline without confirm, gateway.config.rollback, or a failure after the first commit
  -> note router edits of the window (discarded), restore the files atomically,
     config.change per restored config in apply order, result -> results.json,
     gateway.config.result if a session is up; redial fast for 2 minutes
```

A failure before the first commit leaves nothing (`apply_failed`, or `busy`
with `reason` `uncommitted`/`luci_pending` when rpcd refuses). A failure after
it rolls back (`apply_failed` with `data.rolledBack: true` and `data.result`).

**`gateway.config.confirm`** `{applyId}` → `{"state":"confirmed","applyId":…,"hashes":{…}}`.
Refused on the session the apply came on (`not_reconnected`): the proof is the
fresh connection. Repeating it is fine. `deadline_passed` (+ `data.result` when
known) once the window closed, `unknown_apply` otherwise.

**`gateway.config.rollback`** `{applyId}` → `{"state":"rolling_back","applyId":…}`
(the restore runs after the reply; its outcome comes as a result, reason
`admin`). For a finished job it returns that job's outcome as `state`.

**`gateway.config.ack`** `{applyIds:[…]}` → `{"acked":n}`: drops outcomes from
`results` (32 are kept at most).

**Notification `gateway.config.result`** (also the entries of the hello's `results`):

```json
{"applyId":"g3-a41","kind":"apply","outcome":"rolled_back","reason":"confirm_timeout",
 "at":"2026-09-23T10:01:30Z","hashes":{…all readable…},
 "discarded":{"dhcp":[{"name":"lan","type":"dhcp","anonymous":false,"index":1,"options":{…},"secrets":{…},"hash":"…","change":"changed"}]},
 "packages":["kmod-wireguard","wireguard-tools"],"detail":"…"}
```

`outcome` `rolled_back` | `failed` (the restore itself failed; the snapshot is
kept as `rollback/failed-<id>`). `reason` `confirm_timeout` | `admin` |
`reboot` | `commit_failed` | `reload_failed` | `install_failed`. `discarded`
= sections edited on the router during the window, which the rollback undid
(`added` / `changed` / `removed` relative to what the job had committed;
redacted like a read). `packages` = what a package job's rollback removed.

**Restarts and reboots.** At start the daemon reads `pending.json`: no marker
= the router rebooted → restore (`reboot`); not committed = interrupted mid
commit → restore (`commit_failed`); past the deadline → restore
(`confirm_timeout`); otherwise the timer is armed again and any session of the
new process may confirm. The boot guard `perch-collector config-guard`
(init script `perch-collector-guard`, START=15, before `network` at 20) does
the reboot case before any service reads the configs, without reloading;
the daemon then reports the outcome.

**Management path.** `ip route get <server_url host>` gives the device;
netifd's interface on it is the network. Protected sections: that interface,
any interface on its device (or its parent bridge), the `device` section that
is the device or its parent bridge, the `bridge-vlan`s on that bridge, the
firewall zones listing the network, and firewall `defaults` (the controller's
`apply_plan.ts` rules). Reported as `management` in the hello and capabilities.

**Ledger** `/etc/config/perch-managed`: `config synced '<perchId>'` with
`option config`, `option section`, `option domain`; written whole by the agent
(tmp + fsync + rename), never staged through rpcd; the controller reads it and
changes it only through the ops and `ledger` of an apply. Nothing is ever marked inside the foreign configs.

**Signed requests** (plain HTTP with the opt-in). The params become an envelope:

```json
{"payload":"<the method's params as a JSON string>",
 "sig":{"v":1,"ts":1790000000,"nonce":"<16-128 of [A-Za-z0-9_-]>","challenge":"<the session's hello challenge>","mac":"<64 hex>"}}
```

`mac` = hex HMAC-SHA256(key, `"perch-config-sig-v1\n" + method + "\n" +
challenge + "\n" + ts + "\n" + nonce + "\n" + hex(SHA-256(payload bytes))`);
key = `config_sign_key` when set, else the pairing's key (below; `signing.key`
says which). A router with neither refuses every signed request
(`not_paired`).
Refusals: `bad_signature` (wrong key, method, session challenge, tampered
payload, malformed), `stale_signature` (|ts − router clock| > 300 s;
`data.agentTime`), `replayed` (nonce seen in the last 10 minutes). Test vector
(key `k`, method `gateway.config.confirm`, challenge `c0ffee`, ts 1790000000,
nonce `nonce-0000000001`, payload `{"applyId":"a1"}`): payload hash
`275ffaf62583a907a897eaad357b77010508dbaed674bbbd8819b344ceba30e8`, mac
`2ae21083603b5bf27157bf935395c42b2d4c607e8d6b93cf3abe9ba59d7b7e9e`. Over
verified TLS a request may be signed or not. The api_key never signs (owner
decision 29): it is the connection's Bearer token, so over plain HTTP a
passive listener has it. Neither `config_sign_key` nor the pairing's key ever
crosses the wire.

**Pairing** (`internal/gwconfig/pair.go`, `pair_crypto.go`; the controller's
`docs/gateway/config-plane.md` 4.4). A router with `config_access 'write'` and
`config_allow_insecure '1'` that talks plain HTTP agrees on a 32-byte signing
key with the controller over the socket (X25519, a commitment, HKDF), both
ends show a 6-digit code, the admin types the router's code into the
controller and confirms on the router. Requests (server → agent, unsigned
except forget; refusals -32000 with `data.error`):

| Method | Params | Result | Refusals |
|---|---|---|---|
| `gateway.pair.begin` | `{pairingId:"<16 hex>", gatewayId:n, controllerPub:"<64 hex>"}` | `{pairingId, routerPub, commitment, expiresAt}` | `not_managed` (access ≠ write), `pairing_not_needed` (verified TLS), `insecure_transport` (no opt-in), `sign_key_configured` (`config_sign_key` set), `bad_params` (incl. a low-order key) |
| `gateway.pair.reveal` | `{pairingId, controllerNonce:"<64 hex>"}` | `{pairingId, routerNonce}` | `unknown_pairing`; `already_revealed` (a second reveal ends the pairing) |
| `gateway.pair.status` | `{pairingId}` | `{pairingId, state:"waiting_local"\|"paired"\|"expired"\|"cancelled"\|"unknown", keyId?}` | |
| `gateway.pair.cancel` | `{pairingId}` | `{pairingId, state:"cancelled"}` (drops it when it is the one in progress) | |
| `gateway.pair.forget` | `{keyId}` **signed with that key** (unsigned only over verified TLS) | `{state:"forgotten"}` | `not_paired`, `signature_required`, `bad_signature`, `unknown_key` |

Crypto (hex lowercase, keys and nonces 32 bytes): `commitment =
HMAC-SHA256(routerNonce, "perch-pair-commit-v1" ‖ routerPub ‖ controllerPub)`;
`key = HKDF-SHA256(ikm = X25519 shared, salt = controllerNonce ‖ routerNonce,
info = "perch-config-sign-v1:<gatewayId>", 32)`; `SAS =
uint32_be(SHA-256("perch-pair-sas-v1" ‖ controllerPub ‖ routerPub ‖
controllerNonce ‖ routerNonce ‖ "<gatewayId>")[0:4]) mod 10^6` (6 digits);
`keyId = hex(SHA-256("perch-pair-keyid-v1" ‖ key))[0:16]`. The controller's
pinned vector (RFC 7748 6.1 keys, gatewayId 7, nonces `11`×32 / `22`×32 →
commitment `ff24b3e8…`, key `6ab9f1d4…`, SAS `331510`, keyId
`38545dab8f16e8a2`) is `TestPairingVector`. The router commits to its nonce
before it sees the controller's, and takes one reveal per pairing, so a man in
the middle gets one guess in 10^6 at matching codes.

Router state: one pairing at a time (a new begin replaces an unfinished one),
in memory; each step has 10 minutes (begin → reveal, reveal → local confirm),
then it expires. After the reveal the daemon logs the code (`logread | grep
PAIRING`). `perch-collector pair confirm <code>` (spaces and dashes ignored)
with the right code stores the key in `/etc/perch-collector/pairing.json`
(0600, written atomically; kept over sysupgrade by keep.d, lost by a factory
reset, removed with the package), sends the notification `gateway.pair.state
{pairingId, state:"paired", keyId}` and verifies signed writes with it from
then on (the session's challenge stays). Three wrong codes end the pairing
(`rejected`); `pair reject` ends it too; the window's end sends `expired`; a
replayed reveal sends `cancelled`. A later pairing, once confirmed, replaces
the key (a restored controller pairs again). `pair forget` drops the key and
redials, so the next hello says `none` and the controller marks its pairing
`lost`; a signed `gateway.pair.forget` drops it from the controller's side.

The CLI reaches the daemon over `/var/run/perch-collector/pair.sock` (0600 in
a 0700 directory, and on Linux the peer's uid must be the daemon's, i.e.
root): one JSON line `{"cmd":"status"|"confirm"|"reject"|"forget","code"?}`,
one JSON answer `{ok, error?, status?, paired?}`. Without a running daemon
`pair status` reads the stored key and `pair forget` deletes it.

**`gateway.package.install`** `{applyId, packages:[…1..16], confirmTimeoutSeconds?, dryRun?}` →

```json
{"state":"pending_confirm","applyId":"p1","deadline":"…","confirmTimeoutSeconds":90,"manager":"opkg",
 "install":["kmod-wireguard","wireguard-tools"],"alreadyInstalled":[],"needBytes":237000,"freeBytes":5242880,"hashes":{…}}
```

Names must be on the install allowlist (the gateway features' packages; the
router's `list package_allow` adds more; capabilities list them as
`installAllowlist`), else `package_not_allowed`. Steps: `opkg update` / `apk
update`; `opkg install --noaction` / `apk add --simulate` for the list with
dependencies; free flash ≥ 3 × the package files' size + 512 KiB (opkg; apk:
≥ 4 MiB), else `insufficient_flash` (`data.freeBytes`, `data.needBytes`);
snapshot the allowlisted configs; install. A failed install removes what went
in at once (`install_failed`, `data.rolledBack`, `data.result`); otherwise the
job waits for its confirm like an apply, and a rollback removes the installed
packages (requested first, then dependencies) and restores configs their
scripts changed. `noop` when all are installed, `dry_run` stops before the
install, `no_package_manager` without opkg or apk. The request takes as long
as the package manager does (a minute or more with `update`).

**Error codes** (-32000, `data.error`): `not_managed`, `config_not_allowed`
(+`configs`), `insecure_transport`, `signature_required`, `bad_signature`,
`stale_signature`, `replayed`, `stale_base`, `busy` (+`reason`
`apply_pending`|`luci_pending`|`uncommitted`), `foreign_staged` (+`config`,
`changes`), `not_owned`, `name_taken`, `no_section`, `unknown_apply`,
`deadline_passed`, `not_reconnected`, `apply_failed`, `package_not_allowed`,
`no_package_manager`, `insufficient_flash`, `install_failed`. Bad params:
-32602 with `data.error` `bad_params`.

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
