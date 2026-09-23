# Configuration Reference

perch-collector (the Perch Network Collector) is configured via a YAML file, CLI flags and environment variables. CLI flags override YAML values; environment variables override both.

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `-config` | `collector.yaml` | Path to YAML config file |
| `-interface` | _(auto)_ | Network interface to capture on; empty = the interface carrying the IPv4 default route |
| `-listen` | `127.0.0.1:9800` | HTTP API listen address |
| `-bpf` | _(empty)_ | BPF filter expression |

## YAML Configuration

```yaml
# Network interface to capture packets on.
# Empty = auto-detect: the interface that carries the IPv4 default route
# (/proc/net/route, lowest metric wins). Set it explicitly for a LAN bridge
# or a mirror port. Use "any" to capture on all interfaces.
# Default: "" (auto-detect)
interface: ""

# BPF filter expression applied to the capture.
# Empty string means capture all traffic.
# Examples:
#   "not port 22"           — exclude SSH
#   "net 192.168.1.0/24"    — only local subnet
#   "tcp"                   — TCP only
# Default: ""
bpf_filter: ""

# Snapshot length — how many bytes of each packet to capture.
# 96 bytes is enough for Ethernet + IP + TCP/UDP headers.
# Bump to 256+ when classification_mode is "ndpi" so the TLS ClientHello
# (SNI) and QUIC initial packets fit; the daemon prints a startup
# warning if nDPI is enabled with snap_len < 256.
# Default: 96
snap_len: 96

# Protocol classification mode:
#   "port" — stateless lookup of dst/src port against a built-in table
#            (https/dns/ssh/etc.). Zero per-flow memory. Always available.
#   "ndpi" — deep packet inspection via libndpi. Resolves encrypted apps
#            (Netflix, YouTube, WhatsApp, Discord, Spotify, Zoom, …) that
#            port-based mode lumps into "https"/"quic". Requires the
#            binary to be built with `make build-ndpi` (-tags ndpi); a
#            stub build will log a warning and fall back to "port".
# Default: "port"
classification_mode: "port"

# Maximum number of concurrent flows tracked by the nDPI flow table.
# Each flow allocates ~1 KB of nDPI per-flow state until classification
# finalizes (typically within 1-20 packets). The oldest flow is evicted
# when this cap is reached; idle flows are purged separately by the
# idle sweeper (see ndpi_flow_idle_seconds). Ignored when
# classification_mode is "port".
# Default: 50000
ndpi_max_flows: 50000

# How many seconds of inactivity before a tracked flow is evicted from
# the nDPI flow table. Lower values free memory faster at the cost of
# re-classifying long-lived idle connections (rare).
# Default: 120
ndpi_flow_idle_seconds: 120

# Packets a flow keeps its native nDPI state after its first usable label
# (label + server name). 0 finalises at once (least memory), larger values
# let nDPI refine labels. 4 covers the ServerHello burst.
ndpi_partial_extra_packets: 4

# HTTP API listen address.
# Use "127.0.0.1:PORT" for localhost-only access.
# Use "0.0.0.0:PORT" for network access (requires api_key).
# Default: "127.0.0.1:9800"
listen: "127.0.0.1:9800"

# Enable promiscuous mode on the capture interface.
# Required to see traffic not addressed to this host.
# Default: true
promiscuous: true

# Optional API key for authentication.
# When set, all endpoints except /healthz require:
#   Authorization: Bearer <api_key>
# When empty, no authentication is enforced.
# Default: ""
api_key: ""

# Path to write periodic JSON snapshots.
# Set to empty string to disable disk persistence.
# The directory must exist and be writable.
# Default: ""
flush_file: ""

# How often (in seconds) to write a JSON snapshot to flush_file.
# Only relevant if flush_file is set.
# Default: 60
flush_interval: 60

# Ethernet MAC of a single upstream gateway. Kept for backward compatibility;
# prefer gateway_macs (below). When set, it is appended to gateway_macs.
# Default: ""
gateway_mac: ""

# List of Ethernet MACs to treat as upstream-gateway pivots. Any frame whose
# src or dst MAC matches any entry classifies traffic as WAN for the device
# on the other side. Frames where BOTH sides are gateway MACs (typical of
# inter-router relay traffic with policy routing) are dropped to avoid
# double counting.
#
# Empty triggers auto-detection of the single default-route gateway from
# /proc/net/route + /proc/net/arp at startup. Set this explicitly when you
# have multiple upstream routers (e.g. a primary OpenWrt gateway plus a
# secondary WAN container).
# Default: [] (auto-detect single gateway)
gateway_macs: []
#   - "02:00:00:00:00:01"   # primary OpenWrt gateway
#   - "02:00:00:00:00:02"   # secondary WAN container

# Extra CIDRs identifying local LAN address space. These are merged with the
# CIDRs auto-detected from the capture interface. IPs outside this combined
# set are treated as external (and may appear in a device's top_peers).
# Default: [] (auto-detected only)
local_subnets: []

# Maximum number of remote external (WAN) peers tracked per local device.
# The aggregator keeps a min-heap of this size per device, evicting the
# smallest when a heavier new peer arrives. Hard maximum 1000.
# Default: 50
top_peers_count: 50

# Maximum number of LAN neighbours tracked per local device. LAN peers are
# recorded for frames where neither side is a gateway MAC (so they cover the
# "who fed me these bytes over the LAN?" question for SMB, NFS, IP-cam ↔ NVR,
# phone ↔ printer, etc.). Lives in a SEPARATE bounded heap from top_peers_count
# so chatty WAN traffic can never evict an important LAN peer (or vice versa).
# Set to a negative value to disable LAN peer tracking entirely. Hard maximum 1000.
# Default: 50
top_lan_peers_count: 50

# Root URL of the Perch Network Controller, e.g. "http://192.168.1.10:8080" (the
# default install: plain HTTP, keep it on a management VLAN) or
# "https://perch.example.com".
# Empty = the daemon never opens an outbound connection and can only be
# polled. See "The Perch controller" below.
# Default: ""
server_url: ""

# How the collector reaches the controller: "websocket" (dial out, push on
# the controller's schedule; needs api_key), "poll" (announce over HTTP and
# be polled on `listen`), or "auto" = websocket when api_key is set, else
# poll.
# Default: "auto"
transport: auto

# Seconds between HTTP announces (transport poll). Only the opening
# cadence: every reply carries the schedule the server wants and that wins
# from then on. Clamped to [15, 3600].
# Default: 60
announce_interval: 60

# Include the API key in the hello / announce body so the administrator
# never has to copy it by hand. false sends the key's fingerprint only and
# the key is pasted into the dashboard on adopt. The Authorization header
# carries the key either way.
# Default: true
announce_api_key: true

# Explicit stable identity for this collector. Empty = resolve one (see
# "Identity" below) and persist it in instance_id_file.
# Default: ""
instance_id: ""

# Where a resolved instance id is persisted. With the default path, an id in
# /var/lib/go-collector/instance-id (before the rename) is read while this
# file does not exist.
# Default: "/var/lib/perch-collector/instance-id"
instance_id_file: "/var/lib/perch-collector/instance-id"

# Accept a self-signed certificate on an https server_url (announce and
# socket alike). No-op for http.
# Default: false
announce_tls_insecure: false

# PEM bundle trusted on top of the system roots for an https server_url
# signed by a private CA.
# Default: ""
server_ca_file: ""

# Report the router's own health with the traffic (conntrack, established
# TCP, load, memory, WAN counters) for the controller's Gateway page:
# "auto" = on under OpenWrt (the collector runs on the router), "on", "off".
# Default: "auto"
gateway_stats: auto

# WAN interfaces the gateway stats count. Empty = the interfaces holding a
# default route, re-read on every report.
# Default: []
wan_interfaces: []

# The router's Ethernet ports and their link state, in the gateway report
# (the Gateway agent's ports, below): "auto" and "on" = whenever gateway
# stats are on, "off" = leave them out. Without gateway stats there is no
# gateway report, so there are no ports either way.
# Default: "auto"
ports: auto

# Report the router's DHCP leases and static DHCP hosts (observe.dhcp, below)
# so the controller names devices with no transport of its own to the router:
# "auto" = on under OpenWrt, "on", "off". Independent of gateway_stats.
# Default: "auto"
dhcp_leases: auto

# Seconds between resends of unchanged leases (a change goes out with the next
# push). Clamped to 60..3600.
# Default: 600
dhcp_leases_refresh: 600

# Report the router's other runtime state for the managed gateway (the
# observation channel, below): neighbours, interfaces, UPnP mappings, mwan3,
# who answers DNS, the system. "auto" = on under OpenWrt, "on", "off".
# Default: "auto"
observe: auto

# Only these parts of the observation (neighbors, interfaces, upnp, mwan3,
# resolver, system). Empty = all. dhcp has its own switch, dhcp_leases.
# Default: []
observe_parts: []

# Seconds between resends of an unchanged part. Clamped to 60..3600.
# Default: 600
observe_refresh: 600

# Let the controller delete a device's conntrack entries (net.conntrack_flush),
# so blocking a device also ends its running connections. "auto" = on with
# observe; needs ctnetlink (kmod-nf-conntrack-netlink) and root.
# Default: "auto"
conntrack_flush: auto

# Traffic shaping (per-device and bucket caps from /etc/config/perch-qos, the
# perch-qos package). "auto" = on on OpenWrt when perch-qos is installed.
# Default: "auto"
qos: auto

# Configuration backups (gateway.backup, sysupgrade -b) the controller may
# take: "redacted" (secrets replaced, private key files left out), "full"
# (the archive as is) or "off". Offered only with observe on and sysupgrade
# on the PATH.
# Default: "redacted"
gateway_backup: redacted

# File that keeps the controller's last good address, dialed when its host
# name does not resolve. Written only when the address changes. "" = memory
# only. The OpenWrt package uses /etc/perch-collector/controller-address
# (survives a reboot).
# Default: "/var/lib/perch-collector/controller-address"
controller_address_cache: /var/lib/perch-collector/controller-address
```

## Environment Variables

Configuration values can also be set via environment variables. They take the highest precedence (env > CLI > YAML). An empty value counts as unset.

| Variable | Maps to |
|---|---|
| `PERCH_COLLECTOR_INTERFACE` | `interface` |
| `PERCH_COLLECTOR_LISTEN` | `listen` |
| `PERCH_COLLECTOR_API_KEY` | `api_key` |
| `PERCH_COLLECTOR_BPF_FILTER` | `bpf_filter` |
| `PERCH_COLLECTOR_FLUSH_FILE` | `flush_file` |
| `PERCH_COLLECTOR_GATEWAY_MAC` | `gateway_mac` (singular; appended to `gateway_macs`) |
| `PERCH_COLLECTOR_GATEWAY_MACS` | `gateway_macs` (comma-separated list of MACs) |
| `PERCH_COLLECTOR_TOP_PEERS_COUNT` | `top_peers_count` |
| `PERCH_COLLECTOR_TOP_LAN_PEERS_COUNT` | `top_lan_peers_count` |
| `PERCH_COLLECTOR_TOP_SERVICES_COUNT` | `top_services_count` |
| `PERCH_COLLECTOR_TOP_DESTINATIONS_COUNT` | `top_destinations_count` |
| `PERCH_COLLECTOR_TOP_UNNAMED_DESTINATIONS_COUNT` | `top_unnamed_destinations_count` |
| `PERCH_COLLECTOR_CLASSIFICATION_MODE` | `classification_mode` (`port` or `ndpi`) |
| `PERCH_COLLECTOR_SNAP_LEN` | `snap_len` |
| `PERCH_COLLECTOR_NDPI_MAX_FLOWS` | `ndpi_max_flows` |
| `PERCH_COLLECTOR_NDPI_FLOW_IDLE_SECONDS` | `ndpi_flow_idle_seconds` |
| `PERCH_COLLECTOR_NDPI_PARTIAL_EXTRA_PACKETS` | `ndpi_partial_extra_packets` |
| `PERCH_COLLECTOR_PROMISCUOUS` | `promiscuous` (`true`/`false`, `1`/`0`) |
| `PERCH_COLLECTOR_LOCAL_SUBNETS` | `local_subnets` (comma-separated CIDRs) |
| `PERCH_COLLECTOR_SERVER_URL` | `server_url` |
| `PERCH_COLLECTOR_TRANSPORT` | `transport` (`auto`, `websocket`, `poll`) |
| `PERCH_COLLECTOR_ANNOUNCE_INTERVAL` | `announce_interval` (seconds) |
| `PERCH_COLLECTOR_ANNOUNCE_API_KEY` | `announce_api_key` (`true`/`false`, `1`/`0`) |
| `PERCH_COLLECTOR_INSTANCE_ID` | `instance_id` |
| `PERCH_COLLECTOR_INSTANCE_ID_FILE` | `instance_id_file` |
| `PERCH_COLLECTOR_ANNOUNCE_TLS_INSECURE` | `announce_tls_insecure` (`true`/`false`, `1`/`0`) |
| `PERCH_COLLECTOR_SERVER_CA_FILE` | `server_ca_file` |
| `PERCH_COLLECTOR_GATEWAY_STATS` | `gateway_stats` (`auto`, `on`, `off`) |
| `PERCH_COLLECTOR_WAN_INTERFACES` | `wan_interfaces` (comma-separated) |
| `PERCH_COLLECTOR_PORTS` | `ports` (`auto`, `on`, `off`) |
| `PERCH_COLLECTOR_DHCP_LEASES` | `dhcp_leases` (`auto`, `on`, `off`) |
| `PERCH_COLLECTOR_DHCP_LEASES_REFRESH` | `dhcp_leases_refresh` (seconds) |
| `PERCH_COLLECTOR_OBSERVE` | `observe` (`auto`, `on`, `off`) |
| `PERCH_COLLECTOR_OBSERVE_PARTS` | `observe_parts` (comma-separated) |
| `PERCH_COLLECTOR_OBSERVE_REFRESH` | `observe_refresh` (seconds) |
| `PERCH_COLLECTOR_CONNTRACK_FLUSH` | `conntrack_flush` (`auto`, `on`, `off`) |
| `PERCH_COLLECTOR_GATEWAY_BACKUP` | `gateway_backup` (`redacted`, `full`, `off`) |
| `PERCH_COLLECTOR_CONTROLLER_ADDRESS_CACHE` | `controller_address_cache` |
| `PERCH_COLLECTOR_QOS` | `qos` (`auto`, `on`, `off`) |

The names before the rename, `GOCOLLECTOR_<NAME>`, are still read when
`PERCH_COLLECTOR_<NAME>` is unset; the daemon logs one deprecation line per
old variable it used.

## Precedence Order

```
Environment Variables  (highest)
        ↓
    CLI Flags
        ↓
    YAML File
        ↓
    Built-in Defaults  (lowest)
```

## Example Configurations

### Router (typical)

```yaml
interface: "br-lan"
listen: "127.0.0.1:9800"
promiscuous: true
flush_file: "/var/lib/perch-collector/stats.json"
flush_interval: 60
# Gateway MAC and local subnets are auto-detected from br-lan.
top_peers_count: 50
```

### Server with API key, gateway pinned

Set `gateway_macs` explicitly when ARP-based auto-detection isn't possible
(e.g., the daemon runs on a host with no IP on the capture interface, or the
gateway never replies to ARP probes from this machine).

```yaml
interface: "eth0"
listen: "0.0.0.0:9800"
promiscuous: false
api_key: "your-secret-key-here"
bpf_filter: "not port 9800"
flush_file: "/var/lib/perch-collector/stats.json"
flush_interval: 30
gateway_macs:
  - "02:00:00:00:11:22"
local_subnets:
  - "10.0.0.0/16"
  - "fd00:abcd::/48"
top_peers_count: 100
```

### Multi-WAN / policy-routed setups

When OpenWrt (or similar) routes some destination prefixes through a
secondary container or upstream router, list every L3 hop you want treated
as a WAN pivot. Frames between gateways are dropped to avoid double-counting.

```yaml
interface: "br-lan"
gateway_macs:
  - "02:00:00:00:00:01"   # primary OpenWrt gateway
  - "02:00:00:00:00:02"   # a second WAN router's container
  - "02:00:00:00:00:03"   # WireGuard relay container
top_peers_count: 50
```

### Debug / Development

```yaml
interface: "any"
listen: "127.0.0.1:9800"
promiscuous: true
bpf_filter: "net 192.168.1.0/24"
snap_len: 96
flush_file: "./debug-stats.json"
flush_interval: 10
top_peers_count: 200
```

### Deep packet inspection (nDPI mode)

Resolves encrypted apps that port-based mode can't see — Netflix/YouTube
inside TLS, WhatsApp/Discord/Signal calls inside QUIC, BitTorrent on
non-standard ports, etc. Requires `make build-ndpi` against nDPI 5.0 and
libndpi 5 at runtime; distro packages are 4.x, so build it into a prefix
with `scripts/build-ndpi.sh` and pass `NDPI_PREFIX=<prefix>` to make (see
README, Build).

```yaml
interface: "br-lan"
listen: "127.0.0.1:9800"
classification_mode: "ndpi"
snap_len: 1500          # full packets so TLS SNI + QUIC initials fit
ndpi_max_flows: 50000   # ~50 MB peak when fully populated
ndpi_flow_idle_seconds: 120
promiscuous: true
```

## `top_services_count`

Per-device cap on distinct `(server_name, protocol)` rows in the `services`
array of `GET /api/v1/devices`. In `classification_mode: ndpi` the daemon
reads the TLS SNI / HTTP `Host` / QUIC SNI from each flow and credits bytes
to the local device that is the **server** side: `bytes_served` (server →
client) and `bytes_received` (client → server). Devices acting as clients of
remote servers get no rows, so a reverse proxy terminating twenty vhosts
shows twenty rows on one MAC. Default 500; negative disables; port mode
never learns names.

## `top_destinations_count`

Per-device cap on distinct `(server_name, protocol)` rows in the
`destinations` array of `GET /api/v1/devices` — the mirror image of
`services`. Rows are credited to the local device that is the **client** of a
WAN flow (the far end must be outside the local subnets): `bytes_in` is what
it downloaded from that destination, `bytes_out` what it uploaded. The name is
the TLS SNI / HTTP `Host` / QUIC SNI the client asked for; flows with no name
pool under `server_name: ""` per protocol, so an app nDPI recognised from IP
ranges alone ("netflix") is still fully accounted. Each row carries nDPI's
flow `category` (`web`, `streaming`, `social-network`, `advertisement`, …).
LAN-to-LAN flows never create a row. Default 500; negative disables.

Unnamed flows of a name-carrying family (TLS / HTTP / QUIC — the hello was
never captured) are keyed by their peer address instead, `peer_ip` set and
`server_name: ""`, under a separate per-device cap
(`top_unnamed_destinations_count`, default 100, negative = always pool) so
address churn cannot crowd out named rows. Past that cap, and for families
that never carry a name, they land in the `server_name: ""` / `peer_ip: ""`
pool per protocol.

The default category of every protocol label is exported once at startup on
`GET /api/v1/protocols` (`{"protocols":[{"protocol":"youtube","category":"media"},…]}`)
so a consumer can group *protocol* history by category without its own
table. Port mode exports an empty list.

## The Perch controller

Set `server_url` and the collector introduces itself to the Perch Network
Controller instead of being typed into the dashboard by hand. **The
controller never learns anything it can act on until an admin adopts the
collector**: the introduction can only create or refresh one *pending*
registration, and nothing is pushed or polled until someone clicks Adopt in
Settings → Collectors (or the setup wizard).

```yaml
server_url: "http://192.168.1.10:8080"   # empty = talk to no controller (default)
transport: auto                          # websocket with an api_key, else poll
api_key: "change-me-to-something-long"   # the collector's credential
announce_api_key: true                   # send the key so adoption is one click
instance_id: ""                          # empty = resolve and persist one
instance_id_file: "/var/lib/perch-collector/instance-id"
announce_tls_insecure: false             # accept a self-signed https server cert
server_ca_file: ""                       # or trust a private CA
announce_interval: 60                    # transport poll: opening announce cadence
```

`server_url` must be an `http://` or `https://` URL — anything else is a
fatal config error — and `transport websocket` without `api_key` (or without
`server_url`) is one too. `auto` without an `api_key` falls back to announce
and poll with a warning.

### Over the collector's own WebSocket (`transport: websocket`)

The collector dials `<server_url>/api/v1/collector-agent/ws` (`wss://` for
an `https` URL) with

- `Authorization: Bearer <api_key>` and `X-Perch-Instance-Id: <instance id>`,
- subprotocol `perch-collector.v1`, permessage-deflate offered.

Its first message is the JSON-RPC request `collector.hello`: instance id,
hostname, version, capture interface, the key's fingerprint (and the key
itself with `announce_api_key`), capabilities (`gateway_stats`), the OS and
architecture, and the local API's `port` / `tls` / `baseUrl` **only when the
API listens on something other than loopback**. The controller answers with
the collector's id, name and lifecycle, then sends `agent.configure`
(`metricsIntervalSeconds`, 0 = paused, which is what a pending collector
gets). The collector never pushes before that; from then on it sends
`collector.push` every interval — `seq`, `collectedAt`, the `summary`,
`meta` and `devices` of the HTTP API in one compact message, plus `gateway`
with gateway stats on (the ports included) — and answers `collector.status` and
`collector.protocols`. Adopting, disabling or re-timing the collector in the
dashboard reaches it at once, as a new `agent.configure`.

Reconnects:

| Outcome | Next attempt |
|---|---|
| 401 (the controller holds a different key), close 4001 | 5 min |
| 403 `announce_disabled`, 409 `announce_pending_limit`, a refused hello, 404 (a controller without the socket), any other 4xx | 5 min |
| 429 | its `Retry-After` |
| close 4002 (another collector with this instance id) | 60 s |
| close 4003 (dismissed) | 6 h |
| close 1001 (controller restarting) | 2–5 s |
| anything else | 1 s doubling to 30 s (60 s before 1.0.0-rc.2), or a 5xx's `Retry-After` when shorter (`gateway_starting` right after a controller restart); reset after a session that lasted over a minute |

Each state change is one log line (`starting -> pending`, `pending ->
adopted by …`, `pushing every 5s`, `adopted -> error: …`), never one per push.
The wire contract is `docs/collector-agent.md` in the controller repository.

### Announce and poll (`transport: poll`)

The daemon POSTs a small identity document to `POST
<server_url>/api/v1/collectors/announce` shortly after its API starts
listening, then on the cadence the server replies with, and the controller
polls the API on `listen` once adopted.

What is sent: the instance id, hostname, build version, capture interface,
the API port, whether the API speaks TLS, the base URL the daemon *believes*
it has, and — when `announce_api_key` is on — the API key plus the first 8
hex characters of its SHA-256 (the fingerprint the dashboard shows so you can
compare it with the key on the box before adopting). The key is also sent as
`Authorization: Bearer` on every announce, which is what proves an already
adopted collector is really itself. The address the server polls is **derived
from the TCP source address of the announce**, never from the URL the daemon
reports, so a collector behind NAT or a reverse proxy relative to the server
should use the WebSocket transport instead (or be registered by hand).

`announce_interval` is clamped to `[15, 3600]` seconds.
Announcing over plain HTTP puts the API key on the wire in cleartext: use an
`https` `server_url`, or set `announce_api_key: false` and paste the key into
the dashboard when you adopt. The same holds for the socket's hello.

**Identity.** `instance_id` is how the server recognises the same daemon
across restarts, reinstalls and address changes. It is resolved in this
order, and the first answer wins:

1. an explicit `instance_id` (config file or `PERCH_COLLECTOR_INSTANCE_ID`);
2. the id already in `instance_id_file`;
3. an id **derived from this machine**:
   `sha256("go-collector instance id|" + machine id + "|" + capture interface MAC)`
   truncated to 32 hex characters (the salt keeps the pre-rename name, so
   derived ids survive the rename). It is also written to `instance_id_file`
   when that path is writable, which pins the id against a later NIC change;
   failing to write it is not an error;
4. a fresh random id, persisted to `instance_id_file`;
5. a random id that lives only as long as the process, logged as such
   because the collector will need adopting again after a restart.

The machine id is read from `/etc/machine-id` or `/var/lib/dbus/machine-id`.
An image that ships neither — a Debian-slim container, typically — derives
from the capture interface's MAC alone and logs one line saying so. Because
derivation comes *before* generation, a container recreated with no volume
keeps the identity it had as long as it still sees the same host NIC, instead
of piling up pending rows on the server. Set `PERCH_COLLECTOR_INSTANCE_ID`, or
mount a volume at the file's directory, when you want certainty rather than
inference. On OpenWrt the init script always passes the UCI-stored id, so the
file is never touched.

Status shows up in the `meta.announce_status` field of every response that
carries a `meta` block (`starting`, `pending`, `adopted`, `dismissed`,
`error: …`), for either transport, next to `meta.transport` (`websocket` or
`poll`). Both are deliberately absent from `/healthz`, which is
unauthenticated.

## Gateway stats

`gateway_stats: on` (or `auto` under OpenWrt) makes the collector report the
host's own health with every push and as a top-level `gateway` object of
`GET /api/v1/summary`:

```json
{"collectedAt":"2026-09-21T14:17:10Z",
 "conntrack":{"entries":2495,"limit":262144},
 "tcpEstablished":2,
 "load":{"load1":1.44,"load5":1.1,"load15":1.49},
 "memory":{"totalBytes":1073741824,"availableBytes":536870912},
 "wan":[{"name":"wan","rxBytes":693974698743,"txBytes":1697321558462}],
 "wanSource":"default-route"}
```

Sources: `/proc/sys/net/netfilter/nf_conntrack_{count,max}`, `CurrEstab` of
`/proc/net/snmp`, `/proc/loadavg`, `MemTotal` / `MemAvailable` of
`/proc/meminfo` and the byte counters of `/proc/net/dev`. The WAN interfaces
are `wan_interfaces` when set (`wanSource: "configured"`), else those holding
a default route in the main table — IPv4 routes with destination and mask 0,
IPv6 `::/0`, neither down nor reject routes, never `lo` — re-read on every
report. Counters are cumulative; the controller derives the rates. A part the
kernel does not expose is left out, never reported as zero. Only turn it on
where the collector runs on the router: anywhere else these are the numbers
of the wrong machine.

### The Gateway agent's ports

With gateway stats on, the collector is the Perch Network Gateway agent, and
`ports: auto` (the default) adds `ports` to the same `gateway` object: the
router's Ethernet ports in display order, with their link state, for the
controller's infrastructure view.

```json
"ports":[
  {"name":"wan0","label":"wan0","role":"wan","medium":"virtual","mac":"02:00:00:00:00:31",
   "adminUp":true,"carrier":true,"operstate":"up","speedMbps":10000,"duplex":"full","carrierChanges":2},
  {"name":"lan0","label":"lan0","medium":"virtual","mac":"02:00:00:00:00:32",
   "adminUp":true,"carrier":true,"operstate":"up","speedMbps":10000,"duplex":"full","carrierChanges":2}]
```

The ports come from `/sys/class/net`, with labels from the device tree and
roles from OpenWrt's `/etc/board.json` for hardware ports. The interfaces the
report counts as WAN (`wan_interfaces`, else the default routes) are role
`wan`. A router in a container has no hardware port, so it reports its veths
(`medium: "virtual"`). `[]` means the router has no port; the key is left out
with `ports: off` and while `/sys/class/net` cannot be listed. The controller
reads a missing key as "not reported", never as "no ports". `on` behaves like
`auto`; `1` and `0` (UCI) mean on and off. `perch-collector ports` prints the
array once and exits without reading this configuration (README, "The
Gateway agent's ports").

### DHCP leases and static hosts (`observe.dhcp`)

With `dhcp_leases` on (the default on OpenWrt), the collector reports what the
router's DHCP servers handed out, so the controller can show device names
without an SSH or LXC transport to the router (Settings → Hostname
enrichment then says "provided by the gateway agent"):

```json
"observe":{"dhcp":{
  "leases4":[{"mac":"02:00:00:00:10:21","ip":"192.168.1.21","hostname":"laptop",
              "expires":1790000000,"clientId":"01:02:00:00:00:10:21","source":"dnsmasq"}],
  "leases6":[{"duid":"000100012abcdef0020000001021","iaid":12345,"addresses":["fd00::21"],
              "hostname":"laptop","validUntil":1790003600,"source":"dnsmasq"}],
  "hosts":[{"name":"nas","macs":["02:00:00:00:10:30"],"ip":"192.168.1.30"}]}}
```

- **Sources.** `uci show dhcp` names the dnsmasq lease files
  (`dhcp.@dnsmasq[*].leasefile`, `/tmp/dhcp.leases` for a section without
  one); both IPv4 and dnsmasq's DHCPv6 lines are read. When an `odhcpd`
  section exists, `ubus call dhcp ipv6leases` (and `ipv4leases` with
  `maindhcp '1'`) adds odhcpd's leases. `hosts` are the named `host`
  sections of `/etc/config/dhcp` (disabled ones skipped). Nothing depends on
  dnsmasq's DNS port: a router whose port 53 belongs to another resolver
  (dnsmasq on `port '54'` or `'0'`) reports the same.
- **Cost.** Each push stats the lease files and `/etc/config/dhcp`; a file is
  re-read only when its size or mtime changed, `uci` runs again only when
  `/etc/config/dhcp` changed, and odhcpd is asked at most once a minute.
- **When it is sent.** The section rides in `collector.push` only when its
  fingerprint changed, in the first push of every session, and every
  `dhcp_leases_refresh` seconds; `GET /api/v1/summary` carries it on every
  call. An absent `observe` means "nothing new", never "no leases"; the
  lists are `[]` when empty.
- **Cleaning.** dnsmasq's `*` (no name) becomes no `hostname`, control
  characters are dropped, names over 253 bytes are dropped, non-Ethernet
  hardware addresses are skipped, duplicate leases for one MAC and address
  collapse to the one expiring last. `expires` / `validUntil` 0 = infinite.
  At most 4096 leases of each family and 1024 hosts.

`perch-collector dhcp` prints the section once and exits, without reading
this configuration.

Since the observation channel (below) the `dhcp` part also carries `pools`
(one per UCI `config dhcp` section: `network`, `ignore`, `leaseTime` in
seconds with OpenWrt's 12 h default, 0 = infinite, `start`, `limit`; absent
when there is none), each IPv4 lease a `network` when its address lies in
one of the router's subnets, and odhcpd's leases come from its state file
(`dhcp.odhcpd.leasefile`) when `ubus` does not answer.

### The observation channel (`observe`, gateway plan 2 section 3)

With `observe` on (the default on OpenWrt) the push's `observe` section gets
one key per part beside `dhcp`. Everything is runtime state, read only; no
part is config.

```json
"observe":{"full":true,
 "dhcp":{…},
 "neighbors":[{"ip":"192.168.1.21","mac":"02:00:00:00:10:21","device":"br-lan","network":"lan","reachable":true,"state":"reachable"}],
 "interfaces":[{"network":"wan","device":"wan0","proto":"dhcp","up":true,"ipv4":["203.0.113.10/24"],"ipv6":[],
                "uptimeSeconds":86400,"defaultRoute":true,"metric":1,"gateway4":"203.0.113.1","dnsServers":["203.0.113.53"]}],
 "upnp":{"installed":true,"enabled":true,"running":true,
         "mappings":[{"proto":"TCP","extPort":51413,"intIp":"192.168.1.21","intPort":51413,"expires":0,"description":"app"}]},
 "mwan3":{"serviceEnabled":false,"running":false,"configInterfaces":[{"name":"wan","enabled":true,"family":"ipv4","trackIps":["203.0.113.1"]}],
          "interfaces":[{"name":"wan","status":"notracking","enabled":true,"running":false,"up":true,"uptimeSeconds":86400,"tracking":"none","trackIps":[]}],
          "policies":{},"configPolicies":{"balanced":["wan_m1","wanb_m1"]}},
 "resolver":{"dnsmasqPort":54,"port53Process":"AdGuardHome","port53Processes":["AdGuardHome"],
             "controllerHost":{"name":"perch.example.com","addresses":["192.168.1.10"]}},
 "system":{"hostname":"gateway","release":"OpenWrt 24.10.2 r28739-…","version":"24.10.2","board":"x86/64",
           "model":"…","kernel":"6.6.100","uptimeSeconds":123456,"flowOffloading":false,"flowOffloadingHw":false}}
```

| Part | Source | Read at most every |
|---|---|---|
| `neighbors` | rtnetlink neighbour dump (IPv4 + IPv6), `/proc/net/arp` without netlink; unicast Ethernet MACs, no link-local, no failed/incomplete entries; `reachable` = REACHABLE, DELAY or PROBE | 60 s |
| `interfaces` | `ubus call network.interface dump` (loopback left out); `defaultRoute`, `metric` and `gateway4/6` from its routes, so two WANs with metric failover read right without mwan3 | 5 s |
| `upnp` | `upnpd.config` (`enabled`, `upnp_lease_file`, default `/var/run/miniupnpd.leases`), the `miniupnpd` process, the lease file (`PROTO:EXT:IP:INT:EXPIRES:DESC`, 1.x without `EXPIRES`); `installed:false` without miniupnpd | 15 s |
| `mwan3` | UCI (`configInterfaces`, `configPolicies`), `/etc/rc.d` (`serviceEnabled`), the `mwan3track` process (`running`), `ubus call mwan3 status` (`interfaces` with mwan3's own `status` and `tracking`, `policies`); absent when mwan3 is not installed. A service started by hand but disabled at boot reads `serviceEnabled:false, running:true` | 15 s |
| `resolver` | dnsmasq's `port` (UCI, 53 when unset), the process holding a port-53 listener (`/proc/net/{udp,tcp}{,6}` + `/proc/*/fd`), the controller's host name resolved through the router's resolver | 60 s |
| `system` | `ubus call system board` / `info`, `firewall.@defaults[0].flow_offloading(_hw)` | 60 s |

- **When a part is sent.** Each part has its own fingerprint (SHA-256 of its
  JSON, uptimes left out): it rides in the first push of a session, when its
  fingerprint changed (the neighbour table at most once a minute) and every
  `observe_refresh` seconds (`dhcp`: `dhcp_leases_refresh`). `full: true`
  marks a push that carries every part the collector reports. A part that
  has nothing to report (no ubus, mwan3 not installed) is absent: the
  controller keeps what it has. Lists are `[]` when empty.
- **On demand.** The controller's `gateway.observe {parts?: string[]}`
  request answers the same object read fresh, with `collectedAt`; unknown
  part names are ignored, `full` is true when every part was asked for.
- **Caps.** 4096 neighbours, 256 interfaces, 512 UPnP mappings (descriptions
  ≤ 128 bytes), 64 mwan3 interfaces and policies; names ≤ 253 bytes.
- The hello's `capabilities` list `observe.<part>` for every part on, and
  `gateway.observe`.

`perch-collector observe [part...]` prints the section once and exits,
without reading this configuration (the resolver part then resolves no
controller name).

### Conntrack flush (`net.conntrack_flush`)

With `conntrack_flush` on (`auto` = with `observe`) and ctnetlink answering at
start, the hello lists `net.conntrack_flush` and the controller may ask:

```json
{"ips":["192.168.1.21"],"proto":"tcp","dryRun":false}
→ {"flushed":true,"matched":12,"deleted":11,"skipped":1}
```

A flow matches when one of `ips` is its original or reply source or
destination (so a port forward to the device and its masqueraded outbound
flows both go). `proto` is optional (`tcp`, `udp`, `icmp`, `icmpv6`, … or a
number). The collector's own connection to the controller is never deleted
(`skipped`). Refused with -32602 and `data.error`: `conntrack_ips_required`,
`conntrack_too_many_ips` (> 64), `conntrack_ip_invalid` (not a unicast
address), `conntrack_router_address` (one of the router's own addresses:
every NATed flow has the WAN address as its reply destination),
`conntrack_proto_invalid`. When ctnetlink fails at run time the answer is
`flushed:false` with a `reason`. Implemented in pure Go (ti-mo/conntrack over
netlink); no conntrack-tools. `perch-collector conntrack-flush [-dry-run]
[-proto P] IP...` does the same by hand.

### Backups (`gateway.backup`)

With `gateway_backup` not `off`, `observe` on and `sysupgrade` on the PATH,
the hello lists `gateway.backup`. The request `{"redact": true}` (the
default) runs `sysupgrade -b` into a temporary directory under `/tmp` and
answers:

```json
{"filename":"backup-gateway-2026-09-23.tar.gz","createdAt":"2026-09-23T10:00:00Z",
 "release":"OpenWrt 24.10.2","size":20480,"sha256":"…","redacted":true,
 "redactions":[{"file":"/etc/config/wireless","option":"key"},{"file":"/etc/uhttpd.key","removed":true}],
 "contentBase64":"H4sI…"}
```

- **Redaction** (plan 2 P10): in `/etc/config/*` every option or list whose
  name is a secret (`key`, `key1`..`key4`, `password`, `private_key`,
  `preshared_key`, `api_key`, `secret`, `psk`, `faskey`, `sae_password`, and
  names containing `password`, `secret`, `passphrase`, `token`, or ending in
  `_key` other than `public_key`) gets the value `REDACTED-BY-PERCH`, except
  a value that is a file path or a boolean switch (`PasswordAuth 'on'`); `/etc/shadow` password hashes become `*`;
  `key: value` / `key=value` lines of other text files with such a key are
  redacted; private key files (`*.key`, `*host_key*`, `/etc/wireguard/*`,
  anything containing `PRIVATE KEY-----`) are left out. `sha256` is the
  digest of the archive as returned.
- `{"redact": false}` needs `gateway_backup: full` on the router, else
  -32000 `backup_redaction_required`. Other errors: `backup_failed`,
  `backup_too_large` (over 8 MiB). A redacted archive is for reading and
  comparing; restoring it would reset every secret.
- `perch-collector backup [-full] -o FILE` writes one by hand.

### Last good controller address

With the WebSocket transport the collector resolves the controller's host
name itself and dials each address in turn. The address of the connection
whose hello the controller accepted is remembered (in memory and in
`controller_address_cache`, written only when it changes). When the name
does not resolve (the router's DNS broken by a bad change, the front
resolver down, rebind protection), the collector dials that address instead
and logs it once; the URL, the TLS server name and the `Host` header stay the
controller's name, so certificate checks are unchanged. Not used with an
HTTP proxy in the environment.

### Traffic shaping (`qos`, gateway plan 3)

With the `perch-qos` package installed (`qos: auto`) the daemon runs the
shaper: per-device caps, shared buckets (nested up to four deep), network
defaults with a leaf per device, data quotas and weekly schedules, on the LAN
side of the router (how it is built: ARCHITECTURE.md "Traffic shaping"). sqm
on the WAN is left alone and only reported. The controller writes the
structure to `/etc/config/perch-qos` through its config plane and sends the
per-MAC entries over the socket; the shaper keeps working without the
controller (entries come back from `/etc/perch-qos/devices.json`, schedules
run on the router's clock).

`/etc/config/perch-qos` (as the controller's planner renders it; every
option below is read, anything else is warned about and ignored):

```
config globals 'globals'
	option enabled '1'            # '0' = local pause (all Perch tc objects removed)
	option revision '12'          # set by the config plane; reported back
	option min_wan_kbit '1000'    # sqm queues below it are reported (sqm_below_floor)
	option min_device_kbit '64'   # caps below it are raised to it; HTB floor of shared leaves
	option leaf_flows '64'        # fq_codel flows per device leaf
	option leaf_limit '1000'      # fq_codel limit (packets) per device leaf
	option leaf_memory_kb '1024'  # fq_codel memory_limit per device leaf
	option rest_memlimit_kb '4096'# CAKE memlimit per bucket rest leaf
	option dynamic_idle '1800'    # seconds without a confirmed neighbour or bytes → leaf freed
	option dynamic_limit '1024'   # dynamic leaves in all; beyond: pool_exhausted
	list exempt '198.51.100.0/24' # extra never-shaped prefixes (the LAN prefixes always are)
config bucket 'b12'
	option policy '2'             # push key b:2 / r:2 ('' → the section name)
	option class '0x12'           # 0x02-0xff
	option parent ''              # parent bucket; depth ≤ 4
	option down_kbit '50000'      # 0 = unlimited that way
	option up_kbit '10000'
	option fairness 'per_host'    # rest leaf: per_host = CAKE dual-*host, per_flow = fq_codel
	option include_lan '0'
	list schedule 's7'
config network 'guest'            # UCI interface of a LAN
	option policy '2'
	option bucket 'b12'           # '' = none
	option each_down_kbit '5000'  # both '' = no leaf per device
	option each_up_kbit '1000'
	option include_lan '0'        # '1': LAN↔LAN traffic of the network shaped too
	list schedule 's7'
config schedule 's7'
	list window 'mon-fri 18:00-23:00' # days a window starts on; end ≤ start = past midnight
	option policy '2'             # a policy's schedule, or: option assignment '<id>'
	option action 'limit'         # limit | unlimited | block | move
	option down_kbit '25000'      # bucket rates while active ('' = keep, '0' = unlimited)
	option up_kbit ''
	option each_down_kbit '2500'  # member caps while active; for move: the new caps
	option each_up_kbit ''
	option bucket ''              # move: the bucket the members sit in meanwhile
```

The file is refused as a whole (the kernel keeps what it has, the push says
`state: error` with the reasons) on a syntax error, a bucket class outside
0x02-0xff or used twice, a missing or cyclic parent, nesting deeper than 4, a
child bucket allowed more than its parent, children whose rates add up to
more than the parent's, a network or move naming an unknown bucket, or a bad
window.

**Precedence per MAC:** its own entry (on every LAN, so a cap follows the
device across SSIDs and VLANs), else its network's default. Within an entry,
the first active schedule of `schedules` wins; an exhausted quota overrides
schedules (`throttle` → the throttle rates, `block` → drop).

**Schedules** use the router's clock and zone (`/tmp/TZ`, the POSIX TZ string
OpenWrt writes from `system.timezone`). Until the clock is known to be synced
(busybox ntpd's hotplug marker `/tmp/perch-qos/ntp-synced`, or the kernel's
clock discipline) no schedule is in force and the push reports
`schedule_clock_unsynced`. Window edges are applied within the 2 s tick, in
place: rate changes are `tc class change`, moves are `tc filter replace`
after the new class exists, so a flow never stops.

#### Commands

```
perch-collector qos apply    # lift a stop, apply now (idempotent)
perch-collector qos sync     # apply now, a stop stays (hotplug, init reload)
perch-collector qos stop     # remove every Perch tc object; stays off until apply or reboot
perch-collector qos status   # the push section + last apply, JSON
perch-collector qos probe    # qos.probe's answer, JSON
perch-collector qos render [-full]   # the tc batch apply would run (or the whole tree)
perch-collector qos run      # the shaper loop in the foreground (no capture, no controller)
```

Every apply writes `/tmp/perch-qos/last.batch` (what ran), `full.batch` (the
whole tree), `last-apply.json` and `state.json` (class and filter handle
allocations, dynamic devices, epoch). `/etc/init.d/perch-qos`: start = apply,
stop = `qos stop`, reload (triggered by changes of perch-qos, sqm and the
firewall config) = sync. `/etc/hotplug.d/iface/40-perch-qos` syncs on
ifup/ifdown/ifupdate (new IPv6 prefixes become exemptions at once).

#### On the socket

- **Hello:** capability `qos` while perch-qos is installed (and the optional
  `QoSAllowed` gate, the config plane's managed mode, allows it).
- **`qos.probe`** `{}` →
  `{sqm:{installed, version, luci, queues:[device]}, kernel:{htb, htb_class, fq_codel, cake, clsact, flower, skbedit, mirred, matchall, chain, ifb}, conflicts:[pkg], flowOffload:{software, hardware}, lanDevices:[{network, device, prefixes:[cidr], conflict?}], tc, clockSynced, tz, configured, perchQosPackage?}`.
  Kernel features are tried on a scratch ifb (`ifb-pqprobe`). Conflicts are
  installed and enabled `qosify`, `nft-qos`, `eqos`.
- **`qos.devices.set`** `{revision, devices: DeviceEntry[] (≤ 4096)}` →
  `{revision, accepted, rejected:[{mac, error}]}`. `DeviceEntry` is exactly
  the planner's: `{mac, bucket: string|null, downKbit: number|null,
  upKbit: number|null, quota: {limitBytes, usedBytes, onExhausted:
  'block'|'throttle', throttleDownKbit, throttleUpKbit}|null, expiresAt:
  ISO|null, includeLan?: true, schedules?: string[]}` (null rate =
  unlimited that way). Rejected one by one: `invalid_mac`, `duplicate_mac`,
  `router_mac` (the router's own interfaces), `invalid_rate`,
  `invalid_quota`, `invalid_expires_at`. Caps below `min_device_kbit` are
  raised to it. Errors: -32602 (bad params, more than 4096), -32010
  `qos_not_active` (no perch-qos). The set is kept in `/tmp/perch-qos/`
  at once and in `/etc/perch-qos/devices.json` at most once a minute
  (quota counters at most every 15 minutes). A `usedBytes` equal to the one
  the controller sent before keeps the agent's own count; a different one
  (a reset, a new quota) replaces it.
- **`qos.status`** `{}` → `{qos: <push section>, lastApply, lans, summary}`.
- **Push:** `collector.push` gains `qos` (absent = not reported):

```
{ "epoch": "3f2a…",                       // new = counters start over
  "state": "active"|"paused"|"error",
  "pausedBy": "config"|"local"|null,      // globals.enabled '0' | qos stop
  "configRevision": "12"|null, "devicesRevision": 7|null,
  "collectedAt": "…Z",
  "wan": [{ "device": "wan2", "section": "wan2", "enabled": true,
            "egress":  {kind, bandwidthKbit, bytes, packets, drops, overlimits, backlogBytes, ecnMarks, peakDelayUs}|null,
            "ingress": {…}|null }],         // sqm's root qdiscs, as they are
  "classes": [{ "id": "1:200", "key": "d:02:00:00:00:10:11"|"b:2"|"r:2"|"n:guest",
                "dir": "down"|"up", "rateKbit", "ceilKbit",   // as applied now (schedules included)
                "bytes", "packets", "drops", "overlimits", "backlogBytes" }],   // drops/backlog include the leaf qdisc
  "devices": [{ "mac", "classId": "1:200"|"1:112"|null, "network": "guest"|null,
                "dynamic": false, "state": "shaped"|"unshaped"|"blocked"|"throttled" }],
  "quotas": [{ "mac", "usedBytes", "limitBytes", "exhausted", "enforced" }],
  "schedules": [{ "name": "s7", "active": true, "since": "…Z"|null, "until": "…Z"|null }],  // inactive: until = next start
  "errors": [{ "code", "detail" }] }
```

  `errors` codes: `apply_failed`, `stats_unreadable`, config refusals
  (`config_*`), `unknown_bucket`, `unknown_network`, `pool_exhausted`,
  `class_pool_exhausted`, `qos_conflict_sqm_on_lan`,
  `schedule_clock_unsynced`, `sqm_paused` (a queue disabled on the router,
  decision 15: reported, never reverted), `sqm_below_floor`,
  `device_rejected`.
- **`qos.event`** (notification) `{type, at, mac?, detail?}`, queued (128)
  while no session is open: `quota_exhausted` {usedBytes, limitBytes,
  onExhausted, enforced}, `pool_exhausted`, `apply_failed` {errors},
  `local_pause` / `local_resume` {by: config|local},
  `schedule_clock_unsynced`, `sqm_paused` / `sqm_resumed` {section,
  device}, `cap_hit` {dir, classId, ceilKbit, rateKbit} (a device class at
  ≥ 90 % of its ceiling for three reads, then 15 minutes quiet).
- The controller socket is marked DSCP CS6 (CAKE's voice tin on a shaped WAN).

## Packaged deployments

The OpenWrt init script and the Docker image configure the daemon through
`PERCH_COLLECTOR_*` variables only; no YAML file is needed. `GET /healthz` and
every `meta` block report the build `version` (set with
`-ldflags "-X main.version=…"`).
