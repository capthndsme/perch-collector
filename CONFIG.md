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

# The config plane (below): may the controller read, or also change, this
# router's UCI configuration? "none", "read" or "write". Only on OpenWrt and
# with transport websocket.
# Default: "none"
config_access: none

# The UCI configs the controller may read (and with "write", change).
# perch-collector, perch-apd, rpcd, uhttpd, dropbear and luci never are,
# whatever is listed.
# Default: [network, dhcp, firewall]
managed_config: [network, dhcp, firewall]

# Accept config writes over plain http:// or an unverified certificate when
# the controller signs each request (it has to opt in too), and the longest
# confirm window of a config change in seconds (30..3600).
# Default: false, 600
config_allow_insecure: false
config_confirm_max: 600

# The HMAC key of signed writes (16+ characters). Empty = the api_key, which
# also travels as the connection's credential.
# Default: ""
config_sign_key: ""

# Packages the controller may install besides its own list.
# Default: []
package_allow: []

# Where the collector would keep local state; only its storage type is
# detected and reported today. Must be absolute.
# Default: "/etc/perch-collector"
storage_path: /etc/perch-collector

# The UCI network the capture interface belongs to, for the capabilities
# report (the OpenWrt init script sets it from capture_network).
# Default: ""
capture_network: ""
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
| `PERCH_COLLECTOR_CONFIG_ACCESS` | `config_access` (`none`, `read`, `write`) |
| `PERCH_COLLECTOR_MANAGED_CONFIGS` | `managed_config` (comma-separated config names) |
| `PERCH_COLLECTOR_CONFIG_ALLOW_INSECURE` | `config_allow_insecure` (`true`/`false`, `1`/`0`) |
| `PERCH_COLLECTOR_CONFIG_CONFIRM_MAX` | `config_confirm_max` (seconds) |
| `PERCH_COLLECTOR_CONFIG_SIGN_KEY` | `config_sign_key` |
| `PERCH_COLLECTOR_PACKAGE_ALLOW` | `package_allow` (comma-separated package names) |
| `PERCH_COLLECTOR_STORAGE_PATH` | `storage_path` |
| `PERCH_COLLECTOR_CAPTURE_NETWORK` | `capture_network` |

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

## The config plane (`config_access`)

Perch's managed gateway: with the owner's opt-in on the router, the
controller can read the router's UCI configuration and is told when it
changes (`read`), and change it (`write`), with every change confirmed over a
fresh connection or restored on its own. The protocol is in ARCHITECTURE.md
("The config plane"); the design in the controller repository
(`docs/gateway/`).

- **Opt-in.** `config_access` is `none` by default: nothing is read and the
  hello says so. `read` lets the controller read the configs in
  `managed_config` (default `network dhcp firewall`) plus the sync ledger
  `perch-managed`. The agent's own config (so the controller can never flip
  this switch or re-point `server_url`), `perch-apd`, `rpcd`, `uhttpd`,
  `dropbear` and `luci` are never readable. The controller has its own
  switch per gateway (mode `off`/`observe`/`managed`); the effective access
  is the lower of the two.
- **Where.** On OpenWrt (`/etc/openwrt_release`) with `transport websocket`.
  A collector on a server offers no config plane.
- **What is read.** The committed files in `/etc/config`, parsed by the
  kit's libuci-compatible parser (anonymous sections carry the names libuci
  gives them, `cfg0a1b2c`), never staged changes: `uci set` without a
  commit and a LuCI session's unsaved edits are reported only as
  `uncommitted`. Every section also carries a content hash.
- **Secrets never leave the router.** Options named `key`, `password`,
  `secret`, `psk`, `private_key`, `preshared_key`, `auth_secret`,
  `sae_password`, `faskey`, `api_key`, `r0kh`, `r1kh`, `key1`..`key4` or
  ending in `_key`, `_secret`, `_password`, `_passwd`, `_psk`, `_pwd` are
  removed and replaced by `"hmac:" + 16 hex digits` of
  HMAC-SHA256(api_key, `config.section.option=value`): the controller can
  tell a value changed, or check one it holds, without seeing it.
- **Change detection.** While the controller's mode is not `off`, every
  readable config is stat'ed every `watchSeconds` (the controller's setting,
  10..600, default 30) and re-hashed when its size or mtime moved. The
  package's init script adds a procd reload trigger for each allowlisted
  config; its `reload_service` sends SIGHUP, and the daemon re-hashes at once
  (a LuCI save, `uci commit` through rpcd, `reload_config`). A change is
  reported after `debounceSeconds` (1..60, default 5) of quiet, and held while
  a LuCI apply waits for its confirm (at most 5 minutes; one that rolls back
  is never reported). The author is a guess: the one logged-in LuCI user when
  the trigger saw it, `cli` when only polling did, `unknown` otherwise.
- **Writing** (`config_access write`). Each change arrives as one job. The
  agent snapshots the configs it touches to `/etc/perch-collector/rollback/`
  (on the root flash, whatever `storage_path` says), commits them through a
  private rpcd session (a LuCI or `uci` edit in progress is never included),
  lets the services reload, then drops its connection and dials a fresh one:
  the controller confirms on that one. Without a confirm within the window
  (the controller's setting, capped by `config_confirm_max`; at least 300 s
  when the change touches the network the router reaches the controller
  through) the agent restores the snapshot and reloads by itself. Router
  edits made during the window are reported back when a rollback undoes them.
  A reboot during the window is caught by the boot guard (`perch-collector
  config-guard`, init script `perch-collector-guard`), which restores before
  the network starts. Sections Perch manages are listed in
  `/etc/config/perch-managed` (the ledger); nothing is marked inside the
  other configs. While a LuCI apply waits for its confirm, or `uci set` left
  uncommitted changes to `network`, a change is refused.
- **Transport.** Writes need an `https` `server_url` with a verified
  certificate. `config_allow_insecure '1'` also accepts them over plain
  `http://` (or an unverified certificate) when the controller signs each
  request (HMAC with the api_key, or `config_sign_key`; a timestamp within 5
  minutes of the router's clock, a nonce used once, bound to the connection):
  nobody on the path can change the router's config, but they can read it.
  Secret values (Wi-Fi keys, WireGuard keys) are never accepted that way. The
  api_key is also the connection's credential, so over plain `http://` it is
  visible to anyone who can read the traffic; set `config_sign_key` (16+
  characters, entered in the controller too) when that matters.
- **Packages.** The controller may install the packages its features use
  (sqm-scripts, opennds, wireguard-tools, mwan3, pbr, their LuCI apps, ...;
  `list package_allow` adds more) with opkg or apk, after checking the free
  flash; the install is confirmed like a config change and removed again on a
  failure or without a confirm.
- **Capabilities.** OpenWrt release and board, firewall (`fw4`/`fw3`),
  package manager (opkg or apk) and the versions of the packages gateway
  features depend on (read from the package database, never by running
  opkg/apk), whether rpcd's `uci` object or only the uci CLI is there, free
  flash, and what backs `storage_path` (`flash`, `emmc`, `sd`, `usb`,
  `sata`, `nvme`, `disk`, `ram`, `network`, `unknown`; `onRoot` = the path is
  on the router's own root, i.e. a USB stick meant for it is not mounted).

OpenWrt package options (`/etc/config/perch-collector`, `main` section):

```
option config_access 'none'          # none | read | write
list   managed_config 'network'      # the allowlist (package default network dhcp firewall)
list   managed_config 'dhcp'
list   managed_config 'firewall'
option config_allow_insecure '0'     # '1' = signed writes over plain http
# option config_sign_key ''          # HMAC key of those signatures (default: api_key)
option config_confirm_max '600'      # longest confirm window, seconds (30-3600)
# list package_allow 'tcpdump-mini'  # more packages the controller may install
option storage_path '/etc/perch-collector'
```

`perch-collector gateway-config [config...]` prints the capabilities and the
read the controller would get, as JSON, and exits. It takes its settings from
`/etc/config/perch-collector` (environment variables win), reads nothing
with `config_access none`, and writes nothing.

`perch-collector config-guard` is the boot guard: when a change was waiting
for its confirm at a reboot, it restores the configs from the snapshot (the
package runs it at boot, before the network; on a router without the
package, add it to an early init script by hand). The daemon does the same at
start when no guard ran.

## Packaged deployments

The OpenWrt init script and the Docker image configure the daemon through
`PERCH_COLLECTOR_*` variables only; no YAML file is needed. `GET /healthz` and
every `meta` block report the build `version` (set with
`-ldflags "-X main.version=…"`).
