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
# 96 bytes is enough for Ethernet + IP + TCP/UDP headers (port mode).
# With classification_mode "ndpi" the collector ignores lower values and
# captures whole packets (65535 bytes, logged at startup): a TLS
# ClientHello with a post-quantum key share (X25519MLKEM768, the default
# in current browsers and curl) is 1.5-2 KB and reaches the capture as one
# packet above the MTU behind GSO/GRO, and even a plain full-size packet
# is a 1514-byte frame. A cut-off ClientHello never reassembles in nDPI
# and the flow loses its server name.
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

# The guest portal (capability "portal", see "Guest portal" below): Perch's
# own nftables enforcement and the guest pages, set up by the controller.
# Nothing is captive until the controller configures a portal. "auto" = on
# under OpenWrt with the WebSocket transport; "off" also removes any
# enforcement a previous run left (tables, fw4 drop-in, dnsmasq file).
# Default: "auto"
portal: auto
# The guest pages' TCP port (plain HTTP, all addresses; only the portal
# devices may reach it). Not 53, 67 or 80.
# Default: 2080
portal_port: 2080
# Where grants, offline vouchers, keys and the journal are snapshotted.
# Default: "" (/etc/perch-collector/portal/state.db)
portal_storage_path: ""
# Seconds between snapshots of byte/time counters; 0 = by storage kind (300
# on flash, every enforcement tick on eMMC and disks). Grants and journal
# events are written at once. 0 or 5-3600.
# Default: 0
portal_flush_interval: 0
# Mount point portal_storage_path must be on (a USB disk). When it is not
# mounted (and carries no .perch-portal-storage marker), the state stays in
# RAM and is snapshotted to the default path, never onto the empty mount
# point on the router's flash.
# Default: ""
portal_storage_mount: ""

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
| `PERCH_COLLECTOR_OBSERVE` | `observe` (`auto`, `on`, `off`) |
| `PERCH_COLLECTOR_OBSERVE_PARTS` | `observe_parts` (comma-separated) |
| `PERCH_COLLECTOR_OBSERVE_REFRESH` | `observe_refresh` (seconds) |
| `PERCH_COLLECTOR_CONNTRACK_FLUSH` | `conntrack_flush` (`auto`, `on`, `off`) |
| `PERCH_COLLECTOR_GATEWAY_BACKUP` | `gateway_backup` (`redacted`, `full`, `off`) |
| `PERCH_COLLECTOR_CONTROLLER_ADDRESS_CACHE` | `controller_address_cache` |
| `PERCH_COLLECTOR_PORTAL` | `portal` (`auto`, `on`, `off`; UCI `portal_enabled`) |
| `PERCH_COLLECTOR_PORTAL_PORT` | `portal_port` |
| `PERCH_COLLECTOR_PORTAL_STORAGE_PATH` | `portal_storage_path` |
| `PERCH_COLLECTOR_PORTAL_FLUSH_INTERVAL` | `portal_flush_interval` (seconds) |
| `PERCH_COLLECTOR_PORTAL_STORAGE_MOUNT` | `portal_storage_mount` |
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
# snap_len is not needed: nDPI mode always captures whole packets
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

## Guest portal (`portal`, gateway plan 4, owner decision 27)

The router side of the Perch guest portal. The controller's domain and the
HMAC scheme are in the controller repository, `docs/gateway/portal.md`; this
section is the collector's half of the wire contract. Enforcement is Perch's
own nftables (no openNDS): see ARCHITECTURE.md, "Guest portal".

**Hello.** `capabilities` gains `portal`, and the hello carries its details:

```json
"portal": {"version":1, "keyEpoch":1, "configRevision":4, "port":2080, "maxPortals":16,
  "enforcement": {"nft":true, "egress":true, "fw4Include":"ok", "nftset":false, "conntrack":true},
  "storage": {"path":"/etc/perch-collector/portal/state.db", "kind":"flash", "fsType":"jffs2",
    "device":"/dev/mtdblock6", "mountPoint":"/overlay", "persistent":true,
    "flushIntervalSeconds":300, "writeThrough":false, "fallback":false, "warning":""}}
```

`keyEpoch`/`configRevision` are null until the first `portal.configure`.
`egress:false` (kernel < 5.16) = downloads are not counted per MAC; `nftset:false`
= dnsmasq lacks nftset (not dnsmasq-full), the walled garden's names are
resolved by the collector every 5 minutes instead; `fw4Include`: `ok`,
`missing` (fw4 did not include the drop-in, `auto_includes 0`), `none` (no fw4).
`storage.kind`: `flash`, `emmc`, `disk`, `ram`, `unknown`.

**Controller → collector** (requests):

| Method | Params → result |
|---|---|
| `portal.configure` | `{revision, gatewayId, keys?:{epoch, gatewayKey}, settings:{enforceIntervalSeconds, usageIntervalSeconds, guestFailuresPerDevicePerMinute, guestFailuresPerDevicePerHour, guestFailuresPerPortalPerMinute, preauthDnsPerDevicePerMinute, offlineRedemption, relayRequestsPerClientPerMinute}, storage?:{path, flushIntervalSeconds, expectMount}, portals:[{portalId, name, network, device?, enabled, methods:{voucher,password}, templateSha256, cspConnectSrc[], privacyNotice, gatewayName, walledGarden[], ipBinding?, relay?}]}` → `{revision, keyEpoch, missingTemplates[], portals:[{portalId, device, state:'active'\|'disabled'\|'waiting_device'\|'error', listen, counting, issues[]}], enforcement, storage, issues[]}` |
| `portal.template` | `{sha256, files:[{name, contentType, dataBase64}]}` → `{stored:true}` |
| `portal.authorize` | docs §6.4 (`full, serverNow, ackedEventSeq, nonce, keyEpoch, groups[+sig], grants[+sig], revertExternals, sig`) → `{results:[{grantId, localRef?, revision, state:'active'\|'pending_device'\|'rejected', error?}], ended:[{grantId, localRef?}]}` |
| `portal.deauthorize` | `{grantIds, reason, serverNow, nonce, keyEpoch, sig}` → `{ended:[grantId]}` |
| `portal.vouchers` | `{enabled, serverNow, nonce, keyEpoch, vouchers[+sig], sig}` → `{stored, rejected}` |
| `portal.sync` | `{ackedEventSeq}` → `{lastEventSeq, truncated, events[], grants[], externals[]}` (RouterPortalReport, docs §7) |

`portal.configure` is the whole desired portal set of the gateway (a portal
not listed is removed); `keys` is sent when the hello's `keyEpoch` differs,
and the key never leaves the router again. `settings` are clamped like the
controller's settings service; missing = default. `walledGarden` entries are
host names (dnsmasq `nftset=`, or resolved by the collector) or IPv4/IPv6
addresses and CIDRs (static interval sets). Custom templates are stored by
digest; `missingTemplates` lists the digests the router lacks (send them with
`portal.template`); a portal whose template is missing serves the builtin one.

Every signed message is checked: key epoch (`key_epoch_mismatch`, `no_keys`),
envelope signature (`bad_signature`), nonce (last 256 remembered, persisted:
`replayed`), freshness (10 minutes behind the newest accepted `serverNow`:
`stale`); all as -32000 with `data.error`. An item with a bad signature is
refused on its own (`rejected`, `bad_signature`); a grant whose group is not
held is `unknown_group`, one for a portal not configured `unknown_portal`.
A full set ends every held grant it does not list (`grant_ended`, reason
`removed`) except offline redemptions journaled after its `ackedEventSeq`;
a listed grant with both `grantId` and `localRef` maps the router's offline
grant to its id. Group `base*` usage is taken as of `ackedEventSeq`: ended
usage journaled later is added on the router until a newer set covers it.

**Collector → controller.** Requests (sent only while a session is open):

| Method | Params → result |
|---|---|
| `portal.redeem` | `{portalId, mac, ip, hostname?, code, replace?}` (code normalized) → `{grant:{WireGrant+sig}, group:{WireGroup+sig}}` or `{queued:true}`; errors -32000 `data.error` ∈ `invalid_code, invalid_credentials, expired, exhausted, revoked, disabled, device_limit, already_authorized, wrong_portal, rate_limited` |
| `portal.login` | `{portalId, mac, ip, hostname?, username, password, replace?}` → as `portal.redeem` |
| `portal.relay` | `{portalId, op:'authorize'\|'status'\|'deauthorize', mac?, token, body?, clientIp}` → `{status, body}` |

The redeem/login answer's grant and group must be signed like
`portal.authorize` items; the router verifies them and applies the grant at
once (an existing group keeps its `base*` until the next full set). No answer
within 8 s, or no session: the router redeems offline from its held list
(decision 20) and journals `offline_redeemed`; logins need the controller.

Notifications: `portal.event` = one journal entry as it happens (RouterEvent:
`grant_active`, `grant_ended` with `reason` `expired|quota|router_deauth|logout|moved|removed`
and final `bytesUp/bytesDown/activeSeconds`, `external_auth`, `offline_redeemed`
with `voucherId, localRef, placement, demotedGrantId?, demotedLocalRef?, startsAt?, expiresAt?, ip?, hostname?`);
`portal.sessions` every `usageIntervalSeconds` while any grant is live:
`{collectedAt, clients:[GrantUsage & {hostname, sessionStartedAt}], preauthCount, portals:[{portalId, authenticated, preauth}]}`.
The journal (1000 entries, persisted) is the source of truth; notifications
are best effort, `portal.sync` settles.

**Guest pages** (`http://<portal address>:<portal_port>`): `GET /` (login or
status page, `?m=<message_code>`, `?o=<origin url>`), `POST /portal/voucher`
`{code, replace?}`, `POST /portal/login` `{username, password, replace?}`,
`POST /portal/logout` (form posts answer 303 `/?m=<code>`; JSON posts
`200 {ok, status}` or `{ok:false, error, message}` with 400/401/403/409/410/429/503),
`GET /portal/api/status` (`application/captive+json`: `captive, user-portal-url,
seconds-remaining?, bytes-remaining?, can-extend-session:false, perch:{state, mac, methods, grant}`),
`GET /assets/<templateSha256>/<file>` (immutable), and with `relay` the Paid
Hotspot API relay `POST /portal/v1/authorizations`, `GET|DELETE
/portal/v1/authorizations/<mac>` (Bearer token passed to the controller, never
stored; 401 `invalid_api_token`, 404 `relay_disabled`, 429, 503). Any other
host name (a request that reached the pages through the port-80 redirect) is
answered with 302 to the portal (`?o=`), which is what opens the Android,
Apple, Windows and Firefox login sheets; once the device is online such a
probe gets its success answer (204, `Success`, …). Abuse limits: failed codes
and logins only, per MAC 5/min and 20/h, per portal 60/min (settings), 429 +
`Retry-After`; POSTs need `Origin`/`Referer` of the portal or none; bodies
≤ 4 KiB; 16 requests at a time; 10 s timeouts; limiter maps bounded (4096).
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
