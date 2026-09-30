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

# Several networks at once (on the router; see "Several networks" below):
# UCI network names, device names, or "auto" = every LAN-side network netifd
# has (up, proto static or none, not a WAN). Set = `interface` is not
# captured on its own. Default: [] (the single `interface`)
capture_networks: []
# Networks (or devices) left out of capture_networks. Default: []
capture_exclude: []
# Seconds between two reads of netifd for networks that appeared or went
# away (also on SIGHUP). 5-3600. Default: 30
capture_rescan: 30
# Scope rule: "on" counts traffic routed between two local networks, and
# traffic to the router's own LAN addresses, as LAN instead of WAN. "auto" =
# on with capture_networks, off with the single interface. Default: auto
routed_lan: auto
# With capture_networks and nDPI: "shared" = one nDPI detection module
# (about 12 MB) for every capture, each with a classifier and flow table of
# its own; "per_network" = a module per capture (about 12 MB more per
# network, nDPI work spread over the CPUs). Default: shared
ndpi_module: shared

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
# resolver, system, wireguard, ddns). Empty = all. dhcp has its own switch,
# dhcp_leases.
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

# The guest portal (capability "portal", see "Guest portal" below): Perch's
# own nftables enforcement and the guest pages, set up by the controller.
# Nothing is captive until the controller configures a portal. "auto" = on
# under OpenWrt with the WebSocket transport; "off" also removes any
# enforcement a previous run left (tables, fw4 drop-in, dnsmasq file).
# Default: "auto"
portal: auto
# The guest pages' TCP port (plain HTTP). Listened on only on the router's
# addresses on the portal networks, and only while a portal runs there;
# nothing listens without a portal. Not 53, 67 or 80.
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

# A fixed HMAC key of signed writes (16+ characters) that you also enter in
# the controller. Empty = the key of a pairing with the controller
# (perch-collector pair). The api_key never signs.
# Default: ""
config_sign_key: ""

# Packages the controller may install besides its own list. perch-collector,
# perch-qos and perch-apd are ignored here: only self-update installs them.
# Default: []
package_allow: []

# Self-update (agent.update.*, the controller's Settings → Updates): the
# controller may install a newer Perch Network Collector release. Only
# releases signed with a trusted key (the built-in Perch release keys plus
# update_keys: "RW…" signify/usign public key lines) are installed, every
# file is checked here, and the previous version comes back unless the new
# one reaches the controller again (also after a reboot, via the OpenWrt
# boot guard). Allowed over plain http:// too. Only the WebSocket transport
# carries it; a Docker install (PERCH_COLLECTOR_INSTALL=docker, the image's
# default) reports it and updates with docker compose instead.
# Default: true, []
self_update: true
update_keys: []

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
| `PERCH_COLLECTOR_CAPTURE_NETWORKS` | `capture_networks` (comma-separated; `auto`) |
| `PERCH_COLLECTOR_CAPTURE_EXCLUDE` | `capture_exclude` (comma-separated) |
| `PERCH_COLLECTOR_CAPTURE_RESCAN` | `capture_rescan` (seconds) |
| `PERCH_COLLECTOR_ROUTED_LAN` | `routed_lan` (`auto`, `on`, `off`) |
| `PERCH_COLLECTOR_NDPI_MODULE` | `ndpi_module` (`shared`, `per_network`) |
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
| `PERCH_COLLECTOR_MANAGED_CONFIG_AUTO` | `managed_config_auto` (bool, default true) |
| `PERCH_COLLECTOR_MANAGED_CONFIG_EXCLUDE` | `managed_config_exclude` (comma-separated config names) |
| `PERCH_COLLECTOR_CONFIG_ALLOW_INSECURE` | `config_allow_insecure` (`true`/`false`, `1`/`0`) |
| `PERCH_COLLECTOR_CONFIG_CONFIRM_MAX` | `config_confirm_max` (seconds) |
| `PERCH_COLLECTOR_CONFIG_SIGN_KEY` | `config_sign_key` |
| `PERCH_COLLECTOR_PACKAGE_ALLOW` | `package_allow` (comma-separated package names) |
| `PERCH_COLLECTOR_SELF_UPDATE` | `self_update` (bool, default true) |
| `PERCH_COLLECTOR_UPDATE_KEYS` | `update_keys` (comma-separated `RW…` key lines) |
| `PERCH_COLLECTOR_INSTALL` | `docker` in the image: install kind `docker` (updated with docker compose, never in place) |
| `PERCH_COLLECTOR_STORAGE_PATH` | `storage_path` |
| `PERCH_COLLECTOR_CAPTURE_NETWORK` | `capture_network` |
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
   "adminUp":true,"carrier":true,"operstate":"up","speedMbps":10000,"duplex":"full","carrierChanges":2,
   "rxBytes":11542336166,"txBytes":110655073351,"counterScope":"port"}]
```

The ports come from `/sys/class/net`, with labels from the device tree and
roles from OpenWrt's `/etc/board.json` for hardware ports. The interfaces the
report counts as WAN (`wan_interfaces`, else the default routes) are role
`wan`. A router in a container has no hardware port, so it reports its veths
(`medium: "virtual"`). Since 1.1.0 a port with a link also carries its byte
counters (`rxBytes` received from the cable, `txBytes` sent into it,
cumulative) and `counterScope`: `port` when they cover every frame (a DSA
switch port reads the switch's own counters), `cpu` when only what the
router's CPU handled (a switch whose byte counters the collector does not
know). The controller turns them into per-port traffic and the rates on its
cables. `[]` means the router has no port; the key is left out
with `ports: off` and while `/sys/class/net` cannot be listed. The controller
reads a missing key as "not reported", never as "no ports". `on` behaves like
`auto`; `1` and `0` (UCI) mean on and off. `perch-collector ports` prints the
array once and exits without reading this configuration (README, "The
Gateway agent's ports").

### Several networks (`capture_networks`, gateway plan 1 section 8.3)

A router with more than one LAN (a guest network, an IoT network, VLANs)
carries each on its own L3 device: `br-lan`, `br-guest`, `br-lan.110`. With
`capture_networks` the collector captures all of them, each with an engine
(libpcap handle and nDPI instance) of its own, and follows the router as
networks come and go:

- **What `auto` selects.** Every netifd interface (`ubus call
  network.interface dump`) that is up, has an L3 device, proto `static` or
  `none`, and is on the LAN side. The side rule (`internal/netcap/side.go`,
  the same as the controller's): a tunnel proto (`wireguard`, `openvpn`,
  `gre`…) is a VPN; an uplink has a WAN proto (`dhcp`, `dhcpv6`, `pppoe`,
  `qmi`, `6in4`…), a default route, a firewall zone with `masq` on, a UCI
  `gateway`, or is listed in `wan_interfaces`; a `static`/`none` network on
  an uplink's device (or on `@<uplink>`) is a WAN alias, such as a modem's
  management subnet on the WAN port; everything else is LAN. WANs and VPNs
  are never captured, even when named, never listed as networks, and their
  prefixes are never local. Several networks on one device (an alias) share
  one engine, attributed to the first by name that has an IPv4 address.
- **Never twice.** A bridge port is never captured (its bridge is the L3
  device), nor a device whose VLAN devices are captured as well (it would
  see their frames a second time, tagged). `auto` never picks a device that
  carries VLAN devices at all (a VLAN-filtering bridge): excluding a VLAN
  must not make its frames show up on the trunk instead.
- **Names or devices.** An entry that is not a netifd network is taken as a
  device name (a host without netifd), and its network is its own name.
  `capture_exclude` removes networks by network or device name. The
  controller adds its own exclusions (a network whose capture an admin
  turned off: `agent.configure` `capture.exclude`); they join
  `capture_exclude` live, never replace it, and are dropped again when the
  controller's list no longer names them. They are not kept across a
  restart (the controller sends them with every configure). A
  single-interface collector keeps its one capture; the controller drops
  the excluded network's rows itself.
- **Following the router.** netifd is re-read every `capture_rescan` seconds
  and on `SIGHUP` (the OpenWrt package sends one on every interface event:
  `/etc/init.d/perch-collector rescan`). A new network gets an engine, a
  network that went down or away loses its own; the others are never
  touched, and nothing is reset. A device that cannot be opened is retried
  every rescan; while netifd does not answer the running engines stay.
- **The router's MACs and networks.** The pivot MACs are the MACs of every
  LAN-side L3 device plus `gateway_macs`; the local subnets are the prefixes
  of every LAN-side network that is up (IPv4, IPv6 addresses and the prefixes
  assigned from a delegated one) plus `local_subnets`. Both follow the rescan.
- **nDPI.** Every capture has a classifier and flow table of its own: a
  flow routed between two captured networks is seen on both, and one flow
  table would feed it to nDPI twice. `ndpi_max_flows` is split across the
  engines running when an engine starts (at least 4096 each, never more than
  the total). The detection module behind them (its protocol tables and
  host automata, about 12 MB resident) is one for all captures with
  `ndpi_module: shared` (the default; the cgo calls of all captures then
  take one lock), or one per capture with `per_network` (measured on the
  lab router with six networks: 95 MB RSS against 32 MB for one network).

`capture_networks` unset (the default outside the package's new config)
keeps the single `interface` exactly as before: one engine, the configured
or detected gateway MAC, the interface's subnets and the old scope rule. Its
frames are still tagged with the interface's network when netifd knows it,
so the device rows gain `network` there too.

**Scope rule (`routed_lan`, owner decision 8).** With it on, a frame through
the router whose far address is local (a LAN-side prefix, or link-local)
counts as **LAN**: `bytes_in_lan`/`bytes_out_lan` and a `top_lan_peers`
entry for the local device, no destination row. That covers traffic routed
between two local networks, which is seen once on each side and attributed
to a different device on each (sender's `out_lan`, receiver's `in_lan`), and
traffic to the router's own LAN addresses (DNS, LuCI), which used to count
as WAN. Traffic to anything else, private WAN-side addresses included, stays
WAN. `auto` turns it on with `capture_networks` only, so a single-interface
collector's WAN/LAN split does not move without an explicit `routed_lan: on`.

**Device rows** gain two fields, both left out when the capture does not know
the network:

```json
{"mac":"02:00:00:99:30:11", …, "network":"iot", "networks":["iot"]}
```

`network` is the capture network where the MAC was last an endpoint of a
frame, `networks` every one it was seen on (first-seen order, at most 8).

**The networks report.** With gateway stats on and netifd answering, the
`gateway` object gains `networks`: every LAN-side network (not loopback, not
a WAN), up or down, captured or not. Absent = not reported (no netifd, an
older collector); `[]` = none; the same rule as `ports`.

```json
"networks":[
  {"name":"iot","device":"iot","proto":"static","up":true,
   "ipv4":["192.168.30.1/24"],"ipv6":[],
   "rxBytes":1804,"txBytes":52011,"rxRate":0,"txRate":12.4,
   "captured":true,"devices":1,"activeDevices":1,
   "capture":{"bytesInWan":0,"bytesOutWan":0,"bytesInLan":50120,"bytesOutLan":1200,
              "packetsInWan":0,"packetsOutWan":0,"packetsInLan":35,"packetsOutLan":20,
              "scope":"routed","kernelDrops":0}},
  {"name":"office","device":"","proto":"static","up":false,"ipv4":[],"ipv6":[],
   "captured":false,"devices":0,"activeDevices":0}]
```

- `rxBytes`/`txBytes`: the L3 device's `/proc/net/dev` counters, from the
  router's side (rx = received from the network, i.e. its devices' uploads
  and whatever is routed out of it; tx = sent into it). Cumulative, reset
  when the device is recreated; absent while the device does not exist.
- `rxRate`/`txRate`: bytes per second since the collector's previous read
  of that device (at least a second apart); absent on the first read and
  after a counter reset. The controller can derive its own from the counters.
- `captured`, `devices` (device rows whose `network` is this one),
  `activeDevices` (of those, a frame in the last 5 minutes).
- `capture`: the capture's own counters of this network, from its devices'
  side (In = received by the network's devices), split WAN/LAN by the scope
  rule named in `scope` (`routed` or `legacy`). A frame between two devices
  of one network counts once In and once Out; a routed frame Out on the
  sender's network and In on the receiver's. Cumulative since the collector
  started. Only on the network the device's frames are attributed to (an
  alias on the same device shows `captured: true` without it).
- `capture.kernelDrops`: frames the kernel dropped for this network's
  capture since that capture started (libpcap's ring buffer was full; the
  capture counters miss them, the interface counters do not). It restarts at
  0 when the capture restarts. On the lab router (a container) captures kept
  up with 200 Mbit/s routed between two networks to within 0.3 % of iperf3;
  unshaped veth traffic at ~1.7 Gbit/s lost about a fifth, all of it
  reported here.

The hello's `captureInterface` and every `meta.capture_interface` name the
captured devices, comma-separated, cut to 64 characters (`…,+2`).

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
                "uptimeSeconds":86400,"defaultRoute":true,"metric":1,"gateway4":"203.0.113.1","dnsServers":["203.0.113.53"],
                "ipv6Prefixes":[],"ipv6Assigned":[]},
               {"network":"wan6","device":"wan0",…,"ipv6Prefixes":[{"prefix":"2001:db8:10::/56","preferredUntil":1790003600,"validUntil":1790007200}],"ipv6Assigned":[]},
               {"network":"lan","device":"br-lan",…,"ipv6Prefixes":[],"ipv6Assigned":["2001:db8:10:1::/64"]}],
 "upnp":{"installed":true,"enabled":true,"running":true,"secureMode":true,
         "mappings":[{"proto":"TCP","extPort":51413,"intIp":"192.168.1.21","intPort":51413,"expires":0,"description":"app"}]},
 "mwan3":{"serviceEnabled":false,"running":false,"configInterfaces":[{"name":"wan","enabled":true,"family":"ipv4","trackIps":["203.0.113.1"]}],
          "interfaces":[{"name":"wan","status":"notracking","enabled":true,"running":false,"up":true,"uptimeSeconds":86400,"tracking":"none","trackIps":[]}],
          "policies":{},"configPolicies":{"balanced":["wan_m1","wanb_m1"]}},
 "resolver":{"dnsmasqPort":54,"port53Process":"AdGuardHome","port53Processes":["AdGuardHome"],
             "controllerHost":{"name":"perch.example.com","addresses":["192.168.1.10"]}},
 "system":{"hostname":"gateway","release":"OpenWrt 24.10.2 r28739-…","version":"24.10.2","board":"x86/64",
           "model":"…","kernel":"6.6.100","uptimeSeconds":123456,"flowOffloading":false,"flowOffloadingHw":false},
 "wireguard":{"interfaces":[{"name":"wg0","network":"wg0","publicKey":"<base64>","listenPort":51820,
   "peers":[{"publicKey":"<base64>","description":"phone","endpoint":"203.0.113.7:40211",
             "allowedIps":["192.168.9.2/32"],"latestHandshake":1790000000,"rxBytes":123456,"txBytes":654321,"keepalive":25}]}]},
 "ddns":{"installed":true,"serviceEnabled":true,"providers":["cloudflare.com-v4","duckdns.org","no-ip.com"],
   "services":[{"name":"home","enabled":true,"domain":"home.example.com","registeredIp":"203.0.113.10",
                "lastUpdate":1790000000,"running":true,"lastError":null}]}}
```

| Part | Source | Read at most every |
|---|---|---|
| `neighbors` | rtnetlink neighbour dump (IPv4 + IPv6), `/proc/net/arp` without netlink; unicast Ethernet MACs, no link-local, no failed/incomplete entries; `reachable` = REACHABLE, DELAY or PROBE | 60 s |
| `interfaces` | `ubus call network.interface dump` (loopback left out); `defaultRoute`, `metric` and `gateway4/6` from its routes, so two WANs with metric failover read right without mwan3; `ipv6Prefixes` = delegated prefixes on an upstream (netifd's `ipv6-prefix`, lifetimes as Unix times, `null` = infinite), `ipv6Assigned` = what netifd assigned to a LAN (`ipv6-prefix-assignment`), 16 each (feature `observe.ipv6_prefixes` in `gateway.capabilities`) | 5 s |
| `upnp` | `upnpd.config` (`enabled`, `secure_mode` (on when unset, like the init script), `upnp_lease_file`, default `/var/run/miniupnpd.leases`), the `miniupnpd` process, the lease file (`PROTO:EXT:IP:INT:EXPIRES:DESC`, 1.x without `EXPIRES`); `installed:false` without miniupnpd | 15 s |
| `mwan3` | UCI (`configInterfaces`, `configPolicies`), `/etc/rc.d` (`serviceEnabled`), the `mwan3track` process (`running`), `ubus call mwan3 status` (`interfaces` with mwan3's own `status` and `tracking`, `policies`); absent when mwan3 is not installed. A service started by hand but disabled at boot reads `serviceEnabled:false, running:true` | 15 s |
| `resolver` | dnsmasq's `port` (UCI, 53 when unset), the process holding a port-53 listener (`/proc/net/{udp,tcp}{,6}` + `/proc/*/fd`), the controller's host name resolved through the router's resolver | 60 s |
| `system` | `ubus call system board` / `info`, `firewall.@defaults[0].flow_offloading(_hw)` | 60 s |
| `wireguard` | `wg show all` `public-key`, `listen-port`, `peers`, `endpoints`, `allowed-ips`, `latest-handshakes`, `transfer`, `persistent-keepalive` (each prints no secret; `dump`, `private-key` and `preshared-keys` are never run); `network` (the UCI interface of the device) and the peers' `description` from `uci show network`, nothing else of those sections. `latestHandshake` 0 = never; `endpoint`, `keepalive` (off), `description`, an interface's `publicKey` and `network` may be `null`. 16 interfaces, 256 peers, 64 allowed IPs each. Absent without the `wg` tool. `rxBytes`/`txBytes` do not count as a change (they tick) | 30 s |
| `ddns` | Only with ddns-scripts installed (else absent). `uci -X show ddns` (the `service` sections' names, `enabled`, `lookup_host` else `domain`; never the password), `serviceEnabled` = `/etc/rc.d/S??ddns`; per service in the run directory (`ddns.global.ddns_rundir`, default `/var/run/ddns`): `registeredIp` from `<name>.ip`, `lastUpdate` from `<name>.update` (ddns-scripts writes the uptime of the update: turned into a Unix time with the boot time; `null` = none since boot), `running` = the pid of `<name>.pid` runs the updater; `lastError` = the last line with ` ERROR ` or `WARN` of `<ddns_logdir>/<name>.log` (default `/var/log/ddns`) after its last successful update, ≤ 200 bytes; `providers` = the file names of `/usr/share/ddns/{default,custom}/*.json` (≤ 512) | 60 s |

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
  ≤ 128 bytes), 64 mwan3 interfaces and policies, 16 WireGuard interfaces of
  256 peers, 64 DDNS services; names ≤ 253 bytes.
- The hello's `capabilities` list `observe.<part>` for every part on, and
  `gateway.observe`. The interfaces' IPv6 prefixes and the runtime actions
  below are announced in `gateway.capabilities` `features` instead (the
  controller keeps 32 hello capabilities).

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

### UPnP mapping delete and DDNS update now (`gateway.upnp.delete`, `gateway.ddns.update`)

Runtime actions of the managed gateway (gateway-sync protocol 6.2), not
config writes: served on OpenWrt with the config plane, behind its write gate
(`config_access 'write'`; verified TLS, or `config_allow_insecure '1'` and a
request signed like the write methods), and announced as `upnp.delete` and
`ddns.update` in `gateway.capabilities` `features`.

```json
gateway.upnp.delete {"mappings":[{"proto":"TCP","extPort":51413}]}  → {"deleted":1,"notFound":0,"restarted":true}
gateway.ddns.update {"service":"home"}                              → {"started":true}
```

- `gateway.upnp.delete` (1–64 mappings) drops the lines of the lease file
  (`upnpd.config.upnp_lease_file`, default `/var/run/miniupnpd.leases`) whose
  protocol and external port match (by content, never by line number), keeps
  every other line byte for byte, writes the file atomically and runs
  `/etc/init.d/miniupnpd restart` once; miniupnpd installs what the file holds
  when it starts (LuCI's way). Nothing found: nothing written or restarted.
  Refusals (-32000, `data.error`): `upnp_not_installed`, `upnp_failed`
  (`data.detail`).
- `gateway.ddns.update` starts the service's updater the way ddns-scripts
  starts one section: `start-stop-daemon -S -b -x
  /usr/lib/ddns/dynamic_dns_updater.sh -- -v 0 -S <service> -- start` (the
  same flags on 23.05 and 24.10). The updater replaces the section's running
  one, checks at once and sends an update when the registered address differs
  (or the force interval passed); the outcome shows in the `ddns` part.
  Refusals: `ddns_not_installed`, `ddns_unknown_service` (no `service` section
  of that name), `ddns_failed` (`data.detail`).
- Bad params are -32602 with `data.error` `bad_params`; the write gate's
  refusals are the config plane's (`not_managed`, `insecure_transport`,
  `signature_required`, …).

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
	option min_wan_kbit '1000'    # floor of sqm rates: config plane edits below it are refused, queues already below it reported (sqm_below_floor)
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
OpenWrt writes from `system.timezone`; with a zoneinfo package installed and
`system.zonename` set, OpenWrt removes it and links `/etc/localtime` to the zone
file instead, whose POSIX footer is read). Until the clock is known to be synced
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

- **Hello:** capability `qos` while perch-qos is installed, in any mode.
- **Managed-mode gate:** `qos.probe`, `qos.devices.set`, `qos.status` and the
  push's `qos` need the controller's `agent.configure` mode `managed` on the
  config plane (so also `config_access` read or write); otherwise -32010
  `qos_not_active`, and the push carries no `qos`. The shaper keeps running
  what it has meanwhile.
- **`qos.probe`** `{}` →
  `{sqm:{installed, version, luci, queues:[device]}, kernel:{htb, htb_class, fq_codel, cake, clsact, flower, skbedit, mirred, matchall, chain, ifb}, conflicts:[pkg], flowOffload:{software, hardware}, lanDevices:[{network, device, prefixes:[cidr], conflict?}], tc, clockSynced, tz, configured, perchQosPackage?}`.
  Kernel features are tried on a scratch ifb (`ifb-pqprobe`). Conflicts are
  installed and enabled `qosify`, `nft-qos`, `eqos`.
- **`qos.devices.set`** `{revision, devices: DeviceEntry[] (≤ 4096)}` →
  `{revision, accepted, rejected:[{mac, error}]}`. `DeviceEntry` is exactly
  the planner's: `{mac, bucket: string|null, downKbit: number|null,
  upKbit: number|null, quota: {limitBytes, usedBytes, onExhausted:
  'block'|'throttle', throttleDownKbit, throttleUpKbit, resetAt?}|null, expiresAt:
  ISO|null, includeLan?: true, schedules?: string[]}` (null rate =
  unlimited that way). Rejected one by one: `invalid_mac`, `duplicate_mac`,
  `router_mac` (the router's own interfaces), `invalid_rate`,
  `invalid_quota`, `invalid_expires_at`. Caps below `min_device_kbit` are
  raised to it. Errors: -32602 (bad params, more than 4096), -32010
  `qos_not_active` (no perch-qos). The set is kept in `/tmp/perch-qos/`
  at once and in `/etc/perch-qos/devices.json` at most once a minute
  (quota counters at most every 15 minutes). Quota counts (controller
  docs/gateway/qos.md section 6.2): the agent keeps the larger of its own
  count and `usedBytes`, so a resend never rolls usage back; only a
  `quota.resetAt` newer than the one its count started from starts over
  from `usedBytes`.
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

## Guest portal (`portal`, gateway plan 4, owner decision 27)

The router side of the Perch guest portal. The controller's domain and the
HMAC scheme are in the controller repository, `docs/gateway/portal.md`; this
section is the collector's half of the wire contract. Enforcement is Perch's
own nftables (no openNDS): see ARCHITECTURE.md, "Guest portal".

**Hello.** `capabilities` gains `portal`, and the hello carries its details:

```json
"portal": {"version":1, "keyEpoch":1, "configRevision":4, "port":2080, "maxPortals":16,
  "enforcement": {"nft":true, "egress":true, "fw4Include":"ok", "nftset":false, "conntrack":true, "quota":true},
  "storage": {"path":"/etc/perch-collector/portal/state.db", "kind":"flash", "fsType":"jffs2",
    "device":"/dev/mtdblock6", "mountPoint":"/overlay", "persistent":true,
    "flushIntervalSeconds":300, "writeThrough":false, "fallback":false, "warning":""}}
```

`keyEpoch`/`configRevision` are null until the first `portal.configure`.
`egress:false` (kernel < 5.16) = downloads are not counted per MAC; `nftset:false`
= dnsmasq lacks nftset (not dnsmasq-full), the walled garden's names are
resolved by the collector every 5 minutes instead; `fw4Include`: `ok`,
`missing` (fw4 did not include the drop-in, `auto_includes 0`), `none` (no fw4).
`quota:false` = the kernel lacks named nft quotas or object maps (`nft_quota`,
`nft_objref`): data quotas are then enforced by the tick alone and can overshoot
by what a device moves in one tick; with it the kernel cuts a device at the
exact byte (ARCHITECTURE.md, "Guest portal").
`storage.kind`: `flash`, `emmc`, `disk`, `ram`, `unknown`.

**Controller → collector** (requests):

| Method | Params → result |
|---|---|
| `portal.configure` | `{revision, gatewayId, keys?:{epoch, gatewayKey}, settings:{enforceIntervalSeconds, usageIntervalSeconds, guestFailuresPerDevicePerMinute, guestFailuresPerDevicePerHour, guestFailuresPerPortalPerMinute, preauthDnsPerDevicePerMinute, offlineRedemption, relayRequestsPerClientPerMinute}, storage?:{path, flushIntervalSeconds, expectMount}, portals:[{portalId, name, network, device?, enabled, methods:{voucher,password}, templateSha256, cspConnectSrc[], privacyNotice, gatewayName, walledGarden[], ipBinding?, relay?, bypass?[]}]}` → `{revision, keyEpoch, missingTemplates[], portals:[{portalId, device, state:'active'\|'disabled'\|'waiting_device'\|'error', listen, counting, issues[]}], enforcement, storage, issues[]}` |
| `portal.template` | `{sha256, files:[{name, contentType, dataBase64}]}` → `{stored:true}` |
| `portal.authorize` | docs §6.4 (`full, serverNow, ackedEventSeq, nonce, keyEpoch, groups[+sig], grants[+sig], revertExternals, sig`) → `{results:[{grantId, localRef?, revision, state:'active'\|'pending_device'\|'rejected', error?}], ended:[{grantId, localRef?}]}` |
| `portal.deauthorize` | `{grantIds, reason, serverNow, nonce, keyEpoch, sig}` → `{ended:[grantId]}` |
| `portal.vouchers` | `{enabled, serverNow, nonce, keyEpoch, vouchers[+sig], append, part, parts, sig}` → `{stored, rejected}` (`stored` = vouchers taken from this part) |
| `portal.sync` | `{ackedEventSeq}` → `{lastEventSeq, truncated, events[], grants[], externals[]}` (RouterPortalReport, docs §7) |

**Offline voucher list.** `WireOfflineVoucher` = `{voucherId, verifier,
portalIds, groupKey, durationMode, startMode, durationSeconds, quotaBytes,
downKbps, upKbps, maxDevices, redeemBy, expiresAt, timeUsedSeconds, bytesUsed,
revision, firstUsedAt}`, signed in that order (`firstUsedAt`, epoch ms or null,
is the last canonical line). A list longer than 4000 comes in parts, in order,
all with the same `serverNow`: part 1 (`append:false`) replaces the held list,
parts 2… (`append:true`, envelope `reason` = `"append"`) add to it. An append
part whose `serverNow` is not the one of the part 1 last taken is refused
(-32000 `vouchers_out_of_order`, the list is unchanged; the controller sends
the whole list again). `firstUsedAt` tells a used voucher from an unused one:
`redeemBy` only applies while it is null and the router has not redeemed or
started the voucher itself.

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
| `portal.login` | `{portalId, mac, ip, hostname?, username, password, replace?}` → as `portal.redeem`, plus `bound?:{groupId, groupName, moved}` (decision 31: the user's device group took the device; `moved` without a grant = its own network, the guest page says `moving`) |
| `portal.relay` | `{portalId, op:'authorize'\|'status'\|'deauthorize', mac?, token, body?, clientIp}` → `{status, body}` |

The redeem/login answer's grant and group must be signed like
`portal.authorize` items; the router verifies them and applies the grant at
once (an existing group keeps its `base*` until the next full set). The router
redeems offline from its held list (decision 20, journal `offline_redeemed`)
only when no answer can come any more: no session, or the session ended
before the answer. A live session that does not answer within 8 s gives the
guest `controller_unreachable` (503) and never an offline redemption: the
controller refuses a sign-in it could not start within 5 s and answers one
it started, so a code is never spent online and offline at once. The call is
not tied to the guest's HTTP request (a guest closing the page does not turn
it into an offline one). Logins need the controller.

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
  `dropbear` and `luci` are never readable. **Sibling packages** (gateway
  README 7.7): an installed `sqm-scripts` brings `sqm` onto the allowlist by
  itself, an installed `perch-qos` brings `perch-qos`, `miniupnpd-nftables`
  (or `miniupnpd`, `miniupnpd-iptables`) brings `upnpd`, `ddns-scripts`
  brings `ddns` (the package database is looked at every 30 s and right
  after an install job). `mwan3` and `pbr` join **read-only**: the
  controller reads and watches them but can never write them, unless you
  list them yourself (`list managed_config 'mwan3'`). Opt out with
  `option managed_config_auto '0'` (only `managed_config` then), or keep one
  off with `list managed_config_exclude 'sqm'`. The denylist always wins.
  `gateway.capabilities` reports the readable list (`allowedConfigs`), the
  writable one (`writableConfigs`) and each sibling's state
  (`siblingConfigs`). The controller has its own
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
  request with a key only the router and the controller hold (a timestamp
  within 5 minutes of the router's clock, a nonce used once, bound to the
  connection): nobody on the path can change the router's config, but they
  can read it. Secret values (Wi-Fi keys, WireGuard keys) are never accepted
  that way. The key comes from **pairing**: the controller starts it (the
  gateway's page), the router's log shows a 6-digit code (`logread | grep
  PAIRING`), you type that code into the controller and confirm on the router
  with `perch-collector pair confirm <code>` when both codes match. The
  api_key never signs (it is the connection's credential, visible over plain
  `http://`). Instead of pairing, `config_sign_key` (16+ characters, entered
  in the controller too) sets a fixed key; pairing is then refused.
- **Pairing commands** (root, on the router): `perch-collector pair status`
  (the code of a pairing in progress, the paired key's id; `-json`), `pair
  confirm <code>`, `pair reject` (refuse a pairing you did not start), `pair
  forget` (drop the key: signed writes stop until the next pairing; works
  without the daemon). The key lives in `/etc/perch-collector/pairing.json`
  (0600): kept over sysupgrade, lost by a factory reset, removed with the
  package. A pairing waits 10 minutes for each step, then expires.
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
option managed_config_auto '1'       # installed sqm-scripts / perch-qos join by themselves
# list managed_config_exclude 'sqm'  # ...except these
option config_allow_insecure '0'     # '1' = signed writes over plain http
# option config_sign_key ''          # fixed HMAC key of those signatures (default: pair instead)
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

`perch-collector config-guard --overdue` is the watchdog for a daemon that is
gone while the router keeps running: when no perch-collector holds the plane
lock (`/var/run/perch-collector/plane.lock`, held by the daemon for its whole
life, also while it is stopped with SIGSTOP) and a change's confirm deadline
is more than 60 s behind, it restores the change the same way, has procd
reload what it restored and leaves the outcome for the controller ("restored
by the overdue watchdog"). It prints nothing when there is nothing to do. The
package adds it to root's crontab (every minute) and starts cron; removing the
package takes the line out again. By hand:

```sh
echo '* * * * * /usr/bin/perch-collector config-guard --overdue 2>&1 | logger -t perch-collector-guard' >> /etc/crontabs/root
/etc/init.d/cron enable; /etc/init.d/cron restart
```

BusyBox crond logs every job it starts at OpenWrt's default
`system.@system[0].cronloglevel` (5): one syslog line a minute. `cronloglevel
'9'` silences that (the router's own setting; Perch never changes it).

### Paid Hotspot checkouts and click-through

The contract is the controller's `docs/gateway/portal.md` §14; this is the
router's side of it. The hello's `portal` object carries `"hotspot": 1`.

`bypass` (2026-09-24, device groups): MACs that pass the portal without a grant, the
members of the gateway's device groups with a portal bypass. The router authorises them
like a grant's device (never external, put back when removed by hand, never ended) until
a `portal.configure` without them.

`portal.configure` portals gain `methods.payment` and `methods.clickThrough`
and, when on:

```
payment:      {idleTimeoutSeconds (15–600, default 60), priceTableId,
               terminals: [{terminalId, name, token, mac|null, enabled, priceTableId|null}],
               priceTables: [{priceTableId, revision, name, currency, decimals, durationMode,
                              entries: [{amount, minutes, quotaBytes, downKbps, upKbps}]}]}
clickThrough: {minutes (1–1440), quotaBytes, downKbps, upKbps, windowHours (1–720), perWindow (1–24), terms}
```

A terminal's table is its `priceTableId`, else the portal's. Pricing is greedy
(the largest rate as often as it fits, then smaller ones; time and data add
up, the speed tier is the most expensive rate taken, the rest below the
smallest rate is `unusedAmount`). The voucher form (and `/portal/voucher`) is
on when `voucher` or `payment` is: a reference code is a voucher code.

**Terminal API** on the guest-page listener, every request signed:
`X-Perch-Terminal`, `X-Perch-Session` (empty for `/session`), `X-Perch-Seq` (0
for `/session`, then strictly increasing), `X-Perch-Signature` =
base64url(HMAC-SHA256(token, "perch-terminal-v1\n" METHOD "\n" PATH "\n"
terminalId "\n" session "\n" seq "\n" hex(sha256(body)))). The token never
crosses the guest network.

| Route | Body → answer |
|---|---|
| `POST /portal/v1/terminal/session` | `{nonce}` (16–64 `[A-Za-z0-9_-]`, never reused) → `{session, heartbeatSeconds:5, terminal:{terminalId, name, portalId}, currency, decimals, now}` |
| `POST /portal/v1/terminal/heartbeat` | `{status?:{acceptor:"on"\|"off", firmware, error}}` → `{checkout, heartbeatSeconds, now}` |
| `GET /portal/v1/terminal/checkout` | → `{checkout}` |
| `POST /portal/v1/terminal/coins` | `{checkoutRef, eventId, amount (1–1000000)}` → `{accepted, checkout}`; 409 `checkout_closed`/`checkout_full` `{recorded:true}` (journaled `checkout_unclaimed` once per eventId); 422 `bad_amount` |
| `POST /portal/v1/terminal/done` | `{checkoutRef}` → `{checkout}` (finalised, reason `terminal`); 409 `no_checkout`, `below_minimum` |

`checkout` = the terminal's open checkout, else its last closed one for 120 s:
`{checkoutRef, state:open|finalized|cancelled|expired, amount, amountText,
currency, decimals, preview:{durationSeconds, quotaBytes, downKbps, upKbps,
unusedAmount}, previewText, openedAt, idleDeadline, idleSecondsLeft,
referenceCode?}` (`referenceCode` in display form while finalised, for a
receipt printer; never the guest's MAC). Errors are `{error, message}`: 400
`bad_request`, 401 `unknown_terminal`/`invalid_signature`/`session_unknown`,
403 `wrong_portal`/`terminal_disabled`/`mac_mismatch`, 404 `not_found`, 405,
409 `stale_seq {lastSeq}`/`nonce_reused`, 429 `rate_limited` (120 requests a
minute per address; 20 auth failures in 15 minutes block the address). A
terminal is online while it made an authenticated request in the last 20 s.

**Guest routes**: `GET /portal/checkout` → `{checkout, terminals:[{terminalId,
name, state:free|busy|offline|yours}], rates:{currency, decimals,
entries:[{amount, amountText, minutes, quotaBytes, downKbps, upKbps, text}]},
receipt:{referenceCode, amount, amountText, durationSeconds, quotaBytes, text,
finalizedAt}, clickThrough:{available, retryAfterSeconds, minutes, terms}}`
(`checkout` = the device's open checkout or its last one within 10 minutes:
`{checkoutRef, terminalId, terminalName, state, amount, amountText, currency,
decimals, preview, previewText, idleSecondsLeft, terminalOnline, openedAt,
closedAt}`); `POST /portal/checkout` `terminalId` (→ `checkout_started`;
`terminal_busy`, `terminal_offline`, `terminal_unknown`, `checkout_open`,
`not_ready`), `POST /portal/checkout/done` (→ `paid`; `no_checkout`,
`below_minimum`), `POST /portal/checkout/cancel` (→ `checkout_cancelled`;
`checkout_paid` once coins are in), `POST /portal/clickthrough` `accept=1`
(→ `connected`; `terms_required`, `already_authorized`, `clickthrough_used`
429 + Retry-After). Form posts answer 303 `/?m=<code>`, JSON posts `{ok, code,
status, hotspot}`. `status_json` and `/portal/api/status` carry `hotspot` when
the portal offers either method. Template variables `checkout_form`,
`clickthrough_form`, `receipt` (snippets) and `reference_code`; the builtin
pages load `checkout.js` for the live total.

**Journal** (`portal.event`/`portal.sync`): `checkout_finalized` `{portalId,
mac, localRef, ip?, hostname?, checkoutRef, terminalId, amount, currency,
priceTableId, priceRevision, durationMode, durationSeconds, quotaBytes,
downKbps, upKbps, openedAt, finalizedAt, reason:done|timeout|terminal,
unusedAmount, coinCount, coins:[{eventId, amount, at}], keyEpoch, sig,
placement, demotedGrantId?, demotedLocalRef?, startsAt?, expiresAt?}` (the
record fields signed with the signKey; `quotaBytes/downKbps/upKbps` null
when unset); `checkout_unclaimed` `{portalId, mac:"" (or the terminal's
pinned MAC), terminalId, eventId ("" for below_minimum), amount, currency,
checkoutRef?, reason:late|full|below_minimum}`; `clickthrough_granted`
`{portalId, mac, localRef, ip?, hostname?, startsAt, expiresAt,
durationSeconds, quotaBytes, downKbps, upKbps}`; `offline_redeemed` of a
reference code the controller has not acknowledged yet carries `voucherId: 0`
and `checkoutRef`. Notification `portal.terminals` `{collectedAt,
terminals:[{terminalId, portalId, online, lastSeenAt, status, checkout:
{checkoutRef, state, amount, openedAt}|null}]}` every 30 s while terminals are
configured, and at once when a session opens, a checkout opens or closes, or a
terminal goes quiet.

## Self-update (`self_update`, agent-updates design)

With the WebSocket transport the collector reports an `update` block and, when
nothing refuses, the capability `agent_update` in its `collector.hello`, and
serves `agent.update.status`, `.stage`, `.install`, `.confirm`, `.abort` and
`.ack` (formats: the controller's `docs/agent-updates.md`). What it does on the
router:

- Trust: a release manifest signed (Ed25519, signify/usign format) with a
  trusted key, for `perch-collector`, this arch and variant (the static build
  is `ndpi-static`) or this package manager, at or above the router's version
  floor. Every downloaded file is checked against the manifest's SHA-256.
- Install kinds: `package` (the package record's version is the running one:
  `opkg install --force-downgrade` / `apk add --allow-untrusted` of
  `perch-collector`, plus `perch-qos` when installed), `swapped` / `unowned`
  (a binary swap of `/usr/bin/perch-collector`, e.g. the hand-installed static
  build on an OpenWrt 23.05 container, with the release's init scripts and,
  where they exist, a hand-installed perch-qos's files), `docker` and `other`
  (nothing; the dashboard shows the command).
- A config apply that is being made or waits for its confirm makes an update
  wait (`busy_pending_apply`, reason `config_pending`).
- The old files stay on flash (a hardlink) until the new version is confirmed;
  the watchdog (`/etc/perch-collector/update/perch-update.sh`, written by the
  version that planned the update) restores them on a timeout, a crash loop or
  an abort, and `/etc/init.d/perch-collector-guard` restores them after a
  reboot inside the check window, before its config plane step. Capture pauses
  for the few seconds of the swap; the portal's nftables tables and the
  shaper's tc tree stay in place.
- Nothing writes `/etc/config/perch-collector` for an update.

## Packaged deployments

The OpenWrt init script and the Docker image configure the daemon through
`PERCH_COLLECTOR_*` variables only; no YAML file is needed.

On OpenWrt, `list capture_networks` (the package's new config ships `'auto'`),
`list capture_exclude`, `option capture_rescan` and `option routed_lan` map to
the variables above. With `capture_networks` set the init script passes no
capture device and no gateway MAC (the daemon reads them from netifd) and
answers interface events with a `rescan` (SIGHUP) instead of a restart. An
existing config keeps its `capture_network`/`capture_device` on upgrade (the
conffile is kept), and with it the single-interface capture: switch with
`uci delete perch-collector.main.capture_network; uci add_list
perch-collector.main.capture_networks=auto; uci commit perch-collector;
/etc/init.d/perch-collector restart`. `GET /healthz` and
every `meta` block report the build `version` (set with
`-ldflags "-X main.version=…"`).
