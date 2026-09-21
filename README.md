# Perch Network Collector

`perch-collector` is the capture daemon of Perch, a home-network looking
glass in the UniFi style. It captures packet headers via libpcap, keeps
per-device (per-MAC) counters with protocol and application classification
(nDPI), top peers, server names and destinations, and hands them to the
[Perch Network Controller](https://github.com/capthndsme/perch-controller):
pushed over a WebSocket the collector dials itself, or polled from its JSON
API. On the router it also reports the router's own health (connection
tracking, WAN rate, load) for the controller's Gateway page.

Designed for low overhead, 24/7 operation on a router or server.

## Features

- **Per-device traffic accounting** — one record per physical LAN device, keyed by Ethernet MAC; consolidates IPv4 + IPv6 + link-local addresses of the same machine, with separate WAN and LAN byte counters
- **WAN pivot via gateway MAC** — auto-detected (or configured) gateway MACs classify each frame as WAN or LAN for the device on the other side; supports several gateways for multi-WAN / policy-routed setups
- **Protocol and application classification** — port-based by default; with `make build-ndpi` and libndpi installed, nDPI deep packet inspection labels flows (`https`, `youtube`, `bittorrent`, …), reads TLS/HTTP/QUIC server names and assigns each label a category (media, social, download, …). Degrades to port mode on any failure
- **Bounded top-N peers** — per device, a min-heap of its heaviest WAN peers and a separate one for LAN neighbours (default 50 each, hard max 1000); memory stays flat under torrent loads
- **Services and destinations** — per device, bytes *served* per server name (for hosts you run) and bytes *sent to* each site (name, category, protocol) for the "where is my traffic going" view; unnamed TLS/HTTP/QUIC flows are keyed by peer address so a consumer can group them by network. All bounded per device
- **Talks to the controller over its own socket** — dials the controller, authenticates with its API key and pushes on the schedule the controller sets (JSON-RPC 2.0 over WebSocket, compressed); nothing has to reach the collector. Or announces itself over HTTP and is polled
- **Gateway stats** — on the router: conntrack fill, established TCP, load, memory and per-interface WAN counters, read from `/proc`, so the controller needs no node_exporter
- **No ASN database** — peer enrichment (ASN, rDNS) is left to the controller
- **JSON HTTP API** — live device stats, `?since=` windows, protocol → category list
- **Periodic disk flush** — optional JSON snapshots to disk
- **Configurable** — YAML config file + CLI flags + env var overrides ([CONFIG.md](CONFIG.md))
- **API key auth** — the local API's bearer token and the collector's credential towards the controller
- **Low footprint** — headers only (96-byte snaplen) in port mode; nDPI mode wants 256+ bytes for TLS hellos, 1500 for the best QUIC / BitTorrent detection

## OpenWrt package

The collector's natural home is the router itself: the `perch-collector`
package captures on the LAN bridge, generates its API key and instance id on
first start, dials the controller set in `server_url`, reports the gateway
stats, and keeps its local API on 127.0.0.1. Build and install instructions:
[`openwrt/README.md`](openwrt/README.md).

## Run with Docker

The image carries nDPI and captures on the interface that carries the default
route unless told otherwise. No config file is needed. Point it at your
controller and it dials in over the WebSocket; on first start it generates
its API key and keeps it, with its instance id, in `/var/lib/perch-collector`,
so mount a volume there to keep its identity across container upgrades:

```bash
docker run -d --name perch-collector --restart unless-stopped \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v perch-collector-data:/var/lib/perch-collector \
  -e PERCH_COLLECTOR_SERVER_URL=https://perch.example.com \
  ghcr.io/capthndsme/perch-collector:latest
```

It then shows up in the controller under Settings → Collectors → Pending
adoption; the log prints the key's fingerprint to compare before you adopt.
Add `-e PERCH_COLLECTOR_INTERFACE=<name>` to capture on a specific interface (a
LAN bridge like `br-lan`, or a mirror port), and
`-e PERCH_COLLECTOR_GATEWAY_STATS=on` when the Docker host is the router. The
host must actually see the LAN's traffic, meaning it is the router, sits on the
bridge, or hangs off a mirror port; otherwise the collector only sees the
host's own traffic. `--network host` is what makes the host's interfaces
visible, so this needs a Linux Docker host. To be polled instead, leave out
`PERCH_COLLECTOR_SERVER_URL`, set `PERCH_COLLECTOR_LISTEN` to an address the
controller can reach and `PERCH_COLLECTOR_API_KEY` to a shared secret. Every
option in [CONFIG.md](CONFIG.md) has a `PERCH_COLLECTOR_*` variable (the
pre-rename `GOCOLLECTOR_*` names still work, with a deprecation line in the
log). The [controller's](https://github.com/capthndsme/perch-controller)
compose file runs this container next to the controller with
`docker compose --profile collector up -d`.

```bash
make docker      # build the image locally as perch-collector
```

The image build fetches `github.com/capthndsme/perch-agentkit` through the
Go module proxy.

## Requirements

- Go 1.22+
- libpcap-dev (build time)
- libpcap (runtime)
- nDPI 5.0 (nDPI mode only; distro `libndpi-dev` packages are 4.x, too old)
- Root or `CAP_NET_RAW` capability

## Build

```bash
sudo apt install libpcap-dev            # both modes
cd perch-collector
scripts/build-ndpi.sh                   # nDPI mode: builds nDPI 5.0 into ~/.local/ndpi5

make build BIN=out/perch-collector      # port-based classification only
make build-ndpi BIN=out/perch-collector NDPI_PREFIX=$HOME/.local/ndpi5   # nDPI; requires libndpi >= 5.0

# Capability instead of root. It sits on the file: repeat after every rebuild.
sudo setcap cap_net_raw,cap_net_admin=eip out/perch-collector

make test && make test-ndpi NDPI_PREFIX=$HOME/.local/ndpi5   # unit tests without and with the ndpi build tag
scripts/build-static.sh                 # static musl + nDPI 5.0 binary for x86_64 OpenWrt, via Docker
```

nDPI mode requires nDPI 5.0. `NDPI_PREFIX` points pkg-config (and the test
runner's `LD_LIBRARY_PATH`) at a prefix built by `scripts/build-ndpi.sh`;
omit it when libndpi 5 is installed system-wide. A prefix-built binary needs
`LD_LIBRARY_PATH=<prefix>/lib` at run time as well.

The shared device-daemon code (JSON-RPC, the controller session, `/proc`
readers) lives in [perch-agentkit](https://github.com/capthndsme/perch-agentkit).
To build against a local checkout of it, put both in a Go workspace
(`go work init . ../perch-agentkit`); `scripts/build-static.sh` picks up
`../perch-agentkit` on its own.

Build a fresh binary next to the running one (`BIN=out/perch-collector.new`,
then `mv`) when the daemon is live; the running process keeps its inode.

## Usage

```bash
# Run with default config: captures on the default route's interface,
# port-based classification, API on 127.0.0.1:9800
sudo ./out/perch-collector

# Run with config file
sudo ./out/perch-collector -config /etc/perch-collector/collector.yaml

# Override specific settings via CLI
sudo ./out/perch-collector -interface br-lan -listen 127.0.0.1:9800
```

## Install as systemd Service

A systemd unit file is included at [`perch-collector.service`](perch-collector.service).

### Install

```bash
# 1. Build
mkdir -p out
go build -o out/perch-collector .

# 2. Copy binary
sudo cp out/perch-collector /usr/local/bin/perch-collector
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/perch-collector

# 3. Copy config
sudo mkdir -p /etc/perch-collector
sudo cp collector.example.yaml /etc/perch-collector/collector.yaml
# Edit config as needed (server_url, api_key, interface):
#   sudo nano /etc/perch-collector/collector.yaml

# 4. Install and start the service (it creates /var/lib/perch-collector,
#    where the instance id is kept)
sudo cp perch-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable perch-collector
sudo systemctl start perch-collector

# 5. Check status
sudo systemctl status perch-collector
sudo journalctl -u perch-collector -f
```

Upgrading from `go-collector`: the instance id in
`/var/lib/go-collector/instance-id` is still read while
`/var/lib/perch-collector/instance-id` does not exist, so the controller
keeps recognising the box.

### Uninstall

```bash
sudo systemctl stop perch-collector
sudo systemctl disable perch-collector
sudo rm /etc/systemd/system/perch-collector.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/perch-collector
sudo rm -rf /etc/perch-collector
# Optionally remove the instance id and data:
#   sudo rm -rf /var/lib/perch-collector
```

## Configuration

See [CONFIG.md](CONFIG.md) for the full reference.

Quick example (`collector.example.yaml` is the full template; copy it to
`collector.yaml`, which is git-ignored, and edit):

```yaml
interface: "br-lan"      # empty = auto-detect the default route's interface
snap_len: 96
listen: "127.0.0.1:9800"
promiscuous: true
api_key: "change-me-to-something-long"
server_url: "https://perch.example.com"   # the controller; empty = only be polled
transport: auto          # websocket when api_key is set, else announce + poll
gateway_stats: auto      # on under OpenWrt: this is the router
flush_file: "/var/lib/perch-collector/stats.json"
flush_interval: 60
gateway_macs: []          # empty = auto-detect single default-route gateway
local_subnets: []         # extra CIDRs, merged with auto-detected
top_peers_count: 50       # bounded WAN peers per device
top_lan_peers_count: 50   # bounded LAN neighbours per device
```

## API

All responses are `Content-Type: application/json`.

Every response's `meta` names the capture interface, the build, the
`transport` (`websocket` or `poll`) and, when the collector talks to a
controller, `announce_status` (`starting`, `pending`, `adopted`,
`dismissed` or `error: …`).

If `api_key` is set in config, all endpoints except `/healthz` require the header:
```
Authorization: Bearer <api_key>
```

### `GET /api/v1/devices`

Returns all tracked LAN devices keyed by MAC, sorted by total bytes (in + out)
descending.

Query params:
- `since` (optional) — RFC 3339 timestamp; only return devices with activity at or after this time

```bash
curl http://127.0.0.1:9800/api/v1/devices
curl "http://127.0.0.1:9800/api/v1/devices?since=2026-05-25T01:00:00Z"
```

Example response:
```json
{
  "devices": [
    {
      "mac": "02:aa:bb:cc:dd:ee",
      "ips": ["192.168.1.100", "fe80::dead:beef"],
      "bytes_in": 12345678,
      "bytes_out": 87654321,
      "packets_in": 9012,
      "packets_out": 12034,
      "first_seen": "2026-05-25T00:01:23Z",
      "last_seen":  "2026-05-25T02:15:00Z",
      "top_peers": [
        { "ip": "8.8.8.8",    "bytes_in": 540, "bytes_out": 87000000 },
        { "ip": "1.1.1.1",    "bytes_in": 320, "bytes_out":   650000 }
      ],
      "top_lan_peers": [
        { "ip": "192.168.1.10", "bytes_in": 1234567890, "bytes_out": 5000 },
        { "ip": "192.168.1.50", "bytes_in":     200000, "bytes_out": 1500 }
      ]
    }
  ],
  "meta": {
    "capture_interface": "br-lan",
    "query_time": "2026-05-25T02:15:01Z",
    "version": "0.2.0",
    "transport": "websocket",
    "announce_status": "adopted"
  }
}
```

### `GET /api/v1/devices/{mac}`

Returns stats for a single device. The MAC is format-tolerant: colons,
hyphens, dotted Cisco notation, and case all work.

```bash
curl http://127.0.0.1:9800/api/v1/devices/02:aa:bb:cc:dd:ee
```

### `GET /api/v1/summary`

Returns aggregate totals (`total_devices`, `total_bytes`, `total_packets`) and
daemon uptime (`started_at` changes on every restart, which is how the
controller tells a restart from traffic). With gateway stats on, a top-level
`gateway` object sits next to `summary` (see [Gateway stats](#gateway-stats)).

### `POST /api/v1/reset`

Resets all counters to zero and restarts the uptime clock.

### `GET /healthz`

Health check endpoint. No authentication required.

### `services` (bytes served per server name)

With nDPI enabled every device also carries a `services` array — one row per
TLS SNI / HTTP Host / QUIC SNI it **served**, split into `bytes_served`
(server → client) and `bytes_received` (client → server):

```json
"services": [
  { "server_name": "photos.homeapps.example", "protocol": "https",
    "bytes_served": 51200000000, "bytes_received": 92000000,
    "packets_served": 34000000, "packets_received": 1200000 }
]
```

Cap per device: `top_services_count` (see CONFIG.md).

### `destinations` (where a device's WAN bytes went)

The mirror image of `services`: one row per TLS SNI / HTTP Host / QUIC SNI a
device **asked for** as a client of a WAN flow, with nDPI's application
category, from the device's point of view (`bytes_in` downloaded from it,
`bytes_out` uploaded to it). Unnamed flows pool under `"server_name": ""`
per protocol, so "netflix" recognised from IP ranges alone still adds up.

```json
"destinations": [
  { "server_name": "rr4---sn-4g5e6nzl.googlevideo.com", "protocol": "youtube",
    "category": "media", "bytes_in": 4200000000, "bytes_out": 31000000,
    "packets_in": 3100000, "packets_out": 610000 },
  { "server_name": "", "protocol": "netflix", "category": "media",
    "bytes_in": 900000000, "bytes_out": 4000000, "packets_in": 650000, "packets_out": 80000 }
]
```

Cap per device: `top_destinations_count`. `GET /api/v1/protocols` lists the
default category of every protocol label the classifier can emit.

## Talking to the controller

Set `server_url` (or `PERCH_COLLECTOR_SERVER_URL`, or `option server_url` in
UCI) and the collector introduces itself to the Perch Network Controller: it
shows up under **Settings → Collectors** (and in the setup wizard) as
*pending*, with its hostname, version, capture interface and its API key's
fingerprint. Nothing is sent or polled until an admin adopts it. There are
two ways it does that (`transport`):

- **WebSocket** (`websocket`, and `auto` whenever `api_key` is set). The
  collector dials `<server_url>/api/v1/collector-agent/ws` (subprotocol
  `perch-collector.v1`, permessage-deflate) with its key as the bearer and
  its instance id in `X-Perch-Instance-Id`, says `collector.hello`, and from
  the controller's `agent.configure` on pushes `collector.push` — the same
  summary and devices the HTTP API serves, plus the gateway stats — every
  interval the controller sets (0 = paused, e.g. while pending). The
  controller can ask `collector.status` and `collector.protocols` on the same
  socket. Adoption takes effect immediately, nothing has to reach the
  collector (the API can stay on 127.0.0.1), and a NAT between the two does
  not matter. The socket reconnects on its own: a controller restart costs a
  few seconds; a refused key, discovery switched off or a full pending list
  wait five minutes; a dismissed collector retries every six hours. The wire
  contract is `docs/collector-agent.md` in the controller repository.
- **Announce and poll** (`poll`, and `auto` without an `api_key`). The
  collector POSTs its identity to `<server_url>/api/v1/collectors/announce`
  every minute until it is adopted, then slowly, and the controller polls
  its API on `listen`, which therefore has to be reachable. The controller
  derives the address to poll from where the announce came from, never from
  what the daemon claims.

Either way the identity is the instance id (generated and persisted on first
start) and, by default, the API key travels with the introduction so
adoption is one click; set `announce_api_key: false` to send only its
fingerprint and paste the key by hand. Details and every key:
[`CONFIG.md`](CONFIG.md), section "The Perch controller".

## Gateway stats

With `gateway_stats` on (the default under OpenWrt, where the collector runs
on the router), every push — and `GET /api/v1/summary`, for a polled
collector — carries the router's own health:

```json
"gateway": {
  "collectedAt": "2026-09-21T14:17:10Z",
  "conntrack": { "entries": 2495, "limit": 262144 },
  "tcpEstablished": 2,
  "load": { "load1": 1.44, "load5": 1.1, "load15": 1.49 },
  "memory": { "totalBytes": 1073741824, "availableBytes": 536870912 },
  "wan": [ { "name": "wan", "rxBytes": 693974698743, "txBytes": 1697321558462 } ],
  "wanSource": "default-route"
}
```

The counters are cumulative; the controller turns them into rates.
`wan` lists the interfaces holding a default route (IPv4 and IPv6, re-read
every time, so a PPPoE link that comes up later joins in), or the configured
`wan_interfaces` (`wanSource: "configured"`). Anything the kernel does not
expose (no conntrack module, an old kernel without `MemAvailable`) is left
out rather than reported as zero.

## How the controller uses the data

Whichever transport, the controller works on **cumulative counters and
deltas**:

1. Every interval it takes the current counters (a push, or a poll of
   `GET /api/v1/summary` + `GET /api/v1/devices`)
2. It computes the **delta** against the previous reading per MAC, protocol,
   peer, service and destination; a new `started_at` means the collector
   restarted and the reading becomes a fresh baseline
3. It stores the deltas as time buckets in MariaDB and rolls them up
4. Peer enrichment (ASN, rDNS) happens in the controller against each
   device's `top_peers` and `top_lan_peers`, keeping the daemon free of
   GeoIP dependencies

A push that is lost or dropped loses nothing: the next one carries the
counters that include it.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the component diagram and data flow.

## License

MIT; see [LICENSE](LICENSE).
