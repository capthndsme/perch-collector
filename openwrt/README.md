# perch-collector on OpenWrt

The Perch Network Collector as an OpenWrt package: runs on the router,
captures on the LAN bridge (where every LAN ↔ WAN frame passes), keeps
everything in memory and pushes it to the Perch Network Controller over a
WebSocket the router dials itself, together with the router's own health
(connection tracking, established TCP, load, memory, WAN rate) for the
controller's Gateway page. Nothing has to reach the router: the local API
listens on 127.0.0.1 only. Configuration is UCI; the API key and the
instance id are generated on first start.

## Build

With the OpenWrt SDK (or a full buildroot) for your target:

```sh
# feeds.conf.default (or feeds.conf): add this checkout's openwrt/ dir as a feed
echo 'src-link perch /path/to/perch-collector/openwrt' >> feeds.conf.default
./scripts/feeds update -a
./scripts/feeds install perch-collector
make menuconfig            # Network → perch-collector (nDPI option, default on)
make package/perch-collector/compile V=s
ls bin/packages/*/perch/
```

`libpcap` and `libndpi` come from the packages feed; the daemon requires
nDPI 5.0, which is what the feed ships. Turn the nDPI option off for
MT7621-class routers; port-based classification costs almost nothing.

The Go toolchain and `golang-package.mk` from the packages feed handle cgo
cross-compilation; Go modules (including `github.com/capthndsme/perch-agentkit`)
are downloaded through the module proxy during the build. `PKG_HASH` is
`skip` until the first tagged release.

## Install and point it at the controller

```sh
opkg install perch-collector_*.ipk       # apk add on 25.x
uci set perch-collector.main.server_url='https://perch.example.com'
uci commit perch-collector
/etc/init.d/perch-collector enable
/etc/init.d/perch-collector start
logread -e perch-collector
# → the router appears under Settings → Collectors, pending adoption
```

Within a few seconds the router shows up in the controller under **Settings →
Collectors** (or in the setup wizard) as *pending*, with its hostname,
version, capture interface and the first 8 characters of its API key's
SHA-256. Compare that fingerprint with the key on the router before you
adopt it:

```sh
uci get perch-collector.main.api_key | tr -d '\n' | sha256sum | cut -c1-8
```

Nothing is pushed until you click **Adopt**; the moment you do, the
controller tells the collector its schedule over the open socket and the
first data arrives right away. The collector authenticates the socket with
its API key, so after adoption only this router can speak for this row.

The hello carries the API key by default so adoption needs no SSH session.
Over plain `http` that key crosses the network in cleartext: use an `https`
`server_url`, or

```sh
uci set perch-collector.main.announce_api_key='0'
```

and paste the key into the dashboard when you adopt.

`instance_id` is what makes this survive: it is generated on first boot,
stored in UCI (not on the overlay), and sent on every connection, so a
reboot or a new DHCP lease reconnects the *same* collector instead of
appearing as a second one. Check it with
`uci get perch-collector.main.instance_id`.

`logread -e perch-collector` shows the init script's start line,

```
starting on br-lan, API on 127.0.0.1:9800 (ndpi), controller https://perch.example.com
```

then one line per *state change* (`starting -> pending`, `pending ->
adopted by …`, `pushing every 5s`) — never one per push, and never the key.

## Options

`/etc/config/perch-collector`, everything optional:

| Option | Default | Meaning |
|---|---|---|
| `enabled` | `1` | |
| `server_url` | empty | The Perch Network Controller, e.g. `https://perch.example.com`. Empty = talk to no controller (the API can still be polled). |
| `transport` | `auto` | `auto` / `websocket`: dial the controller and push. `poll`: announce over HTTP and be polled on the API address (then set `listen_network 'lan'`). |
| `announce_api_key` | `1` | Send the API key with the hello so adoption is one click. `0` = its fingerprint only. |
| `announce_tls_insecure` | `0` | Accept a self-signed certificate on an `https` `server_url`. |
| `server_ca_file` | empty | PEM bundle of a private CA for an `https` `server_url`. |
| `instance_id` | generated | Stable identity the controller recognises this router by. |
| `announce_interval` | `60` | Seconds between HTTP announces (`transport 'poll'` only; the controller's reply overrides it). |
| `gateway_stats` | `auto` | Report the router's own health for the Gateway page. `auto` = on (this is the router); `on` / `off`. |
| `wan_interface` (list) | the default-route interfaces | UCI networks (`wan`) or devices (`pppoe-wan`) whose counters make the WAN rate. Set it when WAN routes live outside the main table (mwan3, policy routing). |
| `capture_network` / `capture_device` | `lan` / (its device) | Where to capture. The network's device is resolved at start (`br-lan`, `lan0`, …). |
| `listen_network` / `listen_address` / `port` | `loopback` / (its address) / `9800` | Where the local API listens. `loopback` is enough for the WebSocket transport; `lan` to be polled; `listen_address '0.0.0.0'` for everything. |
| `api_key` | generated | The collector's credential towards the controller and the bearer token of the local API. |
| `classification` | `ndpi` | `ndpi` or `port`. |
| `snap_len` | `1500` | Bytes per packet; 96 is enough for `port`. |
| `promiscuous` | `1` | |
| `gateway_mac` (list) | the capture device's MAC | Upstream pivots. The default is right on the gateway itself. |
| `local_subnet` (list) | none | Extra CIDRs that count as LAN. |
| `bpf_filter` | empty | |
| `top_*`, `ndpi_*` | daemon defaults | Per-device caps and the nDPI flow table. |

The init script turns these into the daemon's `PERCH_COLLECTOR_*`
environment variables (see `../CONFIG.md`) and restarts the daemon when the
capture or listen network comes up.

Check the local API on the router itself:

```sh
wget -qO- --header "Authorization: Bearer $(uci get perch-collector.main.api_key)" \
  http://127.0.0.1:9800/api/v1/summary
```

`meta.transport` says `websocket`, `meta.announce_status` how the controller
sees the collector, and `gateway` is what the Gateway page gets.

## Polled instead of pushing

Set `transport 'poll'` and `listen_network 'lan'`: the router announces over
HTTP and the controller polls `http://<router>:9800`. The address it polls
is taken from where the announce came *from*, so a router that reaches the
controller through NAT (port-forward reflection, a reverse proxy) shows up
with the wrong address; adopt it, then edit the address once. The socket
has no such problem, which is why it is the default.

## Without the SDK

For an x86_64 OpenWrt LXC or VM, `scripts/build-static.sh` in the collector
repo produces a static binary with nDPI 5.0 inside, using only Docker. Copy it
to `/usr/bin/perch-collector` together with the three files under `files/`
(init → `/etc/init.d/perch-collector`, config → `/etc/config/perch-collector`,
defaults → `/etc/uci-defaults/90-perch-collector`), run the defaults script
once, set `server_url`, then `enable` and `start`.

Coming from the earlier `metricslite-collector` package: copy `api_key`,
`instance_id`, `server_url` and any capture options from
`/etc/config/metricslite-collector` into `/etc/config/perch-collector` (the
instance id keeps the controller's row and its history), then stop and
disable the old service before starting the new one.

## On a router, two things to know

- **Hardware flow offloading** (MediaTek/Qualcomm PPE) forwards established
  flows without the CPU seeing them: the collector would see connections
  start and miss their bytes. Keep hardware offloading off on the router
  that captures; software offloading is fine.
- **CPU.** nDPI inspects the first packets of every flow. A Filogic or
  ipq807x class router copes at home bandwidths; a MT7621 should run with
  `classification 'port'`. The daemon's own memory is ~35 MB plus the flow
  table.

## Files

```
openwrt/perch-collector/Makefile                 feed package (golang-package.mk, nDPI menuconfig option)
openwrt/perch-collector/files/*.init             procd init: UCI → environment, key generation, interface triggers
openwrt/perch-collector/files/*.config           default /etc/config/perch-collector
openwrt/perch-collector/files/*.defaults         uci-defaults: generate the API key and the instance id on first boot
```
