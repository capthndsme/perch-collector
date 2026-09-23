# perch-collector on OpenWrt

The Perch Network Collector as an OpenWrt package: runs on the router,
captures on the LAN bridge (where every LAN ↔ WAN frame passes), keeps
everything in memory and pushes it to the Perch Network Controller over a
WebSocket the router dials itself, together with the router's own health
(connection tracking, established TCP, load, memory, WAN rate) for the
controller's Gateway page. Nothing has to reach the router: the local API
listens on 127.0.0.1 only. Configuration is UCI; the API key and the
instance id are generated on first start.

## Install a release package

Every release carries the package for OpenWrt 24.10 (`.ipk`, opkg) and 25.12
(`.apk`, apk-tools), built with the official SDKs, one file per architecture:

| Architecture | Routers |
|---|---|
| `mipsel_24kc` | MediaTek MT7621, MT7628 (`ramips`) |
| `mips_24kc` | Qualcomm Atheros `ath79` |
| `aarch64_cortex-a53` | MediaTek Filogic (MT7981, MT7986), Qualcomm `ipq807x` |
| `arm_cortex-a7_neon-vfpv4` | Qualcomm `ipq40xx` |
| `x86_64` | x86/64: PCs, VMs, containers |

`apk --print-arch` (25.12) or the last line of `opkg print-architecture`
(24.10) names the router's architecture.

```sh
V=0.2.0 ARCH=mipsel_24kc
BASE=https://github.com/capthndsme/perch-collector/releases/download/v$V
# OpenWrt 24.10
opkg update
opkg install $BASE/perch-collector_$V-r1_$ARCH.ipk
# OpenWrt 25.12
apk update
wget -O /tmp/perch-collector.apk $BASE/perch-collector_$V-r1_$ARCH.apk
apk add --allow-untrusted /tmp/perch-collector.apk
```

The only runtime dependency is `libpcap`, from the OpenWrt feeds; nDPI 5.0 is
linked into the binary. `--allow-untrusted` because the `.apk` is signed with
the SDK's build key, not OpenWrt's. The installed binary is 10.5 to 12 MB
depending on the architecture and on the Go the OpenWrt release builds with
(see "On a router" below for flash and memory). `SHA256SUMS` on the release
lists every file.

## Build

From a checkout, with nothing but Docker (the official SDK image does the
work, the source is the checkout itself):

```sh
scripts/openwrt-package.sh mipsel_24kc 24.10.8   # out/openwrt/perch-collector_<version>-r1_mipsel_24kc.ipk
scripts/openwrt-package.sh mipsel_24kc 25.12.5   # out/openwrt/perch-collector_<version>-r1_mipsel_24kc.apk
```

`openwrt/sdk.env` pins the OpenWrt releases and lists the architectures the
release workflow (`.github/workflows/release.yml`) builds. A build takes 10 to
20 minutes, most of it the SDK compiling its own Go; the script bootstraps that
with the Go installed on the host when there is one.

Or in an SDK or buildroot of your own, as a feed:

```sh
echo 'src-link perch /path/to/perch-collector/openwrt' >> feeds.conf.default
./scripts/feeds update -a
./scripts/feeds install perch-collector
make package/perch-collector/compile V=s
ls bin/packages/*/perch/
```

The package builds nDPI 5.0 from its release tarball and links it statically:
the daemon binds the nDPI 5.0 API, whatever `libndpi` the packages feed
carries, and the router needs no `libndpi` package. `libpcap` comes from the
OpenWrt feed. The Go toolchain and `golang-package.mk` from the packages feed
handle the cgo cross-compilation; Go modules (including
`github.com/capthndsme/perch-agentkit`) are downloaded through the module proxy
during the build. `PKG_HASH` is `skip`: `scripts/openwrt-package.sh` and the
release workflow put the source tarball in place themselves.

## Install and point it at the controller

```sh
# after installing the package (above); the address you open the dashboard at
uci set perch-collector.main.server_url='http://192.168.1.10:8080'
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
starting on br-lan, API on 127.0.0.1:9800 (ndpi), controller http://192.168.1.10:8080
```

then one line per *state change* (`starting -> pending`, `pending ->
adopted by …`, `pushing every 5s`) — never one per push, and never the key.

## Options

`/etc/config/perch-collector`, everything optional:

| Option | Default | Meaning |
|---|---|---|
| `enabled` | `1` | |
| `server_url` | empty | The Perch Network Controller, e.g. `http://192.168.1.10:8080` (the default install; plain HTTP, so keep the router's management address and the controller on a management VLAN, see the controller README's "Plain HTTP and a management VLAN") or `https://perch.example.com`. Empty = talk to no controller (the API can still be polled). |
| `transport` | `auto` | `auto` / `websocket`: dial the controller and push. `poll`: announce over HTTP and be polled on the API address (then set `listen_network 'lan'`). |
| `announce_api_key` | `1` | Send the API key with the hello so adoption is one click. `0` = its fingerprint only. |
| `announce_tls_insecure` | `0` | Accept a self-signed certificate on an `https` `server_url`. |
| `server_ca_file` | empty | PEM bundle of a private CA for an `https` `server_url`. |
| `instance_id` | generated | Stable identity the controller recognises this router by. |
| `announce_interval` | `60` | Seconds between HTTP announces (`transport 'poll'` only; the controller's reply overrides it). |
| `gateway_stats` | `auto` | Report the router's own health for the Gateway page. `auto` = on (this is the router); `on` / `off`. |
| `wan_interface` (list) | the default-route interfaces | UCI networks (`wan`) or devices (`pppoe-wan`) whose counters make the WAN rate. Set it when WAN routes live outside the main table (mwan3, policy routing). |
| `ports` | `auto` | The router's Ethernet ports and their link state for the controller's infrastructure view (this is the Perch Network Gateway agent); the WAN interfaces are role `wan`. `auto` = whenever `gateway_stats` is on; `off` leaves them out. |
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
sees the collector, and `gateway` is what the Gateway page gets (its `ports`
feed the infrastructure view). `perch-collector ports` prints just the ports,
without reading the configuration or touching the running daemon.

## Polled instead of pushing

Set `transport 'poll'` and `listen_network 'lan'`: the router announces over
HTTP and the controller polls `http://<router>:9800`. The address it polls
is taken from where the announce came *from*, so a router that reaches the
controller through NAT (port-forward reflection, a reverse proxy) shows up
with the wrong address; adopt it, then edit the address once. The socket
has no such problem, which is why it is the default.

## Without the SDK

For an x86_64 OpenWrt LXC or VM, the release's `perch-collector-linux-amd64-ndpi`
(or `scripts/build-static.sh` in the collector repo, using only Docker) is a
static binary with libpcap and nDPI 5.0 inside, for any OpenWrt version. Copy it
to `/usr/bin/perch-collector` together with the three files under `files/`
(init → `/etc/init.d/perch-collector`, config → `/etc/config/perch-collector`,
defaults → `/etc/uci-defaults/90-perch-collector`), run the defaults script
once, set `server_url`, then `enable` and `start`.

Coming from the earlier `metricslite-collector` package: copy `api_key`,
`instance_id`, `server_url` and any capture options from
`/etc/config/metricslite-collector` into `/etc/config/perch-collector` (the
instance id keeps the controller's row and its history), then stop and
disable the old service before starting the new one.

## On a router, three things to know

- **Hardware flow offloading** (MediaTek/Qualcomm PPE) forwards established
  flows without the CPU seeing them: the collector would see connections
  start and miss their bytes. Keep hardware offloading off on the router
  that captures; software offloading is fine.
- **CPU.** nDPI inspects the first packets of every flow. A Filogic or
  ipq807x class router copes at home bandwidths; a MT7621 or ath79 router
  should start with `classification 'port'` and turn nDPI on only if the
  load stays reasonable.
- **Memory and flash.** The daemon itself needs 30 to 50 MB (about 47 MB on
  an x86_64 gateway with 40 devices), plus about 1 KB per flow in nDPI's table
  (`ndpi_max_flows`, default 50000, so up to about 50 MB when it fills). On a 128 MB router set `option ndpi_max_flows '10000'`
  (or use `classification 'port'`); 256 MB and up is fine with the defaults.
  The installed binary is 10.5 to 12 MB (the package about 4 MB). Check
  `df -h /overlay` first: a 16 MB-flash router rarely has room for it, and
  is better served by an image built with the package included.

## Files

```
openwrt/perch-collector/Makefile                 feed package (golang-package.mk, nDPI 5.0 built and linked statically)
openwrt/sdk.env                                  OpenWrt releases and architectures the release builds
scripts/openwrt-package.sh                       one package for one architecture and release, with the SDK's Docker image
openwrt/perch-collector/files/*.init             procd init: UCI → environment, key generation, interface triggers
openwrt/perch-collector/files/*.config           default /etc/config/perch-collector
openwrt/perch-collector/files/*.defaults         uci-defaults: generate the API key and the instance id on first boot
```
