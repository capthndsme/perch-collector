package config

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all daemon configuration.
type Config struct {
	// Interface is the network interface to capture on. Empty means
	// auto-detect: main resolves it to the interface carrying the IPv4
	// default route. Use "any" to capture on all interfaces.
	Interface string `yaml:"interface"`

	// CaptureNetworks turns on multi-interface capture (gateway plan 1
	// section 8.3): UCI network names, device names, or "auto" (every
	// LAN-side network netifd has: up, proto static or none, not a WAN).
	// The daemon captures on each network's L3 device with an engine and
	// classifier of its own, re-reads netifd every CaptureRescan seconds
	// and on SIGHUP, and adds or removes engines without a restart. Empty
	// (the default) = the single Interface, exactly as before.
	CaptureNetworks []string `yaml:"capture_networks"`

	// CaptureExclude removes networks (or devices) from CaptureNetworks,
	// e.g. a guest network that must not be captured.
	CaptureExclude []string `yaml:"capture_exclude"`

	// CaptureRescan is how often, in seconds, netifd is re-read for
	// networks that appeared or went away. Clamped to 5..3600.
	CaptureRescan int `yaml:"capture_rescan"`

	// RoutedLAN is the scope rule (owner decision 8): "on" counts traffic
	// routed between two local networks, and traffic to the router's own
	// LAN addresses, as LAN instead of WAN; "off" keeps the original rule
	// (everything through the router is WAN). "auto" (the default) is on
	// with CaptureNetworks and off with the single Interface, so an
	// existing single-interface collector keeps its WAN/LAN split.
	RoutedLAN string `yaml:"routed_lan"`

	// NDPIModule is how the captures of CaptureNetworks use nDPI: "shared"
	// (the default) runs one detection module (its protocol tables, about
	// 12 MB) for every capture, each still with a classifier and flow
	// table of its own; "per_network" gives every capture a module of its
	// own (about 12 MB more per network, nDPI work spread over the CPUs).
	NDPIModule string `yaml:"ndpi_module"`

	// BPFFilter is a BPF filter expression applied to the capture.
	BPFFilter string `yaml:"bpf_filter"`

	// ClassificationMode sets how protocols are identified: "port" or "ndpi".
	ClassificationMode string `yaml:"classification_mode"`

	// NDPIMaxFlows is the maximum number of concurrent flows tracked in nDPI mode.
	NDPIMaxFlows int `yaml:"ndpi_max_flows"`

	// NDPIFlowIdleSeconds is the timeout for purging idle flows in nDPI mode.
	NDPIFlowIdleSeconds int `yaml:"ndpi_flow_idle_seconds"`

	// NDPIPartialExtraPackets is how many packets a flow keeps native nDPI
	// state after its first usable label (0 = finalise immediately). Bounds
	// memory on busy links; 4 covers the ServerHello burst.
	NDPIPartialExtraPackets int `yaml:"ndpi_partial_extra_packets"`

	// SnapLen is the maximum number of bytes to capture per packet.
	// 96 bytes captures all headers without payload. It applies to port
	// classification only: with nDPI the capture takes whole packets
	// (capture.FullPacketSnapLen) whatever this says.
	SnapLen int32 `yaml:"snap_len"`

	// Listen is the address:port for the HTTP API server.
	Listen string `yaml:"listen"`

	// Promisc enables promiscuous mode on the capture interface.
	Promisc bool `yaml:"promiscuous"`

	// APIKey is an optional bearer token for API authentication.
	// When empty, no authentication is enforced.
	APIKey string `yaml:"api_key"`

	// FlushFile is the path to write periodic JSON snapshots.
	// Empty string disables disk persistence.
	FlushFile string `yaml:"flush_file"`

	// FlushInterval is how often (in seconds) to write JSON snapshots.
	FlushInterval int `yaml:"flush_interval"`

	// GatewayMAC is the Ethernet MAC of a single upstream gateway. Kept for
	// backward compatibility; prefer GatewayMACs. When set, it is merged
	// into GatewayMACs during Validate().
	GatewayMAC string `yaml:"gateway_mac"`

	// GatewayMACs is the list of Ethernet MACs that should be treated as
	// upstream-gateway pivots. Frames whose src or dst MAC appears here are
	// classified as WAN traffic for the device on the other side. When empty,
	// the daemon auto-detects the single default-route gateway at startup;
	// configure this list explicitly when you have multiple upstream routers
	// (e.g. a primary OpenWrt gateway plus a secondary WAN container).
	GatewayMACs []string `yaml:"gateway_macs"`

	// LocalSubnets is an optional list of CIDRs identifying which IPs belong
	// to local LAN devices (vs. external WAN peers). These are appended to
	// the auto-detected subnets from the capture interface.
	LocalSubnets []string `yaml:"local_subnets"`

	// TopPeersCount caps the number of remote (WAN) peers tracked per local
	// device. Bounded memory; smallest-score peers are evicted when the cap
	// is hit. 0 = use built-in default, negative = disable WAN peer list.
	TopPeersCount int `yaml:"top_peers_count"`

	// TopLANPeersCount caps the number of LAN neighbours tracked per local
	// device. LAN peers are recorded for frames where neither side is a
	// gateway MAC (i.e. host ↔ NAS over SMB, IP-cam ↔ NVR, etc.) and live in
	// a separate bounded heap from TopPeersCount so the two scopes can't
	// evict each other. 0 = use built-in default, negative = disable LAN
	// peer list entirely.
	TopLANPeersCount int `yaml:"top_lan_peers_count"`

	// TopServicesCount caps the number of distinct (server name, protocol)
	// pairs tracked per local device for the "bytes served per SNI" view.
	// Names come from nDPI (TLS SNI / HTTP Host / QUIC SNI) and are only
	// recorded on the device that is the *server* of the flow. 0 = built-in
	// default (500), negative = disable service accounting.
	TopServicesCount int `yaml:"top_services_count"`

	// TopDestinationsCount caps the number of distinct (server name,
	// protocol) destination rows tracked per local device for the "where is
	// my traffic going" view. Rows are recorded on the device that is the
	// *client* of a WAN flow; unnamed flows pool per protocol. 0 = built-in
	// default (500), negative = disable destination accounting.
	TopDestinationsCount int `yaml:"top_destinations_count"`

	// TopUnnamedDestinationsCount caps, per local device, the destination
	// rows keyed by peer address: unnamed flows of a name-carrying family
	// (TLS / HTTP / QUIC) whose ClientHello was never seen. Past the cap
	// they join the per-protocol pool. 0 = built-in default (100),
	// negative = never key by address.
	TopUnnamedDestinationsCount int `yaml:"top_unnamed_destinations_count"`

	// ServerURL is the root of the Perch controller this collector
	// announces itself to, e.g. "http://192.168.1.10:8080". Empty (the
	// default) disables announcing entirely and the daemon never opens an
	// outbound connection. An announce only ever creates or refreshes a
	// *pending* registration; the server never learns anything it can act
	// on until an administrator adopts the collector.
	ServerURL string `yaml:"server_url"`

	// AnnounceInterval is the number of seconds between announces. It is
	// the starting cadence only: every reply carries the schedule the
	// server wants (announceIntervalSeconds), which wins from then on.
	// Clamped to [15, 3600] by Validate.
	AnnounceInterval int `yaml:"announce_interval"`

	// AnnounceAPIKey includes the API key in the announce body so the
	// administrator never has to copy it by hand. false announces the
	// identity only and the key is pasted into the dashboard on adopt.
	// Irrelevant when APIKey is empty. The Authorization header carries
	// the key either way, so a deployment that dislikes keys in bodies can
	// turn this off and still be recognised on re-announce.
	AnnounceAPIKey bool `yaml:"announce_api_key"`

	// InstanceID is an explicit, stable identity for this collector, which
	// is how the server recognises the same daemon across restarts and
	// address changes. Empty means the daemon generates one and persists it
	// in InstanceIDFile. OpenWrt passes the UCI-stored value here so UCI
	// stays the only persistence layer on a read-only overlay.
	InstanceID string `yaml:"instance_id"`

	// InstanceIDFile is where the resolved instance id is persisted. The id
	// is derived from the machine id and the capture interface MAC first and
	// written here only to pin it; a path that cannot be written is not an
	// error (see internal/announce.ResolveInstanceID).
	InstanceIDFile string `yaml:"instance_id_file"`

	// AnnounceTLSInsecure accepts a self-signed certificate on an https
	// ServerURL, for the announce and for the WebSocket alike. A no-op for
	// http:// URLs.
	AnnounceTLSInsecure bool `yaml:"announce_tls_insecure"`

	// Transport is how the collector reaches the controller at ServerURL:
	// "websocket" dials out and pushes (nothing has to reach the collector),
	// "poll" announces over HTTP and waits to be polled on Listen, and
	// "auto" (the default) is websocket when api_key is set and poll when
	// it is not. Irrelevant without server_url.
	Transport string `yaml:"transport"`

	// ServerCAFile is a PEM bundle trusted on top of the system roots for an
	// https ServerURL signed by a private CA.
	ServerCAFile string `yaml:"server_ca_file"`

	// GatewayStats reports the router's own health with the traffic data:
	// connection tracking, established TCP, load, memory and the WAN
	// counters, for the controller's Gateway page. "auto" (the default) is
	// on when the collector runs on OpenWrt, i.e. on the router itself;
	// "on" and "off" force it.
	GatewayStats string `yaml:"gateway_stats"`

	// WANInterfaces names the WAN interfaces the gateway stats count. Empty
	// means the interfaces holding a default route, re-read on every report;
	// set it when the WAN routes live outside the main table (policy
	// routing, mwan3).
	WANInterfaces []string `yaml:"wan_interfaces"`

	// Ports reports the router's Ethernet ports and their link state in the
	// gateway report, for the controller's infrastructure view. "auto" (the
	// default) and "on" report them whenever gateway stats are on; "off"
	// leaves them out. They travel in the gateway report, so with gateway
	// stats off there are none either way (see PortsEnabled).
	Ports string `yaml:"ports"`

	// DHCPLeases reports the router's DHCP leases and static DHCP hosts
	// (observe.dhcp) so the controller can name devices without a transport
	// of its own to the router. "auto" (the default) is on when the
	// collector runs on OpenWrt; "on" and "off" force it. Independent of
	// gateway_stats.
	DHCPLeases string `yaml:"dhcp_leases"`

	// DHCPLeasesRefresh is how often, in seconds, the leases are sent even
	// though nothing changed (a change is sent with the next push).
	// Clamped to DHCPLeasesRefreshMin..DHCPLeasesRefreshMax.
	DHCPLeasesRefresh int `yaml:"dhcp_leases_refresh"`

	// Observe reports the router's other runtime state beside the DHCP
	// leases (gateway plan 2 section 3): the neighbour table, the
	// interfaces and their default routes, UPnP mappings, mwan3, who
	// answers DNS, and the system. "auto" (the default) is on when the
	// collector runs on OpenWrt; "on" and "off" force it.
	Observe string `yaml:"observe"`

	// ObserveParts limits Observe to these parts (neighbors, interfaces,
	// upnp, mwan3, resolver, system). Empty = all of them.
	ObserveParts []string `yaml:"observe_parts"`

	// ObserveRefresh is how often, in seconds, an unchanged part is sent
	// again. Clamped like DHCPLeasesRefresh.
	ObserveRefresh int `yaml:"observe_refresh"`

	// ConntrackFlush lets the controller delete a device's conntrack
	// entries (net.conntrack_flush), so a WAN block also ends the flows
	// already running. auto (default) = on with Observe.
	ConntrackFlush string `yaml:"conntrack_flush"`

	// QoS runs the traffic shaper (perch-qos: per-device and bucket caps,
	// gateway plan 3). auto (default) = on when the perch-qos package is
	// installed (/etc/config/perch-qos exists) on OpenWrt.
	QoS string `yaml:"qos"`

	// GatewayBackup is what gateway.backup hands out: "redacted" (the
	// default: secrets replaced, private keys left out), "full" (the
	// sysupgrade -b archive as is) or "off" (no backups).
	GatewayBackup string `yaml:"gateway_backup"`

	// ControllerAddressCache is the file that keeps the controller's last
	// good address, dialed when its name does not resolve. "" = memory only.
	ControllerAddressCache string `yaml:"controller_address_cache"`

	// Portal offers the guest portal to the controller (capability
	// "portal": Perch-owned nftables enforcement and the guest pages).
	// "auto" (the default) is on under OpenWrt with the WebSocket
	// transport; "off" also removes any enforcement a previous run left.
	Portal string `yaml:"portal"`
	// PortalPort is the guest pages' port (plain HTTP, every address; only
	// the portal devices may reach it).
	PortalPort int `yaml:"portal_port"`
	// PortalStoragePath is where the portal state is snapshotted (grants,
	// vouchers, journal); "" = /etc/perch-collector/portal/state.db.
	PortalStoragePath string `yaml:"portal_storage_path"`
	// PortalFlushInterval is how often, in seconds, counters are written
	// there; 0 = by storage kind (300 on flash, every tick on eMMC/disks).
	// Grants are written at once regardless.
	PortalFlushInterval int `yaml:"portal_flush_interval"`
	// PortalStorageMount is the mount point PortalStoragePath must be on
	// (a USB disk, say); when it is not mounted the state stays in RAM and
	// goes to the default path instead, never onto an empty mount point.
	PortalStorageMount string `yaml:"portal_storage_mount"`
	// ConfigPlane is the router's opt-in to the config plane
	// (config_plane.go).
	ConfigPlane `yaml:",inline"`
	// Updates is the router's say on self-update (updates.go).
	Updates `yaml:",inline"`

	// Deprecated lists the pre-rename GOCOLLECTOR_* variables that supplied
	// a value, so main can say once that each has a new name. Never YAML.
	Deprecated []string `yaml:"-"`
}

// Transport values.
const (
	TransportAuto      = "auto"
	TransportWebSocket = "websocket"
	TransportPoll      = "poll"
)

// GatewayStats values.
const (
	GatewayStatsAuto = "auto"
	GatewayStatsOn   = "on"
	GatewayStatsOff  = "off"
)

// Ports values.
const (
	PortsAuto = "auto"
	PortsOn   = "on"
	PortsOff  = "off"
)

// DHCPLeases, Observe and ConntrackFlush values are GatewayStats's: auto, on, off.

// GatewayBackup values.
const (
	GatewayBackupOff      = "off"
	GatewayBackupRedacted = "redacted"
	GatewayBackupFull     = "full"
)

// ObservePartNames are the parts ObserveParts may name.
var ObservePartNames = []string{"neighbors", "interfaces", "upnp", "mwan3", "resolver", "system"}

// DefaultControllerAddressCache is where the last good controller address
// is kept when controller_address_cache is not set.
const DefaultControllerAddressCache = "/var/lib/perch-collector/controller-address"

// NDPIModule values.
const (
	NDPIModuleShared     = "shared"
	NDPIModulePerNetwork = "per_network"
)

// Capture rescan bounds and default, in seconds.
const (
	CaptureRescanMin     = 5
	CaptureRescanMax     = 3600
	CaptureRescanDefault = 30
)

// DHCP lease refresh bounds and default, in seconds. The controller treats a
// router that has not sent its leases for twice the maximum as gone.
const (
	DHCPLeasesRefreshMin     = 60
	DHCPLeasesRefreshMax     = 3600
	DHCPLeasesRefreshDefault = 600
)

// Announce interval bounds. The lower bound keeps a misconfigured collector
// from hammering the server; the upper bound keeps "once a day" from looking
// like a hung daemon.
const (
	AnnounceIntervalMin = 15
	AnnounceIntervalMax = 3600
)

// AnnounceAPIKeyMinLength mirrors the minimum the server's announce
// validator enforces on an API key carried in the announce body.
const AnnounceAPIKeyMinLength = 8

// DefaultInstanceIDFile is where a generated instance id is persisted when
// instance_id_file is not set.
const DefaultInstanceIDFile = "/var/lib/perch-collector/instance-id"

// LegacyInstanceIDFile is where the daemon kept it before the rename to
// perch-collector (see InstanceIDPath).
const LegacyInstanceIDFile = "/var/lib/go-collector/instance-id"

// Defaults returns a Config with sensible defaults.
func Defaults() Config {
	return Config{
		Interface:                   "",
		CaptureRescan:               CaptureRescanDefault,
		RoutedLAN:                   GatewayStatsAuto,
		NDPIModule:                  NDPIModuleShared,
		BPFFilter:                   "",
		ClassificationMode:          "port",
		NDPIMaxFlows:                50000,
		NDPIFlowIdleSeconds:         120,
		NDPIPartialExtraPackets:     4,
		SnapLen:                     96,
		Listen:                      "127.0.0.1:9800",
		Promisc:                     true,
		APIKey:                      "",
		FlushFile:                   "",
		FlushInterval:               60,
		GatewayMAC:                  "",
		GatewayMACs:                 nil,
		LocalSubnets:                nil,
		TopPeersCount:               50,
		TopLANPeersCount:            50,
		TopServicesCount:            500,
		TopDestinationsCount:        500,
		TopUnnamedDestinationsCount: 100,
		ServerURL:                   "",
		AnnounceInterval:            60,
		AnnounceAPIKey:              true,
		InstanceID:                  "",
		InstanceIDFile:              DefaultInstanceIDFile,
		AnnounceTLSInsecure:         false,
		Transport:                   TransportAuto,
		ServerCAFile:                "",
		GatewayStats:                GatewayStatsAuto,
		WANInterfaces:               nil,
		Ports:                       PortsAuto,
		DHCPLeases:                  GatewayStatsAuto,
		DHCPLeasesRefresh:           DHCPLeasesRefreshDefault,
		Observe:                     GatewayStatsAuto,
		ObserveRefresh:              DHCPLeasesRefreshDefault,
		ConntrackFlush:              GatewayStatsAuto,
		QoS:                         GatewayStatsAuto,
		GatewayBackup:               GatewayBackupRedacted,
		ControllerAddressCache:      DefaultControllerAddressCache,
		Portal:                      GatewayStatsAuto,
		PortalPort:                  DefaultPortalPort,
		ConfigPlane:                 defaultConfigPlane(),
		Updates:                     defaultUpdates(),
	}
}

// DefaultPortalPort is the guest pages' port.
const DefaultPortalPort = 2080

// Load reads configuration from a YAML file, then applies CLI flag overrides,
// then applies environment variable overrides. Precedence: env > CLI > YAML > defaults.
func Load() (Config, error) {
	// Define CLI flags.
	configPath := flag.String("config", "collector.yaml", "Path to YAML config file")
	cliInterface := flag.String("interface", "", "Network interface to capture on (empty = the default route's interface)")
	cliListen := flag.String("listen", "", "HTTP API listen address")
	cliBPF := flag.String("bpf", "", "BPF filter expression")
	flag.Parse()

	return load(*configPath, cliOverrides{
		Interface: *cliInterface,
		Listen:    *cliListen,
		BPFFilter: *cliBPF,
	})
}

// cliOverrides carries the parsed CLI flags into load(). An empty string
// means "flag not given" and leaves the YAML/default value alone, which is
// exactly how the flags behaved before they were separated from the loading
// logic.
type cliOverrides struct {
	Interface string
	Listen    string
	BPFFilter string
}

// load is Load without the global flag set: the whole precedence chain
// (defaults → YAML → CLI → env → Validate) in one testable function.
func load(configPath string, cli cliOverrides) (Config, error) {
	cfg := Defaults()

	// Load YAML config file (optional — if it doesn't exist, use defaults).
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return cfg, fmt.Errorf("reading config file %q: %w", configPath, err)
		}
		// Config file not found is fine — use defaults.
	} else {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parsing config file %q: %w", configPath, err)
		}
	}

	// CLI flags override YAML values (only if explicitly set).
	if cli.Interface != "" {
		cfg.Interface = cli.Interface
	}
	if cli.Listen != "" {
		cfg.Listen = cli.Listen
	}
	if cli.BPFFilter != "" {
		cfg.BPFFilter = cli.BPFFilter
	}

	// Environment variables override everything. PERCH_COLLECTOR_<NAME> is
	// the name; GOCOLLECTOR_<NAME> from before the rename still works while
	// the new one is unset, and is listed in cfg.Deprecated.
	env := &envReader{}
	env.str("INTERFACE", &cfg.Interface)
	if list, ok := env.list("CAPTURE_NETWORKS"); ok {
		cfg.CaptureNetworks = list
	}
	if list, ok := env.list("CAPTURE_EXCLUDE"); ok {
		cfg.CaptureExclude = list
	}
	env.integer("CAPTURE_RESCAN", func(n int) { cfg.CaptureRescan = n })
	env.str("ROUTED_LAN", &cfg.RoutedLAN)
	env.str("NDPI_MODULE", &cfg.NDPIModule)
	env.str("LISTEN", &cfg.Listen)
	env.str("API_KEY", &cfg.APIKey)
	env.str("BPF_FILTER", &cfg.BPFFilter)
	env.str("CLASSIFICATION_MODE", &cfg.ClassificationMode)
	env.integer("SNAP_LEN", func(n int) { cfg.SnapLen = int32(n) })
	env.integer("NDPI_MAX_FLOWS", func(n int) { cfg.NDPIMaxFlows = n })
	env.integer("NDPI_FLOW_IDLE_SECONDS", func(n int) { cfg.NDPIFlowIdleSeconds = n })
	env.integer("NDPI_PARTIAL_EXTRA_PACKETS", func(n int) { cfg.NDPIPartialExtraPackets = n })
	env.str("FLUSH_FILE", &cfg.FlushFile)
	env.boolean("PROMISCUOUS", &cfg.Promisc)
	if list, ok := env.list("LOCAL_SUBNETS"); ok {
		cfg.LocalSubnets = list
	}
	env.str("GATEWAY_MAC", &cfg.GatewayMAC)
	if list, ok := env.list("GATEWAY_MACS"); ok {
		// Added to the YAML list, not replacing it (as it always was).
		cfg.GatewayMACs = append(cfg.GatewayMACs, list...)
	}
	env.integer("TOP_PEERS_COUNT", func(n int) { cfg.TopPeersCount = n })
	env.integer("TOP_LAN_PEERS_COUNT", func(n int) { cfg.TopLANPeersCount = n })
	env.integer("TOP_SERVICES_COUNT", func(n int) { cfg.TopServicesCount = n })
	env.integer("TOP_DESTINATIONS_COUNT", func(n int) { cfg.TopDestinationsCount = n })
	env.integer("TOP_UNNAMED_DESTINATIONS_COUNT", func(n int) { cfg.TopUnnamedDestinationsCount = n })
	env.str("SERVER_URL", &cfg.ServerURL)
	env.integer("ANNOUNCE_INTERVAL", func(n int) { cfg.AnnounceInterval = n })
	env.boolean("ANNOUNCE_API_KEY", &cfg.AnnounceAPIKey)
	env.str("INSTANCE_ID", &cfg.InstanceID)
	env.str("INSTANCE_ID_FILE", &cfg.InstanceIDFile)
	env.boolean("ANNOUNCE_TLS_INSECURE", &cfg.AnnounceTLSInsecure)
	env.str("TRANSPORT", &cfg.Transport)
	env.str("SERVER_CA_FILE", &cfg.ServerCAFile)
	env.str("GATEWAY_STATS", &cfg.GatewayStats)
	if list, ok := env.list("WAN_INTERFACES"); ok {
		cfg.WANInterfaces = list
	}
	env.str("PORTS", &cfg.Ports)
	env.str("DHCP_LEASES", &cfg.DHCPLeases)
	env.integer("DHCP_LEASES_REFRESH", func(n int) { cfg.DHCPLeasesRefresh = n })
	env.str("OBSERVE", &cfg.Observe)
	if list, ok := env.list("OBSERVE_PARTS"); ok {
		cfg.ObserveParts = list
	}
	env.integer("OBSERVE_REFRESH", func(n int) { cfg.ObserveRefresh = n })
	env.str("CONNTRACK_FLUSH", &cfg.ConntrackFlush)
	env.str("QOS", &cfg.QoS)
	env.str("GATEWAY_BACKUP", &cfg.GatewayBackup)
	env.str("CONTROLLER_ADDRESS_CACHE", &cfg.ControllerAddressCache)
	env.str("PORTAL", &cfg.Portal)
	env.integer("PORTAL_PORT", func(n int) { cfg.PortalPort = n })
	env.str("PORTAL_STORAGE_PATH", &cfg.PortalStoragePath)
	env.integer("PORTAL_FLUSH_INTERVAL", func(n int) { cfg.PortalFlushInterval = n })
	env.str("PORTAL_STORAGE_MOUNT", &cfg.PortalStorageMount)
	cfg.ConfigPlane.readEnv(env)
	cfg.Updates.readEnv(env)
	cfg.Deprecated = env.deprecated
	if env.err != nil {
		return cfg, env.err
	}

	// Validate.
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// Validate checks that configuration values are sensible.
func (c *Config) Validate() error {
	if c.NDPIPartialExtraPackets < 0 || c.NDPIPartialExtraPackets > 64 {
		return fmt.Errorf("ndpi_partial_extra_packets must be between 0 and 64, got %d", c.NDPIPartialExtraPackets)
	}
	if c.Listen == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if c.SnapLen <= 0 {
		return fmt.Errorf("snap_len must be positive, got %d", c.SnapLen)
	}
	if c.ClassificationMode != "port" && c.ClassificationMode != "ndpi" {
		return fmt.Errorf("classification_mode must be 'port' or 'ndpi', got %q", c.ClassificationMode)
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 60
	}
	if c.GatewayMAC != "" {
		if _, err := net.ParseMAC(c.GatewayMAC); err != nil {
			return fmt.Errorf("invalid gateway_mac %q: %w", c.GatewayMAC, err)
		}
		// Fold the singular form into the list; downstream consumers only
		// need to look at GatewayMACs.
		c.GatewayMACs = append(c.GatewayMACs, c.GatewayMAC)
		c.GatewayMAC = ""
	}
	// Validate + canonicalize every entry, dedupe.
	if len(c.GatewayMACs) > 0 {
		seen := make(map[string]struct{}, len(c.GatewayMACs))
		out := make([]string, 0, len(c.GatewayMACs))
		for _, raw := range c.GatewayMACs {
			s := strings.TrimSpace(raw)
			if s == "" {
				continue
			}
			h, err := net.ParseMAC(s)
			if err != nil {
				return fmt.Errorf("invalid gateway_macs entry %q: %w", raw, err)
			}
			k := h.String()
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
		c.GatewayMACs = out
	}
	for _, s := range c.LocalSubnets {
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("invalid local_subnets entry %q: %w", s, err)
		}
	}
	const hardMax = 1000
	if c.TopPeersCount < 0 {
		return fmt.Errorf("top_peers_count must be >= 0, got %d", c.TopPeersCount)
	}
	if c.TopPeersCount == 0 {
		c.TopPeersCount = 50
	}
	if c.TopPeersCount > hardMax {
		c.TopPeersCount = hardMax
	}
	if c.TopLANPeersCount < 0 {
		return fmt.Errorf("top_lan_peers_count must be >= 0, got %d", c.TopLANPeersCount)
	}
	if c.TopLANPeersCount == 0 {
		c.TopLANPeersCount = 50
	}
	if c.TopLANPeersCount > hardMax {
		c.TopLANPeersCount = hardMax
	}

	// Announcing is opt-in: everything below only bites once server_url is
	// set, so a collector that is polled the old way is unaffected.
	if c.ServerURL != "" {
		trimmed := strings.TrimRight(strings.TrimSpace(c.ServerURL), "/")
		u, err := url.Parse(trimmed)
		if err != nil {
			return fmt.Errorf("invalid server_url %q: %w", c.ServerURL, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("server_url must be an http:// or https:// URL, got %q", c.ServerURL)
		}
		if u.Host == "" {
			return fmt.Errorf("server_url %q has no host", c.ServerURL)
		}
		// Store the normalised form: the announce path is appended to it.
		c.ServerURL = trimmed
		if c.AnnounceTLSInsecure && u.Scheme != "https" {
			fmt.Fprintf(os.Stderr, "WARNING: announce_tls_insecure has no effect with an http:// server_url (%s).\n", c.ServerURL)
		}
		if c.AnnounceInterval < AnnounceIntervalMin || c.AnnounceInterval > AnnounceIntervalMax {
			fmt.Fprintf(os.Stderr, "WARNING: announce_interval %d is outside [%d, %d] seconds; clamping.\n",
				c.AnnounceInterval, AnnounceIntervalMin, AnnounceIntervalMax)
		}
		// The server's announce validator requires at least
		// AnnounceAPIKeyMinLength characters for a key sent in the body, so
		// a shorter one would turn every announce into a 422 nobody sees.
		if c.AnnounceAPIKey && c.APIKey != "" && len(c.APIKey) < AnnounceAPIKeyMinLength {
			return fmt.Errorf(
				"api_key is %d characters; the Perch controller rejects an announced key shorter than %d — "+
					"use a longer api_key, or set announce_api_key: false and paste the key in when you adopt",
				len(c.APIKey), AnnounceAPIKeyMinLength)
		}
	}
	switch t := strings.ToLower(strings.TrimSpace(c.Transport)); t {
	case "", TransportAuto:
		c.Transport = TransportAuto
	case TransportWebSocket, TransportPoll:
		c.Transport = t
	default:
		return fmt.Errorf("transport must be auto, websocket or poll, got %q", c.Transport)
	}
	if c.Transport == TransportWebSocket {
		if c.ServerURL == "" {
			return fmt.Errorf("transport websocket needs server_url: the collector dials the controller there")
		}
		if c.APIKey == "" {
			return fmt.Errorf("transport websocket needs api_key: the controller authenticates the collector's socket with it")
		}
	}
	if c.Transport == TransportAuto && c.ServerURL != "" && c.APIKey == "" {
		fmt.Fprintf(os.Stderr, "WARNING: server_url is set but api_key is empty: announcing over HTTP and waiting to be polled; set api_key to use the WebSocket transport.\n")
	}
	if c.ServerCAFile != "" && c.ServerURL != "" && !strings.HasPrefix(c.ServerURL, "https://") {
		fmt.Fprintf(os.Stderr, "WARNING: server_ca_file has no effect with an http:// server_url (%s).\n", c.ServerURL)
	}
	c.CaptureNetworks = cleanList(c.CaptureNetworks)
	for i, n := range c.CaptureNetworks {
		if strings.EqualFold(n, "auto") {
			c.CaptureNetworks[i] = "auto"
		}
	}
	c.CaptureExclude = cleanList(c.CaptureExclude)
	if c.CaptureRescan == 0 {
		c.CaptureRescan = CaptureRescanDefault
	}
	if c.CaptureRescan < CaptureRescanMin {
		c.CaptureRescan = CaptureRescanMin
	}
	if c.CaptureRescan > CaptureRescanMax {
		c.CaptureRescan = CaptureRescanMax
	}
	rl, ok := normalizeAutoOnOff(c.RoutedLAN)
	if !ok {
		return fmt.Errorf("routed_lan must be auto, on or off, got %q", c.RoutedLAN)
	}
	c.RoutedLAN = rl
	switch m := strings.ToLower(strings.TrimSpace(c.NDPIModule)); m {
	case "", NDPIModuleShared:
		c.NDPIModule = NDPIModuleShared
	case NDPIModulePerNetwork, "per-network", "separate":
		c.NDPIModule = NDPIModulePerNetwork
	default:
		return fmt.Errorf("ndpi_module must be shared or per_network, got %q", c.NDPIModule)
	}
	gs, ok := normalizeAutoOnOff(c.GatewayStats)
	if !ok {
		return fmt.Errorf("gateway_stats must be auto, on or off, got %q", c.GatewayStats)
	}
	c.GatewayStats = gs
	c.WANInterfaces = cleanList(c.WANInterfaces)
	ports, ok := normalizeAutoOnOff(c.Ports)
	if !ok {
		return fmt.Errorf("ports must be auto, on or off, got %q", c.Ports)
	}
	c.Ports = ports
	dl, ok := normalizeAutoOnOff(c.DHCPLeases)
	if !ok {
		return fmt.Errorf("dhcp_leases must be auto, on or off, got %q", c.DHCPLeases)
	}
	c.DHCPLeases = dl
	if c.DHCPLeasesRefresh == 0 {
		c.DHCPLeasesRefresh = DHCPLeasesRefreshDefault
	}
	if c.DHCPLeasesRefresh < DHCPLeasesRefreshMin {
		c.DHCPLeasesRefresh = DHCPLeasesRefreshMin
	}
	if c.DHCPLeasesRefresh > DHCPLeasesRefreshMax {
		c.DHCPLeasesRefresh = DHCPLeasesRefreshMax
	}
	if err := c.validateObserve(); err != nil {
		return err
	}

	if err := c.ConfigPlane.validate(); err != nil {
		return err
	}
	c.validateUpdates()

	// Clamped unconditionally so the value in the struct is always the value
	// the daemon would actually use.
	if c.AnnounceInterval < AnnounceIntervalMin {
		c.AnnounceInterval = AnnounceIntervalMin
	}
	if c.AnnounceInterval > AnnounceIntervalMax {
		c.AnnounceInterval = AnnounceIntervalMax
	}

	return nil
}

// EffectiveTransport resolves Transport against the rest of the config:
// TransportWebSocket, TransportPoll, or "" when there is no server_url (the
// collector opens no outbound connection and can only be polled). Call it
// on a validated Config.
func (c Config) EffectiveTransport() string {
	if c.ServerURL == "" {
		return ""
	}
	switch c.Transport {
	case TransportWebSocket, TransportPoll:
		return c.Transport
	}
	if c.APIKey != "" {
		return TransportWebSocket
	}
	return TransportPoll
}

// MultiCapture reports whether the collector captures on several networks
// (CaptureNetworks set) instead of the single Interface.
func (c Config) MultiCapture() bool { return len(c.CaptureNetworks) > 0 }

// RoutedLANEnabled resolves RoutedLAN: "auto" is on with multi-capture.
func (c Config) RoutedLANEnabled() bool {
	switch c.RoutedLAN {
	case GatewayStatsOn:
		return true
	case GatewayStatsOff:
		return false
	}
	return c.MultiCapture()
}

// GatewayStatsEnabled resolves GatewayStats; onOpenWrt is what "auto"
// becomes.
func (c Config) GatewayStatsEnabled(onOpenWrt bool) bool {
	switch c.GatewayStats {
	case GatewayStatsOn:
		return true
	case GatewayStatsOff:
		return false
	}
	return onOpenWrt
}

// PortsEnabled resolves Ports; gatewayStats is what GatewayStatsEnabled
// said. Ports travel in the gateway report, so without one there are none:
// "auto" and "on" both follow gateway stats, "off" turns them off.
func (c Config) PortsEnabled(gatewayStats bool) bool {
	return gatewayStats && c.Ports != PortsOff
}

// DHCPLeasesEnabled resolves DHCPLeases; onOpenWrt is what "auto" becomes.
func (c Config) DHCPLeasesEnabled(onOpenWrt bool) bool {
	switch c.DHCPLeases {
	case GatewayStatsOn:
		return true
	case GatewayStatsOff:
		return false
	}
	return onOpenWrt
}

// InstanceIDPath is the file the instance id is resolved from and persisted
// to: InstanceIDFile, except that the default path yields to the pre-rename
// LegacyInstanceIDFile while only that one exists, so a bare-metal upgrade
// keeps the identity its controller knows it by.
func (c Config) InstanceIDPath() string {
	return instanceIDPath(c.InstanceIDFile, DefaultInstanceIDFile, LegacyInstanceIDFile)
}

func instanceIDPath(configured, def, legacy string) string {
	if configured != def {
		return configured
	}
	if _, err := os.Stat(def); err == nil {
		return def
	}
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return def
}

// normalizeAutoOnOff reads an auto/on/off switch (gateway_stats, ports,
// dhcp_leases):
// empty is auto, and the usual boolean spellings (UCI's '1' and '0'
// included) are on and off.
func normalizeAutoOnOff(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto":
		return "auto", true
	case "on", "true", "1", "yes", "enabled":
		return "on", true
	case "off", "false", "0", "no", "disabled":
		return "off", true
	}
	return "", false
}

// cleanList trims entries and drops empty ones and repeats, keeping order.
func cleanList(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// envReader applies PERCH_COLLECTOR_* variables, falling back to the
// pre-rename GOCOLLECTOR_* name of each. The first parse error wins.
type envReader struct {
	deprecated []string
	err        error
}

// Environment variable prefixes: the current one and the one before the
// rename.
const (
	EnvPrefix       = "PERCH_COLLECTOR_"
	LegacyEnvPrefix = "GOCOLLECTOR_"
)

// lookup returns the value of NAME and the variable that supplied it; empty
// values count as unset.
func (r *envReader) lookup(name string) (string, string) {
	if v := os.Getenv(EnvPrefix + name); v != "" {
		return v, EnvPrefix + name
	}
	legacy := LegacyEnvPrefix + name
	if v := os.Getenv(legacy); v != "" {
		for _, d := range r.deprecated {
			if d == legacy {
				return v, legacy
			}
		}
		r.deprecated = append(r.deprecated, legacy)
		return v, legacy
	}
	return "", ""
}

func (r *envReader) str(name string, dst *string) {
	if v, _ := r.lookup(name); v != "" {
		*dst = v
	}
}

func (r *envReader) integer(name string, set func(int)) {
	v, from := r.lookup(name)
	if v == "" || r.err != nil {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		r.err = fmt.Errorf("%s must be an integer, got %q", from, v)
		return
	}
	set(n)
}

func (r *envReader) boolean(name string, dst *bool) {
	v, from := r.lookup(name)
	if v == "" || r.err != nil {
		return
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.err = fmt.Errorf("%s must be a boolean, got %q", from, v)
		return
	}
	*dst = b
}

// list splits a comma-separated value; ok is false when the variable is unset.
func (r *envReader) list(name string) ([]string, bool) {
	v, _ := r.lookup(name)
	if v == "" {
		return nil, false
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, true
}

func (c *Config) validateObserve() error {
	o, ok := normalizeAutoOnOff(c.Observe)
	if !ok {
		return fmt.Errorf("observe must be auto, on or off, got %q", c.Observe)
	}
	c.Observe = o
	var parts []string
	for _, p := range cleanList(c.ObserveParts) {
		p = strings.ToLower(p)
		known := false
		for _, n := range ObservePartNames {
			if p == n {
				known = true
			}
		}
		if !known {
			return fmt.Errorf("observe_parts: unknown part %q (known: %s)", p, strings.Join(ObservePartNames, ", "))
		}
		parts = append(parts, p)
	}
	c.ObserveParts = parts
	if c.ObserveRefresh == 0 {
		c.ObserveRefresh = DHCPLeasesRefreshDefault
	}
	if c.ObserveRefresh < DHCPLeasesRefreshMin {
		c.ObserveRefresh = DHCPLeasesRefreshMin
	}
	if c.ObserveRefresh > DHCPLeasesRefreshMax {
		c.ObserveRefresh = DHCPLeasesRefreshMax
	}
	ct, ok := normalizeAutoOnOff(c.ConntrackFlush)
	if !ok {
		return fmt.Errorf("conntrack_flush must be auto, on or off, got %q", c.ConntrackFlush)
	}
	c.ConntrackFlush = ct
	qv, ok := normalizeAutoOnOff(c.QoS)
	if !ok {
		return fmt.Errorf("qos must be auto, on or off, got %q", c.QoS)
	}
	c.QoS = qv
	switch strings.ToLower(strings.TrimSpace(c.GatewayBackup)) {
	case "", GatewayBackupRedacted:
		c.GatewayBackup = GatewayBackupRedacted
	case GatewayBackupFull:
		c.GatewayBackup = GatewayBackupFull
	case GatewayBackupOff, "0", "no", "false", "disabled":
		c.GatewayBackup = GatewayBackupOff
	default:
		return fmt.Errorf("gateway_backup must be redacted, full or off, got %q", c.GatewayBackup)
	}
	c.ControllerAddressCache = strings.TrimSpace(c.ControllerAddressCache)
	return c.validatePortal()
}

func (c *Config) validatePortal() error {
	p, ok := normalizeAutoOnOff(c.Portal)
	if !ok {
		return fmt.Errorf("portal must be auto, on or off, got %q", c.Portal)
	}
	c.Portal = p
	if c.PortalPort == 0 {
		c.PortalPort = DefaultPortalPort
	}
	if c.PortalPort < 1 || c.PortalPort > 65535 || c.PortalPort == 80 || c.PortalPort == 53 || c.PortalPort == 67 {
		return fmt.Errorf("portal_port must be a free TCP port (not 53, 67 or 80), got %d", c.PortalPort)
	}
	if c.PortalFlushInterval < 0 || c.PortalFlushInterval > 3600 {
		return fmt.Errorf("portal_flush_interval must be 0 (auto) or 5-3600 seconds, got %d", c.PortalFlushInterval)
	}
	if c.PortalFlushInterval > 0 && c.PortalFlushInterval < 5 {
		c.PortalFlushInterval = 5
	}
	c.PortalStoragePath = strings.TrimSpace(c.PortalStoragePath)
	c.PortalStorageMount = strings.TrimSpace(c.PortalStorageMount)
	return nil
}

// PortalEnabled resolves Portal; "auto" = on OpenWrt with the WebSocket
// transport (the portal is configured over the socket).
func (c Config) PortalEnabled(onOpenWrt bool, websocket bool) bool {
	switch c.Portal {
	case GatewayStatsOn:
		return true
	case GatewayStatsOff:
		return false
	}
	return onOpenWrt && websocket
}

// ObserveEnabled resolves Observe; onOpenWrt is what "auto" becomes.
func (c Config) ObserveEnabled(onOpenWrt bool) bool {
	switch c.Observe {
	case GatewayStatsOn:
		return true
	case GatewayStatsOff:
		return false
	}
	return onOpenWrt
}

// ObservePartEnabled reports whether a part is on (Observe resolved to
// observeOn, and the part listed in ObserveParts or the list empty).
func (c Config) ObservePartEnabled(observeOn bool, part string) bool {
	if !observeOn {
		return false
	}
	if len(c.ObserveParts) == 0 {
		return true
	}
	for _, p := range c.ObserveParts {
		if p == part {
			return true
		}
	}
	return false
}

// ConntrackFlushEnabled resolves ConntrackFlush; "auto" follows observeOn.
func (c Config) ConntrackFlushEnabled(observeOn bool) bool {
	switch c.ConntrackFlush {
	case GatewayStatsOn:
		return true
	case GatewayStatsOff:
		return false
	}
	return observeOn
}

// QoSEnabled resolves QoS; "auto" is on when perch-qos is installed on
// OpenWrt (installed).
func (c Config) QoSEnabled(installed bool) bool {
	switch c.QoS {
	case GatewayStatsOn:
		return true
	case GatewayStatsOff:
		return false
	}
	return installed
}
