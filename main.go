package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/capthndsme/perch-agentkit/hoststat"
	"github.com/capthndsme/perch-agentkit/link"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/announce"
	"github.com/capthndsme/perch-collector/internal/api"
	"github.com/capthndsme/perch-collector/internal/capture"
	"github.com/capthndsme/perch-collector/internal/classifier"
	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/controller"
	"github.com/capthndsme/perch-collector/internal/flusher"
	"github.com/capthndsme/perch-collector/internal/gateway"
	"github.com/capthndsme/perch-collector/internal/netutil"
)

// version is stamped at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("perch-collector %s starting", version)

	// Load configuration.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	for _, name := range cfg.Deprecated {
		log.Printf("config: %s is deprecated; use %s%s", name, config.EnvPrefix, strings.TrimPrefix(name, config.LegacyEnvPrefix))
	}

	if cfg.Interface == "" {
		iface, err := netutil.DetectDefaultInterface()
		if err != nil {
			log.Fatalf("interface: auto-detection failed: %v; set interface in collector.yaml or PERCH_COLLECTOR_INTERFACE", err)
		}
		log.Printf("interface: auto-detected %s", iface)
		cfg.Interface = iface
	}

	log.Printf("config: interface=%s listen=%s promisc=%v snap_len=%d",
		cfg.Interface, cfg.Listen, cfg.Promisc, cfg.SnapLen)
	if cfg.FlushFile != "" {
		log.Printf("config: flush_file=%s flush_interval=%ds", cfg.FlushFile, cfg.FlushInterval)
	}
	if cfg.APIKey != "" {
		log.Println("config: API key authentication enabled")
	}
	if cfg.BPFFilter != "" {
		log.Printf("config: bpf_filter=%s", cfg.BPFFilter)
	}

	// Resolve gateway MACs: union of explicit YAML/env config and (when the
	// config list is empty) auto-detection of the default-route gateway.
	gatewayMACs := resolveGatewayMACs(cfg)

	// Resolve local subnets: auto-detected from the interface, plus any
	// explicit CIDRs supplied via YAML.
	localSubnets := resolveLocalSubnets(cfg)

	log.Printf("config: top_peers_count=%d top_lan_peers_count=%d top_services_count=%d top_destinations_count=%d",
		cfg.TopPeersCount, cfg.TopLANPeersCount, cfg.TopServicesCount, cfg.TopDestinationsCount)

	// Initialize the aggregator with the resolved networking context.
	agg := aggregator.New(gatewayMACs, localSubnets, cfg.TopPeersCount, cfg.TopLANPeersCount)
	agg.SetTopServicesCount(cfg.TopServicesCount)
	agg.SetTopDestinationsCount(cfg.TopDestinationsCount)
	agg.SetTopUnnamedDestinationsCount(cfg.TopUnnamedDestinationsCount)

	// Initialize the protocol classifier. nDPI is opt-in (requires the
	// `ndpi` build tag and libndpi at runtime); on any failure we
	// degrade to the always-available port-based classifier so the
	// collector never crashes on a misconfigured nDPI install.
	var cls classifier.Classifier
	switch cfg.ClassificationMode {
	case "ndpi":
		classifier.SetNDPIPartialExtraPackets(cfg.NDPIPartialExtraPackets)
		ndpiCls, err := classifier.NewNDPIClassifier(cfg.NDPIMaxFlows, cfg.NDPIFlowIdleSeconds)
		if err != nil {
			log.Printf("classifier: nDPI requested but unavailable (%v); falling back to port-based", err)
			cls = classifier.NewPortClassifier()
		} else {
			log.Printf("classifier: using nDPI (max_flows=%d idle=%ds, NDPIAvailable=%v)",
				cfg.NDPIMaxFlows, cfg.NDPIFlowIdleSeconds, classifier.NDPIAvailable)
			cls = ndpiCls
		}
	case "port":
		log.Println("classifier: using stateless port-based classification")
		cls = classifier.NewPortClassifier()
	default:
		log.Printf("classifier: unknown mode %q, falling back to port-based", cfg.ClassificationMode)
		cls = classifier.NewPortClassifier()
	}

	// Initialize the capture engine.
	captureEngine, err := capture.New(cfg.Interface, cfg.SnapLen, cfg.Promisc, cfg.BPFFilter, agg, cls)
	if err != nil {
		log.Fatalf("capture: %v", err)
	}

	// Start capture in a goroutine.
	go captureEngine.Run()

	// Start the flusher if configured.
	var flush *flusher.Flusher
	if cfg.FlushFile != "" {
		flush = flusher.New(agg, cfg.FlushFile, cfg.FlushInterval)
		go flush.Run()
	}

	// How this collector reaches its controller: its own WebSocket (push),
	// an HTTP announce and being polled, or neither (no server_url).
	transport := cfg.EffectiveTransport()

	// Gateway stats: the router's own health, reported with the traffic
	// when the collector runs on the router (gateway_stats auto = OpenWrt).
	var gatewayStats func() *gateway.Stats
	if cfg.GatewayStatsEnabled(gateway.OnOpenWrt(hoststat.FS{})) {
		reader := gateway.Reader{WANInterfaces: cfg.WANInterfaces}
		gatewayStats = reader.Read
		if len(cfg.WANInterfaces) > 0 {
			log.Printf("gateway: reporting router stats; WAN interfaces %s (configured)", strings.Join(cfg.WANInterfaces, ","))
		} else {
			log.Printf("gateway: reporting router stats; WAN interfaces = those holding a default route (now: %s)", describeWAN(reader.Read()))
		}
	}

	// Build the announcer or the controller client (when the daemon has a
	// server) before the API server starts, so its status can be part of
	// every meta block without racing the first request. Either is only
	// *started* once the API is listening, further down: over HTTP the
	// server probes us back the moment an admin clicks Adopt.
	var (
		ann *announce.Announcer
		ctl *controller.Client
	)
	switch transport {
	case config.TransportWebSocket:
		ctl = buildController(cfg, agg, cls, gatewayStats)
	case config.TransportPoll:
		ann = buildAnnouncer(cfg)
	}

	// Start the HTTP API server. The protocol → category table is a
	// property of the classifier build, so it is exported once here.
	apiServer := api.New(cfg.Listen, agg, cfg.APIKey, cfg.Interface, version)
	if lister, ok := cls.(classifier.CategoryLister); ok {
		categories := lister.ProtocolCategories()
		apiServer.SetProtocolCategories(categories)
		log.Printf("classifier: exporting %d protocol categories at /api/v1/protocols", len(categories))
	}
	if gatewayStats != nil {
		apiServer.SetGatewayStats(gatewayStats)
	}
	switch {
	case ctl != nil:
		apiServer.SetTransport(config.TransportWebSocket)
		apiServer.SetAnnounceStatus(ctl.StatusString)
	case ann != nil:
		apiServer.SetAnnounceStatus(ann.StatusString)
	}
	go func() {
		if err := apiServer.ListenAndServe(); err != nil {
			// http.ErrServerClosed is expected on graceful shutdown.
			log.Printf("api: %v", err)
		}
	}()

	// The API is answering; introduce ourselves to the server.
	if ann != nil {
		go ann.Run()
	}
	ctlCtx, stopCtl := context.WithCancel(context.Background())
	ctlDone := make(chan struct{})
	if ctl != nil {
		go func() {
			ctl.Run(ctlCtx)
			close(ctlDone)
		}()
	} else {
		close(ctlDone)
	}

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("received signal %s, shutting down", sig)

	// Graceful shutdown in order.
	captureEngine.Stop()
	cls.Close()

	if flush != nil {
		flush.Stop()
	}

	if ann != nil {
		ann.Stop()
	}
	// Say goodbye (1001) so the controller knows this is a restart.
	stopCtl()
	select {
	case <-ctlDone:
	case <-time.After(6 * time.Second):
	}

	if err := apiServer.Shutdown(); err != nil {
		log.Printf("api shutdown: %v", err)
	}

	log.Println("perch-collector stopped")
}

// buildAnnouncer prepares the collector's self-announcement to a Perch
// controller over HTTP (transport poll), or returns nil when the daemon
// cannot say where it listens.
//
// Announcing is one-way: the server records an identity and the address the
// announce came from, and an administrator decides whether to poll it.
// Nothing here changes what is captured or served.
func buildAnnouncer(cfg config.Config) *announce.Announcer {
	// The API server is plain HTTP today, so the collector always announces
	// tls=false. The field exists because the server needs to know the
	// scheme to build the URL it polls.
	const apiUsesTLS = false

	port, baseURL, err := announce.SelfAddress(cfg.Listen, apiUsesTLS)
	if err != nil {
		log.Printf("announce: %v; not announcing to %s", err, cfg.ServerURL)
		return nil
	}
	instanceID := resolveInstanceID(cfg)
	if instanceID == "" {
		log.Printf("announce: no usable instance id; not announcing to %s", cfg.ServerURL)
		return nil
	}

	opts := announce.Options{
		ServerURL:        cfg.ServerURL,
		InstanceID:       instanceID,
		APIKey:           cfg.APIKey,
		SendAPIKey:       cfg.AnnounceAPIKey,
		Port:             port,
		TLS:              apiUsesTLS,
		BaseURL:          baseURL,
		Hostname:         hostname(),
		Version:          version,
		CaptureInterface: cfg.Interface,
		Interval:         time.Duration(cfg.AnnounceInterval) * time.Second,
		TLSInsecure:      cfg.AnnounceTLSInsecure,
	}
	if cfg.ServerCAFile != "" {
		client, err := link.NewHTTPClient(link.TLSOptions{Insecure: cfg.AnnounceTLSInsecure, CAFile: cfg.ServerCAFile})
		if err != nil {
			log.Fatalf("config: server_ca_file: %v", err)
		}
		client.Timeout = 10 * time.Second
		opts.Client = client
	}
	return announce.New(opts)
}

// buildController prepares the WebSocket client (transport websocket). The
// socket carries everything the controller would otherwise poll.
func buildController(cfg config.Config, agg *aggregator.Aggregator, cls classifier.Classifier, gatewayStats func() *gateway.Stats) *controller.Client {
	instanceID := resolveInstanceID(cfg)
	if instanceID == "" {
		log.Fatalf("controller: no usable instance id; cannot connect to %s", cfg.ServerURL)
	}
	source := controller.Source{
		Summary: agg.GetSummary,
		Devices: func() []aggregator.DeviceStats { return agg.Snapshot(time.Time{}) },
		Gateway: gatewayStats,
	}
	if lister, ok := cls.(classifier.CategoryLister); ok {
		categories := lister.ProtocolCategories()
		source.Protocols = func() []classifier.ProtocolCategory { return categories }
	}
	ctl, err := controller.New(controller.Options{
		ServerURL:        cfg.ServerURL,
		InstanceID:       instanceID,
		APIKey:           cfg.APIKey,
		SendAPIKey:       cfg.AnnounceAPIKey,
		Hostname:         hostname(),
		Version:          version,
		CaptureInterface: cfg.Interface,
		Listen:           cfg.Listen,
		TLS:              link.TLSOptions{Insecure: cfg.AnnounceTLSInsecure, CAFile: cfg.ServerCAFile},
		System:           controller.SystemInfo(hoststat.FS{}, runtime.GOARCH),
		Source:           source,
	})
	if err != nil {
		log.Fatalf("controller: %v", err)
	}
	return ctl
}

// resolveInstanceID is the identity the controller knows this collector
// by; "" only when nothing at all could be resolved.
func resolveInstanceID(cfg config.Config) string {
	path := cfg.InstanceIDPath()
	if path != cfg.InstanceIDFile {
		log.Printf("instance: reading the id from %s (the pre-rename location)", path)
	}
	id, err := announce.ResolveInstanceID(cfg.InstanceID, path, cfg.Interface)
	if err != nil {
		log.Printf("instance: %v", err)
	}
	return id
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		log.Printf("hostname unavailable: %v", err)
	}
	return h
}

// describeWAN renders the WAN interfaces of one gateway report for a log line.
func describeWAN(s *gateway.Stats) string {
	if s == nil || len(s.WAN) == 0 {
		return "none"
	}
	names := make([]string, len(s.WAN))
	for i, w := range s.WAN {
		names[i] = w.Name
	}
	return strings.Join(names, ",")
}

// resolveGatewayMACs returns the deduplicated set of MAC addresses to treat
// as upstream-gateway pivots. The list is the union of:
//   - every entry in cfg.GatewayMACs (already validated and canonicalised
//     in config.Validate)
//   - the auto-detected default-route gateway, ONLY if the config list is
//     empty (so an explicit YAML list never gets surprise extras)
//
// An empty result is acceptable: the aggregator then treats every packet as
// LAN-to-LAN, which is still useful for isolated-segment visibility.
func resolveGatewayMACs(cfg config.Config) []net.HardwareAddr {
	seen := make(map[string]struct{}, len(cfg.GatewayMACs)+1)
	out := make([]net.HardwareAddr, 0, len(cfg.GatewayMACs)+1)

	for _, s := range cfg.GatewayMACs {
		mac, err := net.ParseMAC(s)
		if err != nil {
			// Validate() already screened this; defence-in-depth.
			log.Fatalf("config: invalid gateway_macs entry %q: %v", s, err)
		}
		k := mac.String()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, mac)
		log.Printf("gateway: configured MAC %s", mac)
	}

	if len(out) == 0 {
		mac, err := netutil.DetectGatewayMAC(cfg.Interface)
		if err != nil {
			log.Printf("gateway: auto-detection failed on %s: %v", cfg.Interface, err)
			log.Println("gateway: continuing without WAN pivot; set gateway_macs in collector.yaml to enable per-device peer tracking")
			return nil
		}
		log.Printf("gateway: auto-detected MAC %s on %s", mac, cfg.Interface)
		out = append(out, mac)
	}
	return out
}

// resolveLocalSubnets merges the CIDRs assigned to the capture interface with
// any CIDRs the operator listed in collector.yaml.
func resolveLocalSubnets(cfg config.Config) []*net.IPNet {
	auto, err := netutil.InterfaceSubnets(cfg.Interface)
	if err != nil {
		log.Printf("subnets: could not enumerate addresses on %s: %v", cfg.Interface, err)
	}
	extra, err := netutil.ParseCIDRs(cfg.LocalSubnets)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	merged := netutil.MergeSubnets(auto, extra)
	if len(merged) == 0 {
		log.Println("subnets: no local CIDRs detected or configured; all IPs will be treated as local")
	} else {
		for _, n := range merged {
			log.Printf("subnets: local %s", n)
		}
	}
	return merged
}
