package main

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/capthndsme/perch-agentkit/hoststat"

	"github.com/capthndsme/perch-collector/internal/aggregator"
	"github.com/capthndsme/perch-collector/internal/capture"
	"github.com/capthndsme/perch-collector/internal/classifier"
	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/gateway"
	"github.com/capthndsme/perch-collector/internal/netcap"
	"github.com/capthndsme/perch-collector/internal/netutil"
	"github.com/capthndsme/perch-collector/internal/observe"
)

// ndpiFlowsFloor is the smallest nDPI flow table an engine gets when
// ndpi_max_flows is split across several captures.
const ndpiFlowsFloor = 4096

// captureSet is what main runs for capture: one engine on the single
// interface (the original mode) or a reconciler keeping one engine per
// LAN-side network (capture_networks).
type captureSet struct {
	// single is the engine of the single-interface mode.
	single *capture.Engine
	// reconciler runs the engines of the multi-capture mode.
	reconciler *netcap.Reconciler
	// reporter builds gateway.networks; nil when the host has no netifd.
	reporter *netcap.Reporter
	// categories is the classifier's protocol → category table (nDPI).
	categories []classifier.ProtocolCategory
	// singleCls is the single engine's classifier.
	singleCls classifier.Classifier

	cancel context.CancelFunc
	done   chan struct{}
	kick   chan struct{}
}

// newClassifier builds one classifier for the configured mode; flows is
// this engine's nDPI flow table. quiet skips the fallback log line (it was
// said once already).
func newClassifier(cfg config.Config, flows int, quiet bool) classifier.Classifier {
	switch cfg.ClassificationMode {
	case "ndpi":
		classifier.SetNDPIPartialExtraPackets(cfg.NDPIPartialExtraPackets)
		c, err := classifier.NewNDPIClassifier(flows, cfg.NDPIFlowIdleSeconds)
		if err != nil {
			if !quiet {
				log.Printf("classifier: nDPI requested but unavailable (%v); falling back to port-based", err)
			}
			return classifier.NewPortClassifier()
		}
		return c
	case "port":
		return classifier.NewPortClassifier()
	}
	if !quiet {
		log.Printf("classifier: unknown mode %q, falling back to port-based", cfg.ClassificationMode)
	}
	return classifier.NewPortClassifier()
}

// flowsPerEngine splits ndpi_max_flows across n engines, at least
// ndpiFlowsFloor each (never more than the configured total).
func flowsPerEngine(total, n int) int {
	if n < 1 {
		n = 1
	}
	per := total / n
	if per < ndpiFlowsFloor {
		per = ndpiFlowsFloor
	}
	if per > total {
		per = total
	}
	return per
}

// engineWithClassifier stops its classifier with the capture.
type engineWithClassifier struct {
	*capture.Engine
	cls classifier.Classifier
}

func (e engineWithClassifier) Stop() {
	e.Engine.Stop()
	e.cls.Close()
}

// startCapture sets up and starts the capture. agg is built already; the
// gateway MACs and local subnets main resolved are the configured ones (and
// in single mode the detected ones).
func startCapture(cfg config.Config, agg *aggregator.Aggregator, configuredMACs []net.HardwareAddr, configuredSubnets []*net.IPNet) *captureSet {
	cs := &captureSet{done: make(chan struct{}), kick: make(chan struct{}, 1)}
	env := &observe.Env{}
	disc := &netcap.Discoverer{Env: env}
	sel := netcap.Selection{Networks: cfg.CaptureNetworks, Exclude: cfg.CaptureExclude, WAN: cfg.WANInterfaces}
	sys := netcap.SysFS{}
	scope := func() string {
		if agg.RoutedLAN() {
			return "routed"
		}
		return "legacy"
	}

	if !cfg.MultiCapture() {
		// The original mode: one engine on cfg.Interface, the gateway MACs
		// and subnets as resolved. The frames carry the interface's network
		// when netifd knows it.
		network := ""
		d := disc.Discover(true)
		var plan netcap.Plan
		if d.Netifd {
			plan = netcap.MakePlan(d, sel, sys)
			network = netcap.NetworkOfDevice(cfg.Interface, plan.LAN)
		}
		if cfg.RoutedLANEnabled() {
			prefixes := configuredSubnets
			if d.Netifd {
				prefixes = netutil.MergeSubnets(plan.LANPrefixes, configuredSubnets)
			}
			agg.SetRoutedLAN(true, prefixes)
			log.Printf("scope: routed_lan on: traffic between local networks and to the router's LAN addresses counts as LAN")
		}
		cls := newClassifier(cfg, cfg.NDPIMaxFlows, false)
		logClassifier(cfg, cls, cfg.NDPIMaxFlows)
		cs.singleCls = cls
		if lister, ok := cls.(classifier.CategoryLister); ok {
			cs.categories = lister.ProtocolCategories()
		}
		e, err := capture.NewForNetwork(cfg.Interface, network, cfg.SnapLen, cfg.Promisc, cfg.BPFFilter, agg, cls)
		if err != nil {
			log.Fatalf("capture: %v", err)
		}
		cs.single = e
		go e.Run()
		if d.Netifd {
			label := network
			if label == "" {
				label = cfg.Interface
			}
			cs.reporter = &netcap.Reporter{
				Discover: func() netcap.Discovery { return disc.Discover(false) }, Selection: sel, Sys: sys,
				Captured: func() map[string]string { return map[string]string{cfg.Interface: label} },
				Agg:      agg, Scope: scope,
			}
		}
		close(cs.done)
		return cs
	}

	// Multi-capture.
	log.Printf("capture: networks %s%s, rescanned every %ds and on SIGHUP",
		strings.Join(cfg.CaptureNetworks, ","), excludeNote(cfg.CaptureExclude), cfg.CaptureRescan)
	routed := cfg.RoutedLANEnabled()
	if routed {
		log.Printf("scope: routed_lan on: traffic between local networks and to the router's LAN addresses counts as LAN")
	} else {
		log.Printf("scope: routed_lan off: everything through the router counts as WAN")
	}
	// The category table is a property of the classifier build: read it
	// once from a classifier of its own.
	probe := newClassifier(cfg, ndpiFlowsFloor, false)
	if lister, ok := probe.(classifier.CategoryLister); ok {
		cs.categories = lister.ProtocolCategories()
	}
	_, ndpiOn := probe.(*classifier.NDPIClassifier)
	probe.Close()

	var applyMu sync.Mutex
	lastApplied := ""
	cs.reconciler = &netcap.Reconciler{
		Discover:  func() netcap.Discovery { return disc.Discover(true) },
		Selection: sel,
		Sys:       sys,
		Apply: func(p netcap.Plan) {
			macs := append(append([]net.HardwareAddr{}, configuredMACs...), p.GatewayMACs...)
			subnets := netutil.MergeSubnets(p.LANPrefixes, configuredSubnets)
			agg.SetGatewayMACs(macs)
			agg.SetLocalSubnets(subnets)
			agg.SetRoutedLAN(routed, subnets)
			applyMu.Lock()
			defer applyMu.Unlock()
			var names, nets []string
			for _, m := range agg.GatewayMACs() {
				names = append(names, m)
			}
			for _, n := range subnets {
				nets = append(nets, n.String())
			}
			key := strings.Join(names, ",") + "|" + strings.Join(nets, ",")
			if key != lastApplied {
				lastApplied = key
				log.Printf("capture: router MACs %s; local %s", strings.Join(names, ","), strings.Join(nets, ","))
			}
		},
		Open: func(t netcap.Target, n int) (netcap.Engine, error) {
			flows := flowsPerEngine(cfg.NDPIMaxFlows, n)
			cls := newClassifier(cfg, flows, true)
			e, err := capture.NewForNetwork(t.Device, t.Network, cfg.SnapLen, cfg.Promisc, cfg.BPFFilter, agg, cls)
			if err != nil {
				cls.Close()
				return nil, err
			}
			if ndpiOn {
				log.Printf("classifier: %s gets its own nDPI engine (max_flows=%d)", t.Device, flows)
			}
			return engineWithClassifier{Engine: e, cls: cls}, nil
		},
	}
	cs.reconciler.Reconcile()
	if len(cs.reconciler.Captured()) == 0 {
		log.Printf("capture: nothing to capture yet (%s); trying again every %ds", cfg.CaptureNetworks, cfg.CaptureRescan)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cs.cancel = cancel
	go func() {
		defer close(cs.done)
		cs.reconciler.Run(ctx, time.Duration(cfg.CaptureRescan)*time.Second, cs.kick)
	}()
	if d := disc.Discover(false); d.Netifd {
		cs.reporter = &netcap.Reporter{
			Discover: func() netcap.Discovery { return disc.Discover(false) }, Selection: sel, Sys: sys,
			Captured: cs.reconciler.Captured, Agg: agg, Scope: scope, FS: hoststat.FS{},
		}
	}
	return cs
}

func excludeNote(ex []string) string {
	if len(ex) == 0 {
		return ""
	}
	return " except " + strings.Join(ex, ",")
}

func logClassifier(cfg config.Config, cls classifier.Classifier, flows int) {
	switch cls.(type) {
	case *classifier.NDPIClassifier:
		log.Printf("classifier: using nDPI (max_flows=%d idle=%ds, NDPIAvailable=%v)", flows, cfg.NDPIFlowIdleSeconds, classifier.NDPIAvailable)
	default:
		if cfg.ClassificationMode == "port" {
			log.Println("classifier: using stateless port-based classification")
		}
	}
}

// Rescan asks the reconciler to re-read the router now (SIGHUP).
func (cs *captureSet) Rescan() {
	if cs.reconciler == nil {
		log.Printf("SIGHUP: single-interface capture, nothing to rescan")
		return
	}
	select {
	case cs.kick <- struct{}{}:
	default:
	}
}

// CaptureInterface is what the collector says it captures on: the
// interface, or the captured devices (at most 64 characters, the
// controller's limit).
func (cs *captureSet) CaptureInterface(single string) func() string {
	if cs.reconciler == nil {
		return func() string { return single }
	}
	return func() string { return netcap.FitInterfaceList(cs.reconciler.Devices(), 64) }
}

// Networks is the gateway report's networks part; nil without netifd.
func (cs *captureSet) Networks() func() *[]gateway.Network {
	if cs.reporter == nil {
		return nil
	}
	return cs.reporter.Read
}

// Stop stops every engine and classifier.
func (cs *captureSet) Stop() {
	if cs.single != nil {
		cs.single.Stop()
		cs.singleCls.Close()
		return
	}
	cs.cancel()
	select {
	case <-cs.done:
	case <-time.After(5 * time.Second):
	}
}
