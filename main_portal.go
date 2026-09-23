package main

import (
	"context"
	"log"
	"time"

	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/gatewayops"
	"github.com/capthndsme/perch-collector/internal/portal"
)

// guestPortal is the running guest portal: the engine (enforcement, grant
// store, tick, portal.* RPCs) and the guest pages.
type guestPortal struct {
	engine *portal.Engine
	fas    *portal.FAS
	cancel context.CancelFunc
	done   chan struct{}
}

// buildPortal starts the guest portal when it is on (portal auto = OpenWrt
// with the WebSocket transport). Persisted portals and grants are
// re-applied at once, before the controller is reached: guests keep their
// access through a collector restart or a router reboot, with no DHCP
// lease needed. With portal off, enforcement a previous run left is removed.
func buildPortal(cfg config.Config, onOpenWrt bool, transport string) *guestPortal {
	if !cfg.PortalEnabled(onOpenWrt, transport == config.TransportWebSocket) {
		if cfg.Portal == config.GatewayStatsOff {
			removePortalLeftovers()
		}
		return nil
	}
	if transport != config.TransportWebSocket {
		log.Printf("portal: on, but the portal is configured over the WebSocket transport; nothing to enforce until it is used")
	}
	storageCfg := portal.StorageConfig{Path: cfg.PortalStoragePath, FlushSeconds: cfg.PortalFlushInterval, ExpectMount: cfg.PortalStorageMount}
	info := portal.ResolveStorage(storageCfg, portal.ReadMounts(), portal.PathExists, 5)
	if info.Warning != "" {
		log.Printf("portal: %s", info.Warning)
	}
	store, warning, err := portal.OpenStore(info.Path)
	if err != nil {
		log.Printf("portal: not offered: %v", err)
		return nil
	}
	if warning != "" {
		log.Printf("portal: %s", warning)
	}
	sys := &portal.HostSystem{Flusher: &gatewayops.Flusher{}}
	engine, err := portal.New(portal.Options{
		System: sys, Store: store, Storage: info, StorageConfig: storageCfg, Port: cfg.PortalPort,
		Leases: portal.LeaseHostnames("/tmp/dhcp.leases"),
	})
	if err != nil {
		log.Printf("portal: not offered: %v", err)
		store.Close()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	engine.Probe(ctx)
	gp := &guestPortal{engine: engine, cancel: cancel, done: make(chan struct{})}
	// The guest pages listen only on the portal networks' router
	// addresses, and only while a portal runs there.
	gp.fas = portal.NewFAS(engine, cfg.PortalPort, nil)
	engine.SetListener(gp.fas.Sync)
	engine.Start(ctx)
	h := engine.Hello()
	log.Printf("portal: offered (guest pages on port %d of the portal networks' addresses; nft %v, egress counters %v, kernel quota cut %v, fw4 drop-in %s, dnsmasq nftset %v; state %s on %s, counters every %ds)",
		cfg.PortalPort, h.Enforcement.Nft, h.Enforcement.Egress, h.Enforcement.Quota, h.Enforcement.Fw4Include, h.Enforcement.Nftset,
		info.Path, info.Kind, info.FlushSeconds)
	go func() {
		engine.Run(ctx)
		close(gp.done)
	}()
	return gp
}

// stop ends the pages and the tick and snapshots the state. The nft tables
// stay: guests keep their access while the collector restarts.
func (gp *guestPortal) stop() {
	if gp == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = gp.fas.Shutdown(ctx)
	cancel()
	gp.cancel()
	select {
	case <-gp.done:
	case <-time.After(3 * time.Second):
	}
}

// removePortalLeftovers takes the enforcement down when the portal is off.
func removePortalLeftovers() {
	sys := &portal.HostSystem{}
	if _, err := sys.ListJSON("table", "inet", portal.TableInet); err == nil {
		if err := sys.Apply(portal.RenderDeleteAll()); err != nil {
			log.Printf("portal: off, but the old enforcement could not be removed: %v", err)
		} else {
			log.Printf("portal: off; removed the enforcement tables a previous run left")
		}
	}
	if removed, _ := sys.RemoveFile(portal.Fw4IncludePath); removed {
		_, _ = sys.Command(context.Background(), "fw4", "-q", "reload")
	}
	for _, dir := range portal.DnsmasqConfDirs() {
		if removed, _ := sys.RemoveFile(dir + "/" + portal.DnsmasqConfName); removed {
			_, _ = sys.Command(context.Background(), "/etc/init.d/dnsmasq", "restart")
		}
	}
}
