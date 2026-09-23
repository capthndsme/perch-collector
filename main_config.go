package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/capthndsme/perch-agentkit/hoststat"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"

	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/gateway"
	"github.com/capthndsme/perch-collector/internal/gwconfig"
)

// The config plane (internal/gwconfig): built for the WebSocket transport on
// OpenWrt, and poked by SIGHUP, which the init script's reload_service sends
// when procd sees a committed change to an allowlisted config.

var (
	planeMu     sync.Mutex
	activePlane *gwconfig.Plane
)

// configPlane builds the config plane when the collector runs on OpenWrt;
// nil elsewhere (a collector on a server has no UCI to offer).
func configPlane(cfg config.Config) *gwconfig.Plane {
	if !gateway.OnOpenWrt(hoststat.FS{}) {
		return nil
	}
	p := gwconfig.New(gwconfig.Options{
		Access:         cfg.ConfigAccess,
		Allowlist:      cfg.ManagedConfigs,
		AllowInsecure:  cfg.ConfigAllowInsecure,
		ConfirmMax:     cfg.ConfigConfirmMax,
		TransportOK:    cfg.ConfigTransportOK(),
		APIKey:         cfg.APIKey,
		StoragePath:    cfg.StoragePath,
		CaptureNetwork: cfg.CaptureNetwork,
		CaptureDevice:  cfg.Interface,
	})
	switch {
	case p.Access() == gwconfig.AccessNone:
		log.Printf("config plane: config_access none: the controller cannot read this router's configuration")
	case p.ConfiguredAccess() != p.Access():
		log.Printf("config plane: config_access %s configured; this version reads only (%s)", p.ConfiguredAccess(), strings.Join(p.Allowed(), " "))
	default:
		log.Printf("config plane: config_access %s: %s", p.Access(), strings.Join(p.Allowed(), " "))
	}
	planeMu.Lock()
	activePlane = p
	planeMu.Unlock()
	return p
}

// watchReloadSignal handles SIGHUP for the lifetime of the daemon: the
// config plane re-hashes now. Without a plane it is ignored (it used to end
// the daemon, and procd would have restarted it).
func watchReloadSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			planeMu.Lock()
			p := activePlane
			planeMu.Unlock()
			if p != nil {
				p.Trigger()
			}
		}
	}()
}

const gatewayConfigUsage = `usage: perch-collector gateway-config [config...]

Prints what the config plane would give the controller, as JSON, and exits:
gateway.capabilities, then gateway.config.read of the named configs (default:
every readable one). Settings come from /etc/config/perch-collector
(config_access, managed_config, api_key for the secret fingerprints,
storage_path), PERCH_COLLECTOR_* variables win; config_access none reads
nothing. No capture, no listener, no network, nothing written.
`

// gatewayConfigCommand is `perch-collector gateway-config`, for a read-only
// look at what a router offers.
func gatewayConfigCommand(args []string, stdout, stderr io.Writer, load func() (config.Config, error)) int {
	for _, a := range args {
		switch a {
		case "-h", "-help", "--help", "help":
			fmt.Fprint(stdout, gatewayConfigUsage)
			return 0
		}
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(stderr, "unexpected flag %q\n\n%s", a, gatewayConfigUsage)
			return 2
		}
	}
	cfg, err := load()
	if err != nil {
		fmt.Fprintf(stderr, "perch-collector gateway-config: %v\n", err)
		return 1
	}
	p := gwconfig.New(gwconfig.Options{
		Access: cfg.ConfigAccess, Allowlist: cfg.ManagedConfigs, AllowInsecure: cfg.ConfigAllowInsecure,
		ConfirmMax: cfg.ConfigConfirmMax, TransportOK: cfg.ConfigTransportOK(), APIKey: cfg.APIKey,
		StoragePath: cfg.StoragePath, CaptureNetwork: cfg.CaptureNetwork, CaptureDevice: cfg.Interface,
	})
	out := map[string]any{"capabilities": p.Capabilities(context.Background())}
	if read, err := p.Read(args); err != nil {
		out["readError"] = err.Error()
	} else {
		out["read"] = read
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "perch-collector gateway-config: %v\n", err)
		return 1
	}
	return 0
}

// routerConfig is the configuration the subcommand works with: defaults and
// PERCH_COLLECTOR_* variables, then, for what the environment does not set,
// the options of /etc/config/perch-collector (the daemon gets those from the
// init script as environment; a shell does not).
func routerConfig() (config.Config, error) {
	cfg, err := config.LoadEnv()
	if err != nil {
		return cfg, err
	}
	l, err := uci.Files{}.Load("perch-collector")
	if err != nil {
		return cfg, nil // not on OpenWrt, or no package config: env only
	}
	s := l.Config.Section("main")
	if s == nil {
		return cfg, nil
	}
	str := func(env, option string, dst *string) {
		if os.Getenv(config.EnvPrefix+env) != "" {
			return
		}
		if v, ok := s.Get(option); ok && v.Str() != "" {
			*dst = v.Str()
		}
	}
	str("CONFIG_ACCESS", "config_access", &cfg.ConfigAccess)
	str("API_KEY", "api_key", &cfg.APIKey)
	str("STORAGE_PATH", "storage_path", &cfg.StoragePath)
	str("CAPTURE_NETWORK", "capture_network", &cfg.CaptureNetwork)
	str("SERVER_URL", "server_url", &cfg.ServerURL)
	if os.Getenv(config.EnvPrefix+"MANAGED_CONFIGS") == "" {
		if v, ok := s.Get("managed_config"); ok {
			cfg.ManagedConfigs = v.Items
		}
	}
	if os.Getenv(config.EnvPrefix+"CONFIG_ALLOW_INSECURE") == "" {
		if v, ok := s.Get("config_allow_insecure"); ok {
			cfg.ConfigAllowInsecure = v.Str() == "1"
		}
	}
	if os.Getenv(config.EnvPrefix+"ANNOUNCE_TLS_INSECURE") == "" {
		if v, ok := s.Get("announce_tls_insecure"); ok {
			cfg.AnnounceTLSInsecure = v.Str() == "1"
		}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}
