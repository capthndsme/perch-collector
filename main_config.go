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
	"time"

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
	p := gwconfig.New(planeOptions(cfg))
	switch {
	case p.Access() == gwconfig.AccessNone:
		log.Printf("config plane: config_access none: the controller cannot read this router's configuration")
	case p.Access() == gwconfig.AccessWrite && !cfg.ConfigTransportOK() && !cfg.ConfigAllowInsecure:
		log.Printf("config plane: config_access write: %s; writes need https with a verified certificate (or config_allow_insecure '1' and signed requests), until then read only", strings.Join(p.Allowed(), " "))
	case p.Access() == gwconfig.AccessWrite && !cfg.ConfigTransportOK():
		log.Printf("config plane: config_access write over an unverified transport: %s; writes must be signed (%s)", strings.Join(p.Allowed(), " "), map[bool]string{true: "config_sign_key", false: "api_key"}[cfg.ConfigSignKey != ""])
	default:
		log.Printf("config plane: config_access %s: %s", p.Access(), strings.Join(p.Allowed(), " "))
	}
	// A pending apply from before this start: resume its window, or restore.
	p.Start()
	planeMu.Lock()
	activePlane = p
	planeMu.Unlock()
	return p
}

// planeOptions maps the daemon's settings onto the plane's.
func planeOptions(cfg config.Config) gwconfig.Options {
	return gwconfig.Options{
		Access:         cfg.ConfigAccess,
		Allowlist:      cfg.ManagedConfigs,
		AllowInsecure:  cfg.ConfigAllowInsecure,
		ConfirmMax:     cfg.ConfigConfirmMax,
		TransportOK:    cfg.ConfigTransportOK(),
		APIKey:         cfg.APIKey,
		SignKey:        cfg.ConfigSignKey,
		ServerURL:      cfg.ServerURL,
		PackageAllow:   cfg.PackageAllow,
		StoragePath:    cfg.StoragePath,
		CaptureNetwork: cfg.CaptureNetwork,
		CaptureDevice:  cfg.Interface,
	}
}

const configGuardUsage = `usage: perch-collector config-guard

The boot guard of the config plane (init script perch-collector-guard, run
before the network comes up): when a config apply was waiting for the
controller's confirm and the router rebooted, restore the configs it changed
from the snapshot in /etc/perch-collector/rollback. Nothing is reloaded (the
services start afterwards). The outcome waits there for the controller. Does
nothing when no apply is pending, or when the daemon owns it (no reboot).
Always exits 0 unless it cannot read its state.
`

// configGuardCommand is `perch-collector config-guard`.
func configGuardCommand(args []string, stdout, stderr io.Writer, root string, apiKey func() string) int {
	for _, a := range args {
		switch a {
		case "-h", "-help", "--help", "help":
			fmt.Fprint(stdout, configGuardUsage)
			return 0
		}
		fmt.Fprintf(stderr, "unexpected argument %q\n\n%s", a, configGuardUsage)
		return 2
	}
	res, err := gwconfig.Guard(root, nil, time.Now(), uci.Redactor{Key: []byte(apiKey())})
	if err != nil {
		fmt.Fprintf(stderr, "perch-collector config-guard: %v\n", err)
		return 1
	}
	if res == nil {
		fmt.Fprintln(stdout, "perch-collector config-guard: no pending apply")
		return 0
	}
	fmt.Fprintf(stdout, "perch-collector config-guard: apply %s was pending at the reboot: %s", res.ApplyID, res.Outcome)
	if res.Detail != "" {
		fmt.Fprintf(stdout, " (%s)", res.Detail)
	}
	fmt.Fprintln(stdout)
	return 0
}

// guardAPIKey is the api_key for the guard's fingerprints of discarded
// router edits: from the environment or the package config; "" is fine.
func guardAPIKey() string {
	if k := os.Getenv(config.EnvPrefix + "API_KEY"); k != "" {
		return k
	}
	if l, err := (uci.Files{}).Load("perch-collector"); err == nil {
		if s := l.Config.Section("main"); s != nil {
			if v, ok := s.Get("api_key"); ok {
				return v.Str()
			}
		}
	}
	return ""
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
	p := gwconfig.New(planeOptions(cfg))
	out := map[string]any{"capabilities": p.Capabilities(context.Background(), "")}
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
	str("CONFIG_SIGN_KEY", "config_sign_key", &cfg.ConfigSignKey)
	if os.Getenv(config.EnvPrefix+"PACKAGE_ALLOW") == "" {
		if v, ok := s.Get("package_allow"); ok {
			cfg.PackageAllow = v.Items
		}
	}
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
