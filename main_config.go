package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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

// qosAllowed is the managed-mode gate of qos.* (gateway plan 3 section 6):
// the shaper takes orders only while the controller runs this gateway in
// managed mode (agent.configure), which needs the config plane.
func qosAllowed(plane *gwconfig.Plane) func() bool {
	return func() bool { return plane != nil && plane.Mode() == gwconfig.ModeManaged }
}

// configPlane builds the config plane when the collector runs on OpenWrt;
// nil elsewhere (a collector on a server has no UCI to offer).
func configPlane(cfg config.Config, captured func() map[string]string) *gwconfig.Plane {
	if !gateway.OnOpenWrt(hoststat.FS{}) {
		return nil
	}
	o := planeOptions(cfg)
	o.CapturedNetworks = captured
	p := gwconfig.New(o)
	switch {
	case p.Access() == gwconfig.AccessNone:
		log.Printf("config plane: config_access none: the controller cannot read this router's configuration")
	case p.Access() == gwconfig.AccessWrite && !cfg.ConfigTransportOK() && !cfg.ConfigAllowInsecure:
		log.Printf("config plane: config_access write: %s; writes need https with a verified certificate (or config_allow_insecure '1' and signed requests), until then read only", strings.Join(p.Allowed(), " "))
	case p.Access() == gwconfig.AccessWrite && !cfg.ConfigTransportOK():
		how := "config_sign_key"
		if cfg.ConfigSignKey == "" {
			how = "the key of a pairing with the controller (perch-collector pair status)"
		}
		log.Printf("config plane: config_access write over an unverified transport: %s; writes must be signed with %s", strings.Join(p.Allowed(), " "), how)
	default:
		log.Printf("config plane: config_access %s: %s", p.Access(), strings.Join(p.Allowed(), " "))
	}
	// A pending apply from before this start: resume its window, or restore.
	p.Start()
	// `perch-collector pair` talks to the daemon over a root-only socket.
	go func() {
		if err := p.ServePairSocket(context.Background()); err != nil {
			log.Printf("config plane: pairing socket: %v (perch-collector pair confirm will not work)", err)
		}
	}()
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
		SiblingsOff:    !cfg.ManagedConfigAuto,
		SiblingExclude: cfg.ManagedConfigExclude,
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
	if os.Getenv(config.EnvPrefix+"MANAGED_CONFIG_AUTO") == "" {
		if v, ok := s.Get("managed_config_auto"); ok {
			cfg.ManagedConfigAuto = v.Str() != "0"
		}
	}
	if os.Getenv(config.EnvPrefix+"MANAGED_CONFIG_EXCLUDE") == "" {
		if v, ok := s.Get("managed_config_exclude"); ok {
			cfg.ManagedConfigExclude = v.Items
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

const pairUsage = `usage: perch-collector pair <command>

Pairing gives a router that takes config writes over plain HTTP
(config_allow_insecure '1') a signing key shared with the controller only;
the api_key never signs. The controller starts it (Gateway → Pair); both
ends then show the same 6-digit code, which is also written to the system
log (logread | grep PAIRING).

  status          what is pending (with its code) and the paired key
  confirm <code>  accept the pairing whose code this is: the controller's
                  signed writes are verified with the new key from now on
  reject          refuse the pairing in progress
  forget          drop the paired key (signed writes are refused until
                  the next pairing); works without the daemon too

Root only. status takes -json.
`

// pairCommand is ` + "`perch-collector pair`" + `.
func pairCommand(args []string, stdout, stderr io.Writer, root string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, pairUsage)
		return 2
	}
	sock := filepath.Join(root, gwconfig.PairSocket)
	if root == "" {
		sock = gwconfig.PairSocket
	}
	call := func(req gwconfig.PairRequest) (*gwconfig.PairResponse, int) {
		res, err := gwconfig.PairCall(sock, req)
		if err != nil {
			fmt.Fprintf(stderr, "perch-collector pair %s: %v\n", req.Cmd, err)
			return nil, 1
		}
		return res, 0
	}
	switch cmd := args[0]; cmd {
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, pairUsage)
		return 0
	case "status":
		asJSON := false
		for _, a := range args[1:] {
			if a != "-json" && a != "--json" {
				fmt.Fprintf(stderr, "unexpected argument %q\n\n%s", a, pairUsage)
				return 2
			}
			asJSON = true
		}
		res, err := gwconfig.PairCall(sock, gwconfig.PairRequest{Cmd: "status"})
		var st *gwconfig.PairLocal
		daemon := true
		switch {
		case err == nil && res.OK:
			st = res.Status
		case errors.Is(err, gwconfig.ErrNoDaemon):
			daemon = false
			info, ferr := gwconfig.ReadPairingFile(root)
			if ferr != nil {
				fmt.Fprintf(stderr, "perch-collector pair status: %v\n", ferr)
				return 1
			}
			st = &gwconfig.PairLocal{Paired: info}
		case err != nil:
			fmt.Fprintf(stderr, "perch-collector pair status: %v\n", err)
			return 1
		default:
			fmt.Fprintf(stderr, "perch-collector pair status: %s\n", res.Error)
			return 1
		}
		if asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			enc.Encode(st)
			return 0
		}
		printPairStatus(stdout, st, daemon, time.Now())
		return 0
	case "confirm":
		if len(args) < 2 {
			fmt.Fprintf(stderr, "perch-collector pair confirm: the 6-digit code is missing\n\n%s", pairUsage)
			return 2
		}
		res, rc := call(gwconfig.PairRequest{Cmd: "confirm", Code: strings.Join(args[1:], "")})
		if res == nil {
			return rc
		}
		if !res.OK {
			fmt.Fprintf(stderr, "perch-collector pair confirm: %s\n", res.Error)
			return 1
		}
		fmt.Fprintf(stdout, "paired: key %s (gateway %d). Signed config writes from this controller are accepted from now on.\n", res.Paired.KeyID, res.Paired.GatewayID)
		fmt.Fprintln(stdout, "If the dashboard still waits, type this router's code there.")
		return 0
	case "reject":
		res, rc := call(gwconfig.PairRequest{Cmd: "reject"})
		if res == nil {
			return rc
		}
		if !res.OK {
			fmt.Fprintf(stderr, "perch-collector pair reject: %s\n", res.Error)
			return 1
		}
		fmt.Fprintln(stdout, "pairing rejected")
		return 0
	case "forget":
		res, err := gwconfig.PairCall(sock, gwconfig.PairRequest{Cmd: "forget"})
		if errors.Is(err, gwconfig.ErrNoDaemon) {
			info, ferr := gwconfig.ForgetPairingFile(root)
			if ferr != nil {
				fmt.Fprintf(stderr, "perch-collector pair forget: %v\n", ferr)
				return 1
			}
			if info == nil {
				fmt.Fprintln(stdout, "not paired: nothing to forget")
				return 0
			}
			fmt.Fprintf(stdout, "forgot key %s (the daemon is not running)\n", info.KeyID)
			return 0
		}
		if err != nil {
			fmt.Fprintf(stderr, "perch-collector pair forget: %v\n", err)
			return 1
		}
		if !res.OK {
			if res.Error == gwconfig.ErrNothingToForget.Error() {
				fmt.Fprintln(stdout, "not paired: nothing to forget")
				return 0
			}
			fmt.Fprintf(stderr, "perch-collector pair forget: %s\n", res.Error)
			return 1
		}
		fmt.Fprintf(stdout, "forgot key %s; the controller sees the router unpaired at its next connection (now)\n", res.Paired.KeyID)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, pairUsage)
		return 2
	}
}

func printPairStatus(w io.Writer, st *gwconfig.PairLocal, daemon bool, now time.Time) {
	if !daemon {
		fmt.Fprintln(w, "(the daemon is not running: only the stored key is shown)")
	}
	if st.SignKey {
		fmt.Fprintln(w, "config_sign_key is set: it signs config writes, pairing is off")
	}
	if p := st.Pending; p != nil {
		left := p.Expires.Sub(now).Round(time.Second)
		switch p.State {
		case gwconfig.PairWaitingLocal:
			fmt.Fprintf(w, "pairing %s waits for your confirmation\n", p.PairingID)
			fmt.Fprintf(w, "  code:        %s\n", p.Code)
			fmt.Fprintf(w, "  controller:  %s (gateway %d)\n", p.Server, p.GatewayID)
			fmt.Fprintf(w, "  expires in:  %s (%d attempt(s) left)\n", left, p.Attempts)
			fmt.Fprintf(w, "If the Perch dashboard shows the same code: perch-collector pair confirm %s\n", p.Code)
			fmt.Fprintln(w, "If you did not start a pairing: perch-collector pair reject")
		default:
			fmt.Fprintf(w, "pairing %s begun by %s, waiting for the controller (expires in %s)\n", p.PairingID, p.Server, left)
		}
	}
	if k := st.Paired; k != nil {
		fmt.Fprintf(w, "paired: key %s, gateway %d", k.KeyID, k.GatewayID)
		if k.Server != "" {
			fmt.Fprintf(w, ", controller %s", k.Server)
		}
		if !k.PairedAt.IsZero() {
			fmt.Fprintf(w, ", since %s", k.PairedAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintln(w)
	} else if st.Pending == nil {
		fmt.Fprintln(w, "not paired")
	}
	if l := st.Last; l != nil && st.Pending == nil && (st.Paired == nil || st.Paired.PairingID != l.PairingID) {
		fmt.Fprintf(w, "last pairing %s: %s\n", l.PairingID, l.State)
	}
}
