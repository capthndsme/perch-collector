package gatewayops

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// DDNS update now (gateway.ddns.update, gateway-sync protocol 6.2): a
// runtime action, not config. It starts the service's updater the way
// ddns-scripts starts one section (its init script and hotplug run exactly
// this for every section): `dynamic_dns_updater.sh -v 0 -S <service> --
// start`, detached with `start-stop-daemon -b`. The updater stops the
// section's running instance itself, checks the registered address at once
// and sends an update when it differs from the current one (or the force
// interval passed); the outcome shows in the ddns observation (lastUpdate,
// registeredIp, lastError). Verified against ddns-scripts' sources of the
// 23.05 and 24.10 branches (same flags and file names in both).

// DDNSUpdaterScript is ddns-scripts' per-section updater.
const DDNSUpdaterScript = "/usr/lib/ddns/dynamic_dns_updater.sh"

// DDNSUpdateParams are gateway.ddns.update's params.
type DDNSUpdateParams struct {
	Service string `json:"service"`
}

// DDNSUpdateResult is gateway.ddns.update's result.
type DDNSUpdateResult struct {
	Started bool `json:"started"`
}

// DDNS starts ddns-scripts updaters.
type DDNS struct {
	// Root prefixes every path ("" = /; tests).
	Root string
	// Run runs start-stop-daemon; nil = ubus.ExecRunner.
	Run ubus.Runner
}

// Installed reports whether ddns-scripts is installed.
func (d *DDNS) Installed() bool {
	_, err := os.Stat(rootPath(d.Root, DDNSUpdaterScript))
	return err == nil
}

// Update starts the updater of one service section.
func (d *DDNS) Update(ctx context.Context, p DDNSUpdateParams) (*DDNSUpdateResult, error) {
	name := strings.TrimSpace(p.Service)
	if !uci.ValidName(name) || len(name) > uci.MaxNameLen {
		return nil, &ParamError{"bad_params", fmt.Sprintf("service: invalid section name %q", p.Service)}
	}
	if !d.Installed() {
		return nil, &ActionError{Code: "ddns_not_installed", Message: "ddns-scripts is not installed on this router"}
	}
	known := false
	if l, err := (uci.Files{Dir: rootPath(d.Root, uci.DefaultDir)}).Load("ddns"); err == nil {
		if s := l.Config.Section(name); s != nil && s.Type == "service" {
			known = true
		}
	}
	if !known {
		return nil, &ActionError{Code: "ddns_unknown_service", Message: fmt.Sprintf("no DDNS service %q in /etc/config/ddns", name)}
	}
	run := d.Run
	if run == nil {
		run = ubus.ExecRunner
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// -x never matches a running updater (a script's process is the shell),
	// so this always starts one; the updater replaces the section's old one.
	_, stderr, code, err := run(cctx, "start-stop-daemon", "-S", "-b", "-x", rootPath(d.Root, DDNSUpdaterScript),
		"--", "-v", "0", "-S", name, "--", "start")
	if err != nil || code != 0 {
		detail := strings.TrimSpace(string(stderr))
		if err != nil {
			detail = err.Error()
		} else if detail == "" {
			detail = fmt.Sprintf("exit status %d", code)
		}
		return nil, &ActionError{Code: "ddns_failed", Message: "starting the DDNS updater failed", Detail: detail}
	}
	return &DDNSUpdateResult{Started: true}, nil
}
