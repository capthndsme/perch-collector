package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/capthndsme/perch-agentkit/hoststat"

	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/controller"
	"github.com/capthndsme/perch-collector/internal/gatewayops"
	"github.com/capthndsme/perch-collector/internal/observe"
	"github.com/capthndsme/perch-collector/internal/portal"
)

// gatewayFeatures are the managed gateway's observation and runtime
// actions, each nil when off.
type gatewayFeatures struct {
	observer  *observe.Observer
	conntrack *gatewayops.Flusher
	backup    *gatewayops.Backuper
	// portal is the guest portal (main_portal.go), nil when off.
	portal *portal.Engine
}

// buildGatewayFeatures resolves observe, dhcp_leases, conntrack_flush and
// gateway_backup; onOpenWrt is what "auto" becomes.
func buildGatewayFeatures(cfg config.Config, onOpenWrt bool) gatewayFeatures {
	var gw gatewayFeatures
	observeOn := cfg.ObserveEnabled(onOpenWrt)
	parts := map[observe.Part]bool{observe.PartDHCP: cfg.DHCPLeasesEnabled(onOpenWrt)}
	for _, name := range config.ObservePartNames {
		if cfg.ObservePartEnabled(observeOn, name) {
			if p, ok := observe.ParsePart(name); ok {
				parts[p] = true
			}
		}
	}
	any := false
	for _, on := range parts {
		any = any || on
	}
	if any {
		gw.observer = observe.NewObserver(&observe.Env{}, parts, serverHost(cfg.ServerURL))
		var names []string
		for _, p := range gw.observer.Parts() {
			names = append(names, string(p))
		}
		log.Printf("observe: reporting %s (unchanged parts resent every %ds, DHCP every %ds)",
			strings.Join(names, ", "), cfg.ObserveRefresh, cfg.DHCPLeasesRefresh)
		if parts[observe.PartDHCP] {
			d, _ := gw.observer.DHCP.Read()
			log.Printf("dhcp: %d IPv4 leases, %d DHCPv6, %d static hosts now", len(d.Leases4), len(d.Leases6), len(d.Hosts))
		}
	}
	if cfg.ConntrackFlushEnabled(observeOn) {
		f := &gatewayops.Flusher{}
		if err := f.Available(); err != nil {
			log.Printf("conntrack: flush not offered: %v", err)
		} else {
			gw.conntrack = f
			log.Printf("conntrack: the controller may flush a device's connections (net.conntrack_flush)")
		}
	}
	if observeOn && cfg.GatewayBackup != config.GatewayBackupOff {
		if gatewayops.SysupgradeAvailable() {
			gw.backup = &gatewayops.Backuper{Policy: cfg.GatewayBackup, Hostname: hostname, Release: release}
			log.Printf("backup: the controller may take %s backups (gateway_backup %s)", cfg.GatewayBackup, cfg.GatewayBackup)
		} else {
			log.Printf("backup: not offered: no sysupgrade on this host")
		}
	}
	return gw
}

func release() string {
	return controller.SystemInfo(hoststat.FS{}, runtime.GOARCH).OS
}

// serverHost is the host name of server_url ("" without one).
func serverHost(serverURL string) string {
	if serverURL == "" {
		return ""
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// gatewayCommand runs the subcommands of the gateway features; ok is false
// when name is not one of them.
func gatewayCommand(name string, args []string, stdout, stderr io.Writer) (int, bool) {
	switch name {
	case "observe":
		return observeCommand(args, stdout, stderr, &observe.Env{}), true
	case "conntrack-flush":
		return conntrackCommand(args, stdout, stderr, &gatewayops.Flusher{}), true
	case "backup":
		return backupCommand(args, stdout, stderr, &gatewayops.Backuper{Policy: gatewayops.BackupFull, Hostname: hostname, Release: release}), true
	}
	return 0, false
}

const observeUsage = `usage: perch-collector observe [part...]

Prints the observation the collector sends its controller (the observe
section of a push) as JSON, and exits: every part, or the named ones
(dhcp, neighbors, interfaces, upnp, mwan3, resolver, system). Read-only; no
configuration, no capture, no listener; the resolver part resolves no
controller name.
`

func observeCommand(args []string, stdout, stderr io.Writer, env *observe.Env) int {
	parts := map[observe.Part]bool{}
	for _, a := range args {
		switch a {
		case "-h", "-help", "--help", "help":
			fmt.Fprint(stdout, observeUsage)
			return 0
		}
		p, ok := observe.ParsePart(a)
		if !ok {
			fmt.Fprintf(stderr, "unknown part %q\n\n%s", a, observeUsage)
			return 2
		}
		parts[p] = true
	}
	if len(parts) == 0 {
		for _, p := range observe.AllParts {
			parts[p] = true
		}
	}
	o := observe.NewObserver(env, parts, "")
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(o.Section(nil, true)); err != nil {
		fmt.Fprintf(stderr, "perch-collector observe: %v\n", err)
		return 1
	}
	return 0
}

func conntrackCommand(args []string, stdout, stderr io.Writer, f *gatewayops.Flusher) int {
	fs := flag.NewFlagSet("conntrack-flush", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dry := fs.Bool("dry-run", false, "count the matching entries, delete nothing")
	proto := fs.String("proto", "", "only this protocol (tcp, udp, icmp, …)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: perch-collector conntrack-flush [-dry-run] [-proto P] IP...\n\n"+
			"Deletes the conntrack entries that have one of the addresses as their\n"+
			"source or destination (original or reply direction), what the controller's\n"+
			"net.conntrack_flush does, and prints the result as JSON.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	res, err := f.Flush(gatewayops.FlushParams{IPs: fs.Args(), Proto: *proto, DryRun: *dry})
	if err != nil {
		fmt.Fprintf(stderr, "perch-collector conntrack-flush: %v\n", err)
		return 2
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	if !res.Flushed {
		return 1
	}
	return 0
}

func backupCommand(args []string, stdout, stderr io.Writer, b *gatewayops.Backuper) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	full := fs.Bool("full", false, "keep the secrets (the archive as sysupgrade -b writes it)")
	out := fs.String("o", "", "write the archive to this file (required)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: perch-collector backup [-full] -o FILE\n\n"+
			"Writes the backup the controller's gateway.backup returns: sysupgrade -b,\n"+
			"redacted unless -full, and prints what was redacted as JSON.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *out == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	redact := !*full
	res, err := b.Backup(context.Background(), gatewayops.BackupParams{Redact: &redact})
	if err != nil {
		fmt.Fprintf(stderr, "perch-collector backup: %v\n", err)
		return 1
	}
	data, _ := base64.StdEncoding.DecodeString(res.ContentBase64)
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		fmt.Fprintf(stderr, "perch-collector backup: %v\n", err)
		return 1
	}
	res.ContentBase64 = ""
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	return 0
}
