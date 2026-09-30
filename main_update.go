package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/capthndsme/perch-agentkit/link"
	"github.com/capthndsme/perch-agentkit/update"

	"github.com/capthndsme/perch-collector/internal/config"
	"github.com/capthndsme/perch-collector/internal/gwconfig"
)

// variant is the binary variant, stamped by scripts/build-static.sh
// (-X main.variant=ndpi-static): a release's binary artefact must carry the
// same one. "" for every other build (they update through packages only).
var variant = ""

// Agent self-update of the collector (agent-updates design, device.md
// 10.2). Where it lives on the router; the boot guard is the kit's
// perch-collector-guard, which the package ships byte for byte (a test
// keeps them equal): the update step first, then config-guard.
const (
	updateStateDir = "/etc/perch-collector/update"
	updateRunDir   = "/tmp/perch-update/perch-collector"
)

// updateTarget is perch-collector for the kit's updater. The files a
// release may write outside the packages: the init scripts and keep list,
// and a hand-installed perch-qos's files only where they exist already.
// Never a config: /etc/config/* and /etc/uci-defaults/* are not on it.
func updateTarget(cfg config.Config) update.Target {
	t := update.Target{
		Product:    update.ProductCollector,
		Service:    "perch-collector",
		Program:    "perch-collector",
		Version:    version,
		Arch:       releaseArch(),
		Variant:    variant,
		Candidates: []string{"/usr/bin/perch-collector"},
		Packages:   []string{"perch-collector", "perch-qos"},
		StateDir:   updateStateDir,
		RunDir:     updateRunDir,
		Guard:      update.CollectorGuard(),
		FileAllow: []update.FileRule{
			{Path: "/etc/init.d/perch-collector"},
			{Path: "/etc/init.d/perch-collector-guard"},
			{Path: "/lib/upgrade/keep.d/perch-collector"},
			{Path: "/etc/init.d/perch-qos", IfExists: true},
			{Path: "/etc/hotplug.d/iface/40-perch-qos", IfExists: true},
			{Path: "/etc/hotplug.d/ntp/40-perch-qos", IfExists: true},
			{Path: "/lib/upgrade/keep.d/perch-qos", IfExists: true},
		},
		// A gateway keeps its rollback copy on flash: a broken new version
		// may not reach the controller to fetch the old one again.
		RollbackStores: []string{update.StoreFlash},
		Enabled:        cfg.SelfUpdate,
		ExtraKeys:      cfg.UpdateKeys,
		TLSInsecure:    cfg.AnnounceTLSInsecure,
		CAFile:         cfg.ServerCAFile,
	}
	if os.Getenv("PERCH_COLLECTOR_INSTALL") == "docker" {
		// The image's ENV: updated with docker compose, never in place.
		t.Kind = func() string { return update.InstallDocker }
	}
	return t
}

// releaseArch names the build's architecture the way release artefacts do
// (amd64, arm64, armv7, armv5, mipsle, mips).
func releaseArch() string {
	if runtime.GOARCH != "arm" {
		return runtime.GOARCH
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "GOARM" && s.Value != "" {
				return "armv" + s.Value[:1]
			}
		}
	}
	return "armv7"
}

// updateBusy is the updater's busy hook (BUILD-PLAN agreement 3): an update
// waits while a config apply is being made, waits for its confirm or is
// being rolled back (the plane's ApplyState).
func updateBusy(state func() gwconfig.ApplyState) func(context.Context) string {
	return func(context.Context) string {
		if st := state(); st.State != "" && st.State != gwconfig.StateIdle {
			return "config_pending"
		}
		return ""
	}
}

// selfUpdater builds the updater for a collector that dials its controller
// (only that transport carries agent.update.*) and acts on what a previous
// run left (the new version in its check, a stale staging). nil when it
// cannot be built (logged).
func selfUpdater(cfg config.Config, plane *gwconfig.Plane) *update.Updater {
	client, err := link.NewHTTPClient(link.TLSOptions{Insecure: cfg.AnnounceTLSInsecure, CAFile: cfg.ServerCAFile})
	if err != nil {
		log.Printf("update: self-update is off: %v", err)
		return nil
	}
	t := updateTarget(cfg)
	if plane != nil {
		t.Busy = updateBusy(plane.ApplyState)
	}
	u, err := update.New(t, client, cfg.ServerURL, slog.Default())
	if err != nil {
		log.Printf("update: self-update is off: %v", err)
		return nil
	}
	u.Startup(context.Background())
	if !cfg.SelfUpdate {
		log.Printf("update: self_update is off: the controller cannot update this collector")
	}
	return u
}

// waitProbation holds a new version's first dial back until the watchdog
// has put its plan in probation (at most max): the controller reads the
// hello's update block once per session, and a candidate that says
// "installing" there would never be confirmed. Anything else returns at
// once.
func waitProbation(ctx context.Context, max time.Duration) {
	deadline := time.Now().Add(max)
	for {
		p, err := update.ReadPlan(updateStateDir)
		if err != nil || p.Phase != update.PhaseInstalling || !update.ParseVersion(version).Known ||
			update.CompareVersions(p.To, version) != 0 {
			return
		}
		if time.Now().After(deadline) {
			log.Printf("update: plan %s still installing after %s; dialing anyway", p.UpdateID, max)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}
