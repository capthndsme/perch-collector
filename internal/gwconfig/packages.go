package gwconfig

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/pkgdb"
	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Package installs (README 7.7): "Install on gateway" for a feature whose
// package is missing. One job installs a list of packages with their
// dependencies, after checking the free flash, with opkg (OpenWrt up to
// 24.10) or apk (25.12+). It shares the apply slot and goes through the
// same confirm window: the agent reconnects, the controller confirms, or the
// agent removes what it installed. A failed install is rolled back at once.
// Only packages on the install allowlist can be installed; nothing else is
// ever run.

// InstallAllowlist are the packages the controller may install: what the
// gateway features use. The router's owner extends it with
// `list package_allow` in /etc/config/perch-collector.
var InstallAllowlist = uniqueNames(pkgdb.WatchList,
	"luci-app-sqm", "kmod-ifb", "tc-full", "tc-tiny", "kmod-sched-core",
	"kmod-wireguard", "luci-proto-wireguard", "wireguard-tools",
	"luci-app-mwan3", "luci-app-pbr", "ip-full",
	"luci-app-opennds",
	// gateway-sync: UPnP and DDNS (protocol 5).
	"miniupnpd-nftables", "luci-app-upnp",
	"ddns-scripts", "ddns-scripts-services", "ddns-scripts-cloudflare", "luci-app-ddns", "ca-bundle",
)

// uniqueNames is base then more, without repeats, in order.
func uniqueNames(base []string, more ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range append(append([]string(nil), base...), more...) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// PackageInstallParams are gateway.package.install's params.
type PackageInstallParams struct {
	ApplyID               string   `json:"applyId"`
	Packages              []string `json:"packages"`
	ConfirmTimeoutSeconds *float64 `json:"confirmTimeoutSeconds,omitempty"`
	DryRun                bool     `json:"dryRun,omitempty"`
}

// PackageInstallResult is its result.
type PackageInstallResult struct {
	State                 string `json:"state"`
	ApplyID               string `json:"applyId"`
	Deadline              string `json:"deadline,omitempty"`
	ConfirmTimeoutSeconds int    `json:"confirmTimeoutSeconds,omitempty"`
	Manager               string `json:"manager"`
	// Install are the packages the job installs (dry run: would install),
	// dependencies included.
	Install []string `json:"install"`
	// AlreadyInstalled are requested packages that were there already.
	AlreadyInstalled []string `json:"alreadyInstalled,omitempty"`
	// NeedBytes is the estimate the flash check used (null: unknown, the
	// minimum free space was required instead).
	NeedBytes *int64            `json:"needBytes"`
	FreeBytes uint64            `json:"freeBytes"`
	Hashes    map[string]string `json:"hashes,omitempty"`
}

// Flash check: the estimate of an install is the sum of the package files'
// sizes times PackageSizeFactor (feeds list the compressed size only), plus
// PackageReserveBytes left free. Without sizes (apk) the free space must
// be at least PackageMinFreeBytes.
const (
	PackageSizeFactor   = 3
	PackageReserveBytes = 512 << 10
	PackageMinFreeBytes = 4 << 20
)

// Timeouts of the package manager's steps.
const (
	pkgUpdateTimeout  = 3 * time.Minute
	pkgInstallTimeout = 10 * time.Minute
	pkgRemoveTimeout  = 2 * time.Minute
)

var packageNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,63}$`)

// installingRe finds "Installing <name> (<version>)" in opkg's --noaction
// and apk's --simulate output.
var installingRe = regexp.MustCompile(`Installing ([A-Za-z0-9+._-]+) \(([^)]*)\)`)

func (p *Plane) installAllowed(name string) bool {
	for _, n := range InstallAllowlist {
		if n == name {
			return true
		}
	}
	for _, n := range p.o.PackageAllow {
		if n == name {
			return true
		}
	}
	return false
}

func (p *Plane) pkgRunner() ubus.Runner {
	if p.o.Run != nil {
		return p.o.Run
	}
	return ubus.ExecRunner
}

func (p *Plane) run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	return p.pkgRunner()(ctx, name, args...)
}

func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

func runPkg(ctx context.Context, run ubus.Runner, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout, stderr, code, err := run(ctx, name, args...)
	out := string(stdout) + string(stderr)
	if err != nil {
		return out, fmt.Errorf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	if code != 0 {
		return out, fmt.Errorf("%s %s: exit status %d: %s", name, strings.Join(args, " "), code, tail([]byte(out), 400))
	}
	return out, nil
}

// InstallPackages runs gateway.package.install.
func (p *Plane) InstallPackages(ctx context.Context, a *PackageInstallParams, sess SessionRef) (*PackageInstallResult, error) {
	if !ValidApplyID(a.ApplyID) {
		return nil, perr(CodeBadParams, "invalid applyId %q", a.ApplyID)
	}
	if len(a.Packages) == 0 || len(a.Packages) > 16 {
		return nil, perr(CodeBadParams, "packages lists 1 to 16 names")
	}
	var refused []string
	seen := map[string]bool{}
	var names []string
	for _, n := range a.Packages {
		if !packageNameRe.MatchString(n) {
			return nil, perr(CodeBadParams, "invalid package name %q", n)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
		if !p.installAllowed(n) {
			refused = append(refused, n)
		}
	}
	if len(refused) > 0 {
		e := perr(CodePackageNotAllowed, "not on the install allowlist (list package_allow in /etc/config/perch-collector extends it): %v", refused)
		e.Data = map[string]any{"packages": refused}
		return nil, e
	}
	if p.Mode() != ModeManaged {
		return nil, &AccessError{Code: ErrNotManaged, Message: "the controller has not put this gateway in managed mode (agent.configure)"}
	}
	if rec, err := p.reserve(a.ApplyID); err != nil {
		return nil, err
	} else if rec != nil {
		return &PackageInstallResult{State: StatePendingConfirm, ApplyID: rec.ApplyID, Deadline: rec.Deadline.UTC().Format(time.RFC3339),
			ConfirmTimeoutSeconds: rec.ConfirmSeconds, Manager: rec.Packages.Manager, Install: rec.Packages.Installed}, nil
	}
	res, err := p.installPackages(ctx, a, names, sess)
	// A sibling package (sqm-scripts, perch-qos) brings its config onto the
	// allowlist: look again now rather than after the cache's TTL.
	p.refreshSiblings()
	if err != nil {
		p.release()
	}
	return res, err
}

func (p *Plane) installPackages(ctx context.Context, a *PackageInstallParams, names []string, sess SessionRef) (*PackageInstallResult, error) {
	db := p.packageDB()
	manager := db.Manager()
	if manager == "" {
		return nil, perr(CodeNoPackageManager, "neither opkg nor apk is installed")
	}
	if uci.PendingState(p.o.Root).LuciPending {
		return nil, busyLuci()
	}
	installed, err := db.Installed()
	if err != nil {
		return nil, perr(CodeInstallFailed, "reading the package database: %v", err)
	}
	var want, already []string
	for _, n := range names {
		if _, ok := installed[n]; ok {
			already = append(already, n)
		} else {
			want = append(want, n)
		}
	}
	res := &PackageInstallResult{ApplyID: a.ApplyID, Manager: manager, Install: []string{}, AlreadyInstalled: already}
	if len(want) == 0 {
		res.State = StateNoop
		p.release()
		return res, nil
	}
	run := p.pkgRunner()
	update := []string{"update"}
	if _, err := runPkg(ctx, run, pkgUpdateTimeout, manager, update...); err != nil {
		e := perr(CodeInstallFailed, "updating the package lists: %v", err)
		return nil, e
	}
	sim := append([]string{"install", "--noaction"}, want...)
	if manager == pkgdb.Apk {
		sim = append([]string{"add", "--simulate"}, want...)
	}
	out, err := runPkg(ctx, run, pkgInstallTimeout, manager, sim...)
	if err != nil {
		return nil, perr(CodeInstallFailed, "%v", err)
	}
	for _, m := range installingRe.FindAllStringSubmatch(out, -1) {
		res.Install = appendUnique(res.Install, m[1])
	}
	for _, n := range want {
		res.Install = appendUnique(res.Install, n)
	}
	// Flash.
	var free uint64
	if mounts, err := pkgdb.Mounts(p.o.Root); err == nil {
		if s, err := pkgdb.FreeSpace(rooted(p.o.Root, pkgdb.FlashPath(mounts))); err == nil {
			free = s.FreeBytes
		}
	}
	res.FreeBytes = free
	required := uint64(PackageMinFreeBytes)
	if manager == pkgdb.Opkg {
		if need, ok := p.opkgSize(ctx, res.Install); ok {
			n := need * PackageSizeFactor
			res.NeedBytes = &n
			required = uint64(n) + PackageReserveBytes
		}
	}
	if free < required {
		e := perr(CodeInsufficientFlash, "not enough free flash: %d bytes free, %d needed", free, required)
		e.Data = map[string]any{"freeBytes": free, "needBytes": required}
		return nil, e
	}
	if a.DryRun {
		res.State = StateDryRun
		p.release()
		return res, nil
	}

	// Snapshot the allowlisted configs: a package's first-boot scripts may
	// edit them, and a rollback puts them back.
	now := p.clock.Now()
	secs := p.confirmSeconds(a.ConfirmTimeoutSeconds, false)
	configs := p.Allowed()
	before := make([]string, 0, len(installed))
	for n := range installed {
		before = append(before, n)
	}
	sort.Strings(before)
	rec := &pendingRecord{ApplyID: a.ApplyID, Kind: KindPackage, CreatedAt: now, Deadline: now.Add(time.Duration(secs) * time.Second),
		ConfirmSeconds: secs, Configs: sortApplyOrder(configs), Packages: &packageRecord{Manager: manager, Requested: want, Before: before}}
	if err := p.prepare(rec); err != nil {
		return nil, err
	}
	args := append([]string{"install"}, want...)
	if manager == pkgdb.Apk {
		args = append([]string{"add"}, want...)
	}
	log.Printf("config plane: package job %s: %s %s", a.ApplyID, manager, strings.Join(args, " "))
	_, installErr := runPkg(ctx, run, pkgInstallTimeout, manager, args...)
	rec.Packages.Installed = p.newPackages(rec.Packages)
	if installErr != nil {
		rec.Committed = true
		rec.HashesAfter = nil
		p.ap.mu.Lock()
		p.ap.pending, p.ap.state = rec, StateRollingBack
		p.ap.mu.Unlock()
		result := p.rollback(rec, ReasonInstallFailed, true, installErr.Error())
		e := perr(CodeInstallFailed, "%v (rolled back)", installErr)
		e.Data = map[string]any{"rolledBack": true, "result": result}
		return nil, e
	}
	if err := p.committed(rec, sess); err != nil {
		return nil, p.failCommittedReason(rec, ReasonInstallFailed, err.Error())
	}
	log.Printf("config plane: package job %s installed %v; confirm by %s", a.ApplyID, rec.Packages.Installed, rec.Deadline.UTC().Format(time.RFC3339))
	go p.afterCommit(a.ApplyID)
	res.State, res.Deadline, res.ConfirmTimeoutSeconds = StatePendingConfirm, rec.Deadline.UTC().Format(time.RFC3339), secs
	res.Install = rec.Packages.Installed
	res.Hashes = p.Hashes()
	return res, nil
}

// newPackages lists what is installed now and was not before.
func (p *Plane) newPackages(r *packageRecord) []string {
	return installedSince(p.packageDB(), r)
}

func installedSince(db pkgdb.DB, r *packageRecord) []string {
	now, err := db.Installed()
	if err != nil {
		return nil
	}
	was := map[string]bool{}
	for _, n := range r.Before {
		was[n] = true
	}
	out := []string{}
	for n := range now {
		if !was[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// opkgSize sums the Size of each package in the feed lists (opkg info).
func (p *Plane) opkgSize(ctx context.Context, names []string) (int64, bool) {
	var total int64
	for _, n := range names {
		out, err := runPkg(ctx, p.pkgRunner(), 30*time.Second, pkgdb.Opkg, "info", n)
		if err != nil {
			return 0, false
		}
		size := int64(-1)
		for _, line := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(line, "Size:"); ok {
				if x, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
					size = x
					break
				}
			}
		}
		if size < 0 {
			return 0, false
		}
		total += size
	}
	return total, true
}

// removePackages undoes a package job: what it installed goes, the
// requested packages first (dependencies after), two passes for what a
// dependency order kept. It returns what was removed.
func removePackages(ctx context.Context, run ubus.Runner, root string, r *packageRecord) ([]string, error) {
	db := pkgdb.DB{Root: root}
	targets := installedSince(db, r)
	if len(targets) == 0 {
		return []string{}, nil
	}
	isTarget := map[string]bool{}
	for _, n := range targets {
		isTarget[n] = true
	}
	var order []string
	for _, n := range r.Requested {
		if isTarget[n] {
			order = append(order, n)
		}
	}
	for i := len(targets) - 1; i >= 0; i-- {
		order = appendUnique(order, targets[i])
	}
	for pass := 0; pass < 2; pass++ {
		now, err := db.Installed()
		if err != nil {
			return nil, err
		}
		var left []string
		for _, n := range order {
			if _, ok := now[n]; ok {
				left = append(left, n)
			}
		}
		if len(left) == 0 {
			break
		}
		if r.Manager == pkgdb.Apk {
			_, _ = runPkg(ctx, run, pkgRemoveTimeout, pkgdb.Apk, append([]string{"del"}, left...)...)
			continue
		}
		for _, n := range left {
			_, _ = runPkg(ctx, run, pkgRemoveTimeout, pkgdb.Opkg, "remove", n)
		}
	}
	now, err := db.Installed()
	if err != nil {
		return nil, err
	}
	var removed, left []string
	for _, n := range order {
		if _, ok := now[n]; ok {
			left = append(left, n)
		} else {
			removed = append(removed, n)
		}
	}
	sort.Strings(removed)
	if removed == nil {
		removed = []string{}
	}
	if len(left) > 0 {
		return removed, fmt.Errorf("could not remove %v", left)
	}
	return removed, nil
}
