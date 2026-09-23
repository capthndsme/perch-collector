package gwconfig

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"strings"

	"github.com/capthndsme/perch-agentkit/openwrt/pkgdb"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// OpenWrt identifies the router's firmware.
type OpenWrt struct {
	Release  string `json:"release,omitempty"`
	Revision string `json:"revision,omitempty"`
	Target   string `json:"target,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Board    string `json:"board,omitempty"`
}

// CaptureNetwork is one network the collector captures.
type CaptureNetwork struct {
	Network string `json:"network,omitempty"`
	Device  string `json:"device"`
}

// Capture lists what is captured.
type Capture struct {
	Networks []CaptureNetwork `json:"networks"`
}

// Flash is the room left where packages and files go.
type Flash struct {
	Path       string `json:"path"`
	TotalBytes uint64 `json:"totalBytes"`
	FreeBytes  uint64 `json:"freeBytes"`
}

// Capabilities is gateway.capabilities' result (plan 1 section 4), plus
// flash and storage (gateway README section 7).
type Capabilities struct {
	Protocol         int      `json:"protocol"`
	Access           string   `json:"access"`
	AccessConfigured string   `json:"accessConfigured"`
	AllowedConfigs   []string `json:"allowedConfigs"`
	TransportOK      bool     `json:"transportOk"`
	AllowInsecure    bool     `json:"allowInsecure"`
	ConfirmMax       int      `json:"confirmMaxSeconds"`
	// Backend is how configs would be written: "ubus" (rpcd), "uci-cli", or
	// null without either.
	Backend        *string           `json:"backend"`
	OpenWrt        *OpenWrt          `json:"openwrt"`
	Firewall       *string           `json:"firewall"`
	PackageManager *string           `json:"packageManager"`
	Packages       map[string]string `json:"packages"`
	// Configs are the readable configs that exist.
	Configs     []string          `json:"configs"`
	Hashes      map[string]string `json:"hashes"`
	Uncommitted []string          `json:"uncommitted"`
	LuciPending bool              `json:"luciPending"`
	Apply       ApplyState        `json:"apply"`
	Capture     Capture           `json:"capture"`
	Flash       *Flash            `json:"flash"`
	Storage     *Storage          `json:"storage"`
	// Signing: how this session's writes are signed (write access only).
	Signing *Signing `json:"signing,omitempty"`
	// Management is the path to the controller (README 3.8).
	Management *ManagementPath `json:"management"`
	// InstallAllowlist: what gateway.package.install accepts.
	InstallAllowlist []string `json:"installAllowlist"`
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Capabilities describes the router and what the plane may do there;
// challenge is the session's signing challenge.
func (p *Plane) Capabilities(ctx context.Context, challenge string) *Capabilities {
	c := &Capabilities{
		Protocol:         Protocol,
		Access:           p.Access(),
		AccessConfigured: p.o.Access,
		AllowedConfigs:   p.Allowed(),
		TransportOK:      p.o.TransportOK,
		AllowInsecure:    p.o.AllowInsecure,
		ConfirmMax:       p.o.ConfirmMax,
		OpenWrt:          p.openwrt(),
		Firewall:         strPtr(p.firewall()),
		Packages:         map[string]string{},
		Configs:          []string{},
		Hashes:           map[string]string{},
		Uncommitted:      []string{},
		Apply:            p.ApplyState(),
		Capture:          Capture{Networks: []CaptureNetwork{}},
		InstallAllowlist: append(append([]string(nil), InstallAllowlist...), p.o.PackageAllow...),
	}
	if p.o.Access == AccessWrite {
		c.Signing = p.SigningFor(challenge)
	}
	if p.o.Access != AccessNone {
		c.Management = p.ManagementPath(ctx)
	}
	if c.AllowedConfigs == nil {
		c.AllowedConfigs = []string{}
	}
	cctx, cancel := p.callCtx(ctx)
	c.Backend = strPtr(uci.Detect(cctx, p.ubus, p.o.LookPath))
	cancel()
	db := p.packageDB()
	c.PackageManager = strPtr(db.Manager())
	if w, err := db.Watched(); err == nil {
		c.Packages = w
	}
	if p.Access() != AccessNone {
		c.Hashes = p.Hashes()
		for _, n := range p.Readable() {
			if _, ok := c.Hashes[n]; ok {
				c.Configs = append(c.Configs, n)
			}
		}
		pending := uci.PendingState(p.o.Root)
		c.Uncommitted = p.filterReadable(pending.Uncommitted)
		c.LuciPending = pending.LuciPending
	}
	if p.o.CaptureDevice != "" {
		c.Capture.Networks = append(c.Capture.Networks, CaptureNetwork{Network: p.o.CaptureNetwork, Device: p.o.CaptureDevice})
	}
	if mounts, err := pkgdb.Mounts(p.o.Root); err == nil {
		fp := pkgdb.FlashPath(mounts)
		if s, err := pkgdb.FreeSpace(rooted(p.o.Root, fp)); err == nil {
			c.Flash = &Flash{Path: fp, TotalBytes: s.TotalBytes, FreeBytes: s.FreeBytes}
		}
	}
	if p.o.StoragePath != "" {
		c.Storage = DetectStorage(p.o.Root, p.o.StoragePath)
	}
	return c
}

// openwrt reads /etc/openwrt_release and the board name.
func (p *Plane) openwrt() *OpenWrt {
	kv := shellVars(rooted(p.o.Root, "/etc/openwrt_release"))
	if kv["DISTRIB_ID"] == "" && kv["DISTRIB_RELEASE"] == "" {
		return nil
	}
	o := &OpenWrt{
		Release:  kv["DISTRIB_RELEASE"],
		Revision: kv["DISTRIB_REVISION"],
		Target:   kv["DISTRIB_TARGET"],
		Arch:     kv["DISTRIB_ARCH"],
	}
	if b, err := os.ReadFile(rooted(p.o.Root, "/tmp/sysinfo/board_name")); err == nil {
		o.Board = strings.TrimSpace(string(b))
	}
	return o
}

// firewall is fw4 when /sbin/fw4 exists, fw3 when only /sbin/fw3 does (on
// 24.10 fw3 is a link to fw4), "" otherwise.
func (p *Plane) firewall() string {
	if _, err := os.Stat(rooted(p.o.Root, "/sbin/fw4")); err == nil {
		return "fw4"
	}
	if _, err := os.Stat(rooted(p.o.Root, "/sbin/fw3")); err == nil {
		return "fw3"
	}
	return ""
}

// shellVars reads KEY='value' lines.
func shellVars(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		out[key] = strings.Trim(value, `"'`)
	}
	return out
}
