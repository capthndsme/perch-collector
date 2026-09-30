package netcap

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/capthndsme/perch-collector/internal/observe"
)

// Discoverer reads netifd's interfaces, the firewall's masquerading zones
// and what the side rule needs of UCI network (side.go). Interfaces are
// asked fresh on every Discover(true) and at most every five seconds
// otherwise; the firewall and UCI network are read at most every
// FirewallTTL.
type Discoverer struct {
	Env *observe.Env
	// FirewallTTL between two `uci show firewall`; 0 = 30 s.
	FirewallTTL time.Duration

	mu      sync.Mutex
	at      time.Time
	last    Discovery
	fwAt    time.Time
	masq    map[string]bool
	gateway map[string]bool
	confDev map[string]string
	fwOnce  bool
}

// Discover returns the router's interfaces; fresh skips the five-second
// cache (the reconciler), otherwise a report within five seconds of the
// last read reuses it.
func (d *Discoverer) Discover(fresh bool) Discovery {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if !fresh && !d.at.IsZero() && now.Sub(d.at) < 5*time.Second {
		return d.last
	}
	ttl := d.FirewallTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if !d.fwOnce || now.Sub(d.fwAt) >= ttl {
		d.fwOnce, d.fwAt = true, now
		if secs, ok := d.Env.UCI("firewall"); ok {
			d.masq = MasqNetworks(secs)
		}
		if secs, ok := d.Env.UCI("network"); ok {
			d.gateway, d.confDev = NetworkUCI(secs)
		}
	}
	list, ok := d.Env.Interfaces()
	d.at = now
	d.last = Discovery{OK: ok, Netifd: ok, Interfaces: list, Masq: d.masq, Gateway: d.gateway, ConfDevice: d.confDev}
	if !ok && !d.hasUbus() {
		// Not OpenWrt: nothing to discover, not a failure.
		d.last.OK = true
	}
	return d.last
}

// hasUbus reports whether the host has the ubus CLI (a test Env with its
// own runner always has).
func (d *Discoverer) hasUbus() bool {
	if d.Env != nil && d.Env.Run != nil {
		return true
	}
	root := ""
	if d.Env != nil {
		root = d.Env.Root
	}
	for _, p := range []string{"/bin/ubus", "/sbin/ubus", "/usr/bin/ubus", "/usr/sbin/ubus"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return true
		}
	}
	return false
}

// MasqNetworks are the networks of the firewall zones with masq on.
func MasqNetworks(secs []observe.UCISection) map[string]bool {
	out := map[string]bool{}
	for _, s := range secs {
		if s.Type != "zone" || !s.Bool("masq", false) {
			continue
		}
		for _, n := range s.Words("network") {
			out[n] = true
		}
	}
	return out
}

// SysFS is SysNet over /sys/class/net under Root ("" = the real one).
type SysFS struct{ Root string }

func (s SysFS) dir(dev string) string {
	return filepath.Join(s.Root, "/sys/class/net", dev)
}

// validDev refuses names that would walk out of /sys/class/net.
func validDev(dev string) bool {
	return dev != "" && dev != "." && dev != ".." && !strings.ContainsAny(dev, "/\x00")
}

// Exists implements SysNet.
func (s SysFS) Exists(dev string) bool {
	if !validDev(dev) {
		return false
	}
	_, err := os.Stat(s.dir(dev))
	return err == nil
}

// Master implements SysNet.
func (s SysFS) Master(dev string) string {
	if !validDev(dev) {
		return ""
	}
	target, err := os.Readlink(filepath.Join(s.dir(dev), "master"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// Uppers implements SysNet.
func (s SysFS) Uppers(dev string) []string {
	if !validDev(dev) {
		return nil
	}
	entries, err := os.ReadDir(s.dir(dev))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if name, ok := strings.CutPrefix(e.Name(), "upper_"); ok {
			out = append(out, name)
		}
	}
	return out
}

// MAC implements SysNet.
func (s SysFS) MAC(dev string) (net.HardwareAddr, bool) {
	if !validDev(dev) {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(s.dir(dev), "address"))
	if err != nil {
		return nil, false
	}
	mac, err := net.ParseMAC(strings.TrimSpace(string(b)))
	if err != nil || len(mac) != 6 {
		return nil, false
	}
	// An all-zero address (a tunnel) is no pivot.
	for _, c := range mac {
		if c != 0 {
			return mac, true
		}
	}
	return nil, false
}
