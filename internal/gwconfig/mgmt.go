package gwconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// ManagementPath is how the agent reaches the controller (README 3.8): the
// L3 device of `ip route get <controller>` and the UCI network (netifd
// interface) on it. Everything that carries that network is protected: a
// job touching it gets a confirm window of at least ProtectedConfirmSeconds.
type ManagementPath struct {
	// Network is the interface section, e.g. "lan"; nil when netifd knows no
	// interface on the device.
	Network *string `json:"network"`
	// Device is the route's L3 device, e.g. "br-lan" or "br-lan.1".
	Device            string `json:"device"`
	ControllerAddress string `json:"controllerAddress,omitempty"`
	ReportedAt        string `json:"reportedAt,omitempty"`
}

// NetworkName is Network or "".
func (m *ManagementPath) NetworkName() string {
	if m == nil || m.Network == nil {
		return ""
	}
	return *m.Network
}

// controllerHost is the host of server_url.
func controllerHost(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ManagementPath finds the path to the controller now; nil when there is
// no controller address or no route (then nothing is protected, and the
// confirm window alone keeps the router safe).
func (p *Plane) ManagementPath(ctx context.Context) *ManagementPath {
	host := controllerHost(p.o.ServerURL)
	if host == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := p.lookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return nil
		}
		// Prefer IPv4, which is what the collector dials first on a
		// dual-stack name in practice.
		for _, a := range addrs {
			if x := net.ParseIP(a); x != nil && x.To4() != nil {
				ip = x
				break
			}
		}
		if ip == nil {
			ip = net.ParseIP(addrs[0])
		}
		if ip == nil {
			return nil
		}
	}
	stdout, _, code, err := p.run(ctx, "ip", "route", "get", ip.String())
	if err != nil || code != 0 {
		return nil
	}
	dev := routeDevice(string(stdout))
	if dev == "" {
		return nil
	}
	m := &ManagementPath{Device: dev, ControllerAddress: ip.String(), ReportedAt: p.o.Now().UTC().Format(time.RFC3339)}
	if raw, err := p.ubus.CallRaw(ctx, "network.interface", "dump", nil); err == nil {
		if n := interfaceOnDevice(raw, dev); n != "" {
			m.Network = &n
		}
	}
	return m
}

func (p *Plane) lookupHost(ctx context.Context, host string) ([]string, error) {
	if p.o.LookupHost != nil {
		return p.o.LookupHost(ctx, host)
	}
	return net.DefaultResolver.LookupHost(ctx, host)
}

// routeDevice reads the `dev` of `ip route get` output ("10.0.0.1 dev br-lan
// src 10.0.0.2 uid 0", or "local 10.0.0.1 dev lo table local ...").
func routeDevice(out string) string {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}

// interfaceOnDevice names the netifd interface whose L3 device (or device)
// is dev in `ubus call network.interface dump`; an interface that is up
// wins over one that is not.
func interfaceOnDevice(raw []byte, dev string) string {
	var dump struct {
		Interface []struct {
			Interface string `json:"interface"`
			Up        bool   `json:"up"`
			L3Device  string `json:"l3_device"`
			Device    string `json:"device"`
		} `json:"interface"`
	}
	if json.Unmarshal(raw, &dump) != nil {
		return ""
	}
	best := ""
	for _, i := range dump.Interface {
		if i.L3Device != dev && i.Device != dev {
			continue
		}
		if i.Up {
			return i.Interface
		}
		if best == "" {
			best = i.Interface
		}
	}
	return best
}

// parentDevice is the bridge (or parent) of a VLAN device: br-lan.10 ->
// br-lan.
func parentDevice(dev string) string {
	if i := strings.LastIndexByte(dev, '.'); i > 0 {
		return dev[:i]
	}
	return dev
}

// protectedSections lists, per config, the sections that carry the
// management path: the path's interface, any interface on its device, the
// device section that is the device or its parent bridge, the bridge-vlans
// on that bridge, the firewall zone listing the network, and the firewall
// defaults. The controller splits jobs by the same built-in rules
// (apply_plan.ts); the agent's check is the safety net that grants the
// longer window when a job carries them anyway.
func protectedSections(configs map[string]*uci.Config, m *ManagementPath) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	if m == nil || m.Device == "" {
		return out
	}
	add := func(config, section string) {
		if out[config] == nil {
			out[config] = map[string]bool{}
		}
		out[config][section] = true
	}
	network := m.NetworkName()
	parent := parentDevice(m.Device)
	nets := map[string]bool{}
	if network != "" {
		nets[network] = true
	}
	if c := configs["network"]; c != nil {
		for _, s := range c.Sections {
			str := func(o string) string { v, _ := s.Get(o); return v.Str() }
			switch s.Type {
			case "interface":
				dev := str("device")
				if dev == "" {
					dev = str("ifname")
				}
				if s.Name == network || dev == m.Device || (dev != "" && dev == parent) {
					add("network", s.Name)
					nets[s.Name] = true
				}
			case "device":
				if name := str("name"); name == m.Device || name == parent {
					add("network", s.Name)
				}
			case "bridge-vlan":
				if str("device") == parent {
					add("network", s.Name)
				}
			}
		}
	}
	if c := configs["firewall"]; c != nil {
		for _, s := range c.Sections {
			switch s.Type {
			case "defaults":
				add("firewall", s.Name)
			case "zone":
				v, _ := s.Get("network")
				for _, n := range v.Items {
					for _, w := range strings.Fields(n) {
						if nets[w] {
							add("firewall", s.Name)
						}
					}
				}
			}
		}
	}
	return out
}

// touchesProtected reports whether a simulation touches a protected
// section, before or after the job.
func touchesProtected(sim *simulation, current map[string]*uci.Config, m *ManagementPath) (bool, string) {
	if m == nil {
		return false, ""
	}
	before := protectedSections(current, m)
	merged := map[string]*uci.Config{}
	for k, v := range current {
		merged[k] = v
	}
	for k, v := range sim.desired {
		merged[k] = v
	}
	after := protectedSections(merged, m)
	for config, sections := range sim.touched {
		for name := range sections {
			if before[config][name] || after[config][name] {
				return true, fmt.Sprintf("%s.%s", config, name)
			}
		}
	}
	return false, ""
}
