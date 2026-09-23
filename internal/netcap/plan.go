// Package netcap is the multi-interface capture of a collector on the
// router (gateway plan 1 section 8.3): it finds the router's LAN-side
// networks in netifd, decides which L3 devices to capture on, keeps one
// capture engine (with its own classifier) per device running as networks
// come and go, and reports the networks with their counters.
//
// The decision is a pure function, MakePlan, over what netifd, the
// firewall and /sys/class/net say; the Reconciler applies it.
package netcap

import (
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/capthndsme/perch-collector/internal/observe"
)

// Auto is the capture_networks value that selects every LAN-side network.
const Auto = "auto"

// Selection is what the configuration asks to capture.
type Selection struct {
	// Networks are UCI network names, device names, or Auto: every
	// interface that is up, has proto static or none and is not a WAN.
	Networks []string
	// Exclude removes networks (by network or device name) from the set.
	Exclude []string
	// WAN are the configured wan_interfaces (network or device names).
	// They are never captured and never local.
	WAN []string
}

// Discovery is one look at the router.
type Discovery struct {
	// OK is false when the router could not be read (netifd did not
	// answer); the reconciler then keeps its captures. A host without
	// netifd at all is OK with no interfaces (device names still work).
	OK bool
	// Netifd is true when the interfaces came from netifd.
	Netifd     bool
	Interfaces []observe.Interface
	// Masq are the networks in a firewall zone with masquerading on: the
	// WAN side, even while it holds no default route.
	Masq map[string]bool
}

// SysNet answers what the plan needs from /sys/class/net.
type SysNet interface {
	// Exists reports whether the device exists.
	Exists(dev string) bool
	// Master is the device's bridge (or bond), "" when it is none's port.
	Master(dev string) string
	// Uppers are the devices stacked on it (its VLAN devices).
	Uppers(dev string) []string
	// MAC is the device's hardware address.
	MAC(dev string) (net.HardwareAddr, bool)
}

// Target is one capture: an L3 device and the network its frames belong to.
type Target struct {
	// Network is the network the frames are attributed to: the device's
	// network, or with several on one device (aliases) the first by name
	// that has an IPv4 address.
	Network string
	// Networks are every selected network on the device.
	Networks []string
	Device   string
}

// Skip is a network the selection named or auto found, and why it is not
// captured.
type Skip struct {
	Network string
	Device  string
	Reason  string
}

// Plan is the outcome of MakePlan.
type Plan struct {
	// Targets, one per L3 device, sorted by network name.
	Targets []Target
	// Skipped lists the selected networks that are not captured.
	Skipped []Skip
	// LAN are the LAN-side networks (not loopback, not WAN), sorted by
	// name: the networks report.
	LAN []observe.Interface
	// LANPrefixes are the prefixes of the LAN-side networks that are up
	// (addresses and assigned IPv6 prefixes), masked and deduplicated: what
	// counts as local.
	LANPrefixes []*net.IPNet
	// GatewayMACs are the MACs of the LAN-side L3 devices that exist (the
	// router's own on each network), sorted, deduplicated.
	GatewayMACs []net.HardwareAddr
}

// IsWAN reports whether the interface is on the WAN side: it holds a default
// route, sits in a masquerading firewall zone, or is a configured WAN.
func IsWAN(i observe.Interface, d Discovery, sel Selection) bool {
	if i.DefaultRoute || d.Masq[i.Network] {
		return true
	}
	for _, w := range sel.WAN {
		if w == i.Network || (i.Device != "" && w == i.Device) {
			return true
		}
	}
	return false
}

// autoProto are the protos auto selects: LAN side, the router's own address.
func autoProto(p string) bool { return p == "static" || p == "none" }

// MakePlan decides what to capture. It never selects a WAN, a device that
// is a bridge port (its bridge is the L3 device), or a device whose VLAN
// devices are captured as well (its frames would arrive twice, once tagged).
func MakePlan(d Discovery, sel Selection, sys SysNet) Plan {
	var p Plan
	byName := map[string]observe.Interface{}
	for _, i := range d.Interfaces {
		if i.Network == "loopback" || i.Device == "lo" {
			continue
		}
		if IsWAN(i, d, sel) {
			continue
		}
		byName[i.Network] = i
		p.LAN = append(p.LAN, i)
	}
	sort.Slice(p.LAN, func(a, b int) bool { return p.LAN[a].Network < p.LAN[b].Network })

	// Local prefixes and the router's MACs over every LAN-side network.
	seenPrefix := map[string]bool{}
	seenMAC := map[string]bool{}
	for _, i := range p.LAN {
		if !i.Up {
			continue
		}
		for _, a := range append(append(append([]string{}, i.IPv4...), i.IPv6...), i.IPv6Assigned...) {
			pr, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			pr = pr.Masked()
			if seenPrefix[pr.String()] {
				continue
			}
			seenPrefix[pr.String()] = true
			_, n, err := net.ParseCIDR(pr.String())
			if err == nil {
				p.LANPrefixes = append(p.LANPrefixes, n)
			}
		}
		if i.Device != "" && sys.Exists(i.Device) {
			if mac, ok := sys.MAC(i.Device); ok && len(mac) > 0 && !seenMAC[mac.String()] {
				seenMAC[mac.String()] = true
				p.GatewayMACs = append(p.GatewayMACs, mac)
			}
		}
	}
	sort.Slice(p.GatewayMACs, func(a, b int) bool { return p.GatewayMACs[a].String() < p.GatewayMACs[b].String() })

	excluded := map[string]bool{}
	for _, x := range sel.Exclude {
		excluded[x] = true
	}
	isExcluded := func(network, dev string) bool { return excluded[network] || (dev != "" && excluded[dev]) }

	// The selected (network, device) pairs.
	type pick struct {
		network, device string
		hasV4           bool
	}
	var picks []pick
	picked := map[string]bool{}
	add := func(network, dev string, hasV4 bool) {
		if picked[network] {
			return
		}
		picked[network] = true
		picks = append(picks, pick{network, dev, hasV4})
	}
	for _, want := range sel.Networks {
		if want == Auto {
			for _, i := range p.LAN {
				if !i.Up || i.Device == "" || !autoProto(i.Proto) || isExcluded(i.Network, i.Device) {
					continue
				}
				// A device with VLAN devices on it (a VLAN-filtering bridge)
				// carries their frames tagged: auto captures the VLAN
				// devices, never it, even when they are excluded.
				if ups := sys.Uppers(i.Device); len(ups) > 0 {
					sort.Strings(ups)
					p.Skipped = append(p.Skipped, Skip{Network: i.Network, Device: i.Device,
						Reason: "carries VLAN devices (" + strings.Join(ups, ", ") + "); auto captures those instead"})
					continue
				}
				add(i.Network, i.Device, len(i.IPv4) > 0)
			}
			continue
		}
		if isExcluded(want, "") {
			continue
		}
		if i, ok := byName[want]; ok {
			switch {
			case isExcluded(i.Network, i.Device):
			case !i.Up || i.Device == "":
				p.Skipped = append(p.Skipped, Skip{Network: want, Device: i.Device, Reason: "down"})
			default:
				add(i.Network, i.Device, len(i.IPv4) > 0)
			}
			continue
		}
		if isWANName(want, d, sel) {
			p.Skipped = append(p.Skipped, Skip{Network: want, Reason: "a WAN is never captured"})
			continue
		}
		// Not a netifd network: a device name (a host without netifd, or a
		// device no interface uses). Its network is its own name.
		if dev := deviceOfNetwork(want, p.LAN); dev != "" {
			add(want, dev, false)
			continue
		}
		if sys.Exists(want) {
			add(want, want, false)
			continue
		}
		p.Skipped = append(p.Skipped, Skip{Network: want, Reason: "no such network or device"})
	}

	// Drop what cannot be captured without double counting.
	devs := map[string]bool{}
	for _, k := range picks {
		devs[k.device] = true
	}
	var kept []pick
	for _, k := range picks {
		switch {
		case !sys.Exists(k.device):
			p.Skipped = append(p.Skipped, Skip{Network: k.network, Device: k.device, Reason: "device does not exist"})
			continue
		case sys.Master(k.device) != "":
			p.Skipped = append(p.Skipped, Skip{Network: k.network, Device: k.device, Reason: "port of " + sys.Master(k.device) + ", which is the L3 device"})
			continue
		}
		var captured []string
		for _, u := range sys.Uppers(k.device) {
			if devs[u] {
				captured = append(captured, u)
			}
		}
		if len(captured) > 0 {
			sort.Strings(captured)
			p.Skipped = append(p.Skipped, Skip{Network: k.network, Device: k.device,
				Reason: "carries " + strings.Join(captured, ", ") + ", captured on their own"})
			continue
		}
		kept = append(kept, k)
	}

	// One target per device.
	byDev := map[string]*Target{}
	primaryV4 := map[string]bool{}
	for _, k := range kept {
		t := byDev[k.device]
		if t == nil {
			t = &Target{Device: k.device}
			byDev[k.device] = t
		}
		t.Networks = append(t.Networks, k.network)
		if t.Network == "" || (k.hasV4 && !primaryV4[k.device]) || (k.hasV4 == primaryV4[k.device] && k.network < t.Network) {
			t.Network = k.network
			primaryV4[k.device] = k.hasV4
		}
	}
	for _, t := range byDev {
		sort.Strings(t.Networks)
		p.Targets = append(p.Targets, *t)
	}
	sort.Slice(p.Targets, func(a, b int) bool { return p.Targets[a].Network < p.Targets[b].Network })
	sort.Slice(p.Skipped, func(a, b int) bool { return p.Skipped[a].Network < p.Skipped[b].Network })
	return p
}

func isWANName(name string, d Discovery, sel Selection) bool {
	for _, i := range d.Interfaces {
		if (i.Network == name || i.Device == name) && IsWAN(i, d, sel) {
			return true
		}
	}
	for _, w := range sel.WAN {
		if w == name {
			return true
		}
	}
	return false
}

// deviceOfNetwork finds a LAN network by its device name and returns the
// device ("" when none uses it).
func deviceOfNetwork(dev string, lan []observe.Interface) string {
	for _, i := range lan {
		if i.Device == dev {
			return dev
		}
	}
	return ""
}

// NetworkOfDevice names the LAN network whose L3 device is dev, "" when
// none is (the single-interface collector's attribution).
func NetworkOfDevice(dev string, lan []observe.Interface) string {
	best := ""
	for _, i := range lan {
		if i.Device == dev && (best == "" || len(i.IPv4) > 0 && i.Network < best) {
			best = i.Network
		}
	}
	return best
}
