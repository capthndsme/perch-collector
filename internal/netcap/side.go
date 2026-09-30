package netcap

import (
	"strings"

	"github.com/capthndsme/perch-collector/internal/observe"
)

// The side rule (gateway-sync protocol 8; the controller's
// gateway_config/domains/side.ts implements the same rule over UCI): which
// side of the router a network is on. Only LAN networks are captured, listed
// in the networks report and counted as local.
//
//  1. loopback: the network loopback or the device lo;
//  2. vpn: a tunnel proto (TunnelProtos), whatever else is true of it:
//     never captured, never local (its prefixes are not LAN prefixes);
//  3. wan: a WAN proto (WANProtos), a default route, a masquerading firewall
//     zone, a UCI gateway, or a configured WAN (wan_interfaces);
//  4. wan (an alias on an uplink): proto static or none on a device that a
//     rule-3 WAN uses (its L3 device or its UCI device), or on @<that WAN>:
//     a modem's management subnet on the WAN port;
//  5. lan otherwise.
//
// Before this rule a static network on a WAN device outside any zone (the
// alias of rule 4) counted as a LAN: listed as a LAN network, captured by
// auto, and its subnet local.

// Side is where a network sits.
type Side string

// Sides.
const (
	SideLoopback Side = "loopback"
	SideLAN      Side = "lan"
	SideWAN      Side = "wan"
	SideVPN      Side = "vpn"
)

// WANProtos are the netifd protos of an uplink.
var WANProtos = []string{"dhcp", "dhcpv6", "pppoe", "pppoa", "pptp", "l2tp", "3g", "qmi", "ncm", "mbim",
	"modemmanager", "wwan", "directip", "6in4", "6to4", "6rd", "dslite", "map", "464xlat"}

// TunnelProtos are the netifd protos of a tunnel.
var TunnelProtos = []string{"wireguard", "openvpn", "gre", "gretap", "grev6", "grev6tap", "vti", "vtiv6", "vxlan", "ipip", "xfrm"}

// IsWANProto reports whether a proto is an uplink's.
func IsWANProto(proto string) bool { return inList(WANProtos, proto) }

// IsTunnelProto reports whether a proto is a tunnel's.
func IsTunnelProto(proto string) bool { return inList(TunnelProtos, proto) }

func inList(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// devicesOf are the devices an interface uses: netifd's (L3) device and its
// UCI device option.
func devicesOf(i observe.Interface, d Discovery) []string {
	var out []string
	if i.Device != "" {
		out = append(out, i.Device)
	}
	if c := d.ConfDevice[i.Network]; c != "" && c != i.Device {
		out = append(out, c)
	}
	return out
}

// uplink is rule 3.
func uplink(i observe.Interface, d Discovery, sel Selection) bool {
	if IsWANProto(i.Proto) || i.DefaultRoute || d.Masq[i.Network] || d.Gateway[i.Network] {
		return true
	}
	for _, w := range sel.WAN {
		if w == i.Network || (i.Device != "" && w == i.Device) {
			return true
		}
	}
	return false
}

// Sides classifies every interface of a discovery by network name.
func Sides(d Discovery, sel Selection) map[string]Side {
	out := make(map[string]Side, len(d.Interfaces))
	wanDev := map[string]bool{}
	for _, i := range d.Interfaces {
		switch {
		case i.Network == "loopback" || i.Device == "lo":
			out[i.Network] = SideLoopback
		case IsTunnelProto(i.Proto):
			out[i.Network] = SideVPN
		case uplink(i, d, sel):
			out[i.Network] = SideWAN
			for _, dev := range devicesOf(i, d) {
				wanDev[dev] = true
			}
			wanDev["@"+i.Network] = true
		}
	}
	for _, i := range d.Interfaces {
		if _, ok := out[i.Network]; ok {
			continue
		}
		out[i.Network] = SideLAN
		if i.Proto != "static" && i.Proto != "none" {
			continue
		}
		for _, dev := range devicesOf(i, d) {
			if wanDev[dev] {
				out[i.Network] = SideWAN
				break
			}
		}
	}
	return out
}

// SideOf is one interface's side among the discovery's.
func SideOf(i observe.Interface, d Discovery, sel Selection) Side {
	found := false
	for _, x := range d.Interfaces {
		if x.Network == i.Network {
			found = true
			break
		}
	}
	if !found {
		d.Interfaces = append(append([]observe.Interface(nil), d.Interfaces...), i)
	}
	return Sides(d, sel)[i.Network]
}

// NetworkUCI reads what the side rule needs from UCI network: the
// interfaces with a gateway option, and each interface's device option
// (ifname on releases before 21.02).
func NetworkUCI(secs []observe.UCISection) (gateway map[string]bool, device map[string]string) {
	gateway, device = map[string]bool{}, map[string]string{}
	for _, s := range secs {
		if s.Type != "interface" || s.Anonymous() {
			continue
		}
		if s.First("gateway") != "" {
			gateway[s.Name] = true
		}
		dev := s.First("device")
		switch {
		case dev != "":
		case s.First("type") == "bridge":
			// Before 21.02 an interface of type bridge is br-<name>, and
			// ifname lists its ports.
			dev = "br-" + s.Name
		default:
			if f := strings.Fields(s.First("ifname")); len(f) > 0 {
				dev = f[0]
			}
		}
		if dev != "" {
			device[s.Name] = dev
		}
	}
	return gateway, device
}
