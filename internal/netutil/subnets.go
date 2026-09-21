package netutil

import (
	"fmt"
	"net"
)

// InterfaceSubnets returns all IPv4/IPv6 CIDRs assigned to iface, normalized
// to their network address (e.g. 192.168.0.5/16 -> 192.168.0.0/16).
func InterfaceSubnets(iface string) ([]*net.IPNet, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("addrs for %s: %w", iface, err)
	}
	out := make([]*net.IPNet, 0, len(addrs))
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		out = append(out, &net.IPNet{
			IP:   ipnet.IP.Mask(ipnet.Mask),
			Mask: ipnet.Mask,
		})
	}
	return out, nil
}

// ParseCIDRs parses a list of CIDR strings into *net.IPNet. Empty strings
// are skipped silently so optional config slices can be passed through.
func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// MergeSubnets returns the deduplicated union of two *net.IPNet slices.
// Equality is by CIDR string form.
func MergeSubnets(a, b []*net.IPNet) []*net.IPNet {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]*net.IPNet, 0, len(a)+len(b))
	for _, list := range [][]*net.IPNet{a, b} {
		for _, n := range list {
			if n == nil {
				continue
			}
			k := n.String()
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, n)
		}
	}
	return out
}

// IsLocal returns true if ip is contained in any of subnets.
func IsLocal(ip net.IP, subnets []*net.IPNet) bool {
	for _, n := range subnets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
