package qos

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// ParseLANs finds the router's LAN networks in `ubus call network.interface
// dump`: interfaces that are up, have an L3 device and an address, hold no
// default route, and are not in a masquerading (WAN) firewall zone. Each
// gets its exact prefixes (IPv4, IPv6 addresses and delegated prefix
// assignments) and the router's own addresses on it.
func ParseLANs(dump []byte, wanNetworks map[string]bool) ([]LAN, bool) {
	var doc struct {
		Interface []struct {
			Interface string `json:"interface"`
			Up        bool   `json:"up"`
			L3Device  string `json:"l3_device"`
			Device    string `json:"device"`
			Proto     string `json:"proto"`
			IPv4      []struct {
				Address string `json:"address"`
				Mask    int    `json:"mask"`
			} `json:"ipv4-address"`
			IPv6 []struct {
				Address string `json:"address"`
				Mask    int    `json:"mask"`
			} `json:"ipv6-address"`
			Assign []struct {
				Address string `json:"address"`
				Mask    int    `json:"mask"`
				Local   *struct {
					Address string `json:"address"`
					Mask    int    `json:"mask"`
				} `json:"local-address"`
			} `json:"ipv6-prefix-assignment"`
			Route []struct {
				Target string `json:"target"`
				Mask   int    `json:"mask"`
			} `json:"route"`
		} `json:"interface"`
	}
	if json.Unmarshal(dump, &doc) != nil {
		return nil, false
	}
	var out []LAN
	for _, it := range doc.Interface {
		dev := it.L3Device
		if dev == "" {
			dev = it.Device
		}
		if !it.Up || dev == "" || dev == "lo" || it.Interface == "loopback" || wanNetworks[it.Interface] || !validName(dev) {
			continue
		}
		wan := false
		for _, r := range it.Route {
			if r.Mask == 0 && (r.Target == "0.0.0.0" || r.Target == "::") {
				wan = true
			}
		}
		if wan {
			continue
		}
		l := LAN{Network: it.Interface, Device: dev}
		addPrefix := func(addr string, mask int, own bool) {
			a, err := netip.ParseAddr(addr)
			if err != nil || mask < 0 || mask > a.BitLen() {
				return
			}
			a = a.Unmap()
			if own {
				l.Addrs = append(l.Addrs, a)
			}
			l.Prefixes = append(l.Prefixes, netip.PrefixFrom(a, mask).Masked())
		}
		for _, a := range it.IPv4 {
			addPrefix(a.Address, a.Mask, true)
		}
		for _, a := range it.IPv6 {
			addPrefix(a.Address, a.Mask, true)
		}
		for _, a := range it.Assign {
			addPrefix(a.Address, a.Mask, false)
			if a.Local != nil {
				if ad, err := netip.ParseAddr(a.Local.Address); err == nil {
					l.Addrs = append(l.Addrs, ad.Unmap())
				}
			}
		}
		if len(l.Prefixes) == 0 {
			continue
		}
		l.Prefixes = uniqPrefixes(l.Prefixes)
		sort.Slice(l.Addrs, func(i, j int) bool { return l.Addrs[i].Less(l.Addrs[j]) })
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Network < out[j].Network })
	return out, true
}

// WANNetworks are the networks of the masquerading firewall zones
// (/etc/config/firewall): the router's WAN side, even while their default
// route is down.
func WANNetworks(firewall []byte) map[string]bool {
	out := map[string]bool{}
	secs, err := parseUCIFile(firewall)
	if err != nil {
		return out
	}
	for _, s := range secs {
		if s.Type != "zone" {
			continue
		}
		if v, _ := s.first("masq"); !uciBool(v, false) {
			continue
		}
		for _, n := range listOption(s, "network") {
			out[n] = true
		}
	}
	return out
}

// SQMQueue is one queue of /etc/config/sqm.
type SQMQueue struct {
	Section  string
	Device   string
	Enabled  bool
	Download int64
	Upload   int64
}

// ParseSQM reads /etc/config/sqm's queues.
func ParseSQM(data []byte) []SQMQueue {
	secs, err := parseUCIFile(data)
	if err != nil {
		return nil
	}
	var out []SQMQueue
	n := 0
	for _, s := range secs {
		if s.Type != "queue" {
			continue
		}
		q := SQMQueue{Section: s.Name}
		if q.Section == "" {
			q.Section = "@queue[" + strconv.Itoa(n) + "]"
		}
		n++
		q.Device, _ = s.first("interface")
		v, _ := s.first("enabled")
		q.Enabled = uciBool(v, false)
		q.Download, _ = kbitOption(s, "download", 0)
		q.Upload, _ = kbitOption(s, "upload", 0)
		out = append(out, q)
	}
	return out
}

// sqmIfb is the ifb sqm-scripts creates for a device's ingress: ifb4<dev>,
// cut to the 15 characters Linux allows.
func sqmIfb(dev string) string {
	n := "ifb4" + dev
	if len(n) > 15 {
		n = n[:15]
	}
	return n
}

// markSQMConflicts flags the LANs whose device has an enabled sqm queue:
// sqm's ingress qdisc and clsact exclude each other.
func markSQMConflicts(lans []LAN, queues []SQMQueue) {
	for i := range lans {
		for _, q := range queues {
			if q.Enabled && q.Device == lans[i].Device {
				lans[i].Conflict = "qos_conflict_sqm_on_lan"
			}
		}
	}
}

func validName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	return !strings.ContainsAny(s, " \t\n/'\"\\")
}
