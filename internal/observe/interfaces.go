package observe

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Interface is one logical network of the router (`ubus call
// network.interface dump`), with what the WAN view needs: whether it holds
// a default route and at which metric. On a router with two WANs and no
// mwan3 (failover by metric) the lowest-metric default route that is up is
// the one in use.
type Interface struct {
	Network string   `json:"network"`
	Device  string   `json:"device,omitempty"`
	Proto   string   `json:"proto,omitempty"`
	Up      bool     `json:"up"`
	IPv4    []string `json:"ipv4"`
	IPv6    []string `json:"ipv6"`
	// UptimeSeconds since the interface came up (0 when down). Not part of
	// the fingerprint: it changes every second.
	UptimeSeconds int64 `json:"uptimeSeconds"`
	// DefaultRoute: the interface holds an IPv4 or IPv6 default route.
	DefaultRoute bool `json:"defaultRoute"`
	// Metric of the interface's routes (UCI `metric`), null when it holds none.
	Metric *int `json:"metric"`
	// Gateway4 / Gateway6 are the default routes' next hops.
	Gateway4   string   `json:"gateway4,omitempty"`
	Gateway6   string   `json:"gateway6,omitempty"`
	DNSServers []string `json:"dnsServers"`
	// Error is netifd's first error code for the interface, if any
	// ("NO_DEVICE", …).
	Error string `json:"error,omitempty"`
	// IPv6Assigned are the prefixes netifd assigned to this (LAN)
	// interface from a delegated prefix (ipv6-prefix-assignment), as
	// prefix/len. Not on the wire of the interfaces part (it predates
	// them); the multi-capture reconciler counts them as local.
	IPv6Assigned []string `json:"-"`
}

// MaxInterfaces caps the interfaces part.
const MaxInterfaces = 256

// ParseInterfaceDump reads `ubus call network.interface dump`. The loopback
// interface is left out.
func ParseInterfaceDump(data []byte) ([]Interface, bool) {
	var doc struct {
		Interface []struct {
			Interface string `json:"interface"`
			Up        bool   `json:"up"`
			Uptime    int64  `json:"uptime"`
			L3Device  string `json:"l3_device"`
			Device    string `json:"device"`
			Proto     string `json:"proto"`
			Metric    *int   `json:"metric"`
			IPv4      []struct {
				Address string `json:"address"`
				Mask    int    `json:"mask"`
			} `json:"ipv4-address"`
			IPv6 []struct {
				Address string `json:"address"`
				Mask    int    `json:"mask"`
			} `json:"ipv6-address"`
			Route []struct {
				Target  string `json:"target"`
				Mask    int    `json:"mask"`
				Nexthop string `json:"nexthop"`
			} `json:"route"`
			Assign []struct {
				Address string `json:"address"`
				Mask    int    `json:"mask"`
			} `json:"ipv6-prefix-assignment"`
			DNS    []string `json:"dns-server"`
			Errors []struct {
				Code string `json:"code"`
			} `json:"errors"`
		} `json:"interface"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil, false
	}
	out := []Interface{}
	for _, it := range doc.Interface {
		name := cleanName(it.Interface)
		if name == "" || name == "loopback" || it.Proto == "none" && it.L3Device == "lo" {
			continue
		}
		i := Interface{Network: name, Proto: cleanName(it.Proto), Up: it.Up, IPv4: []string{}, IPv6: []string{}, DNSServers: []string{}}
		i.Device = cleanName(it.L3Device)
		if i.Device == "" {
			i.Device = cleanName(it.Device)
		}
		if it.Up {
			i.UptimeSeconds = it.Uptime
		}
		for _, a := range it.IPv4 {
			if p, ok := prefixString(a.Address, a.Mask, false); ok && len(i.IPv4) < 32 {
				i.IPv4 = append(i.IPv4, p)
			}
		}
		for _, a := range it.IPv6 {
			if p, ok := prefixString(a.Address, a.Mask, true); ok && len(i.IPv6) < 32 {
				i.IPv6 = append(i.IPv6, p)
			}
		}
		for _, a := range it.Assign {
			if p, ok := prefixString(a.Address, a.Mask, true); ok && len(i.IPv6Assigned) < 32 {
				i.IPv6Assigned = append(i.IPv6Assigned, p)
			}
		}
		for _, r := range it.Route {
			if r.Mask != 0 {
				continue
			}
			switch r.Target {
			case "0.0.0.0":
				i.DefaultRoute = true
				if i.Gateway4 == "" {
					i.Gateway4 = cleanIP(r.Nexthop, false)
				}
			case "::":
				i.DefaultRoute = true
				if i.Gateway6 == "" {
					i.Gateway6 = cleanIP(r.Nexthop, true)
				}
			}
		}
		if len(it.Route) > 0 && it.Metric != nil {
			m := *it.Metric
			i.Metric = &m
		}
		for _, d := range it.DNS {
			ip := cleanIP(d, false)
			if ip == "" {
				ip = cleanIP(d, true)
			}
			if ip != "" && len(i.DNSServers) < 16 {
				i.DNSServers = append(i.DNSServers, ip)
			}
		}
		if len(it.Errors) > 0 {
			i.Error = cleanName(it.Errors[0].Code)
		}
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Network < out[b].Network })
	return capList(out, MaxInterfaces), true
}

func prefixString(addr string, mask int, v6 bool) (string, bool) {
	ip := cleanIP(addr, v6)
	if ip == "" {
		return "", false
	}
	max := 32
	if v6 {
		max = 128
	}
	if mask < 0 || mask > max {
		return "", false
	}
	return ip + "/" + strconv.Itoa(mask), true
}

// Subnet is one network's address range, for tagging leases.
type Subnet struct {
	Network string
	Prefix  netip.Prefix
}

// Subnets are the IPv4 and IPv6 prefixes of the interfaces that are up.
func Subnets(list []Interface) []Subnet {
	var out []Subnet
	for _, i := range list {
		if !i.Up {
			continue
		}
		for _, a := range append(append([]string{}, i.IPv4...), i.IPv6...) {
			if p, err := netip.ParsePrefix(a); err == nil {
				out = append(out, Subnet{Network: i.Network, Prefix: p.Masked()})
			}
		}
	}
	return out
}

// networkOf names the network whose subnet holds ip: the longest prefix
// wins; "" when none does.
func networkOf(nets []Subnet, ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	best, bits := "", -1
	for _, n := range nets {
		if n.Prefix.Contains(a) && n.Prefix.Bits() > bits {
			best, bits = n.Network, n.Prefix.Bits()
		}
	}
	return best
}

func subnetsKey(nets []Subnet) string {
	parts := make([]string, 0, len(nets))
	for _, n := range nets {
		parts = append(parts, n.Network+"="+n.Prefix.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// InterfaceReader asks netifd for the interfaces, at most every MinAge (a
// ubus call costs a fork); between those it answers from its cache.
type InterfaceReader struct {
	Env *Env
	// MinAge between two ubus calls; 0 = 5 s.
	MinAge time.Duration

	mu   sync.Mutex
	at   time.Time
	last []Interface
	ok   bool
}

// Read returns the interfaces; ok is false when netifd never answered.
func (r *InterfaceReader) Read() ([]Interface, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	min := r.MinAge
	if min <= 0 {
		min = 5 * time.Second
	}
	now := r.Env.now()
	if !r.at.IsZero() && now.Sub(r.at) < min {
		return r.last, r.ok
	}
	r.at = now
	if out, err := r.Env.run("ubus", "call", "network.interface", "dump"); err == nil {
		if list, ok := ParseInterfaceDump(out); ok {
			r.last, r.ok = list, true
		}
	}
	return r.last, r.ok
}

// Subnets is Subnets(Read()), for the DHCP reader's lease tagging.
func (r *InterfaceReader) Subnets() []Subnet {
	list, _ := r.Read()
	return Subnets(list)
}

// Interfaces asks netifd for its interfaces right now (`ubus call
// network.interface dump`), uncached; ok is false when netifd did not
// answer or the answer did not parse.
func (e *Env) Interfaces() ([]Interface, bool) {
	out, err := e.run("ubus", "call", "network.interface", "dump")
	if err != nil {
		return nil, false
	}
	return ParseInterfaceDump(out)
}

// UCI runs `uci -q show <pkg>` and parses it; ok is false when uci failed.
func (e *Env) UCI(pkg string) ([]UCISection, bool) { return e.uciShow(pkg) }
