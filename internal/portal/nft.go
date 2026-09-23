package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Perch-owned nftables enforcement (owner decision 27; controller repo
// docs/design amendment-opennds §13). Two tables, both outside fw4's, so
// `fw4 reload` and `/etc/init.d/firewall restart` leave them alone:
//
//   - table inet perch_portal: per portal an authorised-MAC set, the port-80
//     redirect to the guest pages, the walled garden (dnsmasq nftset= fills
//     the timeout sets), the forward gate (IPv4 and IPv6 in one pass), and the
//     input gate (DNS with a per-MAC rate limit before authorisation, DHCP,
//     DHCPv6 when enabled, the pages' port, ICMP; nothing else);
//   - table inet perch_portal_acct: counting and the data cut. Upload is
//     counted per source MAC, download per destination address, traffic to
//     and from the router itself excluded (below). Data quotas are cut here
//     too, exactly: one named `quota` object per group with a data quota
//     (over the bytes the group has left), shared by its devices through a
//     per-portal MAC → quota map (upload) and address → quota maps
//     (download), and rules before the counters that drop a device's
//     packets once its group's quota is used up (upload and download
//     together, like the group's quota). The tick still ends the grant,
//     flushes its connections and reports it;
//   - table netdev perch_portal_fast (kernels with the netdev egress hook):
//     the download the flowtable fast path carries past the IP hooks,
//     counted per destination MAC on the portal device's egress.
//
// Why the counting sits on the IP hooks (2026-09-24). Shaping redirects
// packets through an ifb: sqm's WAN ingress (every download) and
// perch-qos's LAN clsact hooks (a shaped device's upload). The kernel
// re-injects such a packet with the netdev hooks switched off
// (nf_skip_egress, tc_skip_classify): a netdev egress chain on the portal
// device never sees an sqm-shaped download, a netdev ingress chain never
// sees a perch-qos-shaped upload. The lab counted 1.4 kB of a 25 MB
// download that way. Every forwarded packet the slow path carries passes
// prerouting and postrouting, shaped or not, so:
//
//   - upload: prerouting (priority -350), keyed by `ether saddr`;
//   - download: postrouting (priority 350, after the filter), keyed by the
//     destination address. The router knows a device's addresses from its
//     own upload: the upload rule learns `address` and `address . MAC`
//     (dynamic sets, refreshed by traffic) and the tick gives each
//     address's bytes to the MAC that used it last;
//   - the flowtable fast path (fw4 flow offloading) skips both IP hooks.
//     Upload is counted before it anyway: an inet ingress chain on the
//     portal device (priority -500, before the flowtable's hook) counts and
//     marks the packet (CountedMark), and prerouting skips marked packets
//     (and clears the bit before routing sees it). Download on the fast
//     path passes only the portal device's netdev egress: postrouting marks
//     what it counted, and the egress chain counts the unmarked rest per
//     MAC (and clears the bit). The fast path's download is charged by the
//     tick, not by the kernel quota: within one tick of the cut.
//
// fw4's own input chain still has the last word on the router's ports, so
// a drop-in at /usr/share/nftables.d/chain-pre/input/ accepts the portal's
// ports on the portal devices (fw4 includes it on every reload).

// Table names.
const (
	TableInet = "perch_portal"
	// TableAcct counts and cuts (family inet). Before 2026-09-24 a netdev
	// table of the same name did; the first full render removes it.
	TableAcct = "perch_portal_acct"
	// TableFast counts the flowtable fast path's download (family netdev).
	TableFast = "perch_portal_fast"
)

// CountedMark is the packet mark bit the counting passes between the hooks
// (above): set on a packet one chain counted, cleared by the next. It is
// cleared before routing on upload and on the portal device on download, so
// policy routing (mwan3 0x3f00, pbr 0x00ff0000) never sees it.
const CountedMark uint32 = 0x10000000

// addrTimeout is how long a learned address (and its counter) outlives the
// device's last packet.
const addrTimeout = "2h"

var ifnameRe = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,15}$`)

// ValidIfname reports whether a device name is safe to render.
func ValidIfname(s string) bool { return ifnameRe.MatchString(s) }

// PortalSpec is one portal's part of the ruleset.
type PortalSpec struct {
	ID     int64
	Device string
	// Counting: the device exists now, so its netdev chains can be created.
	Counting bool
	Port     int
	// Auth are the authorised MACs.
	Auth []string
	// IPBinding: IPv4 forwarding needs the MAC with its learned address.
	IPBinding bool
	Bind      []MACIP
	// Walled garden: static networks, and carried-over dynamic elements.
	WalledNets4, WalledNets6 []string
	WG4, WG6                 []string
	// DNSPerMinute limits pre-auth DNS per MAC (decision 24); 0 = off.
	DNSPerMinute int
	// DHCPv6 opens 547 on the input gate.
	DHCPv6 bool
	// Quota maps a MAC to the name of its group's quota object (only MACs
	// whose current grant's group has a data quota).
	Quota map[string]string
	// QuotaAddrs maps those MACs' addresses (IPv4 and IPv6) to the same
	// objects: the download direction's cut.
	QuotaAddrs map[string]string
	// Learned are the addresses the authorised devices were seen using,
	// carried over a full render so download counting goes on at once.
	Learned []MACIP
}

// QuotaSpec is one kernel quota object: a group's remaining bytes.
type QuotaSpec struct {
	Name  string
	Bytes int64
}

// MACIP is one binding element.
type MACIP struct {
	MAC string
	IP  string
}

// RulesetSpec is the whole ruleset.
type RulesetSpec struct {
	Portals []PortalSpec
	// Local4/Local6 are the router's own addresses (excluded from counting).
	Local4, Local6 []string
	// Egress: the kernel has the netdev egress hook (5.16+): the fast
	// path's download is counted (TableFast).
	Egress bool
	// Ingress: the kernel has the inet ingress hook (5.10+): the fast
	// path's upload is counted before the flowtable takes it.
	Ingress bool
	// Mark is the counted bit (0 = CountedMark).
	Mark uint32
	// Quota: the kernel has named quotas and object maps (nft_quota,
	// nft_objref): the data cut is rendered. Quotas are the objects.
	Quota  bool
	Quotas []QuotaSpec
}

// quotaMapName is a portal's MAC → quota object map.
func quotaMapName(id int64) string { return setName(id, "quota") }

// quotaAddrMapName is a portal's address → quota object map of one family.
func quotaAddrMapName(id int64, v6 bool) string {
	if v6 {
		return setName(id, "quota6")
	}
	return setName(id, "quota4")
}

// isV6 reports whether an address string is IPv6.
func isV6(ip string) bool { return strings.Contains(ip, ":") }

// quotaMapElems renders a MAC → quota map's elements, sorted by MAC.
func quotaMapElems(m map[string]string) []string {
	macs := make([]string, 0, len(m))
	for mac := range m {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	out := make([]string, len(macs))
	for i, mac := range macs {
		out[i] = mac + " : " + quote(m[mac])
	}
	return out
}

func setName(id int64, what string) string { return "p" + strconv.FormatInt(id, 10) + "_" + what }

func quote(s string) string { return `"` + s + `"` }

func elements(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return "\t\telements = { " + strings.Join(list, ", ") + " }\n"
}

// sortedCopy returns the list sorted and de-duplicated.
func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	j := 0
	for i, s := range out {
		if i == 0 || s != out[j-1] {
			out[j] = s
			j++
		}
	}
	return out[:j]
}

// RenderInet renders the inet table (full replacement script: create,
// delete, create again, all in one nft transaction).
func RenderInet(spec RulesetSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", TableInet, TableInet, TableInet)
	portals := sortedPortals(spec.Portals)
	for _, p := range portals {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr\n%s\t}\n", setName(p.ID, "auth"), elements(sortedCopy(p.Auth)))
		if p.IPBinding {
			var el []string
			for _, x := range p.Bind {
				el = append(el, x.MAC+" . "+x.IP)
			}
			fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr . ipv4_addr\n%s\t}\n", setName(p.ID, "bind4"), elements(sortedCopy(el)))
		}
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tsize 8192\n\t\tflags timeout\n\t\ttimeout 1h\n%s\t}\n", setName(p.ID, "wg4"), elements(sortedCopy(p.WG4)))
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv6_addr\n\t\tsize 8192\n\t\tflags timeout\n\t\ttimeout 1h\n%s\t}\n", setName(p.ID, "wg6"), elements(sortedCopy(p.WG6)))
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n%s\t}\n", setName(p.ID, "wgnet4"), elements(sortedCopy(p.WalledNets4)))
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n%s\t}\n", setName(p.ID, "wgnet6"), elements(sortedCopy(p.WalledNets6)))
		if p.DNSPerMinute > 0 {
			fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr\n\t\tsize 4096\n\t\tflags dynamic,timeout\n\t\ttimeout 2m\n\t}\n", setName(p.ID, "dns"))
		}
	}

	b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat - 5; policy accept;\n")
	for _, p := range portals {
		fmt.Fprintf(&b, "\t\tiifname %s jump %s\n", quote(p.Device), setName(p.ID, "dstnat"))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter - 5; policy accept;\n")
	for _, p := range portals {
		fmt.Fprintf(&b, "\t\tiifname %s jump %s\n", quote(p.Device), setName(p.ID, "forward"))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter - 5; policy accept;\n")
	for _, p := range portals {
		fmt.Fprintf(&b, "\t\tiifname %s jump %s\n", quote(p.Device), setName(p.ID, "input"))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain reject_guest {\n\t\tmeta l4proto tcp reject with tcp reset\n\t\treject with icmpx admin-prohibited\n\t}\n")

	for _, p := range portals {
		auth := "@" + setName(p.ID, "auth")
		walled := func(indent string) {
			fmt.Fprintf(&b, "%sip daddr @%s return\n", indent, setName(p.ID, "wg4"))
			fmt.Fprintf(&b, "%sip daddr @%s return\n", indent, setName(p.ID, "wgnet4"))
			fmt.Fprintf(&b, "%sip6 daddr @%s return\n", indent, setName(p.ID, "wg6"))
			fmt.Fprintf(&b, "%sip6 daddr @%s return\n", indent, setName(p.ID, "wgnet6"))
		}
		// Port 80 of anyone not authorised goes to the guest pages, except
		// towards the walled garden.
		fmt.Fprintf(&b, "\tchain %s {\n", setName(p.ID, "dstnat"))
		fmt.Fprintf(&b, "\t\tether saddr %s return\n", auth)
		b.WriteString("\t\ttcp dport != 80 return\n")
		walled("\t\t")
		fmt.Fprintf(&b, "\t\ttcp dport 80 redirect to :%d\n\t}\n", p.Port)

		fmt.Fprintf(&b, "\tchain %s {\n", setName(p.ID, "forward"))
		if p.IPBinding {
			fmt.Fprintf(&b, "\t\tether saddr . ip saddr @%s return\n", setName(p.ID, "bind4"))
			fmt.Fprintf(&b, "\t\tmeta nfproto ipv6 ether saddr %s return\n", auth)
		} else {
			fmt.Fprintf(&b, "\t\tether saddr %s return\n", auth)
		}
		walled("\t\t")
		b.WriteString("\t\tjump reject_guest\n\t}\n")

		fmt.Fprintf(&b, "\tchain %s {\n", setName(p.ID, "input"))
		b.WriteString("\t\tct state related accept\n")
		if p.DNSPerMinute > 0 {
			fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } th dport 53 ether saddr != %s update @%s { ether saddr limit rate over %d/minute burst %d packets } drop\n",
				auth, setName(p.ID, "dns"), p.DNSPerMinute, dnsBurst(p.DNSPerMinute))
		}
		b.WriteString("\t\tmeta l4proto { tcp, udp } th dport 53 accept\n")
		b.WriteString("\t\tudp dport 67 accept\n")
		if p.DHCPv6 {
			b.WriteString("\t\tudp dport 547 accept\n")
		}
		fmt.Fprintf(&b, "\t\ttcp dport %d accept\n", p.Port)
		b.WriteString("\t\ticmp type { echo-request, echo-reply } accept\n")
		b.WriteString("\t\ticmpv6 type { echo-request, echo-reply, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept\n")
		b.WriteString("\t\tjump reject_guest\n\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func dnsBurst(perMinute int) int {
	b := perMinute / 2
	if b < 10 {
		b = 10
	}
	return b
}

func sortedPortals(in []PortalSpec) []PortalSpec {
	out := append([]PortalSpec(nil), in...)
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

func (spec RulesetSpec) mark() uint32 {
	if spec.Mark != 0 {
		return spec.Mark
	}
	return CountedMark
}

// RenderAcct renders the counting table (full replacement script). It also
// removes the netdev counting table of collectors before 2026-09-24.
// Portals without a present device count nothing (Counting false).
func RenderAcct(spec RulesetSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table netdev %s\ndelete table netdev %s\n", TableAcct, TableAcct)
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", TableAcct, TableAcct, TableAcct)
	local4 := append(append([]string(nil), spec.Local4...), "224.0.0.0/4", "255.255.255.255")
	local6 := append(append([]string(nil), spec.Local6...), "fe80::/10", "ff00::/8")
	fmt.Fprintf(&b, "\tset local4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n%s\t}\n", elements(sortedCopy(local4)))
	fmt.Fprintf(&b, "\tset local6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n%s\t}\n", elements(sortedCopy(local6)))
	if spec.Quota {
		quotas := append([]QuotaSpec(nil), spec.Quotas...)
		sort.Slice(quotas, func(a, b int) bool { return quotas[a].Name < quotas[b].Name })
		for _, q := range quotas {
			fmt.Fprintf(&b, "\tquota %s {\n\t\tover %d bytes\n\t}\n", q.Name, nonNegative(q.Bytes))
		}
	}
	portals := sortedPortals(spec.Portals)
	learned := func(name, typ string, counter bool, elems []string) {
		ctr := ""
		if counter {
			ctr = "\t\tcounter\n"
		}
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tsize 65535\n\t\tflags dynamic,timeout\n\t\ttimeout %s\n%s%s\t}\n",
			name, typ, addrTimeout, ctr, elements(sortedCopy(elems)))
	}
	for _, p := range portals {
		if !p.Counting {
			continue
		}
		id := p.ID
		auth := sortedCopy(p.Auth)
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr\n%s\t}\n", setName(id, "ok"), elements(auth))
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr\n\t\tcounter\n%s\t}\n", setName(id, "up"), elements(auth))
		var ip4, ip6, a4, a6 []string
		for _, l := range p.Learned {
			if isV6(l.IP) {
				ip6, a6 = append(ip6, l.IP), append(a6, l.IP+" . "+l.MAC)
			} else {
				ip4, a4 = append(ip4, l.IP), append(a4, l.IP+" . "+l.MAC)
			}
		}
		learned(setName(id, "ip4"), "ipv4_addr", false, ip4)
		learned(setName(id, "ip6"), "ipv6_addr", false, ip6)
		learned(setName(id, "a4"), "ipv4_addr . ether_addr", false, a4)
		learned(setName(id, "a6"), "ipv6_addr . ether_addr", false, a6)
		learned(setName(id, "d4"), "ipv4_addr", true, nil)
		learned(setName(id, "d6"), "ipv6_addr", true, nil)
		if spec.Quota {
			fmt.Fprintf(&b, "\tmap %s {\n\t\ttype ether_addr : quota\n%s\t}\n", quotaMapName(id), elements(quotaMapElems(p.Quota)))
			v4, v6 := map[string]string{}, map[string]string{}
			for ip, q := range p.QuotaAddrs {
				if isV6(ip) {
					v6[ip] = q
				} else {
					v4[ip] = q
				}
			}
			fmt.Fprintf(&b, "\tmap %s {\n\t\ttype ipv4_addr : quota\n%s\t}\n", quotaAddrMapName(id, false), elements(quotaMapElems(v4)))
			fmt.Fprintf(&b, "\tmap %s {\n\t\ttype ipv6_addr : quota\n%s\t}\n", quotaAddrMapName(id, true), elements(quotaMapElems(v6)))
		}
	}
	mark := spec.mark()
	for _, p := range portals {
		if !p.Counting {
			continue
		}
		id := p.ID
		// Upload, from either hook: the router's own addresses are not
		// usage; the cut before the counter (a dropped packet is not usage);
		// the addresses an authorised device uses are learned.
		fmt.Fprintf(&b, "\tchain %s {\n", setName(id, "up"))
		b.WriteString("\t\tip daddr @local4 return\n\t\tip6 daddr @local6 return\n")
		if spec.Quota {
			fmt.Fprintf(&b, "\t\tquota name ether saddr map @%s drop\n", quotaMapName(id))
		}
		fmt.Fprintf(&b, "\t\tether saddr @%s\n", setName(id, "up"))
		fmt.Fprintf(&b, "\t\tether saddr @%s update @%s { ip saddr } update @%s { ip saddr . ether saddr }\n",
			setName(id, "ok"), setName(id, "ip4"), setName(id, "a4"))
		fmt.Fprintf(&b, "\t\tether saddr @%s update @%s { ip6 saddr } update @%s { ip6 saddr . ether saddr }\n",
			setName(id, "ok"), setName(id, "ip6"), setName(id, "a6"))
		b.WriteString("\t}\n")
		if spec.Ingress {
			fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook ingress device %s priority -500; policy accept;\n", setName(id, "ingress"), quote(p.Device))
			fmt.Fprintf(&b, "\t\tmeta mark set meta mark or 0x%08x jump %s\n\t}\n", mark, setName(id, "up"))
		}
		// Download: after the filter; what the fast path's egress chain must
		// not count again is marked first (the router's own traffic too).
		fmt.Fprintf(&b, "\tchain %s {\n", setName(id, "down"))
		if spec.Egress {
			fmt.Fprintf(&b, "\t\tmeta mark set meta mark or 0x%08x\n", mark)
		}
		b.WriteString("\t\tip saddr @local4 return\n\t\tip6 saddr @local6 return\n")
		if spec.Quota {
			fmt.Fprintf(&b, "\t\tquota name ip daddr map @%s drop\n", quotaAddrMapName(id, false))
			fmt.Fprintf(&b, "\t\tquota name ip6 daddr map @%s drop\n", quotaAddrMapName(id, true))
		}
		fmt.Fprintf(&b, "\t\tip daddr @%s update @%s { ip daddr }\n", setName(id, "ip4"), setName(id, "d4"))
		fmt.Fprintf(&b, "\t\tip6 daddr @%s update @%s { ip6 daddr }\n", setName(id, "ip6"), setName(id, "d6"))
		b.WriteString("\t}\n")
	}
	b.WriteString("\tchain prerouting {\n\t\ttype filter hook prerouting priority -350; policy accept;\n")
	for _, p := range portals {
		if !p.Counting {
			continue
		}
		if spec.Ingress {
			// Counted on the ingress hook already.
			fmt.Fprintf(&b, "\t\tiifname %s meta mark and 0x%08x == 0x%08x meta mark set meta mark and 0x%08x accept\n",
				quote(p.Device), mark, mark, ^mark)
		}
		fmt.Fprintf(&b, "\t\tiifname %s jump %s\n", quote(p.Device), setName(p.ID, "up"))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain postrouting {\n\t\ttype filter hook postrouting priority 350; policy accept;\n")
	for _, p := range portals {
		if p.Counting {
			fmt.Fprintf(&b, "\t\toifname %s jump %s\n", quote(p.Device), setName(p.ID, "down"))
		}
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// RenderFast renders the fast-path table (full replacement script); without
// the egress hook it only removes it.
func RenderFast(spec RulesetSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table netdev %s\ndelete table netdev %s\n", TableFast, TableFast)
	if !spec.Egress {
		return b.String()
	}
	fmt.Fprintf(&b, "table netdev %s {\n", TableFast)
	portals := sortedPortals(spec.Portals)
	for _, p := range portals {
		if p.Counting {
			fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr\n\t\tcounter\n%s\t}\n", setName(p.ID, "fdown"), elements(sortedCopy(p.Auth)))
		}
	}
	mark := spec.mark()
	for _, p := range portals {
		if !p.Counting {
			continue
		}
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook egress device %s priority -500; policy accept;\n", setName(p.ID, "egress"), quote(p.Device))
		fmt.Fprintf(&b, "\t\tmeta mark and 0x%08x == 0x%08x meta mark set meta mark and 0x%08x return\n", mark, mark, ^mark)
		b.WriteString("\t\tmeta protocol != { ip, ip6 } return\n")
		fmt.Fprintf(&b, "\t\tether daddr @%s\n\t}\n", setName(p.ID, "fdown"))
	}
	b.WriteString("}\n")
	return b.String()
}

// RenderDeleteAll removes every Perch portal table (portal off / no portals).
func RenderDeleteAll() string {
	return fmt.Sprintf("table inet %s\ndelete table inet %s\ntable inet %s\ndelete table inet %s\n"+
		"table netdev %s\ndelete table netdev %s\ntable netdev %s\ndelete table netdev %s\n",
		TableInet, TableInet, TableAcct, TableAcct, TableFast, TableFast, TableAcct, TableAcct)
}

// ElementOps is one transaction of set element changes.
type ElementOps struct {
	b strings.Builder
}

func (o *ElementOps) add(family, table, set, elem string) {
	fmt.Fprintf(&o.b, "add element %s %s %s { %s }\n", family, table, set, elem)
}

// del removes an element whether or not it is there: `add` is idempotent
// and makes the `delete` in the same transaction always succeed (`destroy
// element` needs nft 1.0.8 and kernel 6.3, which 23.05 lacks).
func (o *ElementOps) del(family, table, set, elem string) {
	fmt.Fprintf(&o.b, "add element %s %s %s { %s }\n", family, table, set, elem)
	fmt.Fprintf(&o.b, "delete element %s %s %s { %s }\n", family, table, set, elem)
}

// Counting is which counting sets a portal has.
type Counting struct {
	// Acct: the counting table (the portal's device exists).
	Acct bool
	// Fast: the fast-path table too (the kernel has the egress hook).
	Fast bool
}

// Authorize adds a MAC to a portal's sets (counting too, when it counts).
func (o *ElementOps) Authorize(p int64, mac string, c Counting) {
	o.add("inet", TableInet, setName(p, "auth"), mac)
	if c.Acct {
		o.add("inet", TableAcct, setName(p, "ok"), mac)
		o.add("inet", TableAcct, setName(p, "up"), mac)
	}
	if c.Acct && c.Fast {
		o.add("netdev", TableFast, setName(p, "fdown"), mac)
	}
}

// Deauthorize removes a MAC from a portal's sets. The addresses it used
// stay learned until they time out: download to them is counted but
// belongs to no live grant.
func (o *ElementOps) Deauthorize(p int64, mac string, c Counting) {
	o.del("inet", TableInet, setName(p, "auth"), mac)
	if c.Acct {
		o.del("inet", TableAcct, setName(p, "ok"), mac)
		o.del("inet", TableAcct, setName(p, "up"), mac)
	}
	if c.Acct && c.Fast {
		o.del("netdev", TableFast, setName(p, "fdown"), mac)
	}
}

// Bind adds a MAC . IPv4 binding.
func (o *ElementOps) Bind(p int64, mac, ip string) {
	o.add("inet", TableInet, setName(p, "bind4"), mac+" . "+ip)
}

// Unbind removes one.
func (o *ElementOps) Unbind(p int64, mac, ip string) {
	o.del("inet", TableInet, setName(p, "bind4"), mac+" . "+ip)
}

// WalledAddress adds a resolved walled-garden address (fallback without
// dnsmasq nftset support).
func (o *ElementOps) WalledAddress(p int64, ip netip.Addr) {
	if ip.Is4() {
		o.add("inet", TableInet, setName(p, "wg4"), ip.String())
	} else {
		o.add("inet", TableInet, setName(p, "wg6"), ip.String())
	}
}

// AddQuota creates a quota object: over `bytes` bytes, nothing used yet.
func (o *ElementOps) AddQuota(name string, bytes int64) {
	fmt.Fprintf(&o.b, "add quota inet %s %s { over %d bytes }\n", TableAcct, name, nonNegative(bytes))
}

// DeleteQuota removes a quota object nothing refers to any more.
func (o *ElementOps) DeleteQuota(name string) {
	fmt.Fprintf(&o.b, "delete quota inet %s %s\n", TableAcct, name)
}

// MapQuota points a MAC at a quota object (the MAC is not in the map).
func (o *ElementOps) MapQuota(p int64, mac, name string) {
	fmt.Fprintf(&o.b, "add element inet %s %s { %s : %s }\n", TableAcct, quotaMapName(p), mac, quote(name))
}

// UnmapQuota removes a MAC from a portal's quota map (it is there).
func (o *ElementOps) UnmapQuota(p int64, mac string) {
	fmt.Fprintf(&o.b, "delete element inet %s %s { %s }\n", TableAcct, quotaMapName(p), mac)
}

// MapQuotaAddr points an address at a quota object (it is not in the map).
func (o *ElementOps) MapQuotaAddr(p int64, ip, name string) {
	fmt.Fprintf(&o.b, "add element inet %s %s { %s : %s }\n", TableAcct, quotaAddrMapName(p, isV6(ip)), ip, quote(name))
}

// UnmapQuotaAddr removes an address from a portal's quota map (it is there).
func (o *ElementOps) UnmapQuotaAddr(p int64, ip string) {
	fmt.Fprintf(&o.b, "delete element inet %s %s { %s }\n", TableAcct, quotaAddrMapName(p, isV6(ip)), ip)
}

// Append adds another transaction's text after this one's.
func (o *ElementOps) Append(other *ElementOps) {
	if other != nil {
		o.b.WriteString(other.b.String())
	}
}

func nonNegative(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// Script is the transaction text.
func (o *ElementOps) Script() string { return o.b.String() }

// Empty reports whether nothing was queued.
func (o *ElementOps) Empty() bool { return o.b.Len() == 0 }

// NFT runs nft.
type NFT interface {
	// Apply runs a script as one transaction (nft -f -).
	Apply(script string) error
	// ListJSON runs nft -j list <args...>.
	ListJSON(args ...string) ([]byte, error)
}

// ExecNFT is the nft binary.
type ExecNFT struct{ Path string }

func (n ExecNFT) bin() string {
	if n.Path != "" {
		return n.Path
	}
	return "nft"
}

// Apply implements NFT.
func (n ExecNFT) Apply(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.bin(), "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, firstLines(out.String(), 6))
	}
	return nil
}

// ListJSON implements NFT.
func (n ExecNFT) ListJSON(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.bin(), append([]string{"-j", "list"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, &ListError{Missing: strings.Contains(stderr.String(), "No such file or directory"), Msg: firstLines(stderr.String(), 3)}
	}
	return out, nil
}

// ListError is a failed nft list; Missing = the table or set does not exist.
type ListError struct {
	Missing bool
	Msg     string
}

func (e *ListError) Error() string { return "nft list: " + e.Msg }

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}

// Counter is one element's counter.
type Counter struct {
	Packets int64
	Bytes   int64
}

// SetContents is a parsed set: its elements and their counters (and, for
// a map, each key's value).
type SetContents struct {
	Elements []string
	Counters map[string]Counter
	Values   map[string]string
	// Expires is a dynamic element's time left in seconds (the larger, the
	// more recently the traffic refreshed it).
	Expires map[string]int64
}

// QuotaUse is a quota object as the kernel reports it.
type QuotaUse struct {
	Bytes int64 // the limit (over)
	Used  int64 // consumed so far, dropped packets included
}

// Over reports whether the quota is used up (the drop rule fires).
func (q QuotaUse) Over() bool { return q.Used >= q.Bytes }

// ParseQuotasJSON reads the quota objects of `nft -j list table ...`.
func ParseQuotasJSON(data []byte) (map[string]QuotaUse, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := map[string]QuotaUse{}
	for _, item := range doc.Nftables {
		raw, ok := item["quota"]
		if !ok {
			continue
		}
		var q struct {
			Name  string `json:"name"`
			Bytes int64  `json:"bytes"`
			Used  int64  `json:"used"`
		}
		if err := json.Unmarshal(raw, &q); err != nil {
			return nil, err
		}
		out[q.Name] = QuotaUse{Bytes: q.Bytes, Used: q.Used}
	}
	return out, nil
}

// ParseTableJSON parses `nft -j list table ...` into its sets.
func ParseTableJSON(data []byte) (map[string]SetContents, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := map[string]SetContents{}
	for _, item := range doc.Nftables {
		raw, ok := item["set"]
		if !ok {
			raw, ok = item["map"]
		}
		if !ok {
			continue
		}
		var s struct {
			Name string            `json:"name"`
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		sc := SetContents{Counters: map[string]Counter{}, Values: map[string]string{}, Expires: map[string]int64{}}
		for _, e := range s.Elem {
			// A map element is [key, value].
			var pair []json.RawMessage
			if json.Unmarshal(e, &pair) == nil && len(pair) == 2 {
				k, _, ok1 := parseElem(pair[0])
				var v string
				if ok1 && json.Unmarshal(pair[1], &v) == nil {
					sc.Elements = append(sc.Elements, k)
					sc.Values[k] = v
				}
				continue
			}
			val, ctr, ok := parseElem(e)
			if !ok {
				continue
			}
			sc.Elements = append(sc.Elements, val)
			if ctr != nil {
				sc.Counters[val] = *ctr
			}
			if exp, ok := elemExpires(e); ok {
				sc.Expires[val] = exp
			}
		}
		out[s.Name] = sc
	}
	return out, nil
}

// elemExpires reads a dynamic element's "expires" (seconds left).
func elemExpires(raw json.RawMessage) (int64, bool) {
	var obj struct {
		Elem *struct {
			Expires *int64 `json:"expires"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &obj) != nil || obj.Elem == nil || obj.Elem.Expires == nil {
		return 0, false
	}
	return *obj.Elem.Expires, true
}

// parseElem reads one element: a plain value ("02:00:.."), a concatenation
// ({"concat": [...]}), a prefix, or {"elem": {"val": ..., "counter": ...}}.
func parseElem(raw json.RawMessage) (string, *Counter, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, nil, true
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return "", nil, false
	}
	if inner, ok := obj["elem"]; ok {
		var e struct {
			Val     json.RawMessage `json:"val"`
			Counter *struct {
				Packets int64 `json:"packets"`
				Bytes   int64 `json:"bytes"`
			} `json:"counter"`
		}
		if json.Unmarshal(inner, &e) != nil {
			return "", nil, false
		}
		v, _, ok := parseElem(e.Val)
		if !ok {
			return "", nil, false
		}
		if e.Counter != nil {
			return v, &Counter{Packets: e.Counter.Packets, Bytes: e.Counter.Bytes}, true
		}
		return v, nil, true
	}
	if c, ok := obj["concat"]; ok {
		var parts []json.RawMessage
		if json.Unmarshal(c, &parts) != nil {
			return "", nil, false
		}
		var vals []string
		for _, p := range parts {
			v, _, ok := parseElem(p)
			if !ok {
				return "", nil, false
			}
			vals = append(vals, v)
		}
		return strings.Join(vals, " . "), nil, true
	}
	if p, ok := obj["prefix"]; ok {
		var pr struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		if json.Unmarshal(p, &pr) != nil {
			return "", nil, false
		}
		return pr.Addr + "/" + strconv.Itoa(pr.Len), nil, true
	}
	return "", nil, false
}

// ProbeEgress reports whether the kernel accepts a netdev egress chain.
func ProbeEgress(n NFT, device string) bool {
	if !ValidIfname(device) {
		return false
	}
	script := fmt.Sprintf("table netdev perch_portal_probe\ndelete table netdev perch_portal_probe\n"+
		"table netdev perch_portal_probe {\n\tchain e {\n\t\ttype filter hook egress device %s priority -500; policy accept;\n\t}\n}\n"+
		"delete table netdev perch_portal_probe\n", quote(device))
	return n.Apply(script) == nil
}

// ProbeQuota reports whether the kernel has named quotas and object maps
// (nft_quota, nft_objref), which the exact data cut needs.
func ProbeQuota(n NFT) bool {
	script := "table inet perch_portal_probe\ndelete table inet perch_portal_probe\n" +
		"table inet perch_portal_probe {\n\tquota q {\n\t\tover 1 bytes\n\t}\n" +
		"\tmap m {\n\t\ttype ether_addr : quota\n\t\telements = { 02:00:00:00:00:01 : \"q\" }\n\t}\n" +
		"\tmap m4 {\n\t\ttype ipv4_addr : quota\n\t\telements = { 192.0.2.1 : \"q\" }\n\t}\n" +
		"\tchain c {\n\t\tquota name ether saddr map @m drop\n\t\tquota name ip daddr map @m4 drop\n\t}\n}\n" +
		"delete table inet perch_portal_probe\n"
	return n.Apply(script) == nil
}

// ProbeIngress reports whether the kernel accepts an inet ingress chain
// (5.10+): the fast path's upload is then counted before the flowtable.
func ProbeIngress(n NFT, device string) bool {
	if !ValidIfname(device) {
		return false
	}
	script := fmt.Sprintf("table inet perch_portal_probe\ndelete table inet perch_portal_probe\n"+
		"table inet perch_portal_probe {\n\tchain i {\n\t\ttype filter hook ingress device %s priority -500; policy accept;\n\t}\n}\n"+
		"delete table inet perch_portal_probe\n", quote(device))
	return n.Apply(script) == nil
}
