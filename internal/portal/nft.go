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
//   - table netdev perch_portal_acct: per portal device an ingress and an
//     egress chain at priority -500 (before any flowtable fast path) that
//     count every authorised MAC's forwarded bytes in per-element set
//     counters: upload keyed by source MAC, download by destination MAC,
//     traffic to and from the router itself excluded. Data quotas are cut
//     here too, exactly: one named `quota` object per group with a data
//     quota (over the bytes the group has left), shared by its devices
//     through a per-portal MAC → quota map, and a rule before the counters
//     that drops a device's packets once its group's quota is used up
//     (upload and download together, like the group's quota). The tick
//     still ends the grant, flushes its connections and reports it.
//
// fw4's own input chain still has the last word on the router's ports, so
// a drop-in at /usr/share/nftables.d/chain-pre/input/ accepts the portal's
// ports on the portal devices (fw4 includes it on every reload).

// Table names.
const (
	TableInet   = "perch_portal"
	TableNetdev = "perch_portal_acct"
)

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
	// Egress: the kernel has the netdev egress hook (5.16+). Without it the
	// download direction cannot be counted per MAC.
	Egress bool
	// Quota: the kernel has named quotas and object maps (nft_quota,
	// nft_objref): the data cut is rendered. Quotas are the objects.
	Quota  bool
	Quotas []QuotaSpec
}

// quotaMapName is a portal's MAC → quota object map.
func quotaMapName(id int64) string { return setName(id, "quota") }

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

// RenderNetdev renders the counting table (full replacement script).
// Portals without a present device get no chains (Counting false).
func RenderNetdev(spec RulesetSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table netdev %s\ndelete table netdev %s\ntable netdev %s {\n", TableNetdev, TableNetdev, TableNetdev)
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
	for _, p := range sortedPortals(spec.Portals) {
		if !p.Counting {
			continue
		}
		auth := sortedCopy(p.Auth)
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr\n\t\tcounter\n%s\t}\n", setName(p.ID, "up"), elements(auth))
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ether_addr\n\t\tcounter\n%s\t}\n", setName(p.ID, "down"), elements(auth))
		if spec.Quota {
			fmt.Fprintf(&b, "\tmap %s {\n\t\ttype ether_addr : quota\n%s\t}\n", quotaMapName(p.ID), elements(quotaMapElems(p.Quota)))
		}
	}
	for _, p := range sortedPortals(spec.Portals) {
		if !p.Counting {
			continue
		}
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook ingress device %s priority -500; policy accept;\n", setName(p.ID, "ingress"), quote(p.Device))
		b.WriteString("\t\tip daddr @local4 return\n\t\tip6 daddr @local6 return\n")
		if spec.Quota {
			// Before the counter: a dropped packet is not usage.
			fmt.Fprintf(&b, "\t\tquota name ether saddr map @%s drop\n", quotaMapName(p.ID))
		}
		fmt.Fprintf(&b, "\t\tether saddr @%s\n\t}\n", setName(p.ID, "up"))
		if spec.Egress {
			fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook egress device %s priority -500; policy accept;\n", setName(p.ID, "egress"), quote(p.Device))
			b.WriteString("\t\tip saddr @local4 return\n\t\tip6 saddr @local6 return\n")
			if spec.Quota {
				fmt.Fprintf(&b, "\t\tquota name ether daddr map @%s drop\n", quotaMapName(p.ID))
			}
			fmt.Fprintf(&b, "\t\tether daddr @%s\n\t}\n", setName(p.ID, "down"))
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// RenderDeleteAll removes both tables (portal off / no portals).
func RenderDeleteAll() string {
	return fmt.Sprintf("table inet %s\ndelete table inet %s\ntable netdev %s\ndelete table netdev %s\n",
		TableInet, TableInet, TableNetdev, TableNetdev)
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

// Authorize adds a MAC to a portal's sets (counting too, when it counts).
func (o *ElementOps) Authorize(p int64, mac string, counting bool) {
	o.add("inet", TableInet, setName(p, "auth"), mac)
	if counting {
		o.add("netdev", TableNetdev, setName(p, "up"), mac)
		o.add("netdev", TableNetdev, setName(p, "down"), mac)
	}
}

// Deauthorize removes a MAC from a portal's sets.
func (o *ElementOps) Deauthorize(p int64, mac string, counting bool) {
	o.del("inet", TableInet, setName(p, "auth"), mac)
	if counting {
		o.del("netdev", TableNetdev, setName(p, "up"), mac)
		o.del("netdev", TableNetdev, setName(p, "down"), mac)
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
	fmt.Fprintf(&o.b, "add quota netdev %s %s { over %d bytes }\n", TableNetdev, name, nonNegative(bytes))
}

// DeleteQuota removes a quota object nothing refers to any more.
func (o *ElementOps) DeleteQuota(name string) {
	fmt.Fprintf(&o.b, "delete quota netdev %s %s\n", TableNetdev, name)
}

// MapQuota points a MAC at a quota object (the MAC is not in the map).
func (o *ElementOps) MapQuota(p int64, mac, name string) {
	fmt.Fprintf(&o.b, "add element netdev %s %s { %s : %s }\n", TableNetdev, quotaMapName(p), mac, quote(name))
}

// UnmapQuota removes a MAC from a portal's quota map (it is there).
func (o *ElementOps) UnmapQuota(p int64, mac string) {
	fmt.Fprintf(&o.b, "delete element netdev %s %s { %s }\n", TableNetdev, quotaMapName(p), mac)
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
		sc := SetContents{Counters: map[string]Counter{}, Values: map[string]string{}}
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
		}
		out[s.Name] = sc
	}
	return out, nil
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
	script := "table netdev perch_portal_probe\ndelete table netdev perch_portal_probe\n" +
		"table netdev perch_portal_probe {\n\tquota q {\n\t\tover 1 bytes\n\t}\n" +
		"\tmap m {\n\t\ttype ether_addr : quota\n\t\telements = { 02:00:00:00:00:01 : \"q\" }\n\t}\n" +
		"\tchain c {\n\t\tquota name ether saddr map @m drop\n\t}\n}\n" +
		"delete table netdev perch_portal_probe\n"
	return n.Apply(script) == nil
}
