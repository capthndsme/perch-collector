// Package observe reports runtime state of the router the collector runs on
// that is not traffic: today the DHCP leases and the static DHCP hosts, the
// `observe.dhcp` part of the observation channel (docs/collector-agent.md
// section 4.3 in the controller). The controller names devices from it, so a
// collector on the router gives hostnames with no transport to configure.
//
// Everything is read locally with the system's own tools: the dnsmasq lease
// files (their paths from UCI, never assumed), `uci show dhcp` for the static
// hosts, and odhcpd's leases over the `ubus` CLI when odhcpd runs. Nothing
// depends on dnsmasq's DNS port, so a router whose DNS belongs to another
// resolver (dnsmasq on port 54 or 0 behind AdGuard Home) reports the same.
package observe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Limits: what one report may carry. The controller clamps again.
const (
	MaxLeases4 = 4096
	MaxLeases6 = 4096
	MaxHosts   = 1024
	// MaxText is the longest hostname, client id or DUID kept (a DNS name's
	// limit); longer ones are dropped.
	MaxText = 253
)

// Sources, reported per lease.
const (
	SourceDnsmasq = "dnsmasq"
	SourceOdhcpd  = "odhcpd"
)

// DefaultLeaseFile is dnsmasq's lease file when its UCI section names none
// (the OpenWrt init script's default).
const DefaultLeaseFile = "/tmp/dhcp.leases"

// Section is the `observe` object of a push and of GET /api/v1/summary: one
// optional part per kind of observation. An absent part is not reported
// (the controller keeps what it has); a present one replaces it.
type Section struct {
	DHCP *DHCP `json:"dhcp,omitempty"`
}

// DHCP is the `dhcp` part of a push's `observe` section. It is a full
// snapshot: every list is present, [] when empty, and replaces what the
// controller holds for this router.
type DHCP struct {
	Leases4 []Lease4     `json:"leases4"`
	Leases6 []Lease6     `json:"leases6"`
	Hosts   []StaticHost `json:"hosts"`
}

// Lease4 is one IPv4 lease. Expires is a Unix time, 0 = infinite.
type Lease4 struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Expires  int64  `json:"expires"`
	ClientID string `json:"clientId,omitempty"`
	Source   string `json:"source"`
}

// Lease6 is one DHCPv6 lease (an IA with its addresses). ValidUntil is a
// Unix time, 0 = infinite. The controller derives the MAC from the DUID
// where the DUID carries one (types 1 and 3).
type Lease6 struct {
	DUID       string   `json:"duid"`
	IAID       *uint32  `json:"iaid,omitempty"`
	Addresses  []string `json:"addresses"`
	Hostname   string   `json:"hostname,omitempty"`
	ValidUntil int64    `json:"validUntil"`
	Device     string   `json:"device,omitempty"`
	Source     string   `json:"source"`
}

// StaticHost is one UCI `dhcp` `host` section with a name: the operator's
// own naming, which the controller ranks above a lease's hostname.
type StaticHost struct {
	Name    string   `json:"name"`
	MACs    []string `json:"macs"`
	IP      string   `json:"ip,omitempty"`
	Section string   `json:"section,omitempty"`
}

// Runner runs a system tool and returns its standard output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner runs the real binaries.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// Timing defaults.
const (
	// DefaultRecheck is how often odhcpd is asked over ubus even when no
	// file changed (its leases have no file of their own to watch reliably).
	DefaultRecheck = 60 * time.Second
	commandTimeout = 5 * time.Second
	uciConfigFile  = "/etc/config/dhcp"
)

// Reader builds the DHCP observation. It re-reads a source only when its
// file changed (size or modification time), re-reads UCI when
// /etc/config/dhcp changed, and asks odhcpd every Recheck; between those a
// call costs a few stat calls. Safe for concurrent use.
type Reader struct {
	// Root prefixes every path ("" = the real filesystem; tests).
	Root string
	// Run runs uci and ubus; nil = ExecRunner.
	Run Runner
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
	// Recheck overrides DefaultRecheck.
	Recheck time.Duration

	mu        sync.Mutex
	uci       *uciDHCP // last good `uci show dhcp`, nil before the first
	uciStamp  string   // stat of /etc/config/dhcp when uci was read
	files     map[string]string
	leases4   []Lease4 // from the dnsmasq files
	leases6d  []Lease6 // DHCPv6 leases from the dnsmasq files
	odhcpd4   []Lease4
	odhcpd6   []Lease6
	odhcpdAt  time.Time
	odhcpdKey string
	built     *DHCP
	fp        string
}

func (r *Reader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reader) run(name string, args ...string) ([]byte, error) {
	run := r.Run
	if run == nil {
		run = ExecRunner
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return run(ctx, name, args...)
}

func (r *Reader) path(p string) string {
	if r.Root == "" {
		return p
	}
	return filepath.Join(r.Root, p)
}

// stamp is a file's identity for change detection: size and mtime, or "-"
// when it does not exist.
func (r *Reader) stamp(p string) string {
	st, err := os.Stat(r.path(p))
	if err != nil {
		return "-"
	}
	return strconv.FormatInt(st.Size(), 10) + "@" + strconv.FormatInt(st.ModTime().UnixNano(), 10)
}

// Read returns the current observation and its fingerprint (hex SHA-256 of
// its JSON). It never fails: a source that cannot be read contributes
// nothing, and static hosts that cannot be re-read keep their last good
// value.
func (r *Reader) Read() (*DHCP, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false

	// UCI: lease file paths, odhcpd, static hosts.
	if st := r.stamp(uciConfigFile); r.uci == nil || st != r.uciStamp {
		// Tried once per change of the file: a router without uci (or
		// whose uci fails) is not asked again on every push.
		r.uciStamp = st
		if out, err := r.run("uci", "-q", "show", "dhcp"); err == nil {
			u := parseUCIShow(out)
			r.uci = &u
			changed = true
		} else if r.uci == nil {
			// No uci: the defaults (dnsmasq's default lease file, no
			// static hosts).
			r.uci = &uciDHCP{}
			changed = true
		}
	}

	// dnsmasq lease files.
	paths := r.uci.leaseFiles()
	stamps := make(map[string]string, len(paths))
	for _, p := range paths {
		stamps[p] = r.stamp(p)
	}
	if !sameStamps(stamps, r.files) {
		var v4 []Lease4
		var v6 []Lease6
		for _, p := range paths {
			data, err := os.ReadFile(r.path(p))
			if err != nil {
				continue
			}
			a, b := ParseDnsmasqLeases(data)
			v4 = append(v4, a...)
			v6 = append(v6, b...)
		}
		r.files, r.leases4, r.leases6d = stamps, v4, v6
		changed = true
	}

	// odhcpd over ubus: when configured, on a change of its lease file or
	// every Recheck.
	if r.uci.odhcpd {
		recheck := r.Recheck
		if recheck <= 0 {
			recheck = DefaultRecheck
		}
		key := ""
		if r.uci.odhcpdLeaseFile != "" {
			key = r.stamp(r.uci.odhcpdLeaseFile)
		}
		if r.odhcpdAt.IsZero() || key != r.odhcpdKey || r.now().Sub(r.odhcpdAt) >= recheck {
			now := r.now()
			r.odhcpdAt, r.odhcpdKey = now, key
			var v6 []Lease6
			if out, err := r.run("ubus", "call", "dhcp", "ipv6leases"); err == nil {
				v6 = ParseOdhcpdLeases6(out, now)
			}
			var v4 []Lease4
			if r.uci.odhcpdMainDHCP {
				if out, err := r.run("ubus", "call", "dhcp", "ipv4leases"); err == nil {
					v4 = ParseOdhcpdLeases4(out, now)
				}
			}
			if !equalJSON(v6, r.odhcpd6) || !equalJSON(v4, r.odhcpd4) {
				r.odhcpd6, r.odhcpd4 = v6, v4
				changed = true
			}
		}
	} else if r.odhcpd4 != nil || r.odhcpd6 != nil {
		r.odhcpd4, r.odhcpd6 = nil, nil
		changed = true
	}

	if changed || r.built == nil {
		d := &DHCP{
			Leases4: capList(dedupe4(append(append([]Lease4{}, r.leases4...), r.odhcpd4...)), MaxLeases4),
			Leases6: capList(dedupe6(append(append([]Lease6{}, r.leases6d...), r.odhcpd6...)), MaxLeases6),
			Hosts:   capList(r.uci.hosts, MaxHosts),
		}
		if d.Hosts == nil {
			d.Hosts = []StaticHost{}
		}
		b, _ := json.Marshal(d)
		sum := sha256.Sum256(b)
		r.built, r.fp = d, hex.EncodeToString(sum[:])
	}
	return r.built, r.fp
}

func sameStamps(a, b map[string]string) bool {
	if len(a) != len(b) || b == nil {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func capList[T any](in []T, max int) []T {
	if in == nil {
		return []T{}
	}
	if len(in) > max {
		return in[:max]
	}
	return in
}

// dedupe4 keeps one lease per MAC and address pair, the one that expires
// last (0 = infinite counts as last), sorted by MAC then address so the
// fingerprint does not depend on file order.
func dedupe4(in []Lease4) []Lease4 {
	byKey := make(map[string]Lease4, len(in))
	for _, l := range in {
		k := l.MAC + "|" + l.IP
		old, ok := byKey[k]
		if !ok {
			byKey[k] = l
			continue
		}
		keep, other := old, l
		if laterExpiry(l.Expires, old.Expires) {
			keep, other = l, old
		}
		if keep.Hostname == "" {
			keep.Hostname = other.Hostname
		}
		byKey[k] = keep
	}
	out := make([]Lease4, 0, len(byKey))
	for _, l := range byKey {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MAC != out[j].MAC {
			return out[i].MAC < out[j].MAC
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func dedupe6(in []Lease6) []Lease6 {
	byKey := make(map[string]Lease6, len(in))
	for _, l := range in {
		iaid := ""
		if l.IAID != nil {
			iaid = strconv.FormatUint(uint64(*l.IAID), 10)
		}
		k := l.DUID + "|" + iaid + "|" + strings.Join(l.Addresses, ",")
		if old, ok := byKey[k]; ok && !laterExpiry(l.ValidUntil, old.ValidUntil) {
			continue
		}
		byKey[k] = l
	}
	out := make([]Lease6, 0, len(byKey))
	for _, l := range byKey {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DUID != out[j].DUID {
			return out[i].DUID < out[j].DUID
		}
		return strings.Join(out[i].Addresses, ",") < strings.Join(out[j].Addresses, ",")
	})
	return out
}

func laterExpiry(a, b int64) bool {
	if a == 0 {
		return b != 0
	}
	if b == 0 {
		return false
	}
	return a > b
}

// ── text cleaning ────────────────────────────────────────────────────────

// cleanName is a hostname as the controller may show it: no control
// characters, trimmed, valid UTF-8, at most MaxText bytes; "" for dnsmasq's
// "*" (no name) and anything unusable.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if s == "*" || s == "" || len(s) > MaxText || !utf8.ValidString(s) {
		return ""
	}
	return s
}

// NormalizeMAC is the MAC in lower-case colon form, or "" when s is not a
// 6-byte MAC (dnsmasq writes other hardware types as "<type>-<hex>").
func NormalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) == 12 && !strings.ContainsAny(s, ":-") {
		var b strings.Builder
		for i := 0; i < 12; i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(s[i : i+2])
		}
		s = b.String()
	}
	s = strings.ReplaceAll(s, "-", ":")
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}

func cleanIP(s string, v6 bool) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil || (ip.To4() != nil) == v6 {
		return ""
	}
	return ip.String()
}

func cleanHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "*" || s == "" || len(s) > MaxText {
		return ""
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef:", r) {
			return ""
		}
	}
	return s
}

// ── dnsmasq ──────────────────────────────────────────────────────────────

// ParseDnsmasqLeases reads a dnsmasq lease file: IPv4 lines
// "<expiry> <mac> <ip> <hostname|*> <client-id|*>", then, after a
// "duid <server-duid>" line, DHCPv6 lines
// "<expiry> <[T]iaid> <ipv6> <hostname|*> <client-duid>". Malformed lines
// and non-Ethernet hardware addresses are skipped.
func ParseDnsmasqLeases(data []byte) ([]Lease4, []Lease6) {
	var v4 []Lease4
	var v6 []Lease6
	inV6 := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4096), 64*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if f[0] == "duid" {
			inV6 = true
			continue
		}
		if len(f) < 4 {
			continue
		}
		expiry, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil || expiry < 0 {
			continue
		}
		if !inV6 {
			mac := NormalizeMAC(f[1])
			ip := cleanIP(f[2], false)
			if mac == "" || ip == "" {
				continue
			}
			l := Lease4{MAC: mac, IP: ip, Hostname: cleanName(f[3]), Expires: expiry, Source: SourceDnsmasq}
			if len(f) > 4 {
				l.ClientID = cleanHex(f[4])
			}
			v4 = append(v4, l)
			continue
		}
		ip := cleanIP(f[2], true)
		if ip == "" || len(f) < 5 {
			continue
		}
		duid := cleanHex(f[4])
		if duid == "" {
			continue
		}
		l := Lease6{DUID: strings.ReplaceAll(duid, ":", ""), Addresses: []string{ip}, Hostname: cleanName(f[3]), ValidUntil: expiry, Source: SourceDnsmasq}
		if iaid, err := strconv.ParseUint(strings.TrimPrefix(f[1], "T"), 10, 32); err == nil {
			v := uint32(iaid)
			l.IAID = &v
		}
		v6 = append(v6, l)
	}
	return v4, v6
}

// ── odhcpd (ubus call dhcp ipv4leases / ipv6leases) ──────────────────────

type ubusLeases struct {
	Device map[string]struct {
		Leases []map[string]json.RawMessage `json:"leases"`
	} `json:"device"`
}

// infinite is odhcpd's "valid" for a lease that never expires ((uint32)-1).
const infinite = 4294967295

func validUntil(raw json.RawMessage, now time.Time) int64 {
	var v float64
	if json.Unmarshal(raw, &v) != nil {
		return 0
	}
	if v < 0 || v >= infinite {
		return 0
	}
	// odhcpd reports the seconds left: rounded to the minute, so the same
	// lease reads the same on every call and the fingerprint stays put.
	t := now.Unix() + int64(v)
	return (t + 30) / 60 * 60
}

func rawString(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// ParseOdhcpdLeases6 reads `ubus call dhcp ipv6leases`.
func ParseOdhcpdLeases6(data []byte, now time.Time) []Lease6 {
	var doc ubusLeases
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []Lease6
	for dev, d := range doc.Device {
		for _, raw := range d.Leases {
			duid := cleanHex(rawString(raw["duid"]))
			if duid == "" {
				continue
			}
			l := Lease6{DUID: strings.ReplaceAll(duid, ":", ""), Hostname: cleanName(rawString(raw["hostname"])),
				ValidUntil: validUntil(raw["valid"], now), Device: cleanName(dev), Source: SourceOdhcpd, Addresses: []string{}}
			var iaid float64
			if json.Unmarshal(raw["iaid"], &iaid) == nil && iaid >= 0 && iaid < infinite+1 {
				v := uint32(iaid)
				l.IAID = &v
			}
			var addrs []struct {
				Address string `json:"address"`
			}
			_ = json.Unmarshal(raw["ipv6-addr"], &addrs)
			for _, a := range addrs {
				if ip := cleanIP(a.Address, true); ip != "" && len(l.Addresses) < 16 {
					l.Addresses = append(l.Addresses, ip)
				}
			}
			out = append(out, l)
		}
	}
	return out
}

// ParseOdhcpdLeases4 reads `ubus call dhcp ipv4leases` (odhcpd as the main
// DHCPv4 server, `dhcp.odhcpd.maindhcp=1`).
func ParseOdhcpdLeases4(data []byte, now time.Time) []Lease4 {
	var doc ubusLeases
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []Lease4
	for _, d := range doc.Device {
		for _, raw := range d.Leases {
			mac := NormalizeMAC(rawString(raw["mac"]))
			ip := cleanIP(rawString(raw["address"]), false)
			if mac == "" || ip == "" {
				continue
			}
			out = append(out, Lease4{MAC: mac, IP: ip, Hostname: cleanName(rawString(raw["hostname"])),
				Expires: validUntil(raw["valid"], now), Source: SourceOdhcpd})
		}
	}
	return out
}

// ── UCI ──────────────────────────────────────────────────────────────────

// uciDHCP is what the observation needs from `uci show dhcp`.
type uciDHCP struct {
	// dnsmasqLeaseFiles: one entry per dnsmasq section, "" = the default.
	dnsmasqLeaseFiles []string
	dnsmasqSections   bool
	odhcpd            bool
	odhcpdMainDHCP    bool
	odhcpdLeaseFile   string
	hosts             []StaticHost
}

// leaseFiles are the dnsmasq lease files to read: each dnsmasq section's
// `leasefile`, the default for a section without one, and the default alone
// when UCI named no dnsmasq at all (no uci, or a router without it: the
// file then simply does not exist).
func (u *uciDHCP) leaseFiles() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" {
			p = DefaultLeaseFile
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range u.dnsmasqLeaseFiles {
		add(p)
	}
	if !u.dnsmasqSections {
		add("")
	}
	return out
}

type uciSection struct {
	name    string
	typ     string
	options map[string][]string
}

// parseUCIShow reads `uci show dhcp` output ("dhcp.<section>=<type>",
// "dhcp.<section>.<option>=<value>", list values as several quoted words).
func parseUCIShow(data []byte) uciDHCP {
	var order []string
	sections := map[string]*uciSection{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4096), 256*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, "dhcp.") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(key, "dhcp."), ".", 2)
		name := parts[0]
		s := sections[name]
		if s == nil {
			s = &uciSection{name: name, options: map[string][]string{}}
			sections[name] = s
			order = append(order, name)
		}
		words := uciWords(value)
		if len(parts) == 1 {
			if len(words) > 0 {
				s.typ = words[0]
			}
			continue
		}
		s.options[parts[1]] = words
	}

	var u uciDHCP
	for _, name := range order {
		s := sections[name]
		first := func(opt string) string {
			if v := s.options[opt]; len(v) > 0 {
				return strings.TrimSpace(v[0])
			}
			return ""
		}
		switch s.typ {
		case "dnsmasq":
			u.dnsmasqSections = true
			u.dnsmasqLeaseFiles = append(u.dnsmasqLeaseFiles, first("leasefile"))
		case "odhcpd":
			u.odhcpd = true
			u.odhcpdMainDHCP = first("maindhcp") == "1"
			u.odhcpdLeaseFile = first("leasefile")
		case "host":
			if first("enabled") == "0" {
				continue
			}
			h := StaticHost{Name: cleanName(first("name")), MACs: []string{}}
			if h.Name == "" {
				continue
			}
			for _, word := range s.options["mac"] {
				for _, m := range strings.FieldsFunc(word, func(r rune) bool { return r == ' ' || r == ',' }) {
					if mac := NormalizeMAC(m); mac != "" && len(h.MACs) < 16 {
						h.MACs = append(h.MACs, mac)
					}
				}
			}
			h.IP = cleanIP(first("ip"), false)
			if len(h.MACs) == 0 && h.IP == "" {
				continue
			}
			if !strings.HasPrefix(name, "@") {
				h.Section = cleanName(name)
			}
			u.hosts = append(u.hosts, h)
		}
	}
	return u
}

// uciWords splits a `uci show` value into its words: 'quoted' runs, with
// '\” as an embedded quote, separated by spaces.
func uciWords(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, any := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inQuote = !inQuote
			any = true
		case c == '\\' && !inQuote && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			any = true
		case c == ' ' && !inQuote:
			if any {
				out = append(out, cur.String())
				cur.Reset()
				any = false
			}
		default:
			cur.WriteByte(c)
			any = true
		}
	}
	if any {
		out = append(out, cur.String())
	}
	return out
}
