package observe

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseDnsmasqLeases(t *testing.T) {
	v4, v6 := ParseDnsmasqLeases(fixture(t, "dhcp.leases"))
	byMAC := map[string][]Lease4{}
	for _, l := range v4 {
		byMAC[l.MAC] = append(byMAC[l.MAC], l)
	}
	if got := byMAC["02:00:00:00:10:21"]; len(got) != 1 || got[0].Hostname != "laptop" || got[0].IP != "192.168.1.21" ||
		got[0].Expires != 1790000000 || got[0].ClientID != "01:02:00:00:00:10:21" || got[0].Source != SourceDnsmasq {
		t.Errorf("laptop lease = %+v", got)
	}
	if got := byMAC["02:00:00:00:10:22"]; len(got) != 1 || got[0].Hostname != "" {
		t.Errorf(`"*" must read as no hostname: %+v`, got)
	}
	if got := byMAC["02:00:00:00:10:23"]; len(got) != 1 || got[0].Expires != 0 || got[0].ClientID != "" {
		t.Errorf("infinite lease = %+v", got)
	}
	if len(byMAC["02:00:00:00:10:24"]) != 2 {
		t.Errorf("both lines of a duplicated lease are parsed (dedupe comes later): %+v", byMAC["02:00:00:00:10:24"])
	}
	for _, l := range v4 {
		if l.IP == "192.168.1.25" || l.Hostname == "tv" {
			t.Errorf("non-Ethernet hardware address and bad IP must be skipped: %+v", l)
		}
	}
	if len(v4) != 5 {
		t.Errorf("got %d IPv4 leases, want 5: %+v", len(v4), v4)
	}

	if len(v6) != 2 {
		t.Fatalf("got %d DHCPv6 leases, want 2: %+v", len(v6), v6)
	}
	if l := v6[0]; l.DUID != "000100012abcdef0020000001021" || l.IAID == nil || *l.IAID != 12345 ||
		!reflect.DeepEqual(l.Addresses, []string{"fd00::21"}) || l.Hostname != "laptop" || l.ValidUntil != 1790003600 {
		t.Errorf("v6 lease = %+v", l)
	}
	if l := v6[1]; l.IAID == nil || *l.IAID != 777 || l.Hostname != "" {
		t.Errorf("temporary-address lease = %+v", l)
	}
}

func TestParseUCIShow(t *testing.T) {
	u := parseUCIShow(fixture(t, "uci-show-dhcp.txt"))
	if got, want := u.leaseFiles(), []string{"/tmp/dhcp.leases", "/tmp/dhcp.guest.leases"}; !reflect.DeepEqual(got, want) {
		t.Errorf("lease files = %v, want %v", got, want)
	}
	if !u.odhcpd || u.odhcpdMainDHCP || u.odhcpdLeaseFile != "/tmp/hosts/odhcpd" {
		t.Errorf("odhcpd = %v %v %q", u.odhcpd, u.odhcpdMainDHCP, u.odhcpdLeaseFile)
	}
	want := []StaticHost{
		{Name: "nas", MACs: []string{"02:00:00:00:10:30"}, IP: "192.168.1.30"},
		{Name: "dual-nic", MACs: []string{"02:00:00:00:10:31", "02:00:00:00:10:32"}},
		{Name: "o'brien-pc", MACs: []string{"02:00:00:00:10:33"}},
		{Name: "camera", MACs: []string{"02:00:00:00:10:34", "02:00:00:00:10:35"}, Section: "camera"},
		{Name: "ip-only", MACs: []string{}, IP: "192.168.1.40"},
	}
	if !reflect.DeepEqual(u.hosts, want) {
		t.Errorf("hosts =\n%+v\nwant\n%+v", u.hosts, want)
	}
}

func TestLeaseFilesDefault(t *testing.T) {
	// No uci at all, or a dnsmasq section without leasefile: the default.
	if got := (&uciDHCP{}).leaseFiles(); !reflect.DeepEqual(got, []string{DefaultLeaseFile}) {
		t.Errorf("no uci: %v", got)
	}
	u := parseUCIShow([]byte("dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].port='0'\n"))
	if got := u.leaseFiles(); !reflect.DeepEqual(got, []string{DefaultLeaseFile}) {
		t.Errorf("dnsmasq without leasefile: %v", got)
	}
	u = parseUCIShow([]byte("dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].leasefile='/var/lib/misc/dnsmasq.leases'\n"))
	if got := u.leaseFiles(); !reflect.DeepEqual(got, []string{"/var/lib/misc/dnsmasq.leases"}) {
		t.Errorf("custom leasefile: %v", got)
	}
}

func TestParseOdhcpd(t *testing.T) {
	now := time.Unix(1789999980, 0) // a whole minute: odhcpd's times are rounded to one
	v6 := ParseOdhcpdLeases6(fixture(t, "ubus-ipv6leases.json"), now)
	if len(v6) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(v6), v6)
	}
	byDUID := map[string]Lease6{}
	for _, l := range v6 {
		byDUID[l.DUID] = l
	}
	d := byDUID["00030001020000001041"]
	if d.Hostname != "desktop" || d.Device != "br-lan" || d.ValidUntil != 1790003580 || d.Source != SourceOdhcpd ||
		!reflect.DeepEqual(d.Addresses, []string{"fd00::41"}) || d.IAID == nil || *d.IAID != 1 {
		t.Errorf("desktop = %+v", d)
	}
	if o := byDUID["0004deadbeef"]; o.ValidUntil != 0 || !reflect.DeepEqual(o.Addresses, []string{"fd00::42"}) {
		t.Errorf("infinite lease = %+v", o)
	}

	v4 := ParseOdhcpdLeases4(fixture(t, "ubus-ipv4leases.json"), now)
	if len(v4) != 1 || v4[0].MAC != "02:00:00:00:10:51" || v4[0].Hostname != "odhcpd-client" || v4[0].Expires != 1790000580 {
		t.Errorf("odhcpd v4 = %+v", v4)
	}
	if ParseOdhcpdLeases6([]byte("not json"), now) != nil {
		t.Error("garbage must give nil")
	}
}

func TestCleanName(t *testing.T) {
	cases := map[string]string{
		"*":                      "",
		"  laptop ":              "laptop",
		"bad\x01name":            "badname",
		strings.Repeat("a", 254): "",
		"Kitchen Speaker":        "Kitchen Speaker",
	}
	for in, want := range cases {
		if got := cleanName(in); got != want {
			t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeRouter is a root directory with the router's files plus canned uci
// and ubus answers.
type fakeRouter struct {
	root string
	mu   sync.Mutex
	uci  []byte
	ubus map[string][]byte
	runs []string
}

func newFakeRouter(t *testing.T) *fakeRouter {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"tmp/hosts", "etc/config"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeRouter{root: root, ubus: map[string][]byte{}}
}

func (f *fakeRouter) write(t *testing.T, p string, data []byte) {
	t.Helper()
	full := filepath.Join(f.root, p)
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// A distinct mtime even on a coarse clock.
	later := time.Now().Add(time.Duration(len(f.runs)+1) * time.Second)
	_ = os.Chtimes(full, later, later)
}

func (f *fakeRouter) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	f.runs = append(f.runs, cmd)
	switch name {
	case "uci":
		if f.uci == nil {
			return nil, errors.New("uci: not found")
		}
		return f.uci, nil
	case "ubus":
		if b, ok := f.ubus[args[len(args)-1]]; ok {
			return b, nil
		}
		return nil, errors.New("ubus: Not found")
	}
	return nil, errors.New("unexpected command " + cmd)
}

func (f *fakeRouter) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.runs {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func TestReaderEndToEnd(t *testing.T) {
	f := newFakeRouter(t)
	f.uci = fixture(t, "uci-show-dhcp.txt")
	f.write(t, "etc/config/dhcp", []byte("config dnsmasq\n"))
	f.write(t, "tmp/dhcp.leases", fixture(t, "dhcp.leases"))
	f.write(t, "tmp/dhcp.guest.leases", fixture(t, "dhcp-second.leases"))
	f.ubus["ipv6leases"] = fixture(t, "ubus-ipv6leases.json")
	now := time.Unix(1790000000, 0)
	r := &Reader{Root: f.root, Run: f.run, Now: func() time.Time { return now }}

	d, fp := r.Read()
	if fp == "" || d == nil {
		t.Fatal("no observation")
	}
	// Duplicated lease: one row, the later expiry, the hostname kept.
	var dup []Lease4
	for _, l := range d.Leases4 {
		if l.MAC == "02:00:00:00:10:24" {
			dup = append(dup, l)
		}
	}
	if len(dup) != 1 || dup[0].Expires != 1790009999 || dup[0].Hostname != "phone-old" {
		t.Errorf("duplicate lease = %+v", dup)
	}
	if len(d.Leases4) != 5 { // 4 distinct from the main file + 1 from the guest file
		t.Errorf("leases4 = %d: %+v", len(d.Leases4), d.Leases4)
	}
	if len(d.Leases6) != 4 { // 2 from dnsmasq + 2 from odhcpd
		t.Errorf("leases6 = %d: %+v", len(d.Leases6), d.Leases6)
	}
	if len(d.Hosts) != 5 {
		t.Errorf("hosts = %d", len(d.Hosts))
	}

	// Nothing changed: same fingerprint, no new uci run, files not re-read.
	d2, fp2 := r.Read()
	if fp2 != fp || d2 != d {
		t.Error("an unchanged router must give the same observation")
	}
	if n := f.count("uci"); n != 1 {
		t.Errorf("uci ran %d times, want 1", n)
	}

	// A lease goes away.
	f.write(t, "tmp/dhcp.guest.leases", []byte(""))
	d3, fp3 := r.Read()
	if fp3 == fp || len(d3.Leases4) != 4 {
		t.Errorf("removed lease: fp changed=%v leases4=%d", fp3 != fp, len(d3.Leases4))
	}

	// A static host is added: uci is read again because /etc/config/dhcp changed.
	f.uci = append(append([]byte{}, f.uci...), []byte("dhcp.new=host\ndhcp.new.name='added'\ndhcp.new.mac='02:00:00:00:10:99'\n")...)
	f.write(t, "etc/config/dhcp", []byte("config dnsmasq\nconfig host\n"))
	d4, fp4 := r.Read()
	if fp4 == fp3 || len(d4.Hosts) != 6 || d4.Hosts[5].Name != "added" {
		t.Errorf("added host: %+v", d4.Hosts)
	}

	// uci starts failing: the last good static hosts stay.
	f.uci = nil
	f.write(t, "etc/config/dhcp", []byte("broken"))
	d5, _ := r.Read()
	if len(d5.Hosts) != 6 {
		t.Errorf("a failing uci must keep the last good hosts, got %d", len(d5.Hosts))
	}
	// …and is not asked again until the file changes.
	before := f.count("uci")
	r.Read()
	if f.count("uci") != before {
		t.Error("uci retried without a change of /etc/config/dhcp")
	}

	// odhcpd is asked again only after Recheck.
	calls := f.count("ubus")
	now = now.Add(10 * time.Second)
	r.Read()
	if f.count("ubus") != calls {
		t.Error("ubus asked before Recheck")
	}
	now = now.Add(DefaultRecheck)
	r.Read()
	if f.count("ubus") != calls+1 {
		t.Error("ubus not asked after Recheck")
	}
}

func TestReaderWithoutUCI(t *testing.T) {
	// Not OpenWrt: no uci, no ubus; the default lease file still counts.
	f := newFakeRouter(t)
	f.write(t, "tmp/dhcp.leases", []byte("1790000000 02:00:00:00:10:21 192.168.1.21 laptop *\n"))
	r := &Reader{Root: f.root, Run: f.run}
	d, _ := r.Read()
	if len(d.Leases4) != 1 || d.Leases6 == nil || d.Hosts == nil || len(d.Hosts) != 0 {
		t.Errorf("observation = %+v", d)
	}
	if f.count("ubus") != 0 {
		t.Error("ubus must not be asked without an odhcpd section")
	}
	b, _ := json.Marshal(d)
	if !strings.Contains(string(b), `"leases6":[]`) || !strings.Contains(string(b), `"hosts":[]`) {
		t.Errorf("empty lists must be [] on the wire: %s", b)
	}
}

func TestReaderNoLeaseFile(t *testing.T) {
	f := newFakeRouter(t)
	r := &Reader{Root: f.root, Run: f.run}
	d, fp := r.Read()
	if d == nil || fp == "" || len(d.Leases4) != 0 {
		t.Errorf("a router without a lease file reports an empty list: %+v", d)
	}
}
