package portal

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if string(want) != got {
		t.Fatalf("%s differs:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func goldenSpec() RulesetSpec {
	return RulesetSpec{
		Local4: []string{"192.168.20.1", "192.168.110.1", "203.0.113.2"},
		Local6: []string{"2001:db8::1"},
		Egress: true,
		Portals: []PortalSpec{
			{ID: 4, Device: "br-trunk.110", Counting: true, Port: 2080, Auth: []string{"02:00:00:00:99:11"},
				DNSPerMinute: 120, DHCPv6: true, IPBinding: true, Bind: []MACIP{{MAC: "02:00:00:00:99:11", IP: "192.168.110.100"}}},
			{ID: 3, Device: "guest", Counting: true, Port: 2080, Auth: []string{"02:00:00:00:20:12", "02:00:00:00:20:11"},
				WalledNets4: []string{"203.0.113.0/24"}, WalledNets6: []string{"2001:db8:80::/48"}, WG4: []string{"203.0.113.80"},
				DNSPerMinute: 120},
			{ID: 5, Device: "br-trunk.120", Counting: false, Port: 2080},
		},
	}
}

// goldenQuotaSpec is goldenSpec with the kernel data cut: a group shared by
// two devices on portal 3, and one on portal 4.
func goldenQuotaSpec() RulesetSpec {
	spec := goldenSpec()
	spec.Quota = true
	spec.Quotas = []QuotaSpec{{Name: "qv17_1", Bytes: 31457280}, {Name: "qg4_2", Bytes: 1000}}
	spec.Portals[1].Quota = map[string]string{"02:00:00:00:20:11": "qv17_1", "02:00:00:00:20:12": "qv17_1"}
	spec.Portals[0].Quota = map[string]string{"02:00:00:00:99:11": "qg4_2"}
	return spec
}

func TestRenderQuotaGolden(t *testing.T) {
	spec := goldenQuotaSpec()
	golden(t, "netdev-quota.nft", RenderNetdev(spec))
	spec.Egress = false
	golden(t, "netdev-quota-no-egress.nft", RenderNetdev(spec))
	var ops ElementOps
	ops.AddQuota("qv17_2", 1000)
	ops.UnmapQuota(3, "02:00:00:00:20:11")
	ops.MapQuota(3, "02:00:00:00:20:11", "qv17_2")
	ops.DeleteQuota("qv17_1")
	golden(t, "ops-quota.nft", ops.Script())
}

func TestRenderGolden(t *testing.T) {
	spec := goldenSpec()
	golden(t, "inet.nft", RenderInet(spec))
	golden(t, "netdev.nft", RenderNetdev(spec))
	spec.Egress = false
	golden(t, "netdev-no-egress.nft", RenderNetdev(spec))
	golden(t, "fw4-include.nft", RenderFw4Include([]string{"guest", "br-trunk.110"}, []int{2080}, true))
	golden(t, "dnsmasq.conf", RenderDnsmasqNftset(map[int64][]string{3: {"example.com", "pay.example.com"}, 4: {"example.net"}}))
	golden(t, "delete.nft", RenderDeleteAll())
	var ops ElementOps
	ops.Authorize(3, "02:00:00:00:20:11", true)
	ops.Deauthorize(3, "02:00:00:00:20:12", true)
	ops.Bind(4, "02:00:00:00:99:11", "192.168.110.100")
	golden(t, "ops.nft", ops.Script())
}

func TestParseTableJSON(t *testing.T) {
	// Captured from nft 1.1.1 on OpenWrt 24.10 (lab), trimmed.
	data := []byte(`{"nftables": [{"metainfo": {"version": "1.1.1"}}, {"set": {"family": "netdev", "name": "p3_up", "table": "perch_portal_acct", "type": "ether_addr", "handle": 4, "elem": [{"elem": {"val": "02:00:00:00:20:11", "counter": {"packets": 3939, "bytes": 15375774}}}, "02:00:00:00:20:12"]}}, {"set": {"family": "inet", "name": "p3_bind4", "table": "perch_portal", "type": ["ether_addr", "ipv4_addr"], "elem": [{"concat": ["02:00:00:00:20:11", "192.168.20.111"]}]}}, {"set": {"family": "inet", "name": "p3_wgnet4", "elem": [{"prefix": {"addr": "203.0.113.0", "len": 24}}, {"elem": {"val": "203.0.113.80", "timeout": 3600, "expires": 3500}}]}}]}`)
	sets, err := ParseTableJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if c := sets["p3_up"].Counters["02:00:00:00:20:11"]; c.Bytes != 15375774 || c.Packets != 3939 {
		t.Fatalf("%+v", c)
	}
	if len(sets["p3_up"].Elements) != 2 {
		t.Fatalf("%+v", sets["p3_up"])
	}
	if sets["p3_bind4"].Elements[0] != "02:00:00:00:20:11 . 192.168.20.111" {
		t.Fatalf("%+v", sets["p3_bind4"])
	}
	if e := sets["p3_wgnet4"].Elements; len(e) != 2 || e[0] != "203.0.113.0/24" || e[1] != "203.0.113.80" {
		t.Fatalf("%+v", e)
	}
}

func TestDnsmasqNftsetDetection(t *testing.T) {
	if DnsmasqHasNftset("Dnsmasq version 2.93\nCompile time options: IPv6 GNU-getopt no-DBus UBus no-i18n no-IDN DHCP no-DHCPv6 no-Lua TFTP no-conntrack no-ipset no-nftset no-auth\n") {
		t.Fatal("no-nftset read as nftset")
	}
	if !DnsmasqHasNftset("Dnsmasq version 2.93\nCompile time options: IPv6 GNU-getopt DBus UBus no-i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth DNSSEC\n") {
		t.Fatal("nftset missed")
	}
}
