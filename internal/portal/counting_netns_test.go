package portal

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCountingUnderShapingNetns sends real traffic through the rendered
// counting tables in throwaway network namespaces (a router between a guest
// and a server) and checks what the counters see with the shaping setups
// that hid traffic from the old netdev counting: sqm's ifb on the WAN's
// ingress (every download) and perch-qos's clsact redirects on the guest
// device (upload and download of a shaped device). Skipped without nft,
// ping, iproute2 or unprivileged namespaces.
func TestCountingUnderShapingNetns(t *testing.T) {
	for _, tool := range []string{"nft", "ping", "ip", "tc", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("no " + tool)
		}
	}
	if exec.Command("unshare", "-rmn", "sh", "-c", "mount -t tmpfs none /run && ip link add x type ifb").Run() != nil {
		t.Skip("no unprivileged namespaces with ifb")
	}
	const (
		guestMAC = "02:00:00:00:20:11"
		guestIP  = "192.168.20.100"
		pings    = 20
		ipBytes  = 1028 // ping -s 1000: 1000 + ICMP 8 + IPv4 20
	)
	spec := RulesetSpec{
		Local4: []string{"192.168.20.1", "198.51.100.2"}, Egress: true, Ingress: true, Quota: true,
		Quotas: []QuotaSpec{{Name: "qg1_1", Bytes: 1 << 30}},
		Portals: []PortalSpec{{ID: 1, Device: "guest", Counting: true, Port: 2080, Auth: []string{guestMAC},
			Quota: map[string]string{guestMAC: "qg1_1"}, QuotaAddrs: map[string]string{guestIP: "qg1_1"}}},
	}
	dir := t.TempDir()
	ruleset := filepath.Join(dir, "acct.nft")
	if err := os.WriteFile(ruleset, []byte(RenderAcct(spec)+RenderFast(spec)), 0o644); err != nil {
		t.Fatal(err)
	}
	scenarios := []struct{ name, setup string }{
		{"plain", ""},
		{"sqm ingress ifb on the WAN", `
ip -n R link add ifb4wan type ifb; ip -n R link set ifb4wan up
ip netns exec R tc qdisc add dev wan handle ffff: ingress
ip netns exec R tc filter add dev wan parent ffff: protocol all matchall action mirred egress redirect dev ifb4wan`},
		{"perch-qos clsact on the guest device", `
ip -n R link add ifb-pdn type ifb; ip -n R link add ifb-pup type ifb
ip -n R link set ifb-pdn up; ip -n R link set ifb-pup up
ip netns exec R tc qdisc add dev guest clsact
ip netns exec R tc filter add dev guest egress protocol ip matchall action mirred egress redirect dev ifb-pdn
ip netns exec R tc filter add dev guest ingress protocol ip matchall action mirred egress redirect dev ifb-pup`},
		{"both", `
ip -n R link add ifb4wan type ifb; ip -n R link set ifb4wan up
ip netns exec R tc qdisc add dev wan handle ffff: ingress
ip netns exec R tc filter add dev wan parent ffff: protocol all matchall action mirred egress redirect dev ifb4wan
ip -n R link add ifb-pdn type ifb; ip -n R link add ifb-pup type ifb
ip -n R link set ifb-pdn up; ip -n R link set ifb-pup up
ip netns exec R tc qdisc add dev guest clsact
ip netns exec R tc filter add dev guest egress protocol ip matchall action mirred egress redirect dev ifb-pdn
ip netns exec R tc filter add dev guest ingress protocol ip matchall action mirred egress redirect dev ifb-pup`},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			script := `set -e
mount -t tmpfs none /run; mkdir -p /run/netns
ip netns add R; ip netns add C; ip netns add S
ip link add wan netns R type veth peer name s0 netns S
ip link add guest netns R type veth peer name c0 netns C
ip -n R link set dev guest address 02:00:00:00:20:01
ip -n C link set dev c0 address ` + guestMAC + `
ip -n S addr add 198.51.100.1/24 dev s0; ip -n S link set s0 up; ip -n S link set lo up
ip -n C addr add ` + guestIP + `/24 dev c0; ip -n C link set c0 up; ip -n C link set lo up
ip -n R addr add 198.51.100.2/24 dev wan; ip -n R addr add 192.168.20.1/24 dev guest
ip -n R link set wan up; ip -n R link set guest up; ip -n R link set lo up
ip -n S route add default via 198.51.100.2; ip -n C route add default via 192.168.20.1
ip netns exec R sysctl -qw net.ipv4.ip_forward=1
# neighbours resolved before counting starts (ARP is not usage)
ip netns exec C ping -q -c 1 198.51.100.1 >/dev/null
` + sc.setup + `
ip netns exec R nft -f ` + ruleset + `
ip netns exec C ping -q -c 20 -i 0.01 -s 1000 198.51.100.1 >/dev/null
ip netns exec R nft -j list table inet ` + TableAcct + `
echo '#fast'
ip netns exec R nft -j list table netdev ` + TableFast + `
`
			out, err := exec.Command("unshare", "-rmn", "sh", "-c", script).CombinedOutput()
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			acctJSON, fastJSON, ok := strings.Cut(string(out), "#fast")
			if !ok {
				t.Fatalf("output:\n%s", out)
			}
			acct, err := ParseTableJSON([]byte(acctJSON))
			if err != nil {
				t.Fatal(err)
			}
			fast, err := ParseTableJSON([]byte(fastJSON))
			if err != nil {
				t.Fatal(err)
			}
			quotas, err := ParseQuotasJSON([]byte(acctJSON))
			if err != nil {
				t.Fatal(err)
			}
			want := int64(pings * ipBytes)
			if c := acct["p1_up"].Counters[guestMAC]; c.Bytes != want || c.Packets != pings {
				t.Errorf("upload %+v, want %d bytes", c, want)
			}
			if c := acct["p1_d4"].Counters[guestIP]; c.Bytes != want || c.Packets != pings {
				t.Errorf("download %+v, want %d bytes", c, want)
			}
			if owners := addrOwners(acct["p1_a4"], acct["p1_a6"]); owners[guestIP] != guestMAC {
				t.Errorf("address owners %v", owners)
			}
			if c := fast["p1_fdown"].Counters[guestMAC]; c.Bytes != 0 {
				t.Errorf("counted twice on the fast path: %+v", c)
			}
			if q := quotas["qg1_1"]; q.Used != 2*want {
				t.Errorf("quota used %d, want %d (both ways, once)", q.Used, 2*want)
			}
		})
	}
}
