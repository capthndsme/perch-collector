package qos

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// TestTaggedFramesMatchedOnceNetns: a client on a VLAN device (lan.132 over
// lan) is matched by its MAC filter on the VLAN device only. On the port
// below, its frames carry the tag and the 802.1Q pass at PrefTaggedQ ends
// classification first; before it, the same MAC filter matched them there
// too (shaped twice, quota counted twice). Real traffic through two
// namespaces joined by a veth; skipped without unprivileged namespaces.
func TestTaggedFramesMatchedOnceNetns(t *testing.T) {
	for _, tool := range []string{"ping", "ip", "tc", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	if testing.Short() {
		t.Skip("namespace tests are skipped with -short")
	}
	if exec.Command("unshare", "-rmn", "sh", "-c", "mount -t tmpfs none /run && ip link add x type dummy").Run() != nil {
		t.Skip("unprivileged namespaces are not available")
	}
	const (
		client = "02:00:00:00:01:01"
		pings  = 20
	)
	var filters []string
	for _, dev := range []string{"lan", "lan.132"} {
		for _, dir := range []Dir{Down, Up} {
			macKey := "dst_mac"
			if dir == Up {
				macKey = "src_mac"
			}
			hook := dir.Hook()
			for _, f := range []DFilter{
				{Hook: hook, Pref: PrefTaggedQ, Proto: "802.1Q", Handle: 1, Action: ActPass},
				{Hook: hook, Pref: PrefTaggedAD, Proto: "802.1ad", Handle: 1, Action: ActPass},
				// The device filter, counting only (a pass instead of the redirect).
				{Hook: hook, Pref: PrefDevice, Proto: "all", Handle: 1, Match: macKey + "=" + client, Action: ActPass},
			} {
				filters = append(filters, fmt.Sprintf("ip netns exec R tc filter add dev %s %s", dev, filterArgs(f)))
			}
		}
	}
	script := `set -e
mount -t tmpfs none /run; mkdir -p /run/netns
ip netns add R; ip netns add C
ip link add lan netns R type veth peer name c0 netns C
ip netns exec C ip link set c0 address ` + client + `
ip netns exec R ip link set lan up; ip netns exec C ip link set c0 up
ip netns exec R ip link add link lan name lan.132 type vlan id 132
ip netns exec C ip link add link c0 name c0.132 type vlan id 132
ip netns exec R ip addr add 10.0.132.1/24 dev lan.132; ip netns exec R ip link set lan.132 up
ip netns exec C ip addr add 10.0.132.2/24 dev c0.132; ip netns exec C ip link set c0.132 up
ip netns exec R tc qdisc add dev lan clsact
ip netns exec R tc qdisc add dev lan.132 clsact
` + strings.Join(filters, "\n") + `
ip netns exec C ping -q -c ` + fmt.Sprint(pings) + ` -i 0.01 -s 1000 10.0.132.1 >/dev/null
for d in lan lan.132; do for h in ingress egress; do echo "== $d $h"; ip netns exec R tc -s -j filter show dev $d $h; echo; done; done
`
	out, err := exec.Command("unshare", "-rmn", "sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// Packets per (device, hook, pref) from the filters' own statistics.
	type stats struct {
		Stats struct {
			Packets int64 `json:"packets"`
		} `json:"stats"`
	}
	type filter struct {
		Pref    uint16 `json:"pref"`
		Options struct {
			Handle  uint32  `json:"handle"`
			Actions []stats `json:"actions"`
		} `json:"options"`
	}
	got := map[string]int64{}
	var section string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "== "):
			section = strings.TrimPrefix(line, "== ")
		case strings.HasPrefix(line, "["):
			var fs []filter
			if err := json.Unmarshal([]byte(line), &fs); err != nil {
				t.Fatalf("%s: %v\n%s", section, err, line)
			}
			for _, f := range fs {
				if f.Options.Handle == 0 || len(f.Options.Actions) == 0 {
					continue
				}
				got[fmt.Sprintf("%s/%d", section, f.Pref)] += f.Options.Actions[0].Stats.Packets
			}
		}
	}
	for key, want := range map[string]int64{
		// The VLAN device: every echo request (up) and reply (down), once.
		fmt.Sprintf("lan.132 ingress/%d", PrefDevice): pings,
		fmt.Sprintf("lan.132 egress/%d", PrefDevice):  pings,
		// The port below: the same frames, tagged, pass before the MAC filter.
		fmt.Sprintf("lan ingress/%d", PrefDevice): 0,
		fmt.Sprintf("lan egress/%d", PrefDevice):  0,
	} {
		// ARP and the first ping's neighbour discovery add a few frames.
		if n := got[key]; n < want || n > want+4 {
			t.Errorf("%s: %d packets, want %d\n%v", key, n, want, got)
		}
	}
	if got[fmt.Sprintf("lan ingress/%d", PrefTaggedQ)] < pings || got[fmt.Sprintf("lan egress/%d", PrefTaggedQ)] < pings {
		t.Errorf("the tagged frames did not pass at the 802.1Q filter: %v", got)
	}
}
