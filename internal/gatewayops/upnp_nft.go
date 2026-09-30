package gatewayops

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
)

// Orphaned mappings: miniupnpd re-adds its lease file's mappings at start
// through its permission rules. A mapping they now deny (the device was just
// blocked, which itself restarts miniupnpd) loses its lease line, but its
// nftables rules stay: the port stays open and the lease file no longer
// names it. After the lease-file delete, rules still present for a
// requested mapping are removed directly (the DNAT rule in the nat chain,
// then the forward rule to the same internal address and port). Only with
// the nftables backend (miniupnpd-nftables, `upnp_table_name` in its
// generated config).

// UPnPConf is the config miniupnpd's init script generates.
const UPnPConf = "/var/etc/miniupnpd.conf"

const nftTimeout = 10 * time.Second

type upnpChains struct {
	table, natTable, forward, nat string
}

// nftChains reads the chain names from miniupnpd's generated config, or
// reports false when it does not use nftables (or nft is missing).
func (u *UPnP) nftChains() (upnpChains, bool) {
	if _, err := os.Stat(rootPath(u.Root, "/usr/sbin/nft")); err != nil {
		return upnpChains{}, false
	}
	data, err := os.ReadFile(rootPath(u.Root, UPnPConf))
	if err != nil {
		return upnpChains{}, false
	}
	c := upnpChains{forward: "upnp_forward", nat: "upnp_prerouting"}
	nft := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "upnp_table_name":
			c.table, nft = strings.TrimSpace(v), true
		case "upnp_nat_table_name":
			c.natTable = strings.TrimSpace(v)
		case "upnp_forward_chain":
			c.forward = strings.TrimSpace(v)
		case "upnp_nat_chain":
			c.nat = strings.TrimSpace(v)
		}
	}
	if c.natTable == "" {
		c.natTable = c.table
	}
	return c, nft && validNftName(c.table) && validNftName(c.natTable) && validNftName(c.forward) && validNftName(c.nat)
}

var nftNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func validNftName(s string) bool { return nftNameRe.MatchString(s) }

var (
	// iif "wan" @nh,72,8 0x6 th dport 45000 dnat ip to 10.99.10.128:5000 # handle 8536
	natRuleRe = regexp.MustCompile(`@nh,72,8 0x([0-9a-f]+) th dport (\d+) dnat ip to ([0-9.]+):(\d+) .*# handle (\d+)`)
	// iif "wan" th dport 5000 @nh,128,32 0xa630a80 @nh,72,8 0x6 accept # handle 8537
	fwdRuleRe = regexp.MustCompile(`th dport (\d+) @nh,128,32 0x([0-9a-f]+) @nh,72,8 0x([0-9a-f]+) accept .*# handle (\d+)`)
)

func protoName(hex string) string {
	switch hex {
	case "6":
		return "TCP"
	case "11":
		return "UDP"
	}
	return ""
}

func ipHex(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	var n uint32
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return ""
		}
		n = n<<8 | uint32(v)
	}
	return strconv.FormatUint(uint64(n), 16)
}

func nftList(ctx context.Context, run ubus.Runner, table, chain string) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()
	out, _, code, err := run(cctx, "nft", "-a", "list", "chain", "inet", table, chain)
	if err != nil || code != 0 {
		return "", false
	}
	return string(out), true
}

func nftDelete(ctx context.Context, run ubus.Runner, table, chain, handle string) bool {
	cctx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()
	_, _, code, err := run(cctx, "nft", "delete", "rule", "inet", table, chain, "handle", handle)
	return err == nil && code == 0
}

// removeOrphanRules deletes the rules left for the requested mappings and
// returns the keys it removed.
func (u *UPnP) removeOrphanRules(ctx context.Context, run ubus.Runner, want map[string]bool) map[string]bool {
	removed := map[string]bool{}
	c, ok := u.nftChains()
	if !ok {
		return removed
	}
	nat, ok := nftList(ctx, run, c.natTable, c.nat)
	if !ok {
		return removed
	}
	type target struct{ proto, ipHex, port string }
	targets := map[target]bool{}
	for _, line := range strings.Split(nat, "\n") {
		m := natRuleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		proto := protoName(m[1])
		port, _ := strconv.Atoi(m[2])
		key := mappingKey(proto, port)
		if proto == "" || !want[key] {
			continue
		}
		if nftDelete(ctx, run, c.natTable, c.nat, m[5]) {
			removed[key] = true
			targets[target{m[1], ipHex(m[3]), m[4]}] = true
		}
	}
	if len(targets) == 0 {
		return removed
	}
	fwd, ok := nftList(ctx, run, c.table, c.forward)
	if !ok {
		return removed
	}
	for _, line := range strings.Split(fwd, "\n") {
		m := fwdRuleRe.FindStringSubmatch(line)
		if m == nil || !targets[target{m[3], m[2], m[1]}] {
			continue
		}
		nftDelete(ctx, run, c.table, c.forward, m[4])
	}
	return removed
}
