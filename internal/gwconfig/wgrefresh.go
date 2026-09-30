package gwconfig

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"
)

// WireGuard peers live in their own sections (`config wireguard_wg0`), which
// netifd's reload does not compare: after adding, editing or removing a peer
// the interface keeps its old peers until it is set up again. The plane runs
// `ifup` on each such interface after the commit (and after a rollback puts
// the old peers back). Existing tunnels pause for a moment.

const wgRefreshTimeout = 30 * time.Second

// notePeer records the interface of a `wireguard_<iface>` section.
func notePeer(sim *simulation, config, typ string) {
	if config != "network" {
		return
	}
	if iface, ok := strings.CutPrefix(typ, "wireguard_"); ok && iface != "" {
		sim.wgPeers[iface] = true
	}
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (p *Plane) refreshWireguard(applyID string, ifaces []string) {
	for _, iface := range ifaces {
		if !validIfaceName(iface) {
			continue
		}
		log.Printf("config plane: apply %s changed the peers of %s; setting it up again", applyID, iface)
		if _, err := runPkg(context.Background(), p.pkgRunner(), wgRefreshTimeout, "/sbin/ifup", iface); err != nil {
			log.Printf("config plane: apply %s: %v", applyID, err)
		}
	}
}

// validIfaceName: a UCI interface name (what `ifup` takes).
func validIfaceName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}
