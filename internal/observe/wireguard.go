package observe

import (
	"encoding/base64"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// WireGuard is the wireguard part (gateway-sync protocol 6.1): the router's
// WireGuard interfaces and their peers' state. Public keys and peer state
// only: the reader runs `wg show all <field>` for fields that print no
// secret, never `wg show … dump`, `private-key` or `preshared-keys`, and
// takes nothing but names, descriptions and public keys from UCI. A router
// without the `wg` tool reports nothing (the part is absent).
type WireGuard struct {
	Interfaces []WGInterface `json:"interfaces"`
}

// WGInterface is one WireGuard device. Network is the UCI interface
// section it belongs to (netifd names the device after it), null for a
// device netifd does not manage. PublicKey is null without a private key.
// ListenPort 0 = not listening.
type WGInterface struct {
	Name       string   `json:"name"`
	Network    *string  `json:"network"`
	PublicKey  *string  `json:"publicKey"`
	ListenPort int      `json:"listenPort"`
	Peers      []WGPeer `json:"peers"`
}

// WGPeer is one peer. Description is the UCI peer section's `description`
// (null without one); Endpoint null until the peer has one;
// LatestHandshake a Unix time, 0 = never; Keepalive in seconds, null = off.
// RxBytes and TxBytes are not part of the fingerprint (they tick).
type WGPeer struct {
	PublicKey       string   `json:"publicKey"`
	Description     *string  `json:"description"`
	Endpoint        *string  `json:"endpoint"`
	AllowedIPs      []string `json:"allowedIps"`
	LatestHandshake int64    `json:"latestHandshake"`
	RxBytes         int64    `json:"rxBytes"`
	TxBytes         int64    `json:"txBytes"`
	Keepalive       *int     `json:"keepalive"`
}

// Caps of the wireguard part.
const (
	MaxWGInterfaces = 16
	MaxWGPeers      = 256
	MaxWGAllowedIPs = 64
)

// wgFields are the `wg show all <field>` calls the reader makes, in order.
// Each prints public keys and state only.
var wgFields = []string{"public-key", "listen-port", "peers", "endpoints", "allowed-ips",
	"latest-handshakes", "transfer", "persistent-keepalive"}

// validWGKey: base64 of 32 bytes.
func validWGKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// wgLines splits `wg show all <field>` output into its tab-separated rows.
func wgLines(out []byte) [][]string {
	var rows [][]string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows
}

// ParseWireGuard builds the part from the outputs of `wg show all <field>`
// (by field name) and the UCI network config's WireGuard names: networks
// (device → UCI interface) and descriptions ("<device>\t<peer public key>"
// → description).
func ParseWireGuard(out map[string][]byte, networks, descriptions map[string]string) *WireGuard {
	wg := &WireGuard{Interfaces: []WGInterface{}}
	index := map[string]int{}
	for _, row := range wgLines(out["public-key"]) {
		if len(row) != 2 || len(wg.Interfaces) >= MaxWGInterfaces {
			continue
		}
		name := cleanName(row[0])
		if _, dup := index[name]; name == "" || dup || len(name) > 15 {
			continue
		}
		it := WGInterface{Name: name, Peers: []WGPeer{}}
		if validWGKey(row[1]) {
			k := row[1]
			it.PublicKey = &k
		}
		if n, ok := networks[name]; ok {
			n := n
			it.Network = &n
		}
		index[name] = len(wg.Interfaces)
		wg.Interfaces = append(wg.Interfaces, it)
	}
	iface := func(name string) *WGInterface {
		if i, ok := index[name]; ok {
			return &wg.Interfaces[i]
		}
		return nil
	}
	for _, row := range wgLines(out["listen-port"]) {
		if it := iface(row[0]); it != nil && len(row) == 2 {
			if p, err := strconv.Atoi(row[1]); err == nil && p > 0 && p <= 65535 {
				it.ListenPort = p
			}
		}
	}
	// Peers in wg's order; the other fields fill them in.
	seen := map[string]bool{}
	for _, row := range wgLines(out["peers"]) {
		it := iface(row[0])
		if len(row) != 2 || it == nil || !validWGKey(row[1]) || seen[row[0]+"\t"+row[1]] || len(it.Peers) >= MaxWGPeers {
			continue
		}
		seen[row[0]+"\t"+row[1]] = true
		p := WGPeer{PublicKey: row[1], AllowedIPs: []string{}}
		if d, ok := descriptions[row[0]+"\t"+row[1]]; ok && d != "" {
			d := d
			p.Description = &d
		}
		it.Peers = append(it.Peers, p)
	}
	peerOf := func(row []string, n int) *WGPeer {
		if len(row) != n {
			return nil
		}
		it := iface(row[0])
		if it == nil {
			return nil
		}
		for i := range it.Peers {
			if it.Peers[i].PublicKey == row[1] {
				return &it.Peers[i]
			}
		}
		return nil
	}
	for _, row := range wgLines(out["endpoints"]) {
		if p := peerOf(row, 3); p != nil {
			if e := cleanEndpoint(row[2]); e != "" {
				p.Endpoint = &e
			}
		}
	}
	for _, row := range wgLines(out["allowed-ips"]) {
		p := peerOf(row, 3)
		if p == nil {
			continue
		}
		for _, a := range strings.Fields(row[2]) {
			if pr, err := netip.ParsePrefix(a); err == nil && len(p.AllowedIPs) < MaxWGAllowedIPs {
				p.AllowedIPs = append(p.AllowedIPs, pr.String())
			}
		}
	}
	for _, row := range wgLines(out["latest-handshakes"]) {
		if p := peerOf(row, 3); p != nil {
			if ts, err := strconv.ParseInt(row[2], 10, 64); err == nil && ts > 0 {
				p.LatestHandshake = ts
			}
		}
	}
	for _, row := range wgLines(out["transfer"]) {
		if p := peerOf(row, 4); p != nil {
			rx, err1 := strconv.ParseInt(row[2], 10, 64)
			tx, err2 := strconv.ParseInt(row[3], 10, 64)
			if err1 == nil && err2 == nil && rx >= 0 && tx >= 0 {
				p.RxBytes, p.TxBytes = rx, tx
			}
		}
	}
	for _, row := range wgLines(out["persistent-keepalive"]) {
		if p := peerOf(row, 3); p != nil {
			if s, err := strconv.Atoi(row[2]); err == nil && s > 0 && s <= 65535 {
				p.Keepalive = &s
			}
		}
	}
	sort.SliceStable(wg.Interfaces, func(a, b int) bool { return wg.Interfaces[a].Name < wg.Interfaces[b].Name })
	return wg
}

// cleanEndpoint keeps an "address:port" endpoint ("(none)" and anything
// odd are dropped).
func cleanEndpoint(s string) string {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String()
	}
	return ""
}

// wgNames reads the WireGuard names of the UCI network config: interface
// sections with proto wireguard (their name is the device's), and the peer
// sections' descriptions by public key. Nothing else of those sections is
// kept (they hold the private and preshared keys).
func wgNames(secs []UCISection) (networks, descriptions map[string]string) {
	networks, descriptions = map[string]string{}, map[string]string{}
	for _, s := range secs {
		switch {
		case s.Type == "interface" && s.First("proto") == "wireguard" && !s.Anonymous():
			networks[s.Name] = s.Name
		case strings.HasPrefix(s.Type, "wireguard_"):
			if k := s.First("public_key"); validWGKey(k) {
				descriptions[strings.TrimPrefix(s.Type, "wireguard_")+"\t"+k] = cleanDescription(s.First("description"))
			}
		}
	}
	return networks, descriptions
}

// WireGuardReader reads the wireguard part; the UCI names are re-read only
// when /etc/config/network changes.
type WireGuardReader struct {
	Env *Env

	mu           sync.Mutex
	uciStamp     string
	networks     map[string]string
	descriptions map[string]string
}

// Read returns the part; nil when `wg` cannot be run.
func (r *WireGuardReader) Read() *WireGuard {
	r.mu.Lock()
	defer r.mu.Unlock()
	first, err := r.Env.run("wg", "show", "all", wgFields[0])
	if err != nil {
		return nil
	}
	out := map[string][]byte{wgFields[0]: first}
	if len(wgLines(first)) > 0 {
		for _, f := range wgFields[1:] {
			b, err := r.Env.run("wg", "show", "all", f)
			if err != nil {
				return nil
			}
			out[f] = b
		}
	}
	if st := r.Env.stamp("/etc/config/network"); st != r.uciStamp || r.networks == nil {
		r.uciStamp = st
		r.networks, r.descriptions = map[string]string{}, map[string]string{}
		if secs, ok := r.Env.uciShow("network"); ok {
			r.networks, r.descriptions = wgNames(secs)
		}
	}
	return ParseWireGuard(out, r.networks, r.descriptions)
}

// wgStable is the part without the byte counters, for the fingerprint.
func wgStable(w *WireGuard) *WireGuard {
	s := &WireGuard{Interfaces: make([]WGInterface, len(w.Interfaces))}
	for i, it := range w.Interfaces {
		it.Peers = append([]WGPeer(nil), it.Peers...)
		for j := range it.Peers {
			it.Peers[j].RxBytes, it.Peers[j].TxBytes = 0, 0
		}
		s.Interfaces[i] = it
	}
	return s
}
