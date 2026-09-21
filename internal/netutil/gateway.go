// Package netutil provides Linux-specific helpers for discovering the local
// default gateway, its MAC address, and the IPv4/IPv6 subnets attached to a
// capture interface.
package netutil

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	procRoute = "/proc/net/route"
	procArp   = "/proc/net/arp"
)

// DetectGatewayIPv4 reads /proc/net/route and returns the IPv4 default gateway
// for the given interface. Returns an error if no default route is found for iface.
func DetectGatewayIPv4(iface string) (net.IP, error) {
	f, err := os.Open(procRoute)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", procRoute, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	headerSeen := false
	for sc.Scan() {
		line := sc.Text()
		if !headerSeen {
			headerSeen = true
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[0] != iface {
			continue
		}
		// Default route: Destination == 00000000 AND Mask == 00000000.
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		gw, err := parseLEHexIPv4(fields[2])
		if err != nil {
			return nil, fmt.Errorf("parsing gateway hex %q: %w", fields[2], err)
		}
		// 0.0.0.0 means an on-link route with no nexthop; skip.
		if gw.Equal(net.IPv4zero) {
			continue
		}
		return gw, nil
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", procRoute, err)
	}
	return nil, fmt.Errorf("no default IPv4 gateway found for interface %s", iface)
}

// parseLEHexIPv4 decodes an 8-char hex string from /proc/net/route into an
// IPv4 address. The kernel writes the 32-bit address in host byte order; on
// little-endian platforms (the only realistic deployment target) this means
// the four bytes appear reversed relative to dotted-quad notation.
func parseLEHexIPv4(h string) (net.IP, error) {
	if len(h) != 8 {
		return nil, fmt.Errorf("expected 8 hex chars, got %d", len(h))
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return net.IPv4(b[3], b[2], b[1], b[0]), nil
}

// LookupMAC reads /proc/net/arp and returns the MAC address for ip on iface.
// Returns an error if no usable entry is present (cache miss or incomplete).
func LookupMAC(ip net.IP, iface string) (net.HardwareAddr, error) {
	f, err := os.Open(procArp)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", procArp, err)
	}
	defer f.Close()

	target := ip.String()
	sc := bufio.NewScanner(f)
	headerSeen := false
	for sc.Scan() {
		line := sc.Text()
		if !headerSeen {
			headerSeen = true
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		if fields[5] != iface || fields[0] != target {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil {
			return nil, fmt.Errorf("parsing MAC %q: %w", fields[3], err)
		}
		if isZeroMAC(mac) {
			return nil, fmt.Errorf("ARP entry for %s on %s is incomplete", target, iface)
		}
		return mac, nil
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", procArp, err)
	}
	return nil, fmt.Errorf("no ARP entry for %s on %s", target, iface)
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

// pokeARP sends a best-effort UDP datagram to ip so the kernel triggers an
// ARP resolution. Errors are deliberately ignored; the call is for side-effect.
func pokeARP(ip net.IP) {
	addr := &net.UDPAddr{IP: ip, Port: 9} // RFC 863 discard
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = conn.Write([]byte{0})
}

// DetectGatewayMAC resolves the IPv4 default gateway on iface and looks up its
// MAC in the ARP cache. On cache miss it sends a UDP poke to trigger ARP and
// polls the cache for up to ~500ms before giving up.
func DetectGatewayMAC(iface string) (net.HardwareAddr, error) {
	gw, err := DetectGatewayIPv4(iface)
	if err != nil {
		return nil, err
	}
	if mac, err := LookupMAC(gw, iface); err == nil {
		return mac, nil
	}
	pokeARP(gw)
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		if mac, err := LookupMAC(gw, iface); err == nil {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("could not resolve MAC for gateway %s on %s; set gateway_macs in config", gw, iface)
}

// DetectGatewayMACs is the slice form of DetectGatewayMAC. It currently
// returns a single-element slice (the default-route gateway) but is reserved
// for future expansion (e.g. multi-default-route or policy-routed nexthops).
// Returns an empty slice on resolution failure rather than an error so the
// caller can degrade gracefully.
func DetectGatewayMACs(iface string) []net.HardwareAddr {
	mac, err := DetectGatewayMAC(iface)
	if err != nil {
		return nil
	}
	return []net.HardwareAddr{mac}
}
