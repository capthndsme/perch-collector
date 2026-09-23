package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/capthndsme/perch-collector/internal/gatewayops"
	"github.com/capthndsme/perch-collector/internal/observe"
)

// System is everything the portal touches outside its own process, behind
// one interface so the engine is testable without a router.
type System interface {
	NFT
	// WriteFile writes a file when its content differs; changed tells.
	WriteFile(path string, data []byte, mode os.FileMode) (changed bool, err error)
	// RemoveFile removes a file; removed tells whether it existed.
	RemoveFile(path string) (removed bool, err error)
	// Command runs a program (fw4, dnsmasq, ubus, uci).
	Command(ctx context.Context, name string, args ...string) ([]byte, error)
	// Neighbors reads the neighbour table.
	Neighbors() ([]observe.Neighbor, error)
	// LocalAddrs are the router's own addresses.
	LocalAddrs() []netip.Addr
	// DeviceAddrs are the addresses on one device (nil when it is missing).
	DeviceAddrs(device string) ([]netip.Prefix, bool)
	// FlushConntrack deletes the flows of these addresses.
	FlushConntrack(ips []string) (int, error)
	// Resolve looks a walled-garden name up (the fallback without nftset).
	Resolve(ctx context.Context, name string) ([]netip.Addr, error)
}

// HostSystem is the real router.
type HostSystem struct {
	NFT      ExecNFT
	Flusher  *gatewayops.Flusher
	neighbor observe.NeighborReader
}

// Apply implements NFT.
func (h *HostSystem) Apply(script string) error { return h.NFT.Apply(script) }

// ListJSON implements NFT.
func (h *HostSystem) ListJSON(args ...string) ([]byte, error) { return h.NFT.ListJSON(args...) }

// WriteFile implements System (atomic: temp file + rename).
func (h *HostSystem) WriteFile(path string, data []byte, mode os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := path + ".perch-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// RemoveFile implements System.
func (h *HostSystem) RemoveFile(path string) (bool, error) {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Command implements System.
func (h *HostSystem) Command(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", name, err, firstLines(stderr.String(), 3))
	}
	return out, nil
}

// Neighbors implements System.
func (h *HostSystem) Neighbors() ([]observe.Neighbor, error) { return h.neighbor.Read() }

// LocalAddrs implements System.
func (h *HostSystem) LocalAddrs() []netip.Addr {
	var out []netip.Addr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// DeviceAddrs implements System.
func (h *HostSystem) DeviceAddrs(device string) ([]netip.Prefix, bool) {
	ifc, err := net.InterfaceByName(device)
	if err != nil {
		return nil, false
	}
	addrs, _ := ifc.Addrs()
	var out []netip.Prefix
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			ones, _ := n.Mask.Size()
			out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
		}
	}
	return out, true
}

// FlushConntrack implements System.
func (h *HostSystem) FlushConntrack(ips []string) (int, error) {
	if h.Flusher == nil {
		return 0, errors.New("conntrack flush unavailable")
	}
	res, err := h.Flusher.Flush(gatewayops.FlushParams{IPs: ips})
	if err != nil {
		return 0, err
	}
	if !res.Flushed {
		return 0, errors.New(res.Reason)
	}
	return res.Deleted, nil
}

// Resolve implements System.
func (h *HostSystem) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

// ---------------------------------------------------------------------------
// fw4 drop-in: fw4's input chain would otherwise reject the portal's ports
// on a zone with input REJECT. fw4 includes every *.nft under
// /usr/share/nftables.d/chain-pre/input/ at the top of its input chain on
// each start and reload.
// ---------------------------------------------------------------------------

// Fw4IncludePath is the drop-in.
const Fw4IncludePath = "/usr/share/nftables.d/chain-pre/input/30-perch-portal.nft"

// RenderFw4Include accepts the portal's ports on the portal devices in
// fw4's input chain. Everything else from those devices has already been
// dropped by perch_portal's input chain.
func RenderFw4Include(devices []string, ports []int, dhcpv6 bool) string {
	if len(devices) == 0 {
		return ""
	}
	devs := sortedCopy(devices)
	quoted := make([]string, len(devs))
	for i, d := range devs {
		quoted[i] = quote(d)
	}
	set := "{ " + strings.Join(quoted, ", ") + " }"
	sort.Ints(ports)
	var ps []string
	for i, p := range ports {
		if i == 0 || p != ports[i-1] {
			ps = append(ps, fmt.Sprint(p))
		}
	}
	var b strings.Builder
	b.WriteString("# Perch guest portal (perch-collector): the portal devices may reach DNS, DHCP,\n")
	b.WriteString("# the guest pages and ping on the router; table inet perch_portal drops the rest.\n")
	fmt.Fprintf(&b, "iifname %s meta l4proto { tcp, udp } th dport 53 accept comment \"!perch-portal: DNS\"\n", set)
	fmt.Fprintf(&b, "iifname %s udp dport 67 accept comment \"!perch-portal: DHCP\"\n", set)
	if dhcpv6 {
		fmt.Fprintf(&b, "iifname %s udp dport 547 accept comment \"!perch-portal: DHCPv6\"\n", set)
	}
	fmt.Fprintf(&b, "iifname %s tcp dport { %s } accept comment \"!perch-portal: guest pages\"\n", set, strings.Join(ps, ", "))
	fmt.Fprintf(&b, "iifname %s icmp type echo-request accept comment \"!perch-portal: ping\"\n", set)
	fmt.Fprintf(&b, "iifname %s icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept comment \"!perch-portal: ICMPv6\"\n", set)
	return b.String()
}

// ---------------------------------------------------------------------------
// dnsmasq nftset= for the walled garden (dnsmasq-full, 2.87+ built with
// nftset). The lines go into every dnsmasq instance's conf-dir under /tmp:
// runtime state, not UCI, so the config plane never sees a change.
// ---------------------------------------------------------------------------

// DnsmasqConfName is the file written into each conf-dir.
const DnsmasqConfName = "perch-portal-walled-garden.conf"

// DnsmasqHasNftset reads `dnsmasq --version`'s compile options.
func DnsmasqHasNftset(versionOutput string) bool {
	for _, line := range strings.Split(versionOutput, "\n") {
		if !strings.HasPrefix(line, "Compile time options:") {
			continue
		}
		for _, f := range strings.Fields(strings.TrimPrefix(line, "Compile time options:")) {
			if f == "nftset" {
				return true
			}
		}
	}
	return false
}

// RenderDnsmasqNftset renders the walled garden's names per portal.
func RenderDnsmasqNftset(byPortal map[int64][]string) string {
	ids := make([]int64, 0, len(byPortal))
	for id := range byPortal {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	var b strings.Builder
	for _, id := range ids {
		names := sortedCopy(byPortal[id])
		if len(names) == 0 {
			continue
		}
		fmt.Fprintf(&b, "nftset=/%s/4#inet#%s#%s,6#inet#%s#%s\n", strings.Join(names, "/"),
			TableInet, setName(id, "wg4"), TableInet, setName(id, "wg6"))
	}
	if b.Len() == 0 {
		return ""
	}
	return "# Perch guest portal walled garden (perch-collector)\n" + b.String()
}

// DnsmasqConfDirs are the conf-dirs of the running instances.
func DnsmasqConfDirs() []string {
	var out []string
	if st, err := os.Stat("/tmp/dnsmasq.d"); err == nil && st.IsDir() {
		out = append(out, "/tmp/dnsmasq.d")
	}
	matches, _ := filepath.Glob("/tmp/dnsmasq.*.d")
	out = append(out, matches...)
	return sortedCopy(out)
}

// ---------------------------------------------------------------------------
// Network → device (netifd).
// ---------------------------------------------------------------------------

// NetworkStatus is the part of `ubus call network.interface.<n> status` used.
type NetworkStatus struct {
	Up        bool   `json:"up"`
	L3Device  string `json:"l3_device"`
	Device    string `json:"device"`
	IPv6Addrs []struct {
		Address string `json:"address"`
	} `json:"ipv6-address"`
}

// ParseNetworkStatus parses the ubus answer.
func ParseNetworkStatus(data []byte) (NetworkStatus, error) {
	var s NetworkStatus
	err := json.Unmarshal(data, &s)
	return s, err
}

// ResolveNetworkDevice asks netifd for a network's device.
func ResolveNetworkDevice(ctx context.Context, sys System, network string) (string, error) {
	if !ValidIfname(network) {
		return "", fmt.Errorf("invalid network name %q", network)
	}
	out, err := sys.Command(ctx, "ubus", "call", "network.interface."+network, "status")
	if err != nil {
		return "", err
	}
	st, err := ParseNetworkStatus(out)
	if err != nil {
		return "", err
	}
	dev := st.L3Device
	if dev == "" {
		dev = st.Device
	}
	if dev == "" {
		return "", fmt.Errorf("network %s has no device", network)
	}
	return dev, nil
}
