// Package gatewayops holds the actions the controller may ask of the
// collector on the router (gateway plan 2 sections 3 and 4.3): flushing
// conntrack entries of given addresses (net.conntrack_flush) and taking a
// configuration backup (gateway.backup). Both are runtime actions, never
// config writes.
package gatewayops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/ti-mo/conntrack"
)

// Flush limits.
const (
	MaxFlushIPs = 64
)

// FlushParams are net.conntrack_flush's params.
type FlushParams struct {
	// IPs whose flows go: any flow with one of them as the original or
	// reply source or destination. 1..MaxFlushIPs, unicast, not the
	// router's own addresses.
	IPs []string `json:"ips"`
	// Proto limits the flush to one protocol: tcp, udp, icmp, icmpv6, or a
	// number. "" = all.
	Proto string `json:"proto,omitempty"`
	// DryRun counts what would go and deletes nothing.
	DryRun bool `json:"dryRun,omitempty"`
}

// FlushResult is net.conntrack_flush's result.
type FlushResult struct {
	// Flushed is false when conntrack could not be reached; Reason says why.
	Flushed bool `json:"flushed"`
	Matched int  `json:"matched"`
	Deleted int  `json:"deleted"`
	// Skipped: matching flows left alone, the collector's own connection
	// to the controller.
	Skipped int    `json:"skipped"`
	Failed  int    `json:"failed,omitempty"`
	DryRun  bool   `json:"dryRun,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// ParamError is a refusal of the params (JSON-RPC -32602); Code goes into
// the error's data.error.
type ParamError struct {
	Code    string
	Message string
}

func (e *ParamError) Error() string { return e.Message }

// Table is the part of a conntrack connection the flush uses.
type Table interface {
	Dump() ([]conntrack.Flow, error)
	Delete(conntrack.Flow) error
	// Probe makes one cheap request, to find out whether ctnetlink answers
	// (a socket opens without CAP_NET_ADMIN; requests then fail).
	Probe() error
	Close() error
}

type netlinkTable struct{ c *conntrack.Conn }

func (t netlinkTable) Dump() ([]conntrack.Flow, error) { return t.c.Dump(nil) }
func (t netlinkTable) Delete(f conntrack.Flow) error   { return t.c.Delete(f) }
func (t netlinkTable) Close() error                    { return t.c.Close() }
func (t netlinkTable) Probe() error {
	_, err := t.c.StatsGlobal()
	return err
}

// DialConntrack opens ctnetlink.
func DialConntrack() (Table, error) {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return nil, err
	}
	return netlinkTable{c}, nil
}

// Flusher deletes conntrack entries.
type Flusher struct {
	// Dial opens the table; nil = DialConntrack.
	Dial func() (Table, error)
	// LocalAddrs are the router's own addresses (refused as targets);
	// nil = the host's interface addresses.
	LocalAddrs func() []netip.Addr
	// Protected are the collector's controller connection endpoints (local
	// and remote address:port): a flow with both is never deleted.
	Protected func() (local, remote netip.AddrPort)

	mu sync.Mutex // one flush at a time
}

// Available probes ctnetlink once (for the capability).
func (f *Flusher) Available() error {
	t, err := f.dial()
	if err != nil {
		return err
	}
	defer t.Close()
	return t.Probe()
}

func (f *Flusher) dial() (Table, error) {
	if f.Dial != nil {
		return f.Dial()
	}
	return DialConntrack()
}

var protoNumbers = map[string]uint8{"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "icmpv6": 58, "sctp": 132, "udplite": 136}

// Validate checks the params and returns the addresses and protocol (0 = all).
func (f *Flusher) Validate(p FlushParams) ([]netip.Addr, uint8, error) {
	if len(p.IPs) == 0 {
		return nil, 0, &ParamError{"conntrack_ips_required", "ips must name at least one address"}
	}
	if len(p.IPs) > MaxFlushIPs {
		return nil, 0, &ParamError{"conntrack_too_many_ips", fmt.Sprintf("at most %d addresses", MaxFlushIPs)}
	}
	local := map[netip.Addr]bool{}
	for _, a := range f.localAddrs() {
		local[a.Unmap()] = true
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, s := range p.IPs {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nil, 0, &ParamError{"conntrack_ip_invalid", fmt.Sprintf("%q is not an IP address", s)}
		}
		a = a.Unmap().WithZone("")
		if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() {
			return nil, 0, &ParamError{"conntrack_ip_invalid", fmt.Sprintf("%s is not a unicast device address", a)}
		}
		if local[a] {
			// Every NATed flow has the WAN address as its reply
			// destination: flushing the router's own addresses would drop
			// the whole network's connections, the controller's included.
			return nil, 0, &ParamError{"conntrack_router_address", fmt.Sprintf("%s is an address of the router itself", a)}
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	var proto uint8
	if p.Proto != "" {
		n, ok := protoNumbers[strings.ToLower(p.Proto)]
		if !ok {
			var v int
			if _, err := fmt.Sscanf(p.Proto, "%d", &v); err != nil || v < 1 || v > 255 {
				return nil, 0, &ParamError{"conntrack_proto_invalid", fmt.Sprintf("unknown protocol %q", p.Proto)}
			}
			n = uint8(v)
		}
		proto = n
	}
	return out, proto, nil
}

func (f *Flusher) localAddrs() []netip.Addr {
	if f.LocalAddrs != nil {
		return f.LocalAddrs()
	}
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

// Flush deletes the matching flows.
func (f *Flusher) Flush(p FlushParams) (FlushResult, error) {
	ips, proto, err := f.Validate(p)
	if err != nil {
		return FlushResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t, err := f.dial()
	if err != nil {
		return FlushResult{Reason: "conntrack unavailable: " + err.Error()}, nil
	}
	defer t.Close()
	flows, err := t.Dump()
	if err != nil {
		return FlushResult{Reason: "conntrack dump failed: " + err.Error()}, nil
	}
	want := map[netip.Addr]bool{}
	for _, a := range ips {
		want[a] = true
	}
	var local, remote netip.AddrPort
	if f.Protected != nil {
		local, remote = f.Protected()
	}
	res := FlushResult{Flushed: true, DryRun: p.DryRun}
	for _, fl := range flows {
		if !Matches(fl, want, proto) {
			continue
		}
		res.Matched++
		if isConnection(fl, local, remote) {
			res.Skipped++
			continue
		}
		if p.DryRun {
			continue
		}
		del := conntrack.Flow{TupleOrig: fl.TupleOrig, Zone: fl.Zone}
		if err := t.Delete(del); err != nil {
			if isNotFound(err) {
				continue // gone meanwhile
			}
			res.Failed++
			continue
		}
		res.Deleted++
	}
	return res, nil
}

// Matches reports whether a flow involves one of the addresses (as the
// original or reply source or destination) and, with proto set, uses it.
func Matches(fl conntrack.Flow, want map[netip.Addr]bool, proto uint8) bool {
	if proto != 0 && fl.TupleOrig.Proto.Protocol != proto {
		return false
	}
	for _, a := range []netip.Addr{fl.TupleOrig.IP.SourceAddress, fl.TupleOrig.IP.DestinationAddress,
		fl.TupleReply.IP.SourceAddress, fl.TupleReply.IP.DestinationAddress} {
		if a.IsValid() && want[a.Unmap()] {
			return true
		}
	}
	return false
}

// isConnection reports whether the flow is the collector's own connection
// to the controller (seen from either tuple, NAT or not).
func isConnection(fl conntrack.Flow, local, remote netip.AddrPort) bool {
	if !local.IsValid() || !remote.IsValid() {
		return false
	}
	match := func(t conntrack.Tuple, src, dst netip.AddrPort) bool {
		return t.IP.SourceAddress.Unmap() == src.Addr().Unmap() && t.Proto.SourcePort == src.Port() &&
			t.IP.DestinationAddress.Unmap() == dst.Addr().Unmap() && t.Proto.DestinationPort == dst.Port()
	}
	return match(fl.TupleOrig, local, remote) || match(fl.TupleReply, remote, local)
}

func isNotFound(err error) bool {
	return errors.Is(err, syscall.ENOENT)
}
