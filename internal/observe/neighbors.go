package observe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/mdlayher/netlink"
)

// Neighbor is one entry of the router's ARP / NDP table: a device seen on
// one of its links. Reachable is the kernel's recent confirmation
// (REACHABLE, DELAY or PROBE); a STALE entry is known but unconfirmed.
type Neighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Device    string `json:"device,omitempty"`
	Network   string `json:"network,omitempty"`
	Reachable bool   `json:"reachable"`
	// State is the kernel's NUD state in lower case: reachable, stale,
	// delay, probe, permanent.
	State string `json:"state"`
}

// MaxNeighbors caps the neighbors part.
const MaxNeighbors = 4096

// Kernel neighbour states (include/uapi/linux/neighbour.h).
const (
	nudIncomplete = 0x01
	nudReachable  = 0x02
	nudStale      = 0x04
	nudDelay      = 0x08
	nudProbe      = 0x10
	nudFailed     = 0x20
	nudNoARP      = 0x40
	nudPermanent  = 0x80
)

const (
	rtmNewNeigh = 28
	rtmGetNeigh = 30
	ndaDst      = 1
	ndaLLAddr   = 2
	ndmsgLen    = 12
)

func nudName(state uint16) (string, bool) {
	switch {
	case state&nudPermanent != 0:
		return "permanent", false
	case state&nudReachable != 0:
		return "reachable", true
	case state&nudDelay != 0:
		return "delay", true
	case state&nudProbe != 0:
		return "probe", true
	case state&nudStale != 0:
		return "stale", false
	}
	return "", false
}

// neighborWanted keeps entries that name a device: a unicast Ethernet MAC,
// a unicast address that is not link-local, a state other than failed,
// incomplete or noarp.
func neighborWanted(ip netip.Addr, mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
		return false
	}
	if !ip.IsValid() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	return true
}

// ParseNeighMessages reads the RTM_NEWNEIGH messages of a neighbour dump;
// name maps an interface index to its name.
func ParseNeighMessages(msgs []netlink.Message, name func(int) string) []Neighbor {
	var out []Neighbor
	for _, m := range msgs {
		if m.Header.Type != rtmNewNeigh || len(m.Data) < ndmsgLen {
			continue
		}
		ifindex := int(int32(binary.NativeEndian.Uint32(m.Data[4:8])))
		state := binary.NativeEndian.Uint16(m.Data[8:10])
		if state&(nudFailed|nudIncomplete|nudNoARP) != 0 && state&(nudReachable|nudStale|nudDelay|nudProbe|nudPermanent) == 0 {
			continue
		}
		label, reachable := nudName(state)
		if label == "" {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[ndmsgLen:])
		if err != nil {
			continue
		}
		var ip netip.Addr
		var mac net.HardwareAddr
		for ad.Next() {
			switch ad.Type() {
			case ndaDst:
				if a, ok := netip.AddrFromSlice(ad.Bytes()); ok {
					ip = a.Unmap()
				}
			case ndaLLAddr:
				mac = net.HardwareAddr(append([]byte{}, ad.Bytes()...))
			}
		}
		if ad.Err() != nil || !neighborWanted(ip, mac) {
			continue
		}
		n := Neighbor{IP: ip.String(), MAC: mac.String(), Reachable: reachable, State: label}
		if name != nil {
			n.Device = cleanName(name(ifindex))
		}
		out = append(out, n)
	}
	return out
}

// ParseProcARP reads /proc/net/arp (IPv4 only): the fallback when netlink
// is not available. Complete entries (flags 0x2) are "reachable" only in
// the sense that the kernel holds a MAC; their state reads "stale".
func ParseProcARP(data []byte) []Neighbor {
	var out []Neighbor
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		flags := strings.TrimPrefix(f[2], "0x")
		if flags == "0" {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		mac, merr := net.ParseMAC(f[3])
		if err != nil || merr != nil || !neighborWanted(ip, mac) {
			continue
		}
		state := "stale"
		if flags == "6" || flags == "4" {
			state = "permanent"
		}
		out = append(out, Neighbor{IP: ip.String(), MAC: mac.String(), Device: cleanName(f[5]), State: state})
	}
	return out
}

// NeighborReader dumps the kernel's neighbour table over rtnetlink, or
// reads /proc/net/arp when netlink fails.
type NeighborReader struct {
	Env *Env
	// Networks tags each entry with its network (nil = no tagging).
	Networks func() []Subnet
	// dump replaces the netlink dump (tests).
	dump func() ([]netlink.Message, error)

	mu     sync.Mutex
	warned bool
}

// ErrNoNeighbors is returned when neither netlink nor /proc/net/arp answered.
var ErrNoNeighbors = errors.New("no neighbour table")

// Read returns the neighbours, sorted by address.
func (r *NeighborReader) Read() ([]Neighbor, error) {
	dump := r.dump
	if dump == nil {
		dump = dumpNeighbors
	}
	var list []Neighbor
	msgs, err := dump()
	if err == nil {
		list = ParseNeighMessages(msgs, ifaceName())
	} else {
		data, ferr := r.Env.read("/proc/net/arp")
		if ferr != nil {
			return nil, ErrNoNeighbors
		}
		list = ParseProcARP(data)
	}
	if r.Networks != nil {
		nets := r.Networks()
		for i := range list {
			list[i].Network = networkOf(nets, list[i].IP)
		}
	}
	sort.Slice(list, func(a, b int) bool {
		if list[a].IP != list[b].IP {
			return list[a].IP < list[b].IP
		}
		return list[a].Device < list[b].Device
	})
	if list == nil {
		list = []Neighbor{}
	}
	return capList(list, MaxNeighbors), nil
}

func ifaceName() func(int) string {
	names := map[int]string{}
	if list, err := net.Interfaces(); err == nil {
		for _, i := range list {
			names[i.Index] = i.Name
		}
	}
	return func(i int) string { return names[i] }
}

// dumpNeighbors asks rtnetlink for every neighbour (AF_UNSPEC: IPv4 and IPv6).
func dumpNeighbors() ([]netlink.Message, error) {
	c, err := netlink.Dial(0 /* NETLINK_ROUTE */, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	req := netlink.Message{
		Header: netlink.Header{Type: rtmGetNeigh, Flags: netlink.Request | netlink.Dump},
		Data:   make([]byte, ndmsgLen),
	}
	return c.Execute(req)
}
