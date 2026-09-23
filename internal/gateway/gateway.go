// Package gateway reports the router's own health next to the traffic the
// collector captures: connection-tracking fill, established TCP, load,
// memory and the WAN interface counters. It is what the controller's
// Gateway page shows, read from /proc on the router itself instead of from a
// node_exporter scrape (docs/collector-agent.md section 4.1 in the
// controller). With it come the router's Ethernet ports and their link
// state, read from /sys, for the controller's infrastructure view
// (docs/infrastructure-view.md section 4.3): the collector on the router is
// the Perch Network Gateway agent.
package gateway

import (
	"sync"
	"time"

	"github.com/capthndsme/perch-agentkit/hoststat"
)

// WAN interface sources, reported as Stats.WANSource.
const (
	SourceConfigured   = "configured"
	SourceDefaultRoute = "default-route"
)

// Stats is the `gateway` object of a push and of GET /api/v1/summary. A part
// the kernel does not expose is left out rather than reported as zero.
type Stats struct {
	CollectedAt    time.Time   `json:"collectedAt"`
	Conntrack      *Conntrack  `json:"conntrack,omitempty"`
	TCPEstablished *int64      `json:"tcpEstablished,omitempty"`
	Load           *Load       `json:"load,omitempty"`
	Memory         *Memory     `json:"memory,omitempty"`
	WAN            []Interface `json:"wan"`
	WANSource      string      `json:"wanSource"`
	// Ports is the router's Ethernet ports in display order, with their
	// link state. Present whenever port reporting is on, as [] when the
	// router has none; left out when it is off, and when /sys/class/net
	// cannot be listed (the controller reads a missing key as "not
	// reported" and an empty list as "no ports"). A pointer because
	// omitempty would drop an empty list as well.
	Ports *[]hoststat.Port `json:"ports,omitempty"`
}

// Conntrack is the connection-tracking table fill.
type Conntrack struct {
	Entries *uint64 `json:"entries,omitempty"`
	Limit   *uint64 `json:"limit,omitempty"`
}

// Load is the 1, 5 and 15 minute load average.
type Load struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// Memory is MemTotal and MemAvailable in bytes.
type Memory struct {
	TotalBytes     *uint64 `json:"totalBytes,omitempty"`
	AvailableBytes *uint64 `json:"availableBytes,omitempty"`
}

// Interface is one WAN interface's cumulative byte counters.
type Interface struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rxBytes"`
	TxBytes uint64 `json:"txBytes"`
}

// Reader collects Stats.
type Reader struct {
	// FS is the root /proc is read from ("" = the real one).
	FS hoststat.FS
	// WANInterfaces is the configured list; empty = default-route interfaces.
	WANInterfaces []string
	// Ports adds the router's Ethernet ports to every report; nil = port
	// reporting off. Copies of a Reader share it, and with it the port
	// cache.
	Ports *Ports
	// Now stamps CollectedAt (tests).
	Now func() time.Time
}

// Ports reads the router's Ethernet ports for the gateway report: the kit's
// port reader, which keeps the facts that do not change between reads. The
// push and GET /api/v1/summary may each build a report at the same time, and
// the reader's WAN list may only change between two reads, so Read sets it
// and reads under one lock.
type Ports struct {
	mu     sync.Mutex
	reader hoststat.PortReader
}

// NewPorts reads the ports of the host under fs ("" = the real /sys and
// /etc).
func NewPorts(fs hoststat.FS) *Ports {
	return &Ports{reader: hoststat.PortReader{FS: fs}}
}

// Read lists the ports in display order, with role "wan" on the interfaces
// in wan (board.json's roles apply as well, to hardware ports). nil only when
// /sys/class/net cannot be listed; a host without ports gets an empty list.
func (p *Ports) Read(wan []string) []hoststat.Port {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reader.Options.WAN = wan
	return p.reader.Read()
}

// wanInterfaces is the WAN list a report counts, and its source: the
// configured interfaces, else those holding a default route right now.
func (r Reader) wanInterfaces() ([]string, string) {
	if len(r.WANInterfaces) > 0 {
		return r.WANInterfaces, SourceConfigured
	}
	names, _ := r.FS.DefaultRouteInterfaces()
	return names, SourceDefaultRoute
}

// ReadPorts is the ports part of a report alone, with the same WAN list:
// nil when port reporting is off or /sys/class/net cannot be listed.
func (r Reader) ReadPorts() []hoststat.Port {
	if r.Ports == nil {
		return nil
	}
	names, _ := r.wanInterfaces()
	return r.Ports.Read(names)
}

// Read collects one report. It never fails: whatever cannot be read is
// left out, and a router without a default route reports no WAN.
func (r Reader) Read() *Stats {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	s := &Stats{CollectedAt: now().UTC().Truncate(time.Second), WAN: []Interface{}}

	if ct := r.FS.Conntrack(); ct.HasEntries || ct.HasLimit {
		c := &Conntrack{}
		if ct.HasEntries {
			c.Entries = u64(ct.Entries)
		}
		if ct.HasLimit {
			c.Limit = u64(ct.Limit)
		}
		s.Conntrack = c
	}
	if snmp, err := r.FS.Snmp(); err == nil {
		if v, ok := snmp["Tcp"]["CurrEstab"]; ok {
			s.TCPEstablished = &v
		}
	}
	if l, err := r.FS.Loadavg(); err == nil {
		s.Load = &Load{Load1: l.Load1, Load5: l.Load5, Load15: l.Load15}
	}
	if mem, err := r.FS.Meminfo(); err == nil {
		m := &Memory{}
		if v, ok := hoststat.MemValue(mem, "MemTotal"); ok {
			m.TotalBytes = u64(v)
		}
		if v, ok := hoststat.MemValue(mem, "MemAvailable"); ok {
			m.AvailableBytes = u64(v)
		}
		if m.TotalBytes != nil || m.AvailableBytes != nil {
			s.Memory = m
		}
	}

	names, source := r.wanInterfaces()
	s.WANSource = source
	if len(names) > 0 {
		if devs, err := r.FS.NetDev(); err == nil {
			byName := make(map[string]hoststat.NetDev, len(devs))
			for _, d := range devs {
				byName[d.Name] = d
			}
			// An interface that does not exist (a PPPoE link that is down)
			// is left out until it does.
			for _, name := range names {
				if d, ok := byName[name]; ok {
					s.WAN = append(s.WAN, Interface{Name: name, RxBytes: d.RxBytes(), TxBytes: d.TxBytes()})
				}
			}
		}
	}

	// The ports this report counts as WAN are role "wan": in a container,
	// where board.json is the host's, that is the only source of the role.
	if r.Ports != nil {
		if ports := r.Ports.Read(names); ports != nil {
			s.Ports = &ports
		}
	}
	return s
}

// OnOpenWrt reports whether the host is OpenWrt, which is what
// gateway_stats "auto" means: the OpenWrt package runs on the router.
func OnOpenWrt(fs hoststat.FS) bool {
	_, err := fs.Read("/etc/openwrt_release")
	return err == nil
}

func u64(v uint64) *uint64 { return &v }
