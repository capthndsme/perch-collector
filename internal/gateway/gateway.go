// Package gateway reports the router's own health next to the traffic the
// collector captures: connection-tracking fill, established TCP, load,
// memory and the WAN interface counters. It is what the controller's
// Gateway page shows, read from /proc on the router itself instead of from a
// node_exporter scrape (docs/collector-agent.md section 4.1 in the
// controller).
package gateway

import (
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
	// Now stamps CollectedAt (tests).
	Now func() time.Time
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

	names := r.WANInterfaces
	s.WANSource = SourceConfigured
	if len(names) == 0 {
		s.WANSource = SourceDefaultRoute
		names, _ = r.FS.DefaultRouteInterfaces()
	}
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
	return s
}

// OnOpenWrt reports whether the host is OpenWrt, which is what
// gateway_stats "auto" means: the OpenWrt package runs on the router.
func OnOpenWrt(fs hoststat.FS) bool {
	_, err := fs.Read("/etc/openwrt_release")
	return err == nil
}

func u64(v uint64) *uint64 { return &v }
