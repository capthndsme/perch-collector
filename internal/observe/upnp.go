package observe

import (
	"bufio"
	"bytes"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// UPnP is the upnp part: miniupnpd's state and its port mappings (the
// lease file). Enabled is UCI `upnpd.config.enabled`; Running is the
// process. A router without miniupnpd reports installed false and no
// mappings.
type UPnP struct {
	Installed bool          `json:"installed"`
	Enabled   bool          `json:"enabled"`
	Running   bool          `json:"running"`
	Mappings  []UPnPMapping `json:"mappings"`
}

// UPnPMapping is one port mapping a LAN client opened. Expires is a Unix
// time, 0 = none (a permanent mapping).
type UPnPMapping struct {
	Proto       string `json:"proto"`
	ExtPort     int    `json:"extPort"`
	IntIP       string `json:"intIp"`
	IntPort     int    `json:"intPort"`
	Expires     int64  `json:"expires"`
	Description string `json:"description,omitempty"`
}

// MaxUPnPMappings caps the mappings; MaxDescription the description.
const (
	MaxUPnPMappings = 512
	MaxDescription  = 128
)

// DefaultUPnPLeaseFile is OpenWrt's miniupnpd lease file when UCI names none.
const DefaultUPnPLeaseFile = "/var/run/miniupnpd.leases"

// ParseUPnPLeases reads a miniupnpd lease file: lines
// "PROTO:EXTPORT:INTADDR:INTPORT:TIMESTAMP:DESC" (miniupnpd 2.x, TIMESTAMP
// a Unix time or 0) or "PROTO:EXTPORT:INTADDR:INTPORT:DESC" (1.x). The
// description may itself contain colons.
func ParseUPnPLeases(data []byte) []UPnPMapping {
	var out []UPnPMapping
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.SplitN(strings.TrimRight(sc.Text(), "\r"), ":", 6)
		if len(f) < 4 {
			continue
		}
		proto := strings.ToUpper(strings.TrimSpace(f[0]))
		if proto != "TCP" && proto != "UDP" {
			continue
		}
		ext, err1 := strconv.Atoi(f[1])
		in, err2 := strconv.Atoi(f[3])
		ip := cleanIP(f[2], false)
		if err1 != nil || err2 != nil || ip == "" || ext < 1 || ext > 65535 || in < 1 || in > 65535 {
			continue
		}
		m := UPnPMapping{Proto: proto, ExtPort: ext, IntIP: ip, IntPort: in}
		switch {
		case len(f) == 6:
			if ts, err := strconv.ParseInt(f[4], 10, 64); err == nil && ts >= 0 {
				m.Expires = ts
				m.Description = f[5]
			} else {
				m.Description = f[4] + ":" + f[5]
			}
		case len(f) == 5:
			m.Description = f[4]
		}
		m.Description = cleanDescription(m.Description)
		out = append(out, m)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Proto != out[b].Proto {
			return out[a].Proto < out[b].Proto
		}
		return out[a].ExtPort < out[b].ExtPort
	})
	return out
}

func cleanDescription(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > MaxDescription {
		s = s[:MaxDescription]
		for len(s) > 0 && !validUTF8Tail(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func validUTF8Tail(s string) bool {
	return strings.ToValidUTF8(s, "�") == s
}

// UPnPReader reads miniupnpd's state; UCI is re-read only when
// /etc/config/upnpd changes.
type UPnPReader struct {
	Env *Env

	mu        sync.Mutex
	uciStamp  string
	enabled   bool
	leaseFile string
	installed bool
}

// Read returns the part.
func (r *UPnPReader) Read() *UPnP {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.Env.stamp("/etc/config/upnpd"); st != r.uciStamp {
		r.uciStamp = st
		r.enabled, r.leaseFile = false, DefaultUPnPLeaseFile
		if st != "-" {
			if secs, ok := r.Env.uciShow("upnpd"); ok {
				for _, s := range secs {
					if s.Type != "upnpd" {
						continue
					}
					r.enabled = s.Bool("enabled", false)
					if f := s.First("upnp_lease_file"); f != "" {
						r.leaseFile = f
					}
					break
				}
			}
		}
	}
	u := &UPnP{Mappings: []UPnPMapping{}}
	u.Installed = r.Env.exists("/usr/sbin/miniupnpd") || r.Env.exists("/etc/init.d/miniupnpd")
	u.Enabled = u.Installed && r.enabled
	u.Running = r.Env.processRunning("miniupnpd")
	if data, err := r.Env.read(r.leaseFile); err == nil {
		u.Mappings = capList(ParseUPnPLeases(data), MaxUPnPMappings)
	}
	return u
}
