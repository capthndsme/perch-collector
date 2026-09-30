package observe

import (
	"bufio"
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// UPnP is the upnp part: miniupnpd's state and its port mappings (the
// lease file). Enabled is UCI `upnpd.config.enabled`; Running is the
// process; SecureMode is UCI `secure_mode` (on when unset, like the init
// script: a client may only map ports to itself). A router without
// miniupnpd reports installed false and no mappings.
type UPnP struct {
	Installed  bool          `json:"installed"`
	Enabled    bool          `json:"enabled"`
	Running    bool          `json:"running"`
	SecureMode bool          `json:"secureMode"`
	Mappings   []UPnPMapping `json:"mappings"`
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

	mu         sync.Mutex
	uciStamp   string
	enabled    bool
	secureMode bool
	leaseFile  string
	installed  bool
}

// Read returns the part.
func (r *UPnPReader) Read() *UPnP {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.Env.stamp("/etc/config/upnpd"); st != r.uciStamp {
		r.uciStamp = st
		r.enabled, r.secureMode, r.leaseFile = false, true, DefaultUPnPLeaseFile
		if st != "-" {
			if secs, ok := r.Env.uciShow("upnpd"); ok {
				for _, s := range secs {
					if s.Type != "upnpd" {
						continue
					}
					r.enabled = s.Bool("enabled", false)
					r.secureMode = s.Bool("secure_mode", true)
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
	u.SecureMode = u.Installed && r.secureMode
	u.Running = r.Env.processRunning("miniupnpd")
	if data, err := r.Env.read(r.leaseFile); err == nil {
		u.Mappings = capList(ParseUPnPLeases(data), MaxUPnPMappings)
	}
	if u.Running {
		u.Mappings = capList(append(u.Mappings, r.orphans(u.Mappings)...), MaxUPnPMappings)
	}
	return u
}

// OrphanDescription marks a mapping whose nftables rules are there but
// whose lease line is not: miniupnpd refused to re-add it at a restart (its
// permission rules deny it now) and left the port open. The delete removes
// such rules too.
const OrphanDescription = "open without a lease: left by miniupnpd"

// natRuleRe is a DNAT rule miniupnpd-nftables writes:
// iif "wan" @nh,72,8 0x6 th dport 45000 dnat ip to 10.99.10.128:5000 # handle 8536
var natRuleRe = regexp.MustCompile(`@nh,72,8 0x([0-9a-f]+) th dport (\d+) dnat ip to ([0-9.]+):(\d+)`)

// orphans lists miniupnpd-nftables' DNAT rules that the lease file does not
// name (nothing with another backend, or without its generated config).
func (r *UPnPReader) orphans(known []UPnPMapping) []UPnPMapping {
	conf, err := r.Env.read("/var/etc/miniupnpd.conf")
	if err != nil {
		return nil
	}
	table, chain := "", "upnp_prerouting"
	for _, line := range strings.Split(string(conf), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "upnp_nat_table_name":
			table = strings.TrimSpace(v)
		case "upnp_table_name":
			if table == "" {
				table = strings.TrimSpace(v)
			}
		case "upnp_nat_chain":
			chain = strings.TrimSpace(v)
		}
	}
	if !nftName(table) || !nftName(chain) {
		return nil
	}
	out, err := r.Env.run("nft", "list", "chain", "inet", table, chain)
	if err != nil {
		return nil
	}
	have := map[string]bool{}
	for _, m := range known {
		have[m.Proto+":"+strconv.Itoa(m.ExtPort)] = true
	}
	var orphans []UPnPMapping
	for _, line := range strings.Split(string(out), "\n") {
		m := natRuleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		proto := map[string]string{"6": "TCP", "11": "UDP"}[m[1]]
		ext, _ := strconv.Atoi(m[2])
		intPort, _ := strconv.Atoi(m[4])
		if proto == "" || ext < 1 || have[proto+":"+m[2]] {
			continue
		}
		have[proto+":"+m[2]] = true
		orphans = append(orphans, UPnPMapping{Proto: proto, ExtPort: ext, IntIP: m[3], IntPort: intPort, Description: OrphanDescription})
	}
	return orphans
}

func nftName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}
