package observe

import (
	"encoding/json"
	"sort"
	"sync"
)

// MWAN3 is the mwan3 part, read only. The configuration (UCI) and the
// service are reported separately: a router may keep a full mwan3 config
// with the service disabled and fail over by route metrics instead, and
// then the interfaces' live status says "notracking" for all of them.
// A router without mwan3 reports nothing (the part is absent).
type MWAN3 struct {
	// ServiceEnabled: /etc/init.d/mwan3 enabled (starts at boot).
	ServiceEnabled bool `json:"serviceEnabled"`
	// Running: mwan3's tracking runs (a mwan3track process, or any
	// interface reported running).
	Running bool `json:"running"`
	// ConfigInterfaces are the UCI `interface` sections.
	ConfigInterfaces []MWAN3ConfigInterface `json:"configInterfaces"`
	// Interfaces is `ubus call mwan3 status`: the live view ([] when mwan3
	// does not answer).
	Interfaces []MWAN3Interface `json:"interfaces"`
	// Policies is the live policy table, name → members, IPv4 and IPv6
	// merged (the IPv6 name gets a "@ipv6" suffix when both exist).
	Policies map[string][]MWAN3PolicyMember `json:"policies"`
	// ConfigPolicies are the UCI `policy` sections: name → member names.
	ConfigPolicies map[string][]string `json:"configPolicies"`
}

// MWAN3ConfigInterface is one UCI `mwan3.<name>=interface` section.
type MWAN3ConfigInterface struct {
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Family   string   `json:"family,omitempty"`
	TrackIPs []string `json:"trackIps"`
}

// MWAN3Interface is one interface of `mwan3 status`.
type MWAN3Interface struct {
	Name string `json:"name"`
	// Status: online, offline, notracking, disabled, …
	Status        string `json:"status"`
	Enabled       bool   `json:"enabled"`
	Running       bool   `json:"running"`
	Up            bool   `json:"up"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	// Tracking is "active" when mwan3track probes this interface, else
	// "none" (fingerprint-stable form of the status's track state).
	Tracking string         `json:"tracking"`
	TrackIPs []MWAN3TrackIP `json:"trackIps"`
}

// MWAN3TrackIP is one probed address.
type MWAN3TrackIP struct {
	IP string `json:"ip"`
	Up bool   `json:"up"`
}

// MWAN3PolicyMember is one member of a live policy.
type MWAN3PolicyMember struct {
	Interface string `json:"interface"`
	Percent   int    `json:"percent"`
}

// ParseMWAN3Status reads `ubus call mwan3 status`.
func ParseMWAN3Status(data []byte) ([]MWAN3Interface, map[string][]MWAN3PolicyMember, bool) {
	var doc struct {
		Interfaces map[string]struct {
			Status  string `json:"status"`
			Enabled bool   `json:"enabled"`
			Running bool   `json:"running"`
			Up      bool   `json:"up"`
			Uptime  int64  `json:"uptime"`
			TrackIP []struct {
				IP     string `json:"ip"`
				Status string `json:"status"`
			} `json:"track_ip"`
		} `json:"interfaces"`
		Policies map[string]json.RawMessage `json:"policies"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil, nil, false
	}
	ifaces := []MWAN3Interface{}
	for name, it := range doc.Interfaces {
		n := cleanName(name)
		if n == "" {
			continue
		}
		i := MWAN3Interface{Name: n, Status: cleanName(it.Status), Enabled: it.Enabled, Running: it.Running, Up: it.Up,
			UptimeSeconds: it.Uptime, Tracking: "none", TrackIPs: []MWAN3TrackIP{}}
		if it.Running && len(it.TrackIP) > 0 {
			i.Tracking = "active"
		}
		for _, t := range it.TrackIP {
			ip := cleanIP(t.IP, false)
			if ip == "" {
				ip = cleanIP(t.IP, true)
			}
			if ip != "" && len(i.TrackIPs) < 16 {
				i.TrackIPs = append(i.TrackIPs, MWAN3TrackIP{IP: ip, Up: t.Status == "up"})
			}
		}
		ifaces = append(ifaces, i)
	}
	sort.Slice(ifaces, func(a, b int) bool { return ifaces[a].Name < ifaces[b].Name })

	// Policies: {"ipv4": {name: [members]}, "ipv6": {…}} (mwan3 2.8+), or
	// {name: [members]} (older).
	policies := map[string][]MWAN3PolicyMember{}
	add := func(name string, raw json.RawMessage) {
		var members []struct {
			Interface string `json:"interface"`
			Percent   int    `json:"percent"`
		}
		if json.Unmarshal(raw, &members) != nil {
			return
		}
		n := cleanName(name)
		if n == "" || len(policies) >= 64 {
			return
		}
		list := []MWAN3PolicyMember{}
		for _, m := range members {
			if i := cleanName(m.Interface); i != "" && len(list) < 16 {
				list = append(list, MWAN3PolicyMember{Interface: i, Percent: m.Percent})
			}
		}
		policies[n] = list
	}
	for _, fam := range []string{"ipv4", "ipv6"} {
		raw, ok := doc.Policies[fam]
		if !ok {
			continue
		}
		var byName map[string]json.RawMessage
		if json.Unmarshal(raw, &byName) != nil {
			continue
		}
		for name, members := range byName {
			key := name
			if _, dup := policies[cleanName(name)]; dup && fam == "ipv6" {
				key = name + "@ipv6"
			}
			add(key, members)
		}
	}
	for name, raw := range doc.Policies {
		if name != "ipv4" && name != "ipv6" {
			add(name, raw)
		}
	}
	// An IPv6 twin with the same members as its IPv4 policy is noise.
	for name, v6 := range policies {
		if len(name) > 5 && name[len(name)-5:] == "@ipv6" {
			if v4, ok := policies[name[:len(name)-5]]; ok && equalJSON(v4, v6) {
				delete(policies, name)
			}
		}
	}
	return ifaces, policies, true
}

// mwan3FromUCI reads the UCI side.
func mwan3FromUCI(secs []UCISection) ([]MWAN3ConfigInterface, map[string][]string) {
	ifaces := []MWAN3ConfigInterface{}
	policies := map[string][]string{}
	for _, s := range secs {
		switch s.Type {
		case "interface":
			i := MWAN3ConfigInterface{Name: cleanName(s.Name), Enabled: s.Bool("enabled", false), Family: cleanName(s.First("family")), TrackIPs: []string{}}
			for _, t := range s.Words("track_ip") {
				ip := cleanIP(t, false)
				if ip == "" {
					ip = cleanIP(t, true)
				}
				if ip == "" {
					ip = cleanName(t) // a host name is allowed
				}
				if ip != "" && len(i.TrackIPs) < 16 {
					i.TrackIPs = append(i.TrackIPs, ip)
				}
			}
			if i.Name != "" && len(ifaces) < 64 {
				ifaces = append(ifaces, i)
			}
		case "policy":
			if n := cleanName(s.Name); n != "" && len(policies) < 64 {
				members := []string{}
				for _, m := range s.Words("use_member") {
					if c := cleanName(m); c != "" && len(members) < 16 {
						members = append(members, c)
					}
				}
				policies[n] = members
			}
		}
	}
	return ifaces, policies
}

// MWAN3Reader reads the mwan3 part.
type MWAN3Reader struct {
	Env *Env

	mu       sync.Mutex
	uciStamp string
	cfgIf    []MWAN3ConfigInterface
	cfgPol   map[string][]string
}

// Read returns nil when mwan3 is not installed.
func (r *MWAN3Reader) Read() *MWAN3 {
	r.mu.Lock()
	defer r.mu.Unlock()
	installed := r.Env.exists("/etc/init.d/mwan3") || r.Env.exists("/usr/sbin/mwan3")
	st := r.Env.stamp("/etc/config/mwan3")
	if !installed && st == "-" {
		return nil
	}
	if st != r.uciStamp || r.cfgIf == nil {
		r.uciStamp = st
		r.cfgIf, r.cfgPol = []MWAN3ConfigInterface{}, map[string][]string{}
		if secs, ok := r.Env.uciShow("mwan3"); ok {
			r.cfgIf, r.cfgPol = mwan3FromUCI(secs)
		}
	}
	m := &MWAN3{
		ServiceEnabled:   r.Env.serviceEnabled("mwan3"),
		ConfigInterfaces: r.cfgIf,
		ConfigPolicies:   r.cfgPol,
		Interfaces:       []MWAN3Interface{},
		Policies:         map[string][]MWAN3PolicyMember{},
	}
	if out, err := r.Env.run("ubus", "call", "mwan3", "status"); err == nil {
		if ifaces, pol, ok := ParseMWAN3Status(out); ok {
			m.Interfaces, m.Policies = ifaces, pol
		}
	}
	m.Running = r.Env.processRunning("mwan3track")
	for _, i := range m.Interfaces {
		if i.Running {
			m.Running = true
		}
	}
	return m
}
