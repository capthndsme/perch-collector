package observe

import (
	"encoding/json"
	"strings"
	"sync"
)

// System is the system part: what the router is and whether it offloads
// flows (with offloading on, the collector misses the offloaded bytes; with
// hardware offloading it misses them entirely).
type System struct {
	Hostname string `json:"hostname,omitempty"`
	// Release is the firmware's description ("OpenWrt 24.10.2 r28739-…").
	Release  string `json:"release,omitempty"`
	Version  string `json:"version,omitempty"`
	Revision string `json:"revision,omitempty"`
	// Board is the target ("x86/64"); BoardName and Model the hardware.
	Board     string `json:"board,omitempty"`
	BoardName string `json:"boardName,omitempty"`
	Model     string `json:"model,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	// UptimeSeconds is not part of the fingerprint.
	UptimeSeconds    int64 `json:"uptimeSeconds"`
	FlowOffloading   bool  `json:"flowOffloading"`
	FlowOffloadingHw bool  `json:"flowOffloadingHw"`
}

// ParseSystemBoard reads `ubus call system board` into s.
func ParseSystemBoard(data []byte, s *System) bool {
	var doc struct {
		Kernel    string `json:"kernel"`
		Hostname  string `json:"hostname"`
		Model     string `json:"model"`
		BoardName string `json:"board_name"`
		Release   struct {
			Distribution string `json:"distribution"`
			Version      string `json:"version"`
			Revision     string `json:"revision"`
			Target       string `json:"target"`
			Description  string `json:"description"`
		} `json:"release"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return false
	}
	s.Hostname = cleanName(doc.Hostname)
	s.Kernel = cleanName(doc.Kernel)
	s.Model = cleanName(doc.Model)
	s.BoardName = cleanName(doc.BoardName)
	s.Board = cleanName(doc.Release.Target)
	s.Version = cleanName(doc.Release.Version)
	s.Revision = cleanName(doc.Release.Revision)
	s.Release = cleanName(doc.Release.Description)
	if s.Release == "" {
		s.Release = cleanName(strings.TrimSpace(doc.Release.Distribution + " " + doc.Release.Version))
	}
	return true
}

// ParseSystemUptime reads the uptime of `ubus call system info`.
func ParseSystemUptime(data []byte) (int64, bool) {
	var doc struct {
		Uptime *int64 `json:"uptime"`
	}
	if json.Unmarshal(data, &doc) != nil || doc.Uptime == nil {
		return 0, false
	}
	return *doc.Uptime, true
}

// SystemReader builds the system part. The board is asked once (it does
// not change while the collector runs, but a hostname can: asked again
// when /etc/config/system changes); the firewall defaults when
// /etc/config/firewall changes; the uptime on every read.
type SystemReader struct {
	Env *Env

	mu        sync.Mutex
	sysStamp  string
	fwStamp   string
	board     System
	offload   bool
	offloadHw bool
}

// Read returns the part; nil when ubus never answered (not OpenWrt).
func (r *SystemReader) Read() *System {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.Env.stamp("/etc/config/system"); st != r.sysStamp || r.board.Release == "" {
		if out, err := r.Env.run("ubus", "call", "system", "board"); err == nil {
			var b System
			if ParseSystemBoard(out, &b) {
				r.board = b
				r.sysStamp = st
			}
		}
	}
	if st := r.Env.stamp("/etc/config/firewall"); st != r.fwStamp {
		r.fwStamp = st
		r.offload, r.offloadHw = false, false
		if secs, ok := r.Env.uciShow("firewall"); ok {
			for _, s := range secs {
				if s.Type == "defaults" {
					r.offload = s.Bool("flow_offloading", false)
					r.offloadHw = r.offload && s.Bool("flow_offloading_hw", false)
				}
			}
		}
	}
	if r.board.Release == "" && r.board.Hostname == "" {
		return nil
	}
	s := r.board
	s.FlowOffloading, s.FlowOffloadingHw = r.offload, r.offloadHw
	if out, err := r.Env.run("ubus", "call", "system", "info"); err == nil {
		if up, ok := ParseSystemUptime(out); ok {
			s.UptimeSeconds = up
		}
	}
	return &s
}
