package qos

import (
	"bufio"
	"bytes"
	"context"
	"strings"
)

// ProbeResult is qos.probe's answer (plan 3 section 6), with what this
// agent adds: the tc flavour, the clock and the router's time zone.
type ProbeResult struct {
	SQM          ProbeSQM        `json:"sqm"`
	Kernel       map[string]bool `json:"kernel"`
	Conflicts    []string        `json:"conflicts"`
	FlowOffload  FlowOffload     `json:"flowOffload"`
	LANDevices   []ProbeLAN      `json:"lanDevices"`
	Tc           string          `json:"tc"`
	ClockSynced  bool            `json:"clockSynced"`
	TZ           string          `json:"tz"`
	Configured   bool            `json:"configured"`
	PerchVersion string          `json:"perchQosPackage,omitempty"`
}

// ProbeSQM is sqm-scripts on the router.
type ProbeSQM struct {
	Installed bool     `json:"installed"`
	Version   *string  `json:"version"`
	LuCI      bool     `json:"luci"`
	Queues    []string `json:"queues"`
}

// FlowOffload is the firewall's flow offloading.
type FlowOffload struct {
	Software bool `json:"software"`
	Hardware bool `json:"hardware"`
}

// ProbeLAN is one LAN the shaper would use.
type ProbeLAN struct {
	Network  string   `json:"network"`
	Device   string   `json:"device"`
	Prefixes []string `json:"prefixes"`
	Conflict string   `json:"conflict,omitempty"`
}

// KernelFeatures are the features qos.probe tries, in order, each with
// the tc line that proves it on a scratch ifb.
var KernelFeatures = []struct{ Name, Line string }{
	{"htb", "qdisc add dev ifb-pqprobe root handle 1: htb default 0"},
	{"htb_class", "class add dev ifb-pqprobe parent 1: classid 1:10 htb rate 1mbit"},
	{"fq_codel", "qdisc add dev ifb-pqprobe parent 1:10 handle 10: fq_codel"},
	{"cake", "class add dev ifb-pqprobe parent 1: classid 1:11 htb rate 1mbit\nqdisc add dev ifb-pqprobe parent 1:11 handle 11: cake unlimited besteffort dual-dsthost"},
	{"clsact", "qdisc add dev ifb-pqprobe clsact"},
	{"flower", "filter add dev ifb-pqprobe egress pref 10 protocol all handle 1 flower dst_mac 02:00:00:00:00:01 action pass"},
	{"skbedit", "filter add dev ifb-pqprobe egress pref 11 protocol all handle 1 flower dst_mac 02:00:00:00:00:02 action skbedit priority 1:10"},
	{"mirred", "filter add dev ifb-pqprobe egress pref 12 protocol all handle 1 flower dst_mac 02:00:00:00:00:03 action mirred egress redirect dev ifb-pqprobe"},
	{"matchall", "filter add dev ifb-pqprobe ingress pref 1 protocol arp matchall action pass"},
	{"chain", "filter add dev ifb-pqprobe egress chain 1 pref 10 protocol all handle 1 flower action pass"},
}

const probeIfb = "ifb-pqprobe"

// Probe finds out what the router can do (plan 3 section 6). Kernel
// features are found by trial on a scratch ifb, not from kmods: a
// container's kmods mean nothing.
func (e *Engine) Probe(ctx context.Context) ProbeResult {
	r := ProbeResult{Kernel: map[string]bool{}, Conflicts: []string{}, LANDevices: []ProbeLAN{}, SQM: ProbeSQM{Queues: []string{}}}
	e.mu.Lock()
	e.refreshConfigLocked()
	e.refreshLANsLocked(true)
	r.Configured = e.cfg != nil && e.cfg.Present
	r.TZ = e.zoneKey
	for _, q := range e.sqm {
		if q.Enabled && q.Device != "" {
			r.SQM.Queues = append(r.SQM.Queues, q.Device)
		}
	}
	for _, l := range e.lans {
		pl := ProbeLAN{Network: l.Network, Device: l.Device, Prefixes: []string{}, Conflict: l.Conflict}
		for _, p := range l.Prefixes {
			pl.Prefixes = append(pl.Prefixes, p.String())
		}
		r.LANDevices = append(r.LANDevices, pl)
	}
	e.mu.Unlock()
	r.ClockSynced = e.sys.ClockSynced()

	pkgs := e.packages()
	if v, ok := pkgs["sqm-scripts"]; ok {
		r.SQM.Installed = true
		r.SQM.Version = &v
	} else if e.fileExists("/usr/lib/sqm/run.sh") {
		r.SQM.Installed = true
	}
	_, r.SQM.LuCI = pkgs["luci-app-sqm"]
	if v, ok := pkgs["perch-qos"]; ok {
		r.PerchVersion = v
	}
	for _, p := range []string{"qosify", "nft-qos", "eqos"} {
		if _, ok := pkgs[p]; ok && e.fileExists("/etc/rc.d/S"+startPrio(e, p)+p) {
			r.Conflicts = append(r.Conflicts, p)
		}
	}
	if fw, err := e.sys.ReadFile(FirewallPath); err == nil {
		if secs, err := parseUCIFile(fw); err == nil {
			for _, s := range secs {
				if s.Type != "defaults" {
					continue
				}
				v, _ := s.first("flow_offloading")
				hw, _ := s.first("flow_offloading_hw")
				r.FlowOffload.Software = uciBool(v, false)
				r.FlowOffload.Hardware = r.FlowOffload.Software && uciBool(hw, false)
			}
		}
	}

	// Kernel features, by trial.
	for _, f := range KernelFeatures {
		r.Kernel[f.Name] = false
	}
	if err := e.sys.EnsureIfb(probeIfb); err == nil {
		r.Kernel["ifb"] = true
		var lines []string
		idx := map[int]string{}
		for _, f := range KernelFeatures {
			for _, l := range strings.Split(f.Line, "\n") {
				lines = append(lines, l)
				idx[len(lines)] = f.Name
			}
		}
		_, stderr, _ := e.sys.Tc(ctx, lines, false, false)
		failed := map[string]bool{}
		for _, m := range failedLine.FindAllSubmatch(stderr, -1) {
			n := 0
			for _, c := range m[1] {
				n = n*10 + int(c-'0')
			}
			failed[idx[n]] = true
		}
		for _, f := range KernelFeatures {
			r.Kernel[f.Name] = !failed[f.Name]
		}
		_ = e.sys.DeleteLink(probeIfb)
	} else {
		r.Kernel["ifb"] = false
	}
	r.Tc = e.tcFlavour()
	return r
}

// packages lists the installed packages and their versions (opkg or apk).
func (e *Engine) packages() map[string]string {
	out := map[string]string{}
	if data, err := e.sys.ReadFile("/usr/lib/opkg/status"); err == nil {
		var name string
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 4096), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "Package: "):
				name = strings.TrimPrefix(line, "Package: ")
			case strings.HasPrefix(line, "Version: ") && name != "":
				out[name] = strings.TrimPrefix(line, "Version: ")
			case line == "":
				name = ""
			}
		}
	}
	if data, err := e.sys.ReadFile("/lib/apk/db/installed"); err == nil {
		var name string
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 4096), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "P:"):
				name = line[2:]
			case strings.HasPrefix(line, "V:") && name != "":
				out[name] = line[2:]
			case line == "":
				name = ""
			}
		}
	}
	return out
}

// startPrio is a package's init START number (for the rc.d link): read
// from its init script, "" when unknown (the glob below then fails).
func startPrio(e *Engine, name string) string {
	data, err := e.sys.ReadFile("/etc/init.d/" + name)
	if err != nil {
		return "??"
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "START=") {
			return strings.TrimSpace(strings.TrimPrefix(l, "START="))
		}
	}
	return "??"
}

// tcFlavour names the tc binary behind `tc` (OpenWrt's alternatives).
func (e *Engine) tcFlavour() string {
	for _, p := range []string{"/usr/libexec/tc-tiny", "/usr/libexec/tc-full", "/usr/libexec/tc-bpf"} {
		if e.fileExists(p) {
			return strings.TrimPrefix(p, "/usr/libexec/")
		}
	}
	return "tc"
}
