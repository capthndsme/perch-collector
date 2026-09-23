package observe

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resolver is the resolver part: who answers DNS on the router. dnsmasq may
// sit behind another resolver (AdGuard Home on :53, dnsmasq on :54), and
// then a DNS name Perch gives a device only resolves when the front
// resolver forwards the local domain to dnsmasq.
type Resolver struct {
	// DNSMasqPort is the first dnsmasq section's `port` (53 when unset,
	// 0 = its DNS is off); null without dnsmasq.
	DNSMasqPort *int `json:"dnsmasqPort"`
	// Port53Process is the process listening on port 53 (its comm), null
	// when nothing does or it could not be told.
	Port53Process *string `json:"port53Process"`
	// Port53Processes lists every process with a socket on port 53
	// (usually one).
	Port53Processes []string `json:"port53Processes"`
	// ControllerHost is the controller's host name as the router resolves
	// it; null when the collector has no controller URL.
	ControllerHost *ResolvedHost `json:"controllerHost"`
}

// ResolvedHost is a name and what the router's resolver answers for it.
type ResolvedHost struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	// Error is set when the lookup failed ("not_found", "timeout", "error").
	Error string `json:"error,omitempty"`
}

// ProcNetListeners reads /proc/net/{udp,tcp}{,6} content and returns the
// socket inodes bound to port: UDP sockets in state 07 (unconnected) and
// TCP sockets in state 0A (LISTEN).
func ProcNetListeners(data []byte, port int, tcp bool) []uint64 {
	want := strings.ToUpper(strconv.FormatInt(int64(port), 16))
	for len(want) < 4 {
		want = "0" + want
	}
	state := "07"
	if tcp {
		state = "0A"
	}
	var out []uint64
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || !strings.Contains(f[0], ":") {
			continue
		}
		_, p, ok := strings.Cut(f[1], ":")
		if !ok || !strings.EqualFold(p, want) || f[3] != state {
			continue
		}
		if ino, err := strconv.ParseUint(f[9], 10, 64); err == nil && ino != 0 {
			out = append(out, ino)
		}
	}
	return out
}

// socketOwners maps socket inodes to the comm of the processes holding
// them (a /proc/<pid>/fd scan; needs root for other users' processes).
func (e *Env) socketOwners(inodes map[uint64]bool) map[string]int {
	owners := map[string]int{}
	if len(inodes) == 0 {
		return owners
	}
	procs, err := os.ReadDir(e.path("/proc"))
	if err != nil {
		return owners
	}
	for _, p := range procs {
		if !isPID(p.Name()) {
			continue
		}
		fdDir := e.path("/proc/" + p.Name() + "/fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		hits := 0
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err == nil && inodes[ino] {
				hits++
			}
		}
		if hits == 0 {
			continue
		}
		comm, err := e.read("/proc/" + p.Name() + "/comm")
		name := cleanName(trimNL(string(comm)))
		if err != nil || name == "" {
			name = "pid " + p.Name()
		}
		owners[name] += hits
	}
	return owners
}

// Port53Owners returns the processes listening on port 53 (UDP or TCP,
// IPv4 or IPv6), the one holding most sockets first.
func (e *Env) Port53Owners() []string {
	inodes := map[uint64]bool{}
	for _, f := range []struct {
		path string
		tcp  bool
	}{{"/proc/net/udp", false}, {"/proc/net/udp6", false}, {"/proc/net/tcp", true}, {"/proc/net/tcp6", true}} {
		if data, err := e.read(f.path); err == nil {
			for _, ino := range ProcNetListeners(data, 53, f.tcp) {
				inodes[ino] = true
			}
		}
	}
	owners := e.socketOwners(inodes)
	names := make([]string, 0, len(owners))
	for n := range owners {
		names = append(names, n)
	}
	sort.Slice(names, func(a, b int) bool {
		if owners[names[a]] != owners[names[b]] {
			return owners[names[a]] > owners[names[b]]
		}
		return names[a] < names[b]
	})
	return names
}

// ResolverReader builds the resolver part.
type ResolverReader struct {
	Env *Env
	// ControllerHost is the host of the controller URL ("" = none).
	ControllerHost string
	// Lookup resolves a name (tests); nil = the system resolver, 3 s.
	Lookup func(ctx context.Context, host string) ([]string, error)

	mu       sync.Mutex
	uciStamp string
	port     *int
}

// Read returns the part.
func (r *ResolverReader) Read() *Resolver {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.Env.stamp("/etc/config/dhcp"); st != r.uciStamp {
		r.uciStamp = st
		r.port = nil
		if secs, ok := r.Env.uciShow("dhcp"); ok {
			for _, s := range secs {
				if s.Type != "dnsmasq" {
					continue
				}
				p := 53
				if v := s.First("port"); v != "" {
					if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 65535 {
						p = n
					}
				}
				r.port = &p
				break
			}
		}
	}
	res := &Resolver{DNSMasqPort: r.port, Port53Processes: r.Env.Port53Owners()}
	if len(res.Port53Processes) > 0 {
		first := res.Port53Processes[0]
		res.Port53Process = &first
	}
	if len(res.Port53Processes) > 8 {
		res.Port53Processes = res.Port53Processes[:8]
	}
	if r.ControllerHost != "" {
		res.ControllerHost = r.resolve(r.ControllerHost)
	}
	return res
}

func (r *ResolverReader) resolve(host string) *ResolvedHost {
	h := &ResolvedHost{Name: host, Addresses: []string{}}
	if ip := net.ParseIP(host); ip != nil {
		h.Addresses = append(h.Addresses, ip.String())
		return h
	}
	lookup := r.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := lookup(ctx, host)
	if err != nil {
		h.Error = "error"
		if dnsErr, ok := err.(*net.DNSError); ok {
			switch {
			case dnsErr.IsNotFound:
				h.Error = "not_found"
			case dnsErr.IsTimeout:
				h.Error = "timeout"
			}
		}
		return h
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && len(h.Addresses) < 16 {
			h.Addresses = append(h.Addresses, ip.String())
		}
	}
	sort.Strings(h.Addresses)
	return h
}
