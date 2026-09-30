package observe

import (
	"bytes"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DDNS is the ddns part (gateway-sync protocol 6.1): ddns-scripts' services
// and their state. Present only when ddns-scripts is installed. Read from
// UCI `ddns` (names, `enabled`, `lookup_host` or `domain`; never the
// password or anything else of a service), the run directory
// (`ddns.global.ddns_rundir`, default /var/run/ddns: `<name>.ip`,
// `<name>.update`, `<name>.pid`), the log directory (`ddns_logdir`, default
// /var/log/ddns) and the provider definitions under /usr/share/ddns.
type DDNS struct {
	Installed      bool          `json:"installed"`
	ServiceEnabled bool          `json:"serviceEnabled"`
	Providers      []string      `json:"providers"`
	Services       []DDNSService `json:"services"`
}

// DDNSService is one `service` section. Domain is `lookup_host`, else
// `domain` (null without either); RegisteredIP the address the provider
// answered at the last check (null when the lookup failed or never ran);
// LastUpdate the Unix time of the last successful update (null = none since
// boot); Running: its updater process is alive; LastError the last ERROR or
// WARN line of its log after the last successful update (null = none).
type DDNSService struct {
	Name         string  `json:"name"`
	Enabled      bool    `json:"enabled"`
	Domain       *string `json:"domain"`
	RegisteredIP *string `json:"registeredIp"`
	LastUpdate   *int64  `json:"lastUpdate"`
	Running      bool    `json:"running"`
	LastError    *string `json:"lastError"`
}

// Caps and defaults of the ddns part.
const (
	MaxDDNSServices  = 64
	MaxDDNSProviders = 512
	maxDDNSError     = 200
	// maxDDNSLog is how much of a log's end is read (ddns-scripts keeps
	// 250 lines by default).
	maxDDNSLog = 64 << 10

	DDNSUpdater       = "/usr/lib/ddns/dynamic_dns_updater.sh"
	DefaultDDNSRunDir = "/var/run/ddns"
	DefaultDDNSLogDir = "/var/log/ddns"
)

// DDNSProviderDirs hold one <provider>.json per DDNS provider.
var DDNSProviderDirs = []string{"/usr/share/ddns/default", "/usr/share/ddns/custom"}

// DDNSInstalled reports whether ddns-scripts is installed.
func (e *Env) DDNSInstalled() bool { return e.exists(DDNSUpdater) }

// ddnsConfig is what the part takes from UCI.
type ddnsConfig struct {
	runDir, logDir string
	services       []ddnsServiceConfig
}

type ddnsServiceConfig struct {
	name    string
	enabled bool
	domain  string
}

// parseDDNSConfig reads `uci -X show ddns` (real names of anonymous
// sections: the updater's files are named after them).
func parseDDNSConfig(secs []UCISection) ddnsConfig {
	c := ddnsConfig{runDir: DefaultDDNSRunDir, logDir: DefaultDDNSLogDir}
	for _, s := range secs {
		switch s.Type {
		case "ddns":
			if s.Name != "global" {
				continue
			}
			if d := s.First("ddns_rundir"); strings.HasPrefix(d, "/") {
				c.runDir = filepath.Clean(d)
			}
			if d := s.First("ddns_logdir"); strings.HasPrefix(d, "/") {
				c.logDir = filepath.Clean(d)
			}
		case "service":
			if s.Anonymous() || cleanName(s.Name) != s.Name || strings.ContainsAny(s.Name, "/.") || len(c.services) >= MaxDDNSServices {
				continue
			}
			domain := s.First("lookup_host")
			if domain == "" {
				domain = s.First("domain")
			}
			c.services = append(c.services, ddnsServiceConfig{name: s.Name, enabled: s.Bool("enabled", false), domain: cleanName(domain)})
		}
	}
	return c
}

// ddnsLastError is the last ERROR or WARN line of a service's log that
// comes after its last successful update, trimmed to 200 bytes; "" = none.
func ddnsLastError(log []byte) string {
	last := ""
	for _, line := range strings.Split(string(log), "\n") {
		switch {
		case strings.Contains(line, "Update successful") || strings.Contains(line, "update successful"):
			last = ""
		case strings.Contains(line, " ERROR ") || strings.Contains(line, "WARN"):
			last = line
		}
	}
	last = strings.TrimSpace(strings.ToValidUTF8(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, last), ""))
	if len(last) > maxDDNSError {
		last = last[:maxDDNSError]
		for len(last) > 0 && !validUTF8Tail(last) {
			last = last[:len(last)-1]
		}
	}
	return last
}

// DDNSReader reads the ddns part; UCI is re-read only when /etc/config/ddns
// changes, the providers every ten minutes.
type DDNSReader struct {
	Env *Env

	mu          sync.Mutex
	uciStamp    string
	cfg         ddnsConfig
	providers   []string
	providersAt time.Time
	// boot is the boot time as a Unix time: ddns-scripts records the
	// uptime of an update, not the clock. Kept while the clock agrees
	// within 2 s, so the value does not flicker with rounding.
	boot int64
}

// Read returns the part; nil when ddns-scripts is not installed.
func (r *DDNSReader) Read() *DDNS {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.Env
	if !e.DDNSInstalled() {
		return nil
	}
	if st := e.stamp("/etc/config/ddns"); st != r.uciStamp {
		r.uciStamp = st
		r.cfg = ddnsConfig{runDir: DefaultDDNSRunDir, logDir: DefaultDDNSLogDir}
		if out, err := e.run("uci", "-q", "-X", "show", "ddns"); err == nil {
			r.cfg = parseDDNSConfig(ParseUCIShow("ddns", out))
		}
	}
	now := e.now()
	if r.providers == nil || now.Sub(r.providersAt) >= 10*time.Minute || now.Before(r.providersAt) {
		r.providers, r.providersAt = r.readProviders(), now
	}
	uptime, uptimeOK := r.uptime()
	if uptimeOK {
		boot := int64(math.Round(float64(now.UnixNano())/1e9 - uptime))
		if r.boot == 0 || boot-r.boot > 2 || r.boot-boot > 2 {
			r.boot = boot
		}
	}
	d := &DDNS{Installed: true, ServiceEnabled: e.serviceEnabled("ddns"), Providers: r.providers, Services: []DDNSService{}}
	for _, sc := range r.cfg.services {
		s := DDNSService{Name: sc.name, Enabled: sc.enabled}
		if sc.domain != "" {
			v := sc.domain
			s.Domain = &v
		}
		base := filepath.Join(r.cfg.runDir, sc.name)
		if b, err := e.read(base + ".ip"); err == nil {
			if a, err := netip.ParseAddr(strings.TrimSpace(string(b))); err == nil {
				v := a.String()
				s.RegisteredIP = &v
			}
		}
		if b, err := e.read(base + ".update"); err == nil && uptimeOK {
			// Seconds of uptime at the update; later than now = written
			// before a reboot (a run directory that is not on tmpfs).
			if up, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && up > 0 && float64(up) <= uptime+1 {
				v := r.boot + up
				s.LastUpdate = &v
			}
		}
		if b, err := e.read(base + ".pid"); err == nil {
			s.Running = r.updaterAlive(strings.TrimSpace(string(b)))
		}
		if last := ddnsLastError(e.tail(filepath.Join(r.cfg.logDir, sc.name+".log"), maxDDNSLog)); last != "" {
			s.LastError = &last
		}
		d.Services = append(d.Services, s)
	}
	return d
}

// uptime is /proc/uptime's first field.
func (r *DDNSReader) uptime() (float64, bool) {
	b, err := r.Env.read("/proc/uptime")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, false
	}
	up, err := strconv.ParseFloat(f[0], 64)
	return up, err == nil && up > 0
}

// updaterAlive: the pid runs the ddns updater (not a reused pid).
func (r *DDNSReader) updaterAlive(pid string) bool {
	if !isPID(pid) {
		return false
	}
	cmd, err := r.Env.read("/proc/" + pid + "/cmdline")
	return err == nil && strings.Contains(string(cmd), "dynamic_dns_updater")
}

// readProviders lists the provider definitions, sorted, at most 512.
func (r *DDNSReader) readProviders() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, dir := range DDNSProviderDirs {
		matches, _ := filepath.Glob(filepath.Join(r.Env.path(dir), "*.json"))
		for _, m := range matches {
			name := cleanName(strings.TrimSuffix(filepath.Base(m), ".json"))
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	if len(out) > MaxDDNSProviders {
		out = out[:MaxDDNSProviders]
	}
	return out
}

// tail is at most the last max bytes of a file, from the start of a line;
// nil when it cannot be read.
func (e *Env) tail(p string, max int64) []byte {
	f, err := os.Open(e.path(p))
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	off := st.Size() - max
	if off < 0 {
		off = 0
	}
	b := make([]byte, st.Size()-off)
	n, _ := f.ReadAt(b, off)
	b = b[:n]
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b
}
