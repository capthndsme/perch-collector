package gwconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Test harness of the apply engine: a fake clock whose timers fire when the
// test advances it, a backend that stages with the file stager and records
// reloads (optionally failing), a runner answering `ip route get`, ubus and
// the package managers, and a router file tree.

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
	fired   bool
}

func newClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.stopped && !t.fired
		t.stopped = true
		return was
	}
}

// Advance moves the clock and runs every due timer, in this goroutine.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []*fakeTimer
	for _, t := range c.timers {
		if !t.stopped && !t.fired && !t.at.After(c.now) {
			t.fired = true
			due = append(due, t)
		}
	}
	c.mu.Unlock()
	for _, t := range due {
		t.f()
	}
}

// active counts timers that have neither fired nor been stopped.
func (c *fakeClock) active() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped && !t.fired {
			n++
		}
	}
	return n
}

type fakeBackend struct {
	dir string

	mu       sync.Mutex
	reloads  [][]string
	commits  []string
	settled  int
	failOn   map[string]error // commit of this config fails
	dropSets bool             // Set is silently lost (verification must notice)
	stageErr error
}

func (b *fakeBackend) Name() string { return "fake" }

func (b *fakeBackend) Stager(_ context.Context, configs []string, _ string) (uci.Stager, error) {
	return &recStager{fileStager: newFileStager(b.dir, configs), b: b}, nil
}

func (b *fakeBackend) CommitReloads() bool { return false }

func (b *fakeBackend) Reload(_ context.Context, configs []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reloads = append(b.reloads, append([]string(nil), configs...))
	return nil
}

func (b *fakeBackend) Settle(context.Context) error {
	b.mu.Lock()
	b.settled++
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) reloadLog() [][]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]string(nil), b.reloads...)
}

type recStager struct {
	*fileStager
	b *fakeBackend
}

func (s *recStager) Set(ctx context.Context, config, section string, options []uci.Option) error {
	if s.b.dropSets {
		return nil
	}
	return s.fileStager.Set(ctx, config, section, options)
}

func (s *recStager) Add(ctx context.Context, config, typ, name string, options []uci.Option) (string, error) {
	if s.b.stageErr != nil {
		return "", s.b.stageErr
	}
	return s.fileStager.Add(ctx, config, typ, name, options)
}

func (s *recStager) Commit(ctx context.Context, config string) error {
	s.b.mu.Lock()
	err := s.b.failOn[config]
	s.b.commits = append(s.b.commits, config)
	s.b.mu.Unlock()
	if err != nil {
		return err
	}
	return s.fileStager.Commit(ctx, config)
}

// fakeRouter answers commands: ip route get, ubus calls, opkg/apk.
type fakeRouter struct {
	root string

	mu       sync.Mutex
	routeDev string // "" = no route
	netDump  string
	calls    []string
	pkgFail  map[string]bool // opkg install of this name fails (after installing its deps)
	pkgSize  map[string]int64
	pkgDeps  map[string][]string
	// pkgFiles are files (relative to root) an install of the package writes.
	pkgFiles  map[string][]string
	updateErr bool

	// Checks (checks.go): netifd's status per interface (JSON; absent = no
	// such interface), `ip [-6] route show default`, the targets that answer
	// ping, `wg show <dev> latest-handshakes` per device.
	ifStatus map[string]string
	route4   string
	route6   string
	pingOK   map[string]bool
	wgHS     map[string]string
}

// set changes the router's answers between two steps of a test.
func (r *fakeRouter) set(f func(r *fakeRouter)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r)
}

func (r *fakeRouter) log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *fakeRouter) run(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	r.mu.Lock()
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	r.mu.Unlock()
	switch filepath.Base(name) {
	case "ip":
		r.mu.Lock()
		defer r.mu.Unlock()
		switch strings.Join(args, " ") {
		case "route show default":
			return []byte(r.route4), nil, 0, nil
		case "-6 route show default":
			return []byte(r.route6), nil, 0, nil
		}
		if r.routeDev == "" {
			return nil, []byte("RTNETLINK answers: Network is unreachable"), 2, nil
		}
		return []byte(args[len(args)-1] + " dev " + r.routeDev + " src 192.168.1.1 uid 0\n    cache\n"), nil, 0, nil
	case "ubus":
		r.mu.Lock()
		defer r.mu.Unlock()
		call := strings.Join(args, " ")
		switch {
		case strings.Contains(call, "call network.interface dump"):
			return []byte(r.netDump), nil, 0, nil
		case strings.Contains(call, "list uci"):
			return nil, []byte("Command failed: Not found"), 4, nil
		case strings.Contains(call, "call network.interface.") && strings.HasSuffix(call, " status"):
			f := strings.Fields(call)
			for i, w := range f {
				if n, ok := strings.CutPrefix(w, "network.interface."); ok && i+1 < len(f) {
					if st, ok := r.ifStatus[n]; ok {
						return []byte(st), nil, 0, nil
					}
				}
			}
			return nil, []byte("Command failed: Not found"), 4, nil
		}
		return []byte("{}"), nil, 0, nil
	case "ping":
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.pingOK[args[len(args)-1]] {
			return []byte("1 packets transmitted, 1 packets received\n"), nil, 0, nil
		}
		return []byte("1 packets transmitted, 0 packets received\n"), nil, 1, nil
	case "wg":
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(args) == 3 && args[0] == "show" && args[2] == "latest-handshakes" {
			if out, ok := r.wgHS[args[1]]; ok {
				return []byte(out), nil, 0, nil
			}
			return nil, []byte("Unable to access interface: No such device\n"), 1, nil
		}
		// Anything else (dump, private-key) would print a secret.
		return []byte("PRIVATE-KEY-MATERIAL\n"), nil, 0, nil
	case "opkg":
		return r.opkg(args)
	}
	if name == "/etc/init.d/network" {
		return nil, nil, 0, nil
	}
	return nil, []byte("not found"), 127, nil
}

func (r *fakeRouter) statusPath() string { return filepath.Join(r.root, "usr/lib/opkg/status") }

func (r *fakeRouter) installed() map[string]bool {
	data, _ := os.ReadFile(r.statusPath())
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if n, ok := strings.CutPrefix(line, "Package: "); ok {
			out[n] = true
		}
	}
	return out
}

func (r *fakeRouter) writeInstalled(set map[string]bool) {
	var names []string
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "Package: %s\nVersion: 1.0-r1\nStatus: install user installed\nArchitecture: x86_64\n\n", n)
	}
	os.MkdirAll(filepath.Dir(r.statusPath()), 0o755)
	os.WriteFile(r.statusPath(), []byte(b.String()), 0o644)
}

// closure: name plus its dependencies, dependencies first.
func (r *fakeRouter) closure(name string) []string {
	var out []string
	for _, d := range r.pkgDeps[name] {
		out = append(out, r.closure(d)...)
	}
	return append(out, name)
}

func (r *fakeRouter) opkg(args []string) ([]byte, []byte, int, error) {
	switch args[0] {
	case "update":
		if r.updateErr {
			return nil, []byte("wget returned 4"), 1, nil
		}
		return []byte("Updated list of available packages\n"), nil, 0, nil
	case "info":
		if s, ok := r.pkgSize[args[1]]; ok {
			return []byte(fmt.Sprintf("Package: %s\nVersion: 1.0-r1\nSize: %d\n", args[1], s)), nil, 0, nil
		}
		return nil, nil, 0, nil
	case "install":
		dry := args[1] == "--noaction"
		names := args[1:]
		if dry {
			names = args[2:]
		}
		have := r.installed()
		var out strings.Builder
		for _, n := range names {
			if _, ok := r.pkgSize[n]; !ok {
				return []byte("Unknown package '" + n + "'.\n"), nil, 255, nil
			}
			for _, x := range r.closure(n) {
				if have[x] {
					continue
				}
				if !dry && x == n && r.pkgFail[n] {
					r.writeInstalled(have)
					return []byte(out.String()), []byte(" * check_data_file_clashes: Package " + n + " wants to install file /usr/bin/x\n"), 255, nil
				}
				fmt.Fprintf(&out, "Installing %s (1.0-r1) to root...\n", x)
				if !dry {
					have[x] = true
					for _, f := range r.pkgFiles[x] {
						path := filepath.Join(r.root, f)
						_ = os.MkdirAll(filepath.Dir(path), 0o755)
						_ = os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755)
					}
				}
			}
		}
		if !dry {
			r.writeInstalled(have)
		}
		return []byte(out.String()), nil, 0, nil
	case "remove":
		have := r.installed()
		// Refuse to remove a package another installed one depends on.
		for p := range have {
			for _, d := range r.pkgDeps[p] {
				if d == args[1] {
					return nil, []byte("dependent package " + p), 255, nil
				}
			}
		}
		delete(have, args[1])
		r.writeInstalled(have)
		return []byte("Removing package " + args[1] + " from root...\n"), nil, 0, nil
	}
	return nil, nil, 1, nil
}

const fixNetwork = `
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'

config interface 'guest'
	option device 'br-guest'
	option proto 'static'
	option ipaddr '192.168.2.1'
	option netmask '255.255.255.0'
`

const fixDHCP = `
config dnsmasq
	option domainneeded '1'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'

config host
	option name 'printer'
	option mac '02:00:00:00:00:10'
	option ip '192.168.1.10'

config host 'nas'
	option name 'nas'
	option mac '02:00:00:00:00:11'
	option ip '192.168.1.11'
`

const fixFirewall = `
config defaults
	option input 'REJECT'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'

config rule 'r1'
	option name 'Allow-A'
	option target 'ACCEPT'

config rule 'r2'
	option name 'Allow-B'
	option target 'ACCEPT'

config rule 'r3'
	option name 'Router-only'
	option target 'DROP'
`

const netDumpLan = `{"interface":[{"interface":"lan","up":true,"pending":false,"l3_device":"br-lan","device":"br-lan"},{"interface":"guest","up":true,"pending":false,"l3_device":"br-guest","device":"br-guest"}]}`

type env struct {
	t       *testing.T
	root    string
	clock   *fakeClock
	be      *fakeBackend
	router  *fakeRouter
	p       *Plane
	mu      sync.Mutex
	recon   []string
	results []Result
	notes   []ChecksNote
	reconCh chan string
}

type envOpt func(*Options)

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{"network": fixNetwork, "dhcp": fixDHCP, "firewall": fixFirewall} {
		put(t, root, "etc/config/"+name, body)
	}
	put(t, root, "proc/mounts", "/dev/root / ext4 rw,noatime 0 0\nproc /proc proc rw 0 0\n")
	put(t, root, "etc/openwrt_release", "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.8'\n")
	os.MkdirAll(filepath.Join(root, "var/run"), 0o755)
	os.MkdirAll(filepath.Join(root, "tmp"), 0o755)
	e := &env{t: t, root: root, clock: newClock(), reconCh: make(chan string, 16)}
	e.be = &fakeBackend{dir: filepath.Join(root, "etc/config"), failOn: map[string]error{}}
	e.router = &fakeRouter{root: root, routeDev: "br-lan", netDump: netDumpLan, pkgFail: map[string]bool{},
		pkgSize: map[string]int64{}, pkgDeps: map[string][]string{}}
	e.router.writeInstalled(map[string]bool{"base-files": true, "dnsmasq": true, "firewall4": true})
	o := Options{
		Access: AccessWrite, Allowlist: DefaultAllowlist, TransportOK: true, ConfirmMax: 600,
		APIKey: "test-api-key", ServerURL: "https://perch.example.com", Root: root,
		Clock: e.clock, Backend: e.be, Run: e.router.run,
		Ubus:       &ubus.Client{Bin: "ubus", Run: e.router.run, LookPath: func(string) (string, error) { return "/bin/ubus", nil }},
		LookPath:   func(string) (string, error) { return "", errors.New("none") },
		LookupHost: func(context.Context, string) ([]string, error) { return []string{"192.168.1.5"}, nil },
	}
	for _, f := range opts {
		f(&o)
	}
	e.p = New(o)
	e.p.Configure(Configure{Mode: ModeManaged})
	e.hook()
	return e
}

func (e *env) hook() {
	e.p.SetHooks(Hooks{
		Reconnect: func(reason string) {
			e.mu.Lock()
			e.recon = append(e.recon, reason)
			e.mu.Unlock()
			e.reconCh <- reason
		},
		Result: func(r Result) bool {
			e.mu.Lock()
			e.results = append(e.results, r)
			e.mu.Unlock()
			return true
		},
		Checks: func(n ChecksNote) bool {
			e.mu.Lock()
			e.notes = append(e.notes, n)
			e.mu.Unlock()
			return true
		},
	})
}

func (e *env) sentNotes() []ChecksNote {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]ChecksNote(nil), e.notes...)
}

func (e *env) sentResults() []Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Result(nil), e.results...)
}

// waitReconnect waits for the plane's Reconnect hook.
func (e *env) waitReconnect() string {
	e.t.Helper()
	select {
	case r := <-e.reconCh:
		return r
	case <-time.After(3 * time.Second):
		e.t.Fatal("no reconnect after the apply")
	}
	return ""
}

func (e *env) file(name string) string {
	data, err := os.ReadFile(filepath.Join(e.root, "etc/config", name))
	if err != nil {
		return ""
	}
	return string(data)
}

func (e *env) hash(name string) string {
	data, err := os.ReadFile(filepath.Join(e.root, "etc/config", name))
	if err != nil {
		return ""
	}
	return uci.FileHash(data)
}

func (e *env) load(name string) *uci.Config {
	e.t.Helper()
	l, err := uci.Files{Dir: filepath.Join(e.root, "etc/config")}.Load(name)
	if err != nil {
		e.t.Fatal(err)
	}
	return l.Config
}

func (e *env) base(configs ...string) map[string]string {
	m := map[string]string{}
	for _, c := range configs {
		m[c] = e.hash(c)
	}
	return m
}

func (e *env) exists(p string) bool {
	_, err := os.Stat(filepath.Join(e.root, p))
	return err == nil
}

// apply parses params from JSON and applies them on session gen 1.
func (e *env) apply(js string) (*ApplyResult, error) {
	e.t.Helper()
	var a ApplyParams
	if err := json.Unmarshal([]byte(js), &a); err != nil {
		e.t.Fatal(err)
	}
	return e.p.Apply(context.Background(), &a, SessionRef{Gen: 1, Challenge: "c1"}, true)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func code(err error) string {
	var pe *PlaneError
	if errors.As(err, &pe) {
		return pe.Code
	}
	var ae *AccessError
	if errors.As(err, &ae) {
		return ae.Code.Error()
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func data(err error) map[string]any {
	var pe *PlaneError
	if errors.As(err, &pe) {
		return pe.Data
	}
	return nil
}
