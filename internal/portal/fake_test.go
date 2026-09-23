package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/capthndsme/perch-collector/internal/observe"
)

// fakeSystem is a router in memory: an nft that understands the scripts
// the portal writes (tables, sets with elements, element add/delete), a
// neighbour table, device addresses and a conntrack flush log.
type fakeSystem struct {
	mu        sync.Mutex
	tables    map[string]bool               // "inet perch_portal"
	sets      map[string]map[string]bool    // "inet perch_portal p1_auth" → elements
	counters  map[string]map[string]Counter // set key → mac → counter
	scripts   []string
	failNext  bool
	neighbors []observe.Neighbor
	devices   map[string][]netip.Prefix
	flushed   [][]string
	files     map[string]string
	commands  []string
	dnsmasq   string
	fw4       bool
}

func newFakeSystem() *fakeSystem {
	return &fakeSystem{
		tables: map[string]bool{}, sets: map[string]map[string]bool{}, counters: map[string]map[string]Counter{},
		devices: map[string][]netip.Prefix{"guest": {netip.MustParsePrefix("192.168.20.1/24")}},
		files:   map[string]string{}, dnsmasq: "Dnsmasq version 2.90\nCompile time options: IPv6 GNU-getopt no-DBus nftset\n", fw4: true,
	}
}

var (
	reTable     = regexp.MustCompile(`^table (inet|netdev) (\S+)( \{)?$`)
	reDelTable  = regexp.MustCompile(`^delete table (inet|netdev) (\S+)$`)
	reSet       = regexp.MustCompile(`^set (\S+) \{$`)
	reElements  = regexp.MustCompile(`^elements = \{ (.*) \}$`)
	reElementOp = regexp.MustCompile(`^(add|delete) element (inet|netdev) (\S+) (\S+) \{ (.*) \}$`)
)

func (f *fakeSystem) Apply(script string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, script)
	if f.failNext {
		f.failNext = false
		return fmt.Errorf("nft: injected failure")
	}
	// Transaction semantics: work on copies, commit at the end.
	tables := map[string]bool{}
	for k, v := range f.tables {
		tables[k] = v
	}
	sets := map[string]map[string]bool{}
	for k, v := range f.sets {
		c := map[string]bool{}
		for e := range v {
			c[e] = true
		}
		sets[k] = c
	}
	var table, set string
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := reTable.FindStringSubmatch(line); m != nil {
			table = m[1] + " " + m[2]
			tables[table] = true
			continue
		}
		if m := reDelTable.FindStringSubmatch(line); m != nil {
			t := m[1] + " " + m[2]
			if !tables[t] {
				return fmt.Errorf("no such table %s", t)
			}
			delete(tables, t)
			for k := range sets {
				if strings.HasPrefix(k, t+" ") {
					delete(sets, k)
				}
			}
			continue
		}
		if m := reSet.FindStringSubmatch(line); m != nil && table != "" {
			set = table + " " + m[1]
			sets[set] = map[string]bool{}
			continue
		}
		if m := reElements.FindStringSubmatch(line); m != nil && set != "" {
			for _, e := range strings.Split(m[1], ", ") {
				sets[set][e] = true
			}
			continue
		}
		if line == "}" {
			set = ""
			continue
		}
		if m := reElementOp.FindStringSubmatch(line); m != nil {
			k := m[2] + " " + m[3] + " " + m[4]
			s, ok := sets[k]
			if !ok {
				return fmt.Errorf("no such set %s", k)
			}
			if m[1] == "add" {
				s[m[5]] = true
			} else {
				if !s[m[5]] {
					return fmt.Errorf("no such element %s in %s", m[5], k)
				}
				delete(s, m[5])
			}
		}
	}
	// Counters vanish with their elements.
	for k, byMAC := range f.counters {
		for mac := range byMAC {
			if !sets[k][mac] {
				delete(byMAC, mac)
			}
		}
	}
	f.tables, f.sets = tables, sets
	return nil
}

func (f *fakeSystem) ListJSON(args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(args) == 4 && args[0] == "chain" {
		if f.fw4 {
			return []byte(`{"nftables":[{"rule":{"comment":"!perch-portal: guest pages"}}]}`), nil
		}
		return nil, &ListError{Missing: true, Msg: "no fw4"}
	}
	if len(args) != 3 || args[0] != "table" {
		return nil, fmt.Errorf("unsupported list %v", args)
	}
	t := args[1] + " " + args[2]
	if t == "inet fw4" {
		if f.fw4 {
			return []byte(`{"nftables":[]}`), nil
		}
		return nil, &ListError{Missing: true}
	}
	if !f.tables[t] {
		return nil, &ListError{Missing: true, Msg: "No such file or directory"}
	}
	var items []any
	names := []string{}
	for k := range f.sets {
		if strings.HasPrefix(k, t+" ") {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		var elems []any
		keys := []string{}
		for e := range f.sets[k] {
			keys = append(keys, e)
		}
		sort.Strings(keys)
		for _, e := range keys {
			if c, ok := f.counters[k][e]; ok {
				elems = append(elems, map[string]any{"elem": map[string]any{"val": e, "counter": map[string]any{"packets": c.Packets, "bytes": c.Bytes}}})
			} else {
				elems = append(elems, e)
			}
		}
		items = append(items, map[string]any{"set": map[string]any{"name": strings.TrimPrefix(k, t+" "), "elem": elems}})
	}
	return json.Marshal(map[string]any{"nftables": items})
}

// count adds bytes to a MAC's counter in a set (the kernel counting).
func (f *fakeSystem) count(set, mac string, bytes int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := "netdev " + TableNetdev + " " + set
	if !f.sets[k][mac] {
		return
	}
	if f.counters[k] == nil {
		f.counters[k] = map[string]Counter{}
	}
	c := f.counters[k][mac]
	c.Bytes += bytes
	c.Packets++
	f.counters[k][mac] = c
}

func (f *fakeSystem) has(family, set, elem string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	table := TableInet
	if family == "netdev" {
		table = TableNetdev
	}
	return f.sets[family+" "+table+" "+set][elem]
}

func (f *fakeSystem) setElem(family, set, elem string, present bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	table := TableInet
	if family == "netdev" {
		table = TableNetdev
	}
	k := family + " " + table + " " + set
	if present {
		f.sets[k][elem] = true
	} else {
		delete(f.sets[k], elem)
	}
}

func (f *fakeSystem) WriteFile(path string, data []byte, mode os.FileMode) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.files[path] == string(data) {
		return false, nil
	}
	f.files[path] = string(data)
	return true, nil
}

func (f *fakeSystem) RemoveFile(path string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[path]
	delete(f.files, path)
	return ok, nil
}

func (f *fakeSystem) Command(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	switch {
	case name == "dnsmasq":
		return []byte(f.dnsmasq), nil
	case name == "ubus" && len(args) == 3 && strings.HasPrefix(args[1], "network.interface."):
		n := strings.TrimPrefix(args[1], "network.interface.")
		if n == "guest" {
			return []byte(`{"up":true,"l3_device":"guest","device":"guest"}`), nil
		}
		if n == "vlan110" {
			return []byte(`{"up":true,"l3_device":"br-trunk.110","device":"br-trunk.110"}`), nil
		}
		return nil, fmt.Errorf("Not found")
	case name == "uci":
		return nil, fmt.Errorf("uci: Entry not found")
	}
	return nil, nil
}

func (f *fakeSystem) Neighbors() ([]observe.Neighbor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]observe.Neighbor(nil), f.neighbors...), nil
}

func (f *fakeSystem) LocalAddrs() []netip.Addr {
	return []netip.Addr{netip.MustParseAddr("192.168.20.1"), netip.MustParseAddr("203.0.113.2")}
}

func (f *fakeSystem) DeviceAddrs(device string) ([]netip.Prefix, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.devices[device]
	return a, ok
}

func (f *fakeSystem) FlushConntrack(ips []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ips == nil {
		return 0, fmt.Errorf("conntrack_ips_required")
	}
	f.flushed = append(f.flushed, append([]string(nil), ips...))
	return len(ips), nil
}

func (f *fakeSystem) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.80")}, nil
}

// fakeAgent is a controller session.
type fakeAgent struct {
	mu      sync.Mutex
	calls   []string
	notes   []string
	handler func(method string, params any, result any) error
	down    bool
}

func (a *fakeAgent) Call(ctx context.Context, method string, params, result any) error {
	a.mu.Lock()
	a.calls = append(a.calls, method)
	h := a.handler
	a.mu.Unlock()
	if a.down || h == nil {
		return context.DeadlineExceeded
	}
	return h(method, params, result)
}

func (a *fakeAgent) Notify(method string, params any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.notes = append(a.notes, method)
	return nil
}

// testClock is a settable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// newTestEngine builds an engine on a fake router with a settable clock.
func newTestEngine(t *testing.T, sys *fakeSystem, path string) (*Engine, *testClock) {
	t.Helper()
	store, _, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.db.Close() })
	tc := &testClock{now: time.UnixMilli(1790000000000)}
	clock := &Clock{now: tc.Now}
	clock.started = tc.Now()
	e, err := New(Options{System: sys, Store: store, Storage: StorageInfo{Path: path, FlushSeconds: 300}, Port: 2080, Log: quietLog, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	e.tickNow = tc.Now
	e.Probe(context.Background())
	return e, tc
}
