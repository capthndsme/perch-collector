package qos

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSys is an in-memory System: files, a clock, and a tc that answers
// reads from a captured kernel and records what it is asked to apply.
type fakeSys struct {
	mu      sync.Mutex
	files   map[string][]byte
	mtimes  map[string]time.Time
	now     time.Time
	answers map[string]string // read command → JSON
	applied [][]string
	dump    []byte
	neigh   []Neighbor
	writes  map[string]int
}

func newFakeSys(t *testing.T) *fakeSys {
	f := &fakeSys{files: map[string][]byte{}, mtimes: map[string]time.Time{}, answers: map[string]string{},
		writes: map[string]int{}, now: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)}
	for name, dst := range map[string]string{"planner-perch-qos": ConfigPath, "firewall": FirewallPath, "sqm": SQMPath} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		f.put(dst, data)
	}
	f.put(TZPath, []byte("UTC0\n"))
	f.dump, _ = os.ReadFile("testdata/ubus-interface-dump.json")
	return f
}

func (f *fakeSys) put(p string, data []byte) {
	f.files[p] = data
	f.mtimes[p] = f.now.Add(time.Duration(len(f.mtimes)) * time.Millisecond)
}

// fromFixture makes tc answer reads with the captured kernel.
func (f *fakeSys) fromFixture(t *testing.T) {
	_, fx := loadKernelFixture(t)
	answers, err := parseBatchOutput(fx.Commands, []byte(fx.Stdout), []byte(fx.Stderr))
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range fx.Commands {
		if answers[i] != nil {
			f.answers[c] = string(answers[i])
		}
	}
}

func (f *fakeSys) Tc(_ context.Context, lines []string, asJSON, _ bool) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !asJSON {
		f.applied = append(f.applied, lines)
		return nil, nil, nil
	}
	var out, errb strings.Builder
	for i, l := range lines {
		a, ok := f.answers[l]
		if !ok {
			errb.WriteString("Cannot find device\nCommand failed -:" + itoa10(i+1) + "\n")
			continue
		}
		out.WriteString(a + "\n")
	}
	return []byte(out.String()), []byte(errb.String()), nil
}

func itoa10(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (f *fakeSys) EnsureIfb(string) error         { return nil }
func (f *fakeSys) DeleteLink(string) error        { return nil }
func (f *fakeSys) Interfaces() ([]byte, error)    { return f.dump, nil }
func (f *fakeSys) Neighbors() ([]Neighbor, error) { return f.neigh, nil }
func (f *fakeSys) LocalMACs() map[string]bool     { return map[string]bool{"02:00:00:00:99:01": true} }
func (f *fakeSys) Now() time.Time                 { return f.now }
func (f *fakeSys) ClockSynced() bool              { return true }
func (f *fakeSys) Lock(string) (func(), error)    { return func() {}, nil }
func (f *fakeSys) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return d, nil
}
func (f *fakeSys) WriteFile(p string, data []byte, _ os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes[p]++
	f.put(p, append([]byte{}, data...))
	return nil
}
func (f *fakeSys) Remove(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, p)
	return nil
}

type fakeInfo struct {
	size int64
	mt   time.Time
}

func (i fakeInfo) Name() string       { return "" }
func (i fakeInfo) Size() int64        { return i.size }
func (i fakeInfo) Mode() os.FileMode  { return 0o644 }
func (i fakeInfo) ModTime() time.Time { return i.mt }
func (i fakeInfo) IsDir() bool        { return false }
func (i fakeInfo) Sys() any           { return nil }

func (f *fakeSys) Stat(p string) (os.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeInfo{int64(len(d)), f.mtimes[p]}, nil
}

func plannerSet(t *testing.T) DevicesSetParams {
	data, err := os.ReadFile("testdata/planner-devices.json")
	if err != nil {
		t.Fatal(err)
	}
	var p DevicesSetParams
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEngineSectionFromRealKernel(t *testing.T) {
	f := newFakeSys(t)
	f.fromFixture(t)
	f.neigh = []Neighbor{
		{MAC: "02:00:00:00:10:11", Device: "lan", Confirmed: true},
		{MAC: "02:00:00:00:20:11", Device: "guest", Confirmed: true},
		{MAC: "02:00:00:00:20:99", Device: "guest", Confirmed: true},
		{MAC: "02:00:00:00:30:99", Device: "iot", Confirmed: true},
	}
	e := NewEngine(f, true)
	e.epoch = "golden"
	if _, err := e.SetDevices(plannerSet(t)); err != nil {
		t.Fatal(err)
	}
	// Quota 10:15 arrives exhausted (used 5000 of 1000): one event.
	evs := e.DrainEvents()
	if len(evs) != 1 || evs[0].Type != EventQuotaExhausted || evs[0].MAC != "02:00:00:00:10:15" {
		t.Fatalf("events: %+v", evs)
	}
	// The fixture kernel already holds exactly this plan: nothing to do.
	f.put(statePath, mustJSON(t, goldenState(t)))
	r := e.Reconcile("test", true)
	if len(r.Errors) > 0 || r.Commands != 0 {
		t.Fatalf("reconcile: %+v applied %v", r, f.applied)
	}
	s := e.Section()
	if s == nil || s.State != "active" || s.PausedBy != nil || *s.DevicesRevision != 7 {
		t.Fatalf("section: %+v", s)
	}
	if len(s.Classes) != 2*len(e.Desired().Classes) {
		t.Errorf("classes: %d of %d", len(s.Classes), 2*len(e.Desired().Classes))
	}
	var c1 *ClassStats
	for i := range s.Classes {
		if s.Classes[i].Key == "d:02:00:00:00:10:11" && s.Classes[i].Dir == "up" {
			c1 = &s.Classes[i]
		}
	}
	if c1 == nil || c1.ID != "1:200" || c1.CeilKbit != 1000 {
		t.Errorf("c1 up: %+v", c1)
	}
	if len(s.Wan) != 2 || s.Wan[0].Section != "wan2" || !s.Wan[0].Enabled || s.Wan[1].Enabled {
		t.Errorf("wan: %+v", s.Wan)
	}
	codes := map[string]bool{}
	for _, i := range s.Errors {
		codes[i.Code] = true
	}
	if !codes["sqm_paused"] {
		t.Errorf("a disabled sqm queue is not reported: %v", s.Errors)
	}
	if len(s.Quotas) != 2 || !s.Quotas[1].Exhausted || !s.Quotas[1].Enforced {
		t.Errorf("quotas: %+v", s.Quotas)
	}
	b, _ := json.Marshal(s)
	for _, want := range []string{`"classId":null`, `"network":"guest"`, `"schedules":[{"name":"s7","active":false,"since":null,"until":"2026-09-23T18:00:00Z"}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("section JSON lacks %s", want)
		}
	}
}

func goldenState(t *testing.T) *State {
	st := NewState("golden")
	Plan(fixtureInputs(t, time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)), st)
	return st
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEngineQuotaSeedingAndCounting(t *testing.T) {
	f := newFakeSys(t)
	e := NewEngine(f, true)
	mac := "02:00:00:00:10:14"
	set := func(used, limit int64) {
		p := DevicesSetParams{Revision: 1, Devices: []DeviceEntry{{MAC: mac, DownKbit: i64(3000),
			Quota: &DeviceQuota{LimitBytes: limit, UsedBytes: used, OnExhausted: "block"}}}}
		if _, err := e.SetDevices(p); err != nil {
			t.Fatal(err)
		}
	}
	set(100, 10_000)
	st := NewState("x")
	st.Handles[mac] = 7
	f.put(statePath, mustJSON(t, st))
	kern := func(bytes uint64) *Kernel {
		return &Kernel{Devs: map[string]*DevState{"lan": {Clsact: true, Filters: []KFilter{
			{Hook: "egress", Pref: PrefDevice, Proto: "all", Handle: 7, Action: "class:200@ifb-pdn", Bytes: bytes},
			{Hook: "ingress", Pref: PrefDevice, Proto: "all", Handle: 7, Action: "class:200@ifb-pup", Bytes: bytes / 10},
			{Hook: "egress", Pref: PrefDevice, Proto: "all", Handle: 8, Bytes: 1 << 30},
		}}}}
	}
	e.mu.Lock()
	e.countQuotasLocked(kern(1000)) // first read after start: baseline only
	e.countQuotasLocked(kern(3000))
	used := e.devices.Quotas[mac].Used
	e.mu.Unlock()
	if used != 100+2000+200 {
		t.Fatalf("used %d", used)
	}
	// The controller echoes the old seed: ours stays.
	set(100, 10_000)
	if got := e.devices.Quotas[mac].Used; got != 2300 {
		t.Errorf("after an echo: %d", got)
	}
	// A reset from the controller replaces it.
	set(0, 10_000)
	if got := e.devices.Quotas[mac].Used; got != 0 {
		t.Errorf("after a reset: %d", got)
	}
	e.DrainEvents()
	e.mu.Lock()
	e.countQuotasLocked(kern(13000)) // +10000 +1000: over the limit
	exhausted := !e.devices.Quotas[mac].ExhaustedAt.IsZero()
	e.mu.Unlock()
	if !exhausted {
		t.Fatal("not exhausted")
	}
	if evs := e.DrainEvents(); len(evs) != 1 || evs[0].Type != EventQuotaExhausted {
		t.Errorf("events %+v", evs)
	}
	if !e.exhaustedLocked()[mac] {
		t.Error("not enforced")
	}
}

func TestEngineFlashCacheAndFailOpen(t *testing.T) {
	f := newFakeSys(t)
	e := NewEngine(f, true)
	p := plannerSet(t)
	if _, err := e.SetDevices(p); err != nil {
		t.Fatal(err)
	}
	e.flush(false)
	if f.writes[FlashDevicesPath] != 1 {
		t.Fatalf("flash writes %d", f.writes[FlashDevicesPath])
	}
	p.Revision = 8
	e.SetDevices(p)
	f.now = f.now.Add(30 * time.Second)
	e.flush(false)
	if f.writes[FlashDevicesPath] != 1 {
		t.Error("written again within a minute")
	}
	f.now = f.now.Add(31 * time.Second)
	e.flush(false)
	if f.writes[FlashDevicesPath] != 2 {
		t.Error("not written after a minute")
	}
	// A reboot: /tmp is gone, the flash cache returns the entries with
	// quotas failing open.
	delete(f.files, runtimeDevices)
	e2 := NewEngine(f, true)
	e2.LoadDevices()
	if !e2.devices.FromFlash || e2.devices.Revision != 8 || len(e2.entries) != len(p.Devices) {
		t.Fatalf("restored %+v", e2.devices)
	}
	if len(e2.exhaustedLocked()) != 0 {
		t.Error("quotas enforced after a reboot")
	}
	e2.SetDevices(p)
	if !e2.exhaustedLocked()["02:00:00:00:10:15"] {
		t.Error("quotas not enforced once the controller sent its set")
	}
}

func TestEngineNotActiveWithoutConfig(t *testing.T) {
	f := newFakeSys(t)
	delete(f.files, ConfigPath)
	e := NewEngine(f, true)
	if _, err := e.SetDevices(DevicesSetParams{}); !errors.Is(err, ErrNotActive) {
		t.Errorf("err %v", err)
	}
	if e.Section() != nil {
		t.Error("a section without perch-qos")
	}
}

func TestEngineEventsOnPauseAndSQM(t *testing.T) {
	f := newFakeSys(t)
	e := NewEngine(f, true)
	e.Reconcile("start", true)
	e.DrainEvents()
	cfg := strings.Replace(string(f.files[ConfigPath]), "option enabled '1'", "option enabled '0'", 1)
	f.put(ConfigPath, []byte(cfg))
	f.put(SQMPath, []byte(strings.Replace(string(f.files[SQMPath]), "option enabled '1'", "option enabled '0'", 1)))
	e.Reconcile("tick", false)
	types := map[string]bool{}
	for _, ev := range e.DrainEvents() {
		types[ev.Type] = true
	}
	if !types[EventLocalPause] || !types[EventSQMPaused] {
		t.Errorf("events %v", types)
	}
	if s := e.Section(); s.State != "paused" || *s.PausedBy != "config" {
		t.Errorf("state %s", s.State)
	}
	// Paused: every Perch object goes (the fixture kernel is empty here,
	// so the plan is just inactive).
	if d := e.Desired(); d.Active {
		t.Error("active while paused")
	}
}

func TestEngineKeepsKernelOnBrokenConfig(t *testing.T) {
	f := newFakeSys(t)
	f.fromFixture(t)
	f.put(statePath, mustJSON(t, goldenState(t)))
	f.neigh = []Neighbor{{MAC: "02:00:00:00:20:99", Device: "guest", Confirmed: true}}
	e := NewEngine(f, true)
	e.SetDevices(plannerSet(t))
	e.Reconcile("start", true)
	f.applied = nil
	f.put(ConfigPath, []byte("config bucket 'b2\n"))
	r := e.Reconcile("tick", false)
	if len(f.applied) != 0 {
		t.Errorf("a broken config changed the kernel: %v", f.applied)
	}
	if s := e.Section(); s.State != "error" {
		t.Errorf("state %s (%+v)", s.State, r)
	}
}
