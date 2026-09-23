package qos

import (
	"strings"
	"testing"
	"time"
)

func i64(v int64) *int64 { return &v }
func str(v string) *string { return &v }

func TestValidateDevices(t *testing.T) {
	list := []DeviceEntry{
		{MAC: "02-00-00-00-00-0B", DownKbit: i64(5000), UpKbit: i64(10)},
		{MAC: "02:00:00:00:00:0a", Bucket: str("b12")},
		{MAC: "02:00:00:00:00:0a"},
		{MAC: "not a mac"},
		{MAC: "03:00:00:00:00:01"},
		{MAC: "02:00:00:00:99:01"},
		{MAC: "02:00:00:00:00:0c", DownKbit: i64(-1)},
		{MAC: "02:00:00:00:00:0d", Quota: &DeviceQuota{LimitBytes: 0, OnExhausted: "block"}},
		{MAC: "02:00:00:00:00:0e", ExpiresAt: str("tomorrow")},
		{MAC: "02:00:00:00:00:0f", Quota: &DeviceQuota{LimitBytes: 100, OnExhausted: "throttle", ThrottleDownKbit: i64(8)}, ExpiresAt: str("2026-12-31T00:00:00.000Z"), Schedules: []string{"s1", " "}},
	}
	entries, rejected := ValidateDevices(list, 64, map[string]bool{"02:00:00:00:99:01": true})
	var codes []string
	for _, r := range rejected {
		codes = append(codes, r.Error)
	}
	if got := strings.Join(codes, ","); got != "duplicate_mac,invalid_mac,invalid_mac,router_mac,invalid_rate,invalid_quota,invalid_expires_at" {
		t.Errorf("rejected: %s", got)
	}
	if len(entries) != 3 || entries[0].MAC != "02:00:00:00:00:0a" || entries[1].MAC != "02:00:00:00:00:0b" {
		t.Fatalf("entries: %+v", entries)
	}
	if entries[0].Caps != nil || entries[0].Bucket != "b12" {
		t.Errorf("bucket only: %+v", entries[0])
	}
	if *entries[1].Caps != (Rate{5000, 64}) {
		t.Errorf("floor: %+v", entries[1].Caps)
	}
	e := entries[2]
	if *e.Quota.ThrottleDownKbit != 64 || e.Expires.IsZero() || len(e.Schedules) != 1 {
		t.Errorf("quota entry: %+v", e)
	}
	// Round trip through the cache shape.
	back, rej := ValidateDevices([]DeviceEntry{e.DeviceEntry(), entries[1].DeviceEntry()}, 64, nil)
	if len(rej) != 0 || !back[1].Expires.Equal(e.Expires) || *back[0].Caps != *entries[1].Caps {
		t.Errorf("round trip: %+v %v", back, rej)
	}
}

func TestPlanExpiryAndQuotaThrottle(t *testing.T) {
	c := DefaultConfig()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	lans := []LAN{{Network: "lan", Device: "lan"}}
	entries := []Entry{
		{MAC: "02:00:00:00:00:01", Caps: &Rate{1000, 1000}, Expires: now.Add(-time.Second)},
		{MAC: "02:00:00:00:00:02", Caps: &Rate{3000, 1000}, Quota: &DeviceQuota{LimitBytes: 10, OnExhausted: "throttle", ThrottleDownKbit: i64(256), ThrottleUpKbit: i64(128)}},
	}
	d := Plan(Inputs{Config: c, Entries: entries, LANs: lans, Now: now, Exhausted: map[string]bool{"02:00:00:00:00:02": true}}, NewState("x"))
	if len(d.Placements) != 1 || d.Placements[0].State != "throttled" {
		t.Fatalf("placements: %+v", d.Placements)
	}
	if len(d.Classes) != 1 || d.Classes[0].Rate[Down].CeilKbit != 256 || d.Classes[0].Rate[Up].CeilKbit != 128 {
		t.Errorf("throttle class: %+v", d.Classes)
	}
}

func TestAllocatorStableAndBusy(t *testing.T) {
	st := NewState("x")
	a := newAllocator(st, map[uint16]bool{0x200: true})
	m1, _ := a.minor("d:a|1")
	m2, _ := a.minor("d:b|1")
	if m1 != 0x201 || m2 != 0x202 {
		t.Fatalf("minors %x %x", m1, m2)
	}
	h := a.handle("a")
	a.retain()
	a = newAllocator(st, nil)
	if m, _ := a.minor("d:b|1"); m != 0x202 {
		t.Errorf("b moved to %x", m)
	}
	if a.handle("a") != h {
		t.Error("handle moved")
	}
	a.retain() // d:a|1 unused now: released
	if _, ok := st.Minors["d:a|1"]; ok {
		t.Error("not released")
	}
	a = newAllocator(st, map[uint16]bool{0x201: true})
	if m, _ := a.minor("d:c|1"); m != 0x200 {
		t.Errorf("c got %x", m)
	}
	if m, _ := a.minor("d:e|1"); m != 0x203 {
		t.Errorf("busy 0x201 reused: %x", m)
	}
}

func TestDynamicDevices(t *testing.T) {
	c := ParseConfig([]byte("config globals 'globals'\n\toption dynamic_limit '2'\n\toption dynamic_idle '60'\n" +
		"config bucket 'b2'\n\toption class '0x2'\n\toption down_kbit '10000'\n\toption up_kbit '10000'\n" +
		"config network 'guest'\n\toption bucket 'b2'\n\toption each_down_kbit '2000'\n\toption each_up_kbit '500'\n"))
	if !c.Valid() {
		t.Fatal(c.Errors)
	}
	lans := []LAN{{Network: "guest", Device: "guest"}, {Network: "lan", Device: "lan"}}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	st := NewState("x")
	neigh := []Neighbor{
		{MAC: "02:00:00:00:00:01", Device: "guest", Confirmed: true},
		{MAC: "02:00:00:00:00:02", Device: "guest", Confirmed: true},
		{MAC: "02:00:00:00:00:03", Device: "guest", Confirmed: true},
		{MAC: "02:00:00:00:00:04", Device: "lan", Confirmed: true}, // no default on lan
	}
	plan := func(at time.Time, n []Neighbor, bytes map[uint16]uint64) *Desired {
		return Plan(Inputs{Config: c, LANs: lans, Neighbors: n, Now: at, ClassBytes: bytes}, st)
	}
	d := plan(now, neigh, nil)
	dyn := 0
	for _, p := range d.Placements {
		if p.Dynamic {
			dyn++
		}
	}
	if dyn != 2 || len(st.Dynamic) != 3 {
		t.Fatalf("dynamic %d, tracked %d", dyn, len(st.Dynamic))
	}
	found := false
	for _, i := range d.Issues {
		found = found || i.Code == "pool_exhausted"
	}
	if !found {
		t.Error("no pool_exhausted issue")
	}
	// The guest default filter catches the third one in the rest leaf.
	var def *DFilter
	for _, f := range d.Filters["guest"] {
		if f.Pref == PrefDefault && f.Hook == "egress" {
			f := f
			def = &f
		}
	}
	if def == nil || def.Action != "class:102" {
		t.Errorf("default: %+v", def)
	}
	for _, f := range d.Filters["lan"] {
		if f.Pref == PrefDevice || f.Pref == PrefDefault {
			t.Errorf("dynamic filter on lan: %+v", f)
		}
	}
	// Idle: gone from the neighbour table and no bytes for over a minute.
	var m1 uint16
	for k, m := range st.Minors {
		if strings.HasPrefix(k, "d:02:00:00:00:00:01|") {
			m1 = m
		}
	}
	later := now.Add(2 * time.Minute)
	plan(later, neigh[1:2], map[uint16]uint64{m1: 5000}) // 01 moved bytes: kept
	if _, ok := st.Dynamic["02:00:00:00:00:01"]; !ok {
		t.Error("a device with traffic was dropped")
	}
	plan(later.Add(2*time.Minute), neigh[1:2], map[uint16]uint64{m1: 5000})
	if _, ok := st.Dynamic["02:00:00:00:00:01"]; ok {
		t.Error("an idle device was kept")
	}
	if _, ok := st.Dynamic["02:00:00:00:00:03"]; ok {
		t.Error("an idle device (no leaf) was kept")
	}
}

func TestIncludeLanNetworkDefaultUsesLANChain(t *testing.T) {
	c := ParseConfig([]byte("config bucket 'b2'\n\toption class '0x2'\n\toption down_kbit '10000'\n\toption up_kbit '10000'\n\toption include_lan '1'\n" +
		"config network 'lan'\n\toption bucket 'b2'\n\toption include_lan '1'\n"))
	lans := []LAN{{Network: "lan", Device: "lan"}}
	entries := []Entry{{MAC: "02:00:00:00:00:01", Caps: &Rate{1000, 1000}}}
	d := Plan(Inputs{Config: c, Entries: entries, LANs: lans, Now: time.Now()}, NewState("x"))
	var gotoLAN, chainPass, chainDefault bool
	for _, f := range d.Filters["lan"] {
		switch {
		case f.Pref == PrefExemptV6 && f.Action == ActLAN:
			gotoLAN = true
		case f.Chain == lanChain && f.Pref == PrefDevice && f.Action == ActPass:
			chainPass = true
		case f.Chain == lanChain && f.Pref == PrefDefault && f.Action == "class:102":
			chainDefault = true
		}
	}
	if !gotoLAN || !chainPass || !chainDefault {
		t.Errorf("goto %v pass %v default %v:\n%s", gotoLAN, chainPass, chainDefault, Render(d).Text())
	}
}

func TestSQMConflictSkipsDevice(t *testing.T) {
	dump := []byte(`{"interface":[{"interface":"lan","up":true,"l3_device":"br-lan","ipv4-address":[{"address":"192.168.1.1","mask":24}]},
	{"interface":"wan","up":true,"l3_device":"eth1","ipv4-address":[{"address":"192.0.2.2","mask":24}],"route":[{"target":"0.0.0.0","mask":0}]}]}`)
	lans, ok := ParseLANs(dump, nil)
	if !ok || len(lans) != 1 || lans[0].Device != "br-lan" || lans[0].Addrs[0].String() != "192.168.1.1" {
		t.Fatalf("lans %+v", lans)
	}
	markSQMConflicts(lans, []SQMQueue{{Device: "br-lan", Enabled: true}})
	c := ParseConfig([]byte("config bucket 'b2'\n\toption class '0x2'\n\toption down_kbit '1000'\n\toption up_kbit '1000'\nconfig network 'lan'\n\toption bucket 'b2'\n"))
	d := Plan(Inputs{Config: c, LANs: lans, Now: time.Now()}, NewState("x"))
	if len(d.Filters) != 0 {
		t.Errorf("filters on a conflicted device: %v", d.Filters)
	}
	if len(d.Issues) == 0 || d.Issues[0].Code != "qos_conflict_sqm_on_lan" {
		t.Errorf("issues: %v", d.Issues)
	}
}

func TestParseSQM(t *testing.T) {
	q := ParseSQM([]byte("config queue 'wan2'\n\toption enabled '1'\n\toption interface 'wan2'\n\toption download '50000'\nconfig queue\n\toption interface 'wan'\n"))
	if len(q) != 2 || !q[0].Enabled || q[0].Download != 50000 || q[1].Section != "@queue[1]" || q[1].Enabled {
		t.Errorf("%+v", q)
	}
	if sqmIfb("wan2") != "ifb4wan2" || len(sqmIfb("averyverylongname")) != 15 {
		t.Error("sqm ifb name")
	}
}
