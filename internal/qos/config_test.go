package qos

import (
	"strings"
	"testing"
	"time"
)

func TestParseUCIFile(t *testing.T) {
	secs, err := parseUCIFile([]byte(`
package perch-qos

config globals 'globals'
	option enabled '1'   # trailing comment
	list exempt "198.51.100.0/24"
	list exempt 2001:db8::/32
	option note 'it'\''s here'

config bucket b12
	option class 0x12
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(secs) != 2 || secs[0].Type != "globals" || secs[1].Name != "b12" {
		t.Fatalf("sections: %+v", secs)
	}
	if got := secs[0].Options["exempt"]; len(got) != 2 || got[1] != "2001:db8::/32" || !secs[0].Lists["exempt"] {
		t.Errorf("exempt: %v", got)
	}
	if v, _ := secs[0].first("note"); v != "it's here" {
		t.Errorf("note: %q", v)
	}
	if v, _ := secs[0].first("enabled"); v != "1" {
		t.Errorf("enabled: %q", v)
	}
	for _, bad := range []string{"option x 'y'", "config", "config a b c d", "option a 'b", "frobnicate x"} {
		if _, err := parseUCIFile([]byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestParseConfigFixture(t *testing.T) {
	c := loadFixtureConfig(t)
	if !c.Present || !c.Enabled || c.MinDeviceKbit != 64 || c.DynamicIdle != 30*time.Minute || c.DynamicLimit != 1024 {
		t.Errorf("globals: %+v", c)
	}
	if len(c.Exempt) != 1 || c.Exempt[0].String() != "198.51.100.0/24" {
		t.Errorf("exempt: %v", c.Exempt)
	}
	if len(c.Buckets) != 2 || c.Buckets[0].Name != "b12" || c.Buckets[1].Parent != "b12" || c.Buckets[1].Depth != 2 {
		t.Fatalf("buckets: %+v %+v", c.Buckets[0], c.Buckets[1])
	}
	if b := c.Bucket("b13"); b.Minor != 0x13 || b.Rate != (Rate{6000, 6000}) || b.Policy != "3" || len(b.Schedules) != 1 {
		t.Errorf("b13: %+v", b)
	}
	n := c.Networks[0]
	if n.Name != "guest" || n.Bucket != "b12" || n.Each == nil || *n.Each != (Rate{5000, 1000}) {
		t.Errorf("network: %+v", n)
	}
	s7 := c.Schedule("s7")
	if s7.Action != "limit" || s7.Down == nil || *s7.Down != 3000 || s7.Up != nil || s7.EachDown != nil || s7.Policy != "3" {
		t.Errorf("s7: %+v", s7)
	}
	s9 := c.Schedule("s9")
	if s9.Action != "move" || s9.Assignment != "1" || s9.Bucket != "b12" || *s9.EachDown != 5000 {
		t.Errorf("s9: %+v", s9)
	}
	if len(c.Warnings) != 0 {
		t.Errorf("warnings: %v", c.Warnings)
	}
}

func configErrors(text string) string {
	c := ParseConfig([]byte(text))
	var codes []string
	for _, e := range c.Errors {
		codes = append(codes, e.Code)
	}
	return strings.Join(codes, ",")
}

func TestParseConfigRefusals(t *testing.T) {
	bucket := func(name, class, parent, down string) string {
		return "config bucket '" + name + "'\n\toption class '" + class + "'\n\toption parent '" + parent + "'\n\toption down_kbit '" + down + "'\n\toption up_kbit '" + down + "'\n"
	}
	cases := []struct{ name, text, want string }{
		{"ok", bucket("b2", "0x2", "", "1000") + bucket("b3", "0x3", "b2", "500"), ""},
		{"bad class", bucket("b2", "0x100", "", "1000"), "config_bad_class"},
		{"not hex", bucket("b2", "12", "", "1000"), "config_bad_class"},
		{"duplicate class", bucket("b2", "0x2", "", "1000") + bucket("b3", "0x2", "", "1000"), "config_duplicate_class"},
		{"missing parent", bucket("b3", "0x3", "b9", "500"), "config_unknown_bucket"},
		{"child above parent", bucket("b2", "0x2", "", "1000") + bucket("b3", "0x3", "b2", "2000"), "config_child_exceeds_parent,config_child_exceeds_parent,config_children_exceed_parent,config_children_exceed_parent"},
		{"unlimited child in limited parent", bucket("b2", "0x2", "", "1000") + bucket("b3", "0x3", "b2", "0"), "config_child_exceeds_parent,config_child_exceeds_parent"},
		{"children sum", bucket("b2", "0x2", "", "1000") + bucket("b3", "0x3", "b2", "600") + bucket("b4", "0x4", "b2", "600"), "config_children_exceed_parent,config_children_exceed_parent"},
		{"depth 5", bucket("b2", "0x2", "", "1000") + bucket("b3", "0x3", "b2", "900") + bucket("b4", "0x4", "b3", "800") + bucket("b5", "0x5", "b4", "700") + bucket("b6", "0x6", "b5", "600"), "config_bucket_too_deep"},
		{"depth 4 is fine", bucket("b2", "0x2", "", "1000") + bucket("b3", "0x3", "b2", "900") + bucket("b4", "0x4", "b3", "800") + bucket("b5", "0x5", "b4", "700"), ""},
		{"cycle", bucket("b2", "0x2", "b3", "1000") + bucket("b3", "0x3", "b2", "1000"), "config_bucket_cycle"},
		{"network unknown bucket", "config network 'guest'\n\toption bucket 'b9'\n", "config_unknown_bucket"},
		{"bad window", "config schedule 's1'\n\tlist window 'someday 10:00-11:00'\n", "config_bad_window"},
		{"no window", "config schedule 's1'\n\toption action 'limit'\n", "config_bad_window"},
		{"bad action", "config schedule 's1'\n\tlist window 'mon 10:00-11:00'\n\toption action 'explode'\n", "config_bad_value"},
		{"syntax", "config bucket 'b2\n", "config_syntax"},
		{"duplicate section", bucket("b2", "0x2", "", "1") + bucket("b2", "0x3", "", "1"), "config_duplicate"},
	}
	for _, tc := range cases {
		if got := configErrors(tc.text); !strings.Contains(got, tc.want) || (tc.want == "" && got != "") {
			t.Errorf("%s: errors %q, want %q", tc.name, got, tc.want)
		}
	}
	// Parents come first whatever the file order.
	c := ParseConfig([]byte(bucket("b3", "0x3", "b2", "500") + bucket("b2", "0x2", "", "1000")))
	if c.Buckets[0].Name != "b2" {
		t.Errorf("order: %s first", c.Buckets[0].Name)
	}
}

func TestParseConfigGlobals(t *testing.T) {
	c := ParseConfig([]byte("config globals 'globals'\n\toption enabled '0'\n\toption revision '12'\n\toption leaf_flows 'x'\n\tlist exempt '192.0.2.7'\n\tlist exempt 'nonsense'\n"))
	if c.Enabled || c.Revision != "12" || c.LeafFlows != defaultLeafFlows {
		t.Errorf("%+v", c)
	}
	if len(c.Warnings) != 1 || c.Warnings[0].Code != "config_bad_value" {
		t.Errorf("warnings: %v", c.Warnings)
	}
	if len(c.Exempt) != 1 || c.Exempt[0].String() != "192.0.2.7/32" || len(c.Errors) != 1 {
		t.Errorf("exempt %v errors %v", c.Exempt, c.Errors)
	}
}

func TestWindows(t *testing.T) {
	for in, want := range map[string]string{
		"mon-fri 21:00-06:30":         "mon,tue,wed,thu,fri 21:00-06:30",
		"sat,sun 08:00-12:00":         "sat,sun 08:00-12:00",
		"fri-mon 00:00-00:00":         "mon,fri,sat,sun 00:00-00:00",
		"mon,wed,fri-sun 18:00-23:00": "mon,wed,fri,sat,sun 18:00-23:00",
	} {
		w, err := ParseWindow(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if w.String() != want {
			t.Errorf("%s → %s, want %s", in, w, want)
		}
	}
	for _, bad := range []string{"mon 10:00", "mon 25:00-26:00", "xyz 10:00-11:00", "mon 10:0-11:00", "mon-fri", ""} {
		if _, err := ParseWindow(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	night, _ := ParseWindow("mon-fri 21:00-06:30")
	at := func(s string) time.Time {
		v, err := time.Parse("2006-01-02 15:04 Mon", s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		at     string
		active bool
		start  string
	}{
		{"2026-09-21 21:00 Mon", true, "2026-09-21 21:00"},
		{"2026-09-22 06:29 Tue", true, "2026-09-21 21:00"},
		{"2026-09-22 06:30 Tue", false, ""},
		{"2026-09-21 20:59 Mon", false, ""},
		{"2026-09-26 03:00 Sat", true, "2026-09-25 21:00"}, // Friday's window runs into Saturday
		{"2026-09-27 03:00 Sun", false, ""},                // no window starts on Saturday
		{"2026-09-21 03:00 Mon", false, ""},                // nor on Sunday
	}
	for _, tc := range cases {
		start, end, ok := night.Occurrence(at(tc.at))
		if ok != tc.active {
			t.Errorf("%s: active %v", tc.at, ok)
			continue
		}
		if ok {
			if got := start.Format("2006-01-02 15:04"); got != tc.start {
				t.Errorf("%s: start %s want %s", tc.at, got, tc.start)
			}
			if end.Sub(start) != 9*time.Hour+30*time.Minute {
				t.Errorf("%s: length %s", tc.at, end.Sub(start))
			}
		}
	}
	if n := night.NextStart(at("2026-09-26 03:00 Sat")); n.Format("2006-01-02 15:04") != "2026-09-28 21:00" {
		t.Errorf("next start after Saturday: %s", n)
	}
	allDay, _ := ParseWindow("sun 00:00-00:00")
	if _, _, ok := allDay.Occurrence(at("2026-09-27 23:59 Sun")); !ok {
		t.Error("equal start and end is 24 hours")
	}
	if _, _, ok := allDay.Occurrence(at("2026-09-28 00:00 Mon")); ok {
		t.Error("24 hours end at the next midnight")
	}
}

func TestScheduleStatesUnsyncedClock(t *testing.T) {
	c := loadFixtureConfig(t)
	now := time.Date(2026, 9, 23, 19, 0, 0, 0, time.UTC)
	for _, s := range ScheduleStates(c, now, UTCZone, false) {
		if s.Active || s.Since != nil {
			t.Errorf("%s active on an unsynced clock", s.Name)
		}
	}
	d := Plan(Inputs{Config: c, Now: now, Zone: UTCZone, ClockSynced: false}, NewState("x"))
	found := false
	for _, i := range d.Issues {
		found = found || i.Code == "schedule_clock_unsynced"
	}
	if !found {
		t.Error("no schedule_clock_unsynced issue")
	}
}
