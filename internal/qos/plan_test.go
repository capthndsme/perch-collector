package qos

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func loadFixtureConfig(t *testing.T) *Config {
	t.Helper()
	data, err := os.ReadFile("testdata/planner-perch-qos")
	if err != nil {
		t.Fatal(err)
	}
	c := ParseConfig(data)
	if !c.Valid() {
		t.Fatalf("fixture config: %v", c.Errors)
	}
	return c
}

func loadFixtureEntries(t *testing.T, c *Config) []Entry {
	t.Helper()
	data, err := os.ReadFile("testdata/planner-devices.json")
	if err != nil {
		t.Fatal(err)
	}
	var p DevicesSetParams
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	entries, rejected := ValidateDevices(p.Devices, c.MinDeviceKbit, nil)
	if len(rejected) > 0 {
		t.Fatalf("rejected: %v", rejected)
	}
	return entries
}

func loadFixtureLANs(t *testing.T) []LAN {
	t.Helper()
	dump, err := os.ReadFile("testdata/ubus-interface-dump.json")
	if err != nil {
		t.Fatal(err)
	}
	fw, err := os.ReadFile("testdata/firewall")
	if err != nil {
		t.Fatal(err)
	}
	lans, ok := ParseLANs(dump, WANNetworks(fw))
	if !ok {
		t.Fatal("dump unreadable")
	}
	return lans
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file (go test -run %s -update to accept):\n%s", name, t.Name(), lineDiff(string(want), got))
	}
}

func lineDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	var out []string
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			out = append(out, fmt.Sprintf("%4d - %s\n     + %s", i+1, x, y))
		}
		if len(out) > 20 {
			break
		}
	}
	return strings.Join(out, "\n")
}

func fixtureInputs(t *testing.T, now time.Time) Inputs {
	c := loadFixtureConfig(t)
	return Inputs{
		Config:  c,
		Entries: loadFixtureEntries(t, c),
		LANs:    loadFixtureLANs(t),
		Neighbors: []Neighbor{
			{MAC: "02:00:00:00:10:11", Device: "lan", Confirmed: true},
			{MAC: "02:00:00:00:20:11", Device: "guest", Confirmed: true},
			{MAC: "02:00:00:00:20:99", Device: "guest", Confirmed: true},
			{MAC: "02:00:00:00:30:99", Device: "iot", Confirmed: true},
		},
		Now:         now,
		Zone:        UTCZone,
		ClockSynced: true,
		Exhausted:   map[string]bool{"02:00:00:00:10:15": true},
	}
}

// describe renders the non-tc parts of a plan for the golden files.
func describe(d *Desired) string {
	var b strings.Builder
	fmt.Fprintf(&b, "active %v\n", d.Active)
	for _, c := range d.Classes {
		fmt.Fprintf(&b, "class 1:%x parent 1:%x %s %s down %d/%d up %d/%d leaf %q\n", c.Minor, c.Parent, c.Kind, c.Key,
			c.Rate[Down].RateKbit, c.Rate[Down].CeilKbit, c.Rate[Up].RateKbit, c.Rate[Up].CeilKbit, c.Leaf)
	}
	for _, p := range d.Placements {
		fmt.Fprintf(&b, "device %s class %q network %q dynamic %v %s\n", p.MAC, p.ClassID, p.Network, p.Dynamic, p.State)
	}
	for _, s := range d.Schedules {
		fmt.Fprintf(&b, "schedule %s active %v", s.Name, s.Active)
		if s.Since != nil {
			fmt.Fprintf(&b, " since %s", s.Since.Format(time.RFC3339))
		}
		if s.Until != nil {
			fmt.Fprintf(&b, " until %s", s.Until.Format(time.RFC3339))
		}
		b.WriteString("\n")
	}
	for _, i := range d.Issues {
		fmt.Fprintf(&b, "issue %s\n", i)
	}
	return b.String()
}

// TestRenderGolden renders the controller planner's own output (testdata/
// planner-*) at four moments of the week: no schedule, s7 (the voucher
// tier's evening limit), s9 (the weekend move) and s8 (the night block).
func TestRenderGolden(t *testing.T) {
	cases := []struct {
		name string
		at   time.Time
	}{
		{"weekday-noon", time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)},
		{"weekday-evening-s7", time.Date(2026, 9, 23, 19, 0, 0, 0, time.UTC)},
		{"saturday-morning-s9", time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)},
		{"sunday-night-s8", time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := NewState("golden")
			d := Plan(fixtureInputs(t, tc.at), st)
			golden(t, tc.name+".batch", Render(d).Text())
			golden(t, tc.name+".plan", describe(d))
		})
	}
}

func TestPlanDeterministicAcrossRuns(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	st := NewState("x")
	a := Plan(fixtureInputs(t, now), st)
	b := Plan(fixtureInputs(t, now), st)
	if a.Fingerprint != b.Fingerprint || Render(a).Text() != Render(b).Text() {
		t.Fatal("the same inputs and state gave two plans")
	}
}
