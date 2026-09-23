package qos

import (
	"testing"
	"time"
)

func TestParseTZRefusals(t *testing.T) {
	for _, bad := range []string{"X1", "CET", "CET-1CEST,M3.5", "CET-1CEST,M13.5.0,M10.5.0", "<+08", "CET-99"} {
		if _, err := ParseTZ(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	z, err := ParseTZ("")
	if err != nil || z != UTCZone {
		t.Errorf("empty TZ: %v %v", z, err)
	}
}

// TestZoneMatchesZoneinfo compares the POSIX rules with the zoneinfo
// database over two years, every 30 minutes, for zones OpenWrt writes.
func TestZoneMatchesZoneinfo(t *testing.T) {
	cases := map[string]string{
		"UTC":                 "UTC0",
		"Asia/Manila":         "PST-8",
		"Europe/Berlin":       "CET-1CEST,M3.5.0,M10.5.0/3",
		"Europe/London":       "GMT0BST,M3.5.0/1,M10.5.0",
		"America/New_York":    "EST5EDT,M3.2.0,M11.1.0",
		"Australia/Sydney":    "AEST-10AEDT,M10.1.0,M4.1.0/3",
		"America/Sao_Paulo":   "<-03>3",
		"Asia/Kolkata":        "IST-5:30",
		"Pacific/Chatham":     "<+1245>-12:45<+1345>,M9.5.0/2:45,M4.1.0/3:45",
		"America/Godthab":     "<-02>2<-01>,M3.5.0/-1,M10.5.0/0",
		"Pacific/Auckland":    "NZST-12NZDT,M9.5.0,M4.1.0/3",
		"America/Los_Angeles": "PST8PDT,M3.2.0,M11.1.0",
	}
	for name, spec := range cases {
		loc, err := time.LoadLocation(name)
		if err != nil {
			t.Logf("%s: no zoneinfo here (%v)", name, err)
			continue
		}
		z, err := ParseTZ(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for tm := start; tm.Before(start.AddDate(2, 0, 0)); tm = tm.Add(30 * time.Minute) {
			_, want := tm.In(loc).Zone()
			got, _ := z.Offset(tm)
			if got != want {
				t.Errorf("%s at %s: offset %d, zoneinfo %d", spec, tm, got, want)
				break
			}
		}
	}
}

func TestZoneWallAndInstant(t *testing.T) {
	z, _ := ParseTZ("CET-1CEST,M3.5.0,M10.5.0/3")
	summer := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	if w := z.Wall(summer); w.Hour() != 12 {
		t.Errorf("wall %s", w)
	}
	if back := z.Instant(z.Wall(summer)); !back.Equal(summer) {
		t.Errorf("instant %s", back)
	}
	winter := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	if w := z.Wall(winter); w.Hour() != 11 {
		t.Errorf("wall %s", w)
	}
	// A schedule on the router's clock: 18:00-23:00 local in summer is
	// 16:00-21:00 UTC.
	w, _ := ParseWindow("mon-sun 18:00-23:00")
	c := &Config{Schedules: []*Schedule{{Name: "s1", Windows: []Window{w}}}}
	c.index()
	st := ScheduleStates(c, time.Date(2026, 7, 1, 16, 30, 0, 0, time.UTC), z, true)
	if !st[0].Active || st[0].Since.Format(time.RFC3339) != "2026-07-01T16:00:00Z" || st[0].Until.Format(time.RFC3339) != "2026-07-01T21:00:00Z" {
		t.Errorf("state %+v %s %s", st[0], st[0].Since, st[0].Until)
	}
}
