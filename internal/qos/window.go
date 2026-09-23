package qos

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Window is one weekly window of a schedule: `<days> <HH:MM>-<HH:MM>` in
// the router's local time. Days are the days a window starts on; an end at
// or before the start runs past midnight (equal = 24 hours).
type Window struct {
	// Days: bit 0 = Monday … bit 6 = Sunday.
	Days  uint8
	Start int // minutes after midnight, 0-1439
	End   int
}

var dayNames = [7]string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

func dayIndex(s string) (int, bool) {
	for i, n := range dayNames {
		if n == s {
			return i, true
		}
	}
	return 0, false
}

// ParseWindow reads the `list window` grammar of perch-qos (metrics-be
// docs/gateway/qos.md section 3.4): days are a comma list of mon…sun and
// ranges (mon-fri, fri-mon wraps), then HH:MM-HH:MM.
func ParseWindow(s string) (Window, error) {
	f := strings.Fields(strings.ToLower(s))
	if len(f) != 2 {
		return Window{}, fmt.Errorf("window %q: want \"<days> HH:MM-HH:MM\"", s)
	}
	var w Window
	for _, part := range strings.Split(f[0], ",") {
		a, b, isRange := strings.Cut(part, "-")
		from, ok := dayIndex(a)
		if !ok {
			return Window{}, fmt.Errorf("window %q: unknown day %q", s, a)
		}
		to := from
		if isRange {
			if to, ok = dayIndex(b); !ok {
				return Window{}, fmt.Errorf("window %q: unknown day %q", s, b)
			}
		}
		for d := from; ; d = (d + 1) % 7 {
			w.Days |= 1 << d
			if d == to {
				break
			}
		}
	}
	start, end, ok := strings.Cut(f[1], "-")
	if !ok {
		return Window{}, fmt.Errorf("window %q: want HH:MM-HH:MM", s)
	}
	var err error
	if w.Start, err = parseHHMM(start); err != nil {
		return Window{}, fmt.Errorf("window %q: %v", s, err)
	}
	if w.End, err = parseHHMM(end); err != nil {
		return Window{}, fmt.Errorf("window %q: %v", s, err)
	}
	return w, nil
}

func parseHHMM(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 || len(m) != 2 {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	return hh*60 + mm, nil
}

// String renders the window in the perch-qos grammar (days as a list).
func (w Window) String() string {
	var days []string
	for i := 0; i < 7; i++ {
		if w.Days&(1<<i) != 0 {
			days = append(days, dayNames[i])
		}
	}
	return fmt.Sprintf("%s %02d:%02d-%02d:%02d", strings.Join(days, ","), w.Start/60, w.Start%60, w.End/60, w.End%60)
}

func (w Window) length() time.Duration {
	if w.End > w.Start {
		return time.Duration(w.End-w.Start) * time.Minute
	}
	return time.Duration(24*60-w.Start+w.End) * time.Minute
}

// weekday index with Monday = 0.
func mondayIndex(t time.Time) int { return (int(t.Weekday()) + 6) % 7 }

// Occurrence returns the occurrence of the window that covers wall (a
// local wall-clock time, location ignored): its start and end in wall time.
func (w Window) Occurrence(wall time.Time) (start, end time.Time, ok bool) {
	midnight := time.Date(wall.Year(), wall.Month(), wall.Day(), 0, 0, 0, 0, time.UTC)
	for back := 0; back <= 1; back++ {
		day := midnight.AddDate(0, 0, -back)
		if w.Days&(1<<mondayIndex(day)) == 0 {
			continue
		}
		s := day.Add(time.Duration(w.Start) * time.Minute)
		e := s.Add(w.length())
		wt := asUTC(wall)
		if !wt.Before(s) && wt.Before(e) {
			return s, e, true
		}
	}
	return time.Time{}, time.Time{}, false
}

// NextStart is the first start of the window after wall (wall time).
func (w Window) NextStart(wall time.Time) time.Time {
	midnight := time.Date(wall.Year(), wall.Month(), wall.Day(), 0, 0, 0, 0, time.UTC)
	wt := asUTC(wall)
	for fwd := 0; fwd <= 8; fwd++ {
		day := midnight.AddDate(0, 0, fwd)
		if w.Days&(1<<mondayIndex(day)) == 0 {
			continue
		}
		if s := day.Add(time.Duration(w.Start) * time.Minute); s.After(wt) {
			return s
		}
	}
	return time.Time{}
}

// asUTC keeps the wall-clock fields of t and drops its location.
func asUTC(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}
