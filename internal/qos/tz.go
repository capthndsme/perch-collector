package qos

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Zone is a POSIX TZ string ("CET-1CEST,M3.5.0,M10.5.0/3"), what OpenWrt
// writes to /tmp/TZ from system.timezone and what its C library uses: the
// router's own idea of local time, without a zoneinfo database (Go reads
// the TZ variable only as a zoneinfo name).
type Zone struct {
	spec           string
	stdName        string
	dstName        string
	stdOff, dstOff int // seconds east of UTC
	hasDST         bool
	start, end     tzRule
}

type tzRule struct {
	kind byte // 'J' (1-365, no Feb 29), 'N' (0-365), 'M' (month.week.day)
	day  int
	week int
	mon  int
	secs int // local time of the transition
}

// UTCZone is the zone of a router without a timezone.
var UTCZone = &Zone{spec: "UTC0", stdName: "UTC"}

// TZifFooter is the POSIX TZ string at the end of a TZif file (version 2
// and later: "\n<TZ>\n" after the data), or "" when data is not one.
func TZifFooter(data []byte) string {
	if len(data) < 5 || string(data[:4]) != "TZif" || data[4] < '2' || data[len(data)-1] != '\n' {
		return ""
	}
	body := data[:len(data)-1]
	i := bytes.LastIndexByte(body, '\n')
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(string(body[i+1:]))
}

// ParseTZ reads a POSIX TZ string.
func ParseTZ(s string) (*Zone, error) {
	spec := strings.TrimSpace(s)
	z := &Zone{spec: spec}
	rest := strings.TrimPrefix(spec, ":")
	if rest == "" {
		return UTCZone, nil
	}
	var ok bool
	if z.stdName, rest, ok = tzName(rest); !ok {
		return nil, fmt.Errorf("TZ %q: bad zone name", s)
	}
	if rest == "" {
		// "UTC", "GMT": OpenWrt's default system.timezone. musl reads a
		// missing offset as 0; so does this.
		return z, nil
	}
	off, rest, ok := tzOffset(rest)
	if !ok {
		return nil, fmt.Errorf("TZ %q: bad offset", s)
	}
	z.stdOff = -off
	if rest == "" {
		return z, nil
	}
	if z.dstName, rest, ok = tzName(rest); !ok {
		return nil, fmt.Errorf("TZ %q: bad DST name", s)
	}
	z.hasDST = true
	z.dstOff = z.stdOff + 3600
	if rest != "" && rest[0] != ',' {
		if off, rest, ok = tzOffset(rest); !ok {
			return nil, fmt.Errorf("TZ %q: bad DST offset", s)
		}
		z.dstOff = -off
	}
	if rest == "" {
		rest = ",M3.2.0,M11.1.0" // the US rule, POSIX's default
	}
	if rest[0] != ',' {
		return nil, fmt.Errorf("TZ %q: want ,start,end", s)
	}
	parts := strings.Split(rest[1:], ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("TZ %q: want start,end", s)
	}
	var err error
	if z.start, err = tzParseRule(parts[0]); err != nil {
		return nil, fmt.Errorf("TZ %q: %v", s, err)
	}
	if z.end, err = tzParseRule(parts[1]); err != nil {
		return nil, fmt.Errorf("TZ %q: %v", s, err)
	}
	return z, nil
}

func tzName(s string) (name, rest string, ok bool) {
	if strings.HasPrefix(s, "<") {
		i := strings.IndexByte(s, '>')
		if i < 2 {
			return "", s, false
		}
		return s[1:i], s[i+1:], true
	}
	i := 0
	for i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z') {
		i++
	}
	if i < 3 {
		return "", s, false
	}
	return s[:i], s[i:], true
}

// tzOffset reads [+-]hh[:mm[:ss]]: seconds WEST of UTC (POSIX sign).
func tzOffset(s string) (int, string, bool) {
	sign := 1
	if s != "" && (s[0] == '+' || s[0] == '-') {
		if s[0] == '-' {
			sign = -1
		}
		s = s[1:]
	}
	secs, rest, ok := tzClock(s, 24)
	return sign * secs, rest, ok
}

// tzClock reads hh[:mm[:ss]] with hh ≤ maxH.
func tzClock(s string, maxH int) (int, string, bool) {
	n, rest, ok := tzNum(s)
	if !ok || n > maxH {
		return 0, s, false
	}
	secs := n * 3600
	for _, mult := range []int{60, 1} {
		if !strings.HasPrefix(rest, ":") {
			break
		}
		v, r, ok := tzNum(rest[1:])
		if !ok || v > 59 {
			return 0, s, false
		}
		secs += v * mult
		rest = r
	}
	return secs, rest, true
}

func tzNum(s string) (int, string, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i > 3 {
		return 0, s, false
	}
	n, _ := strconv.Atoi(s[:i])
	return n, s[i:], true
}

func tzParseRule(s string) (tzRule, error) {
	r := tzRule{secs: 2 * 3600}
	date, tm, hasTime := strings.Cut(s, "/")
	switch {
	case strings.HasPrefix(date, "M"):
		f := strings.Split(date[1:], ".")
		if len(f) != 3 {
			return r, fmt.Errorf("rule %q: want Mm.w.d", s)
		}
		m, e1 := strconv.Atoi(f[0])
		w, e2 := strconv.Atoi(f[1])
		d, e3 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil || e3 != nil || m < 1 || m > 12 || w < 1 || w > 5 || d < 0 || d > 6 {
			return r, fmt.Errorf("rule %q: bad Mm.w.d", s)
		}
		r.kind, r.mon, r.week, r.day = 'M', m, w, d
	case strings.HasPrefix(date, "J"):
		n, err := strconv.Atoi(date[1:])
		if err != nil || n < 1 || n > 365 {
			return r, fmt.Errorf("rule %q: bad Jn", s)
		}
		r.kind, r.day = 'J', n
	default:
		n, err := strconv.Atoi(date)
		if err != nil || n < 0 || n > 365 {
			return r, fmt.Errorf("rule %q: bad day", s)
		}
		r.kind, r.day = 'N', n
	}
	if hasTime {
		// POSIX.1-2017 / RFC 8536 extension: -167..167 hours.
		sign := 1
		if strings.HasPrefix(tm, "-") {
			sign, tm = -1, tm[1:]
		} else {
			tm = strings.TrimPrefix(tm, "+")
		}
		secs, rest, ok := tzClock(tm, 167)
		if !ok || rest != "" {
			return r, fmt.Errorf("rule %q: bad time", s)
		}
		r.secs = sign * secs
	}
	return r, nil
}

// at is the UTC instant of the rule's transition in year, for a clock
// running at offset (seconds east).
func (r tzRule) at(year int, offset int) time.Time {
	var day time.Time
	switch r.kind {
	case 'J':
		d := r.day
		if isLeap(year) && d >= 60 {
			d++
		}
		day = time.Date(year, 1, d, 0, 0, 0, 0, time.UTC)
	case 'N':
		day = time.Date(year, 1, 1+r.day, 0, 0, 0, 0, time.UTC)
	default:
		first := time.Date(year, time.Month(r.mon), 1, 0, 0, 0, 0, time.UTC)
		dom := 1 + (r.day-int(first.Weekday())+7)%7 + (r.week-1)*7
		last := time.Date(year, time.Month(r.mon)+1, 0, 0, 0, 0, 0, time.UTC).Day()
		for dom > last {
			dom -= 7
		}
		day = time.Date(year, time.Month(r.mon), dom, 0, 0, 0, 0, time.UTC)
	}
	return day.Add(time.Duration(r.secs-offset) * time.Second)
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

// Offset is the zone's offset from UTC at t, in seconds east, and whether
// daylight saving time is in effect.
func (z *Zone) Offset(t time.Time) (int, bool) {
	if !z.hasDST {
		return z.stdOff, false
	}
	year := t.UTC().Add(time.Duration(z.stdOff) * time.Second).Year()
	start := z.start.at(year, z.stdOff)
	end := z.end.at(year, z.dstOff)
	var dst bool
	if start.Before(end) {
		dst = !t.Before(start) && t.Before(end)
	} else {
		dst = t.Before(end) || !t.Before(start)
	}
	if dst {
		return z.dstOff, true
	}
	return z.stdOff, false
}

// Wall is t on the zone's clock, as a time whose fields are the local wall
// clock (its location is UTC and means nothing).
func (z *Zone) Wall(t time.Time) time.Time {
	off, _ := z.Offset(t)
	return t.UTC().Add(time.Duration(off) * time.Second)
}

// Instant converts a wall-clock time back to the instant (the later one
// in a repeated hour, the shifted one in a skipped hour).
func (z *Zone) Instant(wall time.Time) time.Time {
	w := asUTC(wall)
	guess := w.Add(-time.Duration(z.stdOff) * time.Second)
	off, _ := z.Offset(guess)
	t := w.Add(-time.Duration(off) * time.Second)
	if off2, _ := z.Offset(t); off2 != off {
		t = w.Add(-time.Duration(off2) * time.Second)
	}
	return t
}

// String is the TZ string.
func (z *Zone) String() string { return z.spec }
