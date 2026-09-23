package observe

import (
	"bufio"
	"bytes"
	"strings"
)

// UCISection is one section of `uci show <pkg>` output.
type UCISection struct {
	// Name is the section name, "@type[N]" for an anonymous one.
	Name string
	Type string
	// Options holds every option; a list has several words, a scalar one.
	Options map[string][]string
}

// Anonymous reports whether uci named the section "@type[N]".
func (s UCISection) Anonymous() bool { return strings.HasPrefix(s.Name, "@") }

// First is the option's first word, trimmed ("" when unset).
func (s UCISection) First(opt string) string {
	if v := s.Options[opt]; len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

// Words are every word of an option, list items and space-separated words
// of a scalar alike (UCI accepts "a b" for many list options).
func (s UCISection) Words(opt string) []string {
	var out []string
	for _, w := range s.Options[opt] {
		out = append(out, strings.Fields(w)...)
	}
	return out
}

// Bool reads a UCI boolean ("1", "yes", "on", "true", "enabled"); def when
// the option is unset.
func (s UCISection) Bool(opt string, def bool) bool {
	v, ok := s.Options[opt]
	if !ok || len(v) == 0 {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v[0])) {
	case "1", "yes", "on", "true", "enabled":
		return true
	case "0", "no", "off", "false", "disabled":
		return false
	}
	return def
}

// ParseUCIShow reads `uci show <pkg>` output ("pkg.<section>=<type>",
// "pkg.<section>.<option>=<value>", list values as several quoted words),
// sections in file order.
func ParseUCIShow(pkg string, data []byte) []UCISection {
	prefix := pkg + "."
	var order []string
	sections := map[string]*UCISection{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4096), 256*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, prefix) {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(key, prefix), ".", 2)
		name := parts[0]
		s := sections[name]
		if s == nil {
			s = &UCISection{Name: name, Options: map[string][]string{}}
			sections[name] = s
			order = append(order, name)
		}
		words := uciWords(value)
		if len(parts) == 1 {
			if len(words) > 0 {
				s.Type = words[0]
			}
			continue
		}
		s.Options[parts[1]] = words
	}
	out := make([]UCISection, 0, len(order))
	for _, name := range order {
		out = append(out, *sections[name])
	}
	return out
}

// uciWords splits a `uci show` value into its words: 'quoted' runs, with
// '\” as an embedded quote, separated by spaces.
func uciWords(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, any := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inQuote = !inQuote
			any = true
		case c == '\\' && !inQuote && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			any = true
		case c == ' ' && !inQuote:
			if any {
				out = append(out, cur.String())
				cur.Reset()
				any = false
			}
		default:
			cur.WriteByte(c)
			any = true
		}
	}
	if any {
		out = append(out, cur.String())
	}
	return out
}
