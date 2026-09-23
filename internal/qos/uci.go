package qos

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// uciSection is one section of a UCI config file.
type uciSection struct {
	Type string
	Name string // "" for an anonymous section
	// Options: a scalar option has one value, a list one value per entry.
	Options map[string][]string
	// Lists marks the options written with `list`.
	Lists map[string]bool
}

func (s *uciSection) first(opt string) (string, bool) {
	v, ok := s.Options[opt]
	if !ok || len(v) == 0 {
		return "", ok
	}
	return v[len(v)-1], true
}

// parseUCIFile reads a committed UCI config file (/etc/config/<pkg>): the
// file, not `uci show`, because `uci show` also returns uncommitted changes
// staged under /tmp/.uci and the shaper must only follow committed config.
// Grammar: `config <type> ['<name>']`, `option <key> '<value>'`,
// `list <key> '<value>'`, comments with #; values quoted with ' or ", or
// bare words; a backslash outside quotes escapes one character, so a
// single quote inside a single-quoted value is written as quote, backslash,
// quote, quote (what uci export writes).
func parseUCIFile(data []byte) ([]*uciSection, error) {
	var out []*uciSection
	var cur *uciSection
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		words, err := uciWords(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", line, err)
		}
		if len(words) == 0 {
			continue
		}
		switch words[0] {
		case "package":
			continue
		case "config":
			if len(words) < 2 || len(words) > 3 {
				return nil, fmt.Errorf("line %d: config needs a type and at most a name", line)
			}
			cur = &uciSection{Type: words[1], Options: map[string][]string{}, Lists: map[string]bool{}}
			if len(words) == 3 {
				cur.Name = words[2]
			}
			out = append(out, cur)
		case "option", "list":
			if cur == nil {
				return nil, fmt.Errorf("line %d: %s outside a section", line, words[0])
			}
			if len(words) != 3 {
				return nil, fmt.Errorf("line %d: %s needs a name and one value", line, words[0])
			}
			key := words[1]
			if words[0] == "list" {
				cur.Lists[key] = true
				cur.Options[key] = append(cur.Options[key], words[2])
			} else {
				cur.Options[key] = []string{words[2]}
			}
		default:
			return nil, fmt.Errorf("line %d: unknown keyword %q", line, words[0])
		}
	}
	return out, sc.Err()
}

// uciWords splits one line into words, honouring quotes, backslash escapes
// outside single quotes, and # comments outside quotes.
func uciWords(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	have := false
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				continue
			}
			if c == '\\' && quote == '"' && i+1 < len(s) {
				i++
				c = s[i]
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			have = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			have = true
		case c == '#':
			i = len(s)
		case c == ' ' || c == '\t' || c == '\r':
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if have {
		out = append(out, cur.String())
	}
	return out, nil
}
