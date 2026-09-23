package gwconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// fileStager stages changes on the parsed config in memory and commits by
// rendering the whole file (tmp + fsync + rename). It is the write path
// when rpcd's uci object is missing: the uci command line cannot write in
// isolation (its commit also writes foreign deltas staged in /tmp/.uci,
// uci-settle amendment section 5), so the fallback never runs it. The
// rendered file is what `uci commit` would write (comments are dropped, as
// uci does). A commit refuses when the file changed since it was loaded.
type fileStager struct {
	dir     string
	allowed map[string]bool
	loaded  map[string]*stagedConfig
}

type stagedConfig struct {
	cfg     *uci.Config
	hash    string // "" = no file when loaded
	changes []uci.Change
}

func newFileStager(dir string, configs []string) *fileStager {
	s := &fileStager{dir: dir, allowed: map[string]bool{}, loaded: map[string]*stagedConfig{}}
	for _, c := range configs {
		s.allowed[c] = true
	}
	return s
}

func (s *fileStager) load(config string) (*stagedConfig, error) {
	if !s.allowed[config] {
		return nil, fmt.Errorf("uci: config %s is not in this stager", config)
	}
	if sc, ok := s.loaded[config]; ok {
		return sc, nil
	}
	l, err := uci.Files{Dir: s.dir}.Load(config)
	sc := &stagedConfig{}
	switch {
	case errors.Is(err, uci.ErrNoConfig):
		sc.cfg = &uci.Config{Name: config}
	case err != nil:
		return nil, err
	default:
		sc.cfg, sc.hash = l.Config, l.Hash
	}
	s.loaded[config] = sc
	return sc, nil
}

func (s *fileStager) section(config, name string) (*stagedConfig, *uci.Section, error) {
	sc, err := s.load(config)
	if err != nil {
		return nil, nil, err
	}
	sec := sc.cfg.Section(name)
	if sec == nil {
		return nil, nil, fmt.Errorf("%w: %s.%s", uci.ErrNoSection, config, name)
	}
	return sc, sec, nil
}

func (s *fileStager) Add(_ context.Context, config, typ, name string, options []uci.Option) (string, error) {
	sc, err := s.load(config)
	if err != nil {
		return "", err
	}
	if name == "" {
		name = uci.AnonymousName(len(sc.cfg.Sections)+1, typ)
	}
	if sc.cfg.Section(name) != nil {
		return "", fmt.Errorf("uci: %s.%s exists", config, name)
	}
	sec := &uci.Section{Name: name, Type: typ}
	for _, o := range options {
		sec.Set(o.Name, o.Value)
	}
	sc.cfg.Sections = append(sc.cfg.Sections, sec)
	sc.changes = append(sc.changes, uci.Change{Op: "add", Section: name, Value: typ})
	for _, o := range options {
		sc.changes = append(sc.changes, uci.Change{Op: "set", Section: name, Option: o.Name, Value: o.Value.Str()})
	}
	return name, nil
}

func (s *fileStager) Set(_ context.Context, config, section string, options []uci.Option) error {
	sc, sec, err := s.section(config, section)
	if err != nil {
		return err
	}
	for _, o := range options {
		sec.Set(o.Name, o.Value)
		sc.changes = append(sc.changes, uci.Change{Op: "set", Section: section, Option: o.Name, Value: o.Value.Str()})
	}
	return nil
}

func (s *fileStager) DeleteOptions(_ context.Context, config, section string, options ...string) error {
	sc, sec, err := s.section(config, section)
	if err != nil {
		return err
	}
	for _, o := range options {
		if sec.Delete(o) {
			sc.changes = append(sc.changes, uci.Change{Op: "remove", Section: section, Option: o})
		}
	}
	return nil
}

func (s *fileStager) DeleteSection(_ context.Context, config, section string) error {
	sc, sec, err := s.section(config, section)
	if err != nil {
		return err
	}
	for i, x := range sc.cfg.Sections {
		if x == sec {
			sc.cfg.Sections = append(sc.cfg.Sections[:i], sc.cfg.Sections[i+1:]...)
			break
		}
	}
	sc.changes = append(sc.changes, uci.Change{Op: "remove", Section: section})
	return nil
}

func (s *fileStager) Rename(_ context.Context, config, section, name string) error {
	sc, sec, err := s.section(config, section)
	if err != nil {
		return err
	}
	if sc.cfg.Section(name) != nil {
		return fmt.Errorf("uci: %s.%s exists", config, name)
	}
	sec.Name, sec.Anonymous = name, false
	sc.changes = append(sc.changes, uci.Change{Op: "rename", Section: section, Value: name})
	return nil
}

// Order moves the listed sections to the front, in this order (rpcd's
// semantics).
func (s *fileStager) Order(_ context.Context, config string, sections []string) error {
	sc, err := s.load(config)
	if err != nil {
		return err
	}
	front := make([]*uci.Section, 0, len(sections))
	listed := map[*uci.Section]bool{}
	for i, name := range sections {
		sec := sc.cfg.Section(name)
		if sec == nil {
			return fmt.Errorf("%w: %s.%s", uci.ErrNoSection, config, name)
		}
		if !listed[sec] {
			front = append(front, sec)
			listed[sec] = true
			sc.changes = append(sc.changes, uci.Change{Op: "order", Section: name, Value: fmt.Sprint(i)})
		}
	}
	for _, sec := range sc.cfg.Sections {
		if !listed[sec] {
			front = append(front, sec)
		}
	}
	sc.cfg.Sections = front
	return nil
}

func (s *fileStager) Changes(_ context.Context, config string) ([]uci.Change, error) {
	if sc, ok := s.loaded[config]; ok {
		return append([]uci.Change{}, sc.changes...), nil
	}
	return []uci.Change{}, nil
}

func (s *fileStager) Revert(_ context.Context, config string) error {
	delete(s.loaded, config)
	return nil
}

func (s *fileStager) Commit(_ context.Context, config string) error {
	sc, ok := s.loaded[config]
	if !ok || len(sc.changes) == 0 {
		return nil
	}
	path := uci.Files{Dir: s.dir}.Path(config)
	now := ""
	if data, err := os.ReadFile(path); err == nil {
		now = uci.FileHash(data)
	}
	if now != sc.hash {
		return fmt.Errorf("uci: %s changed on the router while it was staged", config)
	}
	sc.cfg.Reindex()
	if err := writeFileSync(path, uci.Render(sc.cfg), fileMode(path)); err != nil {
		return err
	}
	delete(s.loaded, config)
	return nil
}

func (s *fileStager) Close(context.Context) error {
	s.loaded = map[string]*stagedConfig{}
	return nil
}

var _ uci.Stager = (*fileStager)(nil)

// foreignStaged returns the delta lines staged in /tmp/.uci for a config
// (the uci CLI's default save directory), secrets redacted; nil when there
// are none. netifd and every init script that loads its config through
// config_load apply these deltas on a reload, so an apply's reload would
// make them live (uci-settle amendment section 6).
func foreignStaged(root, config string) []string {
	data, err := os.ReadFile(rooted(root, uci.DefaultSaveDir+"/"+config))
	if err != nil || len(data) == 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, redactDelta(line))
	}
	return out
}

// redactDelta hides the value of a delta line that sets a secret option
// ("network.wg0.private_key='…'").
func redactDelta(line string) string {
	body := strings.TrimLeft(line, "+-@^|~")
	path, _, hasValue := strings.Cut(body, "=")
	parts := strings.Split(path, ".")
	if hasValue && len(parts) == 3 && uci.IsSecret(parts[2]) {
		return line[:len(line)-len(body)] + path + "=<redacted>"
	}
	return line
}

// changesOf lists a stager's staged changes for configs, sorted by apply
// order.
func changesOf(ctx context.Context, st uci.Stager, configs []string) ([]ChangeEntry, error) {
	out := []ChangeEntry{}
	for _, c := range configs {
		list, err := st.Changes(ctx, c)
		if err != nil {
			return nil, err
		}
		for _, ch := range list {
			v := ch.Value
			if ch.Option != "" && uci.IsSecret(ch.Option) {
				v = "<redacted>"
			}
			out = append(out, ChangeEntry{Config: c, Section: ch.Section, Op: ch.Op, Option: ch.Option, Value: v})
		}
	}
	return out, nil
}
