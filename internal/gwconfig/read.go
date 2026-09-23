package gwconfig

import (
	"errors"
	"sort"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Read limits (plan 1 section 11): a config file above MaxConfigBytes, or a
// read above MaxReadBytes or MaxReadSections in total, is refused whole,
// never cut.
const (
	MaxConfigBytes  = 2 << 20
	MaxReadBytes    = 2 << 20
	MaxReadSections = 2000
)

// Section is one section as gateway.config.read returns it: secrets removed
// and fingerprinted, and the hash of its content (uci.Redacted.Hash).
type Section struct {
	Name      string               `json:"name"`
	Type      string               `json:"type"`
	Anonymous bool                 `json:"anonymous"`
	Index     int                  `json:"index"`
	Options   map[string]uci.Value `json:"options"`
	Secrets   map[string]string    `json:"secrets,omitempty"`
	Hash      string               `json:"hash"`
}

// Config is one config of a read. Missing: an allowlisted config that does
// not exist on the router (no file); its hash is "".
type Config struct {
	Name     string    `json:"name"`
	Hash     string    `json:"hash"`
	Missing  bool      `json:"missing,omitempty"`
	Sections []Section `json:"sections"`
}

// LedgerEntry is one section of the sync ledger (/etc/config/perch-managed):
// `config synced '<perchId>'` with options config, section and domain.
type LedgerEntry struct {
	PerchID string `json:"perchId"`
	Config  string `json:"config"`
	Section string `json:"section"`
	Domain  string `json:"domain,omitempty"`
}

// ReadResult is gateway.config.read's result.
type ReadResult struct {
	ReadAt      string        `json:"readAt"`
	Configs     []Config      `json:"configs"`
	Ledger      []LedgerEntry `json:"ledger"`
	Uncommitted []string      `json:"uncommitted"`
	LuciPending bool          `json:"luciPending"`
}

// Read reads configs for the controller: the named ones, or every readable
// one when names is empty. Committed state only, from the files, with
// secrets redacted.
func (p *Plane) Read(names []string) (*ReadResult, error) {
	if err := p.RequireAccess(AccessRead); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		names = p.Readable()
	}
	var refused []string
	seen := map[string]bool{}
	var list []string
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if !p.readable(n) {
			refused = append(refused, n)
			continue
		}
		list = append(list, n)
	}
	if len(refused) > 0 {
		sort.Strings(refused)
		return nil, &AccessError{Code: ErrConfigNotAllowed, Message: "not on the router's allowlist (managed_config, or an installed sibling package such as sqm-scripts or perch-qos), or never readable", Configs: refused}
	}
	sort.Strings(list)
	res := &ReadResult{
		ReadAt:  p.o.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Configs: []Config{},
		Ledger:  []LedgerEntry{},
	}
	total, sections := 0, 0
	for _, n := range list {
		l, err := p.files.Load(n)
		if errors.Is(err, uci.ErrNoConfig) {
			res.Configs = append(res.Configs, Config{Name: n, Missing: true, Sections: []Section{}})
			continue
		}
		if err != nil {
			return nil, err
		}
		total += l.Size
		sections += len(l.Config.Sections)
		if l.Size > MaxConfigBytes || total > MaxReadBytes || sections > MaxReadSections {
			return nil, &AccessError{Code: ErrTooLarge, Message: "the read exceeds 2 MiB or 2000 sections; read fewer configs at once", Configs: []string{n}}
		}
		c := Config{Name: n, Hash: l.Hash, Sections: make([]Section, 0, len(l.Config.Sections))}
		for _, s := range l.Config.Sections {
			r := p.redact.Section(n, s)
			c.Sections = append(c.Sections, Section{
				Name: s.Name, Type: s.Type, Anonymous: s.Anonymous, Index: s.Index,
				Options: r.Section.Values(), Secrets: r.Secrets, Hash: r.Hash(),
			})
		}
		res.Configs = append(res.Configs, c)
		if n == LedgerConfig {
			res.Ledger = ledger(l.Config)
		}
	}
	pending := uci.PendingState(p.o.Root)
	res.Uncommitted = p.filterReadable(pending.Uncommitted)
	res.LuciPending = pending.LuciPending
	return res, nil
}

// ledger reads the ledger's `synced` sections.
func ledger(c *uci.Config) []LedgerEntry {
	out := []LedgerEntry{}
	for _, s := range c.OfType("synced") {
		cfg, _ := s.Get("config")
		sec, _ := s.Get("section")
		dom, _ := s.Get("domain")
		if cfg.Str() == "" || sec.Str() == "" {
			continue
		}
		out = append(out, LedgerEntry{PerchID: s.Name, Config: cfg.Str(), Section: sec.Str(), Domain: dom.Str()})
	}
	return out
}

func (p *Plane) filterReadable(names []string) []string {
	out := []string{}
	for _, n := range names {
		if p.readable(n) {
			out = append(out, n)
		}
	}
	return out
}
