package gwconfig

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// The apply's pure core: it runs the ops against the router's current
// configs in memory, checks ownership through the ledger, and produces the
// configs as they must look after the commit, the stager steps that get
// them there, and the new ledger. Nothing here touches the router, so the
// whole op semantics is testable on fixtures, and the committed files are
// checked against the simulation afterwards.

// stepKind is one call on a uci.Stager.
type stepKind int

const (
	stepAdd stepKind = iota
	stepSet
	stepDeleteOptions
	stepDeleteSection
	stepRename
	stepOrder
)

type step struct {
	kind    stepKind
	section string
	typ     string
	name    string
	options []uci.Option
	names   []string
}

// simulation is the outcome of running an apply's ops.
type simulation struct {
	// configs are the foreign configs the ops touch, in apply order.
	configs []string
	// desired holds every touched config as it must be after the commit.
	desired map[string]*uci.Config
	// steps per config, in the order they are staged.
	steps map[string][]step
	// touched: per config, the section names the ops touch (old and new
	// names), for the management-path check.
	touched map[string]map[string]bool
	// puts: per config, the sections a put wrote (final names), deleted
	// the ones a delete removed; the commit is verified against them.
	puts    map[string][]string
	deleted map[string][]string
	// ledger is the ledger after the apply; ledgerChanged when it differs.
	ledger        []LedgerEntry
	ledgerChanged bool
	// renames: an adopt renamed a section (renaming an anonymous section is
	// a functional change: README 7.6 puts it through the confirm window).
	renames int
	// usesSecrets: an op resolved a {"$secret"} value.
	usesSecrets bool
}

// changed reports whether a touched config's content differs from its
// current one.
func (s *simulation) changed(current map[string]*uci.Config, config string) bool {
	cur := current[config]
	des := s.desired[config]
	if cur == nil || des == nil {
		return cur != des
	}
	return cur.ContentHash() != des.ContentHash()
}

// PlaneError is a refusal of a config plane method with a code
// (`data.error`) and optional extra data.
type PlaneError struct {
	Code    string
	Message string
	Data    map[string]any
}

func (e *PlaneError) Error() string { return e.Code + ": " + e.Message }

func perr(code, format string, args ...any) *PlaneError {
	return &PlaneError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Error codes of the write methods (plan 1 section 4, plus the ones this
// implementation adds).
const (
	CodeBadParams         = "bad_params"
	CodeStaleBase         = "stale_base"
	CodeBusy              = "busy"
	CodeNotOwned          = "not_owned"
	CodeNameTaken         = "name_taken"
	CodeNoSection         = "no_section"
	CodeUnknownApply      = "unknown_apply"
	CodeDeadlinePassed    = "deadline_passed"
	CodeApplyFailed       = "apply_failed"
	CodeNotReconnected    = "not_reconnected"
	CodeSignatureRequired = "signature_required"
	CodeBadSignature      = "bad_signature"
	CodeStaleSignature    = "stale_signature"
	CodeReplayed          = "replayed"
	CodePackageNotAllowed = "package_not_allowed"
	CodeNoPackageManager  = "no_package_manager"
	CodeInsufficientFlash = "insufficient_flash"
	CodeInstallFailed     = "install_failed"
)

type simInput struct {
	current map[string]*uci.Config // every config an op or the ledger names; nil entry = no file
	ledger  []LedgerEntry
	params  *ApplyParams
	// writable reports whether a config may be written.
	writable func(string) bool
}

// ledgerIndex finds entries by perch id and by (config, section).
type ledgerIndex struct {
	entries []LedgerEntry
}

func (l *ledgerIndex) byPerch(id string) int {
	for i, e := range l.entries {
		if e.PerchID == id {
			return i
		}
	}
	return -1
}

func (l *ledgerIndex) bySection(config, section string) int {
	for i, e := range l.entries {
		if e.Config == config && e.Section == section {
			return i
		}
	}
	return -1
}

func (l *ledgerIndex) set(e LedgerEntry) {
	if i := l.byPerch(e.PerchID); i >= 0 {
		l.entries[i] = e
		return
	}
	l.entries = append(l.entries, e)
}

func (l *ledgerIndex) remove(i int) {
	l.entries = append(l.entries[:i], l.entries[i+1:]...)
}

// simulate runs the ops. Errors are *PlaneError.
func simulate(in simInput) (*simulation, error) {
	p := in.params
	if len(p.Ops) > MaxOps {
		return nil, perr(CodeBadParams, "at most %d ops per apply", MaxOps)
	}
	if len(p.Secrets) > MaxSecrets {
		return nil, perr(CodeBadParams, "at most %d secrets per apply", MaxSecrets)
	}
	sim := &simulation{
		desired: map[string]*uci.Config{},
		steps:   map[string][]step{},
		touched: map[string]map[string]bool{},
		puts:    map[string][]string{},
		deleted: map[string][]string{},
	}
	led := &ledgerIndex{entries: append([]LedgerEntry(nil), in.ledger...)}
	// owned: sections adopted or created by this apply, per config.
	owned := map[string]map[string]bool{}
	mark := func(m map[string]map[string]bool, config, section string) {
		if m[config] == nil {
			m[config] = map[string]bool{}
		}
		m[config][section] = true
	}
	needOrder := map[string]bool{}

	desired := func(config string) (*uci.Config, error) {
		if !uci.ValidConfigName(config) {
			return nil, perr(CodeBadParams, "invalid config name %q", config)
		}
		if !in.writable(config) {
			return nil, &PlaneError{Code: ErrConfigNotAllowed.Error(), Message: "not on the router's allowlist (managed_config, or an installed sibling package such as sqm-scripts or perch-qos), or never writable", Data: map[string]any{"configs": []string{config}}}
		}
		if c, ok := sim.desired[config]; ok {
			return c, nil
		}
		cur, ok := in.current[config]
		if !ok {
			return nil, perr(CodeBadParams, "config %s was not loaded", config)
		}
		var c *uci.Config
		if cur == nil {
			// No file: a put may create the config.
			c = &uci.Config{Name: config}
		} else {
			c = cur.Clone()
		}
		sim.desired[config] = c
		sim.configs = append(sim.configs, config)
		return c, nil
	}
	isOwned := func(config, section string) bool {
		return owned[config][section] || led.bySection(config, section) >= 0
	}
	addStep := func(config string, s step) { sim.steps[config] = append(sim.steps[config], s) }

	for i, op := range p.Ops {
		where := fmt.Sprintf("ops[%d] (%s %s.%s)", i, op.Op, op.Config, op.Section)
		c, err := desired(op.Config)
		if err != nil {
			return nil, err
		}
		switch op.Op {
		case "adopt":
			sec := c.Section(op.Section)
			if sec == nil {
				return nil, perr(CodeNoSection, "%s: no such section", where)
			}
			if !validPerchID(op.PerchID) {
				return nil, perr(CodeBadParams, "%s: invalid perchId %q", where, op.PerchID)
			}
			if j := led.bySection(op.Config, op.Section); j >= 0 && led.entries[j].PerchID != op.PerchID {
				return nil, perr(CodeNotOwned, "%s: the section is in the ledger as %s", where, led.entries[j].PerchID)
			}
			final := op.Section
			if op.RenameTo != "" && op.RenameTo != op.Section {
				if !uci.ValidName(op.RenameTo) || len(op.RenameTo) > uci.MaxNameLen {
					return nil, perr(CodeBadParams, "%s: invalid renameTo %q", where, op.RenameTo)
				}
				if c.Section(op.RenameTo) != nil {
					return nil, perr(CodeNameTaken, "%s: %s.%s exists", where, op.Config, op.RenameTo)
				}
				addStep(op.Config, step{kind: stepRename, section: op.Section, name: op.RenameTo})
				mark(sim.touched, op.Config, op.Section)
				sec.Name, sec.Anonymous = op.RenameTo, false
				final = op.RenameTo
				sim.renames++
				// Verified after the commit like a put: same content, new name.
				sim.puts[op.Config] = appendUnique(sim.puts[op.Config], final)
			} else if sec.Anonymous {
				return nil, perr(CodeBadParams, "%s: an anonymous section is adopted with renameTo (its name changes with its position)", where)
			}
			mark(sim.touched, op.Config, final)
			mark(owned, op.Config, final)
			domain := op.Domain
			if j := led.byPerch(op.PerchID); j >= 0 && domain == "" {
				domain = led.entries[j].Domain
			}
			// Re-link: an existing entry of this perch id now points here.
			led.set(LedgerEntry{PerchID: op.PerchID, Config: op.Config, Section: final, Domain: domain})

		case "put":
			if err := checkSectionName(where, op.Section); err != nil {
				return nil, err
			}
			if !validSectionType(op.Type) {
				return nil, perr(CodeBadParams, "%s: invalid section type %q", where, op.Type)
			}
			sec := c.Section(op.Section)
			if sec != nil && !isOwned(op.Config, op.Section) {
				return nil, perr(CodeNotOwned, "%s: the section exists and is not in the ledger (adopt it first)", where)
			}
			opts, keep, usedSecret, err := resolveOptions(where, op.Options, p.Secrets)
			if err != nil {
				return nil, err
			}
			sim.usesSecrets = sim.usesSecrets || usedSecret
			mark(sim.touched, op.Config, op.Section)
			mark(owned, op.Config, op.Section)
			switch {
			case sec == nil:
				ns := &uci.Section{Name: op.Section, Type: op.Type, Options: opts}
				c.Sections = append(c.Sections, ns)
				addStep(op.Config, step{kind: stepAdd, typ: op.Type, name: op.Section, options: opts})
			case sec.Type != op.Type:
				// A type cannot be changed in place: delete and add, then put it
				// back where it was.
				ns := &uci.Section{Name: op.Section, Type: op.Type, Options: opts}
				for j, s := range c.Sections {
					if s == sec {
						c.Sections[j] = ns
					}
				}
				addStep(op.Config, step{kind: stepDeleteSection, section: op.Section})
				addStep(op.Config, step{kind: stepAdd, typ: op.Type, name: op.Section, options: opts})
				needOrder[op.Config] = true
			default:
				set, del := replaceOptions(sec, opts, keep)
				if len(set) > 0 {
					addStep(op.Config, step{kind: stepSet, section: op.Section, options: set})
				}
				if len(del) > 0 {
					addStep(op.Config, step{kind: stepDeleteOptions, section: op.Section, names: del})
				}
			}
			if op.Position != nil {
				if err := place(c, op.Section, op.Position); err != nil {
					return nil, perr(CodeBadParams, "%s: %v", where, err)
				}
				needOrder[op.Config] = true
			}
			sim.puts[op.Config] = appendUnique(sim.puts[op.Config], op.Section)

		case "delete":
			if err := checkSectionName(where, op.Section); err != nil {
				return nil, err
			}
			sec := c.Section(op.Section)
			if sec == nil {
				// Already gone: nothing to do (a retried job).
				if j := led.bySection(op.Config, op.Section); j >= 0 {
					led.remove(j)
				}
				continue
			}
			if !isOwned(op.Config, op.Section) {
				return nil, perr(CodeNotOwned, "%s: the section is not in the ledger", where)
			}
			for j, s := range c.Sections {
				if s == sec {
					c.Sections = append(c.Sections[:j], c.Sections[j+1:]...)
					break
				}
			}
			addStep(op.Config, step{kind: stepDeleteSection, section: op.Section})
			mark(sim.touched, op.Config, op.Section)
			sim.deleted[op.Config] = appendUnique(sim.deleted[op.Config], op.Section)
			for {
				j := led.bySection(op.Config, op.Section)
				if j < 0 {
					break
				}
				led.remove(j)
			}

		case "order":
			if len(op.Sections) == 0 {
				continue
			}
			seen := map[string]bool{}
			var slots []int
			for _, name := range op.Sections {
				if seen[name] {
					return nil, perr(CodeBadParams, "%s: %s listed twice", where, name)
				}
				seen[name] = true
				idx := -1
				for j, s := range c.Sections {
					if s.Name == name {
						idx = j
					}
				}
				if idx < 0 {
					return nil, perr(CodeNoSection, "%s: no section %s", where, name)
				}
				if op.Type != "" && c.Sections[idx].Type != op.Type {
					return nil, perr(CodeBadParams, "%s: %s is not of type %s", where, name, op.Type)
				}
				if !isOwned(op.Config, name) {
					return nil, perr(CodeNotOwned, "%s: %s is not in the ledger", where, name)
				}
				slots = append(slots, idx)
				mark(sim.touched, op.Config, name)
			}
			// The listed sections keep the positions they occupy together, in
			// the listed order: nothing else moves.
			sort.Ints(slots)
			moved := make([]*uci.Section, len(op.Sections))
			for j, name := range op.Sections {
				moved[j] = c.Section(name)
			}
			for j, slot := range slots {
				c.Sections[slot] = moved[j]
			}
			needOrder[op.Config] = true

		default:
			return nil, perr(CodeBadParams, "ops[%d]: unknown op %q", i, op.Op)
		}
	}

	// Ledger edits of the job.
	for _, e := range p.Ledger.Set {
		if !validPerchID(e.PerchID) || !uci.ValidConfigName(e.Config) || !uci.ValidName(e.Section) {
			return nil, perr(CodeBadParams, "ledger.set: invalid entry %+v", e)
		}
		c, err := desired(e.Config)
		if err != nil {
			return nil, err
		}
		sec := c.Section(e.Section)
		if sec == nil {
			return nil, perr(CodeNoSection, "ledger.set %s: no section %s.%s", e.PerchID, e.Config, e.Section)
		}
		if sec.Anonymous {
			return nil, perr(CodeBadParams, "ledger.set %s: %s.%s is anonymous; adopt it with renameTo", e.PerchID, e.Config, e.Section)
		}
		if j := led.bySection(e.Config, e.Section); j >= 0 && led.entries[j].PerchID != e.PerchID {
			return nil, perr(CodeNotOwned, "ledger.set %s: %s.%s is in the ledger as %s", e.PerchID, e.Config, e.Section, led.entries[j].PerchID)
		}
		if !owned[e.Config][e.Section] && led.byPerch(e.PerchID) < 0 {
			// A pre-existing router section enters the ledger only through
			// adopt (README 7.6), never as a side effect.
			return nil, perr(CodeNotOwned, "ledger.set %s: %s.%s was not created or adopted by this apply", e.PerchID, e.Config, e.Section)
		}
		led.set(e)
	}
	for _, id := range p.Ledger.Remove {
		if j := led.byPerch(id); j >= 0 {
			led.remove(j)
		}
	}

	// Order steps last, with the whole config's final order: foreign
	// sections keep theirs.
	for _, config := range sim.configs {
		c := sim.desired[config]
		c.Reindex()
		if !needOrder[config] {
			continue
		}
		names := make([]string, len(c.Sections))
		for j, s := range c.Sections {
			names[j] = s.Name
		}
		addStep(config, step{kind: stepOrder, names: names})
	}
	// Configs that only a ledger entry named are not touched.
	var touchedConfigs []string
	for _, config := range sim.configs {
		if len(sim.steps[config]) > 0 {
			touchedConfigs = append(touchedConfigs, config)
		} else {
			delete(sim.desired, config)
		}
	}
	sim.configs = sortApplyOrder(touchedConfigs)

	sort.SliceStable(led.entries, func(i, j int) bool { return led.entries[i].PerchID < led.entries[j].PerchID })
	sim.ledger = led.entries
	sim.ledgerChanged = !sameLedger(in.ledger, sim.ledger)
	return sim, nil
}

func checkSectionName(where, name string) error {
	if !uci.ValidName(name) || len(name) > uci.MaxNameLen {
		return perr(CodeBadParams, "%s: invalid section name %q", where, name)
	}
	return nil
}

// validSectionType is libuci's rule: printable ASCII without spaces.
func validSectionType(s string) bool {
	if s == "" || len(s) > uci.MaxNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// resolveOptions turns wire values into options (sorted by name, the order
// rpcd adds them in), the names to keep as they are, and whether a secret
// was used.
func resolveOptions(where string, in map[string]WireValue, secrets map[string]string) ([]uci.Option, map[string]bool, bool, error) {
	names := make([]string, 0, len(in))
	for n := range in {
		names = append(names, n)
	}
	sort.Strings(names)
	var opts []uci.Option
	keep := map[string]bool{}
	used := false
	for _, n := range names {
		if !uci.ValidName(n) || len(n) > uci.MaxNameLen {
			return nil, nil, false, perr(CodeBadParams, "%s: invalid option name %q", where, n)
		}
		w := in[n]
		var v uci.Value
		switch {
		case w.Keep:
			keep[n] = true
			continue
		case w.Secret != "":
			s, ok := secrets[w.Secret]
			if !ok {
				return nil, nil, false, perr(CodeBadParams, "%s: option %s: secret %q not in secrets", where, n, w.Secret)
			}
			v, used = uci.String(s), true
		default:
			v = w.Value
		}
		for _, item := range v.Items {
			if err := uci.CheckValue(item); err != nil {
				return nil, nil, false, perr(CodeBadParams, "%s: option %s: %v", where, n, err)
			}
		}
		if v.IsList && len(v.Items) == 0 {
			continue // an empty list is no option at all in UCI
		}
		opts = append(opts, uci.Option{Name: n, Value: v})
	}
	return opts, keep, used, nil
}

// replaceOptions rewrites sec in place to hold exactly opts plus the kept
// options, the way libuci does it (a set keeps an option's position, a new
// one is appended), and returns what has to be set and deleted.
func replaceOptions(sec *uci.Section, opts []uci.Option, keep map[string]bool) (set []uci.Option, del []string) {
	want := map[string]uci.Value{}
	for _, o := range opts {
		want[o.Name] = o.Value
	}
	var out []uci.Option
	have := map[string]bool{}
	for _, o := range sec.Options {
		have[o.Name] = true
		if keep[o.Name] {
			out = append(out, o)
			continue
		}
		v, ok := want[o.Name]
		if !ok {
			del = append(del, o.Name)
			continue
		}
		if !v.Equal(o.Value) {
			set = append(set, uci.Option{Name: o.Name, Value: v})
		}
		out = append(out, uci.Option{Name: o.Name, Value: v})
	}
	for _, o := range opts {
		if !have[o.Name] {
			set = append(set, o)
			out = append(out, o)
		}
	}
	sec.Options = out
	return set, del
}

// place moves a section next to another one.
func place(c *uci.Config, name string, pos *Position) error {
	ref := pos.After
	after := true
	if ref == "" {
		ref, after = pos.Before, false
	}
	if ref == "" || ref == name {
		return nil
	}
	var sec *uci.Section
	rest := c.Sections[:0:0]
	for _, s := range c.Sections {
		if s.Name == name {
			sec = s
			continue
		}
		rest = append(rest, s)
	}
	if sec == nil {
		return fmt.Errorf("no section %s", name)
	}
	out := make([]*uci.Section, 0, len(c.Sections))
	found := false
	for _, s := range rest {
		if s.Name == ref {
			found = true
			if after {
				out = append(out, s, sec)
			} else {
				out = append(out, sec, s)
			}
			continue
		}
		out = append(out, s)
	}
	if !found {
		return fmt.Errorf("position: no section %s", ref)
	}
	c.Sections = out
	return nil
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func sameLedger(a, b []LedgerEntry) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(e LedgerEntry) string {
		return e.PerchID + "\x00" + e.Config + "\x00" + e.Section + "\x00" + e.Domain
	}
	m := map[string]int{}
	for _, e := range a {
		m[key(e)]++
	}
	for _, e := range b {
		if m[key(e)] == 0 {
			return false
		}
		m[key(e)]--
	}
	return true
}

// ApplyOrder is the order configs are committed and reloaded in within one
// job (README 3.5); anything else follows alphabetically.
var ApplyOrder = []string{"system", "network", "dhcp", "firewall", "sqm", "perch-qos", "opennds", "mwan3", "pbr"}

func sortApplyOrder(configs []string) []string {
	rank := func(c string) int {
		for i, o := range ApplyOrder {
			if o == c {
				return i
			}
		}
		return len(ApplyOrder)
	}
	out := append([]string(nil), configs...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank(out[i]), rank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}

// renderLedger renders the ledger config: one `config synced '<perchId>'`
// per entry, sorted by perch id.
func renderLedger(entries []LedgerEntry) []byte {
	c := &uci.Config{Name: LedgerConfig}
	for _, e := range entries {
		s := &uci.Section{Name: e.PerchID, Type: "synced"}
		s.Set("config", uci.String(e.Config))
		s.Set("section", uci.String(e.Section))
		if e.Domain != "" {
			s.Set("domain", uci.String(e.Domain))
		}
		c.Sections = append(c.Sections, s)
	}
	var b bytes.Buffer
	b.WriteString("# Perch sync ledger: written by perch-collector only. perch_id -> section.\n")
	b.Write(uci.Render(c))
	return b.Bytes()
}

// verifyCommitted compares what was committed with the simulation: every
// put (or renamed) section has exactly the simulated content and every
// deleted one is gone. Order is not compared (the stager's order call is
// libuci's).
func verifyCommitted(sim *simulation, config string, got *uci.Config) error {
	want := sim.desired[config]
	var problems []string
	for _, name := range sim.puts[config] {
		w, g := want.Section(name), got.Section(name)
		switch {
		case w == nil:
			continue // put, then deleted again in the same job
		case g == nil:
			problems = append(problems, name+" missing")
		case !bytes.Equal(uci.Canonical(w, nil), uci.Canonical(g, nil)):
			problems = append(problems, name+" differs")
		}
	}
	for _, name := range sim.deleted[config] {
		if want.Section(name) == nil && got.Section(name) != nil {
			problems = append(problems, name+" still present")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s after commit: %s", config, strings.Join(problems, ", "))
	}
	return nil
}
