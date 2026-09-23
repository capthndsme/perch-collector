package gwconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Apply kinds (gateway.config.apply `kind`, plus `package` for
// gateway.package.install, which shares the one pending slot).
const (
	KindApply   = "apply"
	KindRevert  = "revert"
	KindAdopt   = "adopt"
	KindPackage = "package"
)

// Apply states in replies and in the hello's apply block.
const (
	StateIdle           = "idle"
	StateApplying       = "applying"
	StatePendingConfirm = "pending_confirm"
	StateRollingBack    = "rolling_back"
	StateApplied        = "applied"
	StateNoop           = "noop"
	StateDryRun         = "dry_run"
	StateConfirmed      = "confirmed"
)

// Outcomes and reasons of gateway.config.result (plan 1 section 4).
const (
	OutcomeConfirmed  = "confirmed"
	OutcomeRolledBack = "rolled_back"
	OutcomeFailed     = "failed"

	ReasonConfirmTimeout = "confirm_timeout"
	ReasonAdmin          = "admin"
	ReasonReboot         = "reboot"
	ReasonReloadFailed   = "reload_failed"
	ReasonCommitFailed   = "commit_failed"
	ReasonInstallFailed  = "install_failed"
)

// Confirm windows, seconds. The controller asks for a window; the agent
// clamps it to [MinConfirmSeconds, config_confirm_max]. A job that carries
// the management path (README 3.8) gets at least ProtectedConfirmSeconds
// (the controller's managementConfirmTimeoutSeconds default), capped the
// same way.
const (
	DefaultConfirmSeconds   = 90
	MinConfirmSeconds       = 30
	ProtectedConfirmSeconds = 300
)

// Limits of one apply.
const (
	MaxOps     = 2000
	MaxSecrets = 256
)

var applyIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// ValidApplyID reports whether s can be an apply id: it names a directory
// on flash, so letters, digits and _ . : - only, at most 64 characters.
func ValidApplyID(s string) bool { return applyIDRe.MatchString(s) }

// validPerchID: a perch id is the ledger's section name (at most 24
// characters, plan 1 section 9).
func validPerchID(s string) bool { return uci.ValidName(s) && len(s) <= 24 }

// WireValue is an option value in an apply op: a string, a list, {"$keep":
// true} (leave the router's value) or {"$secret": ref} (resolve from the
// apply's secrets).
type WireValue struct {
	Value  uci.Value
	Keep   bool
	Secret string
}

// UnmarshalJSON implements json.Unmarshaler.
func (w *WireValue) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		var o struct {
			Keep   *bool   `json:"$keep"`
			Secret *string `json:"$secret"`
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return fmt.Errorf(`a value object is {"$keep":true} or {"$secret":"<ref>"}: %w`, err)
		}
		switch {
		case o.Keep != nil && o.Secret == nil && *o.Keep:
			*w = WireValue{Keep: true}
		case o.Secret != nil && o.Keep == nil && *o.Secret != "":
			*w = WireValue{Secret: *o.Secret}
		default:
			return errors.New(`a value object is {"$keep":true} or {"$secret":"<ref>"}`)
		}
		return nil
	}
	return json.Unmarshal(b, &w.Value)
}

// MarshalJSON implements json.Marshaler (tests, dry runs).
func (w WireValue) MarshalJSON() ([]byte, error) {
	switch {
	case w.Keep:
		return []byte(`{"$keep":true}`), nil
	case w.Secret != "":
		return json.Marshal(map[string]string{"$secret": w.Secret})
	}
	return w.Value.MarshalJSON()
}

// Position places a created or moved section next to another one.
type Position struct {
	After  string `json:"after,omitempty"`
	Before string `json:"before,omitempty"`
}

// Op is one operation of gateway.config.apply (plan 1 section 4):
//
//	put     config section type options [position]  create or fully replace an owned section
//	adopt   config section perchId [renameTo] [domain] register an existing section in the ledger
//	delete  config section                          remove an owned section
//	order   config type sections                    put owned sections of a type in this order
type Op struct {
	Op       string               `json:"op"`
	Config   string               `json:"config"`
	Section  string               `json:"section,omitempty"`
	Type     string               `json:"type,omitempty"`
	Options  map[string]WireValue `json:"options,omitempty"`
	Position *Position            `json:"position,omitempty"`
	PerchID  string               `json:"perchId,omitempty"`
	RenameTo string               `json:"renameTo,omitempty"`
	Domain   string               `json:"domain,omitempty"`
	Sections []string             `json:"sections,omitempty"`
}

// LedgerChange are the ledger edits that ride with an apply.
type LedgerChange struct {
	Set    []LedgerEntry `json:"set,omitempty"`
	Remove []string      `json:"remove,omitempty"`
}

// ApplyParams are gateway.config.apply's params.
type ApplyParams struct {
	ApplyID string `json:"applyId"`
	Kind    string `json:"kind"`
	// Protected: the controller flags a job that carries the management
	// path (README 3.8); the agent also detects it itself.
	Protected             bool              `json:"protected,omitempty"`
	ConfirmTimeoutSeconds *float64          `json:"confirmTimeoutSeconds,omitempty"`
	DryRun                bool              `json:"dryRun,omitempty"`
	Base                  map[string]string `json:"base"`
	Ops                   []Op              `json:"ops"`
	Ledger                LedgerChange      `json:"ledger"`
	Secrets               map[string]string `json:"secrets,omitempty"`
}

// ChangeEntry is one staged change of a dry run: rpcd's `uci changes`
// entry with its config.
type ChangeEntry struct {
	Config  string `json:"config"`
	Section string `json:"section"`
	Op      string `json:"op"`
	Option  string `json:"option,omitempty"`
	Value   string `json:"value,omitempty"`
}

// ApplyResult is gateway.config.apply's result.
type ApplyResult struct {
	State    string `json:"state"`
	ApplyID  string `json:"applyId"`
	Deadline string `json:"deadline,omitempty"`
	// ConfirmTimeoutSeconds is the window the agent granted.
	ConfirmTimeoutSeconds int               `json:"confirmTimeoutSeconds,omitempty"`
	Protected             bool              `json:"protected,omitempty"`
	Hashes                map[string]string `json:"hashes,omitempty"`
	Changes               []ChangeEntry     `json:"changes,omitempty"`
}

// ApplyIDParams is the params of confirm and rollback.
type ApplyIDParams struct {
	ApplyID string `json:"applyId"`
}

// AckParams is the params of gateway.config.ack.
type AckParams struct {
	ApplyIDs []string `json:"applyIds"`
}

// DiscardedSection is a router edit made during a confirm window that a
// rollback undid: the section as it was just before the rollback (redacted
// like a read), or only its name and type when the router had removed it.
type DiscardedSection struct {
	Section
	// Change is added, changed or removed (relative to what the apply had
	// committed).
	Change string `json:"change"`
}

// Result is one apply outcome, sent as gateway.config.result and kept in
// the hello's results until the controller acks it.
type Result struct {
	ApplyID string            `json:"applyId"`
	Kind    string            `json:"kind,omitempty"`
	Outcome string            `json:"outcome"`
	Reason  string            `json:"reason,omitempty"`
	At      string            `json:"at"`
	Hashes  map[string]string `json:"hashes"`
	// Discarded are router edits of the window that the rollback undid, by
	// config (plan 1 section 5.5: they come back as conflicts).
	Discarded map[string][]DiscardedSection `json:"discarded,omitempty"`
	// Packages: for a package job, what the rollback removed.
	Packages []string `json:"packages,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}
