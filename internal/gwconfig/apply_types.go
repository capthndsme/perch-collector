package gwconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

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
	// ReasonChecksFailed: the apply's checks (checks.go) did not pass within
	// their budget, so the agent rolled back before the deadline.
	ReasonChecksFailed = "checks_failed"
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
// true} (leave the router's value), {"$secret": ref} (resolve from the
// apply's secrets) or {"$generate": kind} (the agent generates the value,
// gateway-sync protocol 2; kinds in GenerateKinds).
type WireValue struct {
	Value    uci.Value
	Keep     bool
	Secret   string
	Generate string
}

// Generated value kinds of {"$generate": …}.
const (
	// GenerateWGPrivateKey is a WireGuard private key, generated on the
	// router; only its public key is reported (ApplyResult.Generated).
	GenerateWGPrivateKey = "wg_private_key"
)

// GenerateKinds are the kinds the wire accepts.
var GenerateKinds = []string{GenerateWGPrivateKey}

const valueObjectForms = `a value object is {"$keep":true}, {"$secret":"<ref>"} or {"$generate":"<kind>"}`

// UnmarshalJSON implements json.Unmarshaler.
func (w *WireValue) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		var o struct {
			Keep     *bool   `json:"$keep"`
			Secret   *string `json:"$secret"`
			Generate *string `json:"$generate"`
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return fmt.Errorf("%s: %w", valueObjectForms, err)
		}
		switch {
		case o.Keep != nil && o.Secret == nil && o.Generate == nil && *o.Keep:
			*w = WireValue{Keep: true}
		case o.Secret != nil && o.Keep == nil && o.Generate == nil && *o.Secret != "":
			*w = WireValue{Secret: *o.Secret}
		case o.Generate != nil && o.Keep == nil && o.Secret == nil && *o.Generate != "":
			*w = WireValue{Generate: *o.Generate}
		default:
			return errors.New(valueObjectForms)
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
	case w.Generate != "":
		return json.Marshal(map[string]string{"$generate": w.Generate})
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
//	service name [enabled] [running]                an init service's state (gateway-sync protocol 3; no config)
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
	// Name, Enabled and Running are the service op's: the init script
	// (ServiceAllowlist) and its wanted rc.d and running states (absent =
	// leave as it is).
	Name    string `json:"name,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
	Running *bool  `json:"running,omitempty"`
}

// OpService is the service op.
const OpService = "service"

// ServiceAllowlist are the init services a service op may drive; the config
// of the same name must be writable.
var ServiceAllowlist = []string{"mwan3", "pbr"}

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
	// Checks are what the router verifies after the commit before it
	// accepts the confirm (gateway-sync protocol 1). nil = none asked for
	// (the agent may add its own net, checks.go); an empty items list = the
	// controller explicitly wants none.
	Checks *Checks `json:"checks,omitempty"`
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
	// Checks: the job's checks with their baseline (pending_confirm only).
	Checks *ChecksReply `json:"checks,omitempty"`
	// Generated are the public halves of values the agent generated.
	Generated []Generated `json:"generated,omitempty"`
}

// Generated is one {"$generate"} value of an apply, by its public half.
type Generated struct {
	Config    string `json:"config"`
	Section   string `json:"section"`
	Option    string `json:"option"`
	PublicKey string `json:"publicKey"`
}

// ApplyIDParams is the params of rollback.
type ApplyIDParams struct {
	ApplyID string `json:"applyId"`
}

// ConfirmParams is the params of confirm. OverrideChecks confirms although
// the apply's checks have not passed (the admin's "Keep anyway").
type ConfirmParams struct {
	ApplyID        string `json:"applyId"`
	OverrideChecks bool   `json:"overrideChecks,omitempty"`
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
	// Checks: the job's checks as they stood when it ended (reason
	// checks_failed, or any rollback of a job that carried checks).
	Checks *ChecksView `json:"checks,omitempty"`
}

// Apply checks (gateway-sync protocol 1): health checks the router runs
// after the commit. The confirm is refused until they pass; when a required
// one cannot pass within the budget the agent rolls back at once
// (checks_failed) instead of waiting for the deadline.

// ChecksVersion is the only checks version this build understands.
const ChecksVersion = 1

// Limits of an apply's checks.
const (
	MinChecksSeconds = 10
	MaxChecksSeconds = 900
	MaxCheckItems    = 16
	// ChecksMargin is kept between the checks' budget and the confirm
	// deadline, so a failure rolls back before the deadline would.
	ChecksMargin = 20
)

// Check kinds.
const (
	CheckInterfaceUp  = "interface_up"
	CheckDefaultRoute = "default_route"
	CheckReach        = "reach"
	CheckResolve      = "resolve"
	CheckWGHandshake  = "wg_handshake"
)

// CheckKinds are the kinds this build runs.
var CheckKinds = []string{CheckInterfaceUp, CheckDefaultRoute, CheckReach, CheckResolve, CheckWGHandshake}

// Check states, of an item and of the whole set. An item is pending,
// running, passed, failed or skipped (it failed at the baseline, before the
// job, so the job cannot be blamed); the set is pending (not started yet),
// running, passed, failed or overridden (the admin confirmed anyway).
const (
	CheckPending    = "pending"
	CheckRunning    = "running"
	CheckPassed     = "passed"
	CheckFailed     = "failed"
	CheckSkipped    = "skipped"
	CheckOverridden = "overridden"
)

// GatewayTargetPrefix marks a reach target that is a network's current next
// hop: "$gateway:wan".
const GatewayTargetPrefix = "$gateway:"

// Checks is gateway.config.apply's `checks`.
type Checks struct {
	V int `json:"v"`
	// TimeoutSeconds is the budget from the end of the commit (after the
	// reload settled), 10..900, clamped to the confirm window minus
	// ChecksMargin.
	TimeoutSeconds int         `json:"timeoutSeconds,omitempty"`
	Items          []CheckItem `json:"items"`
}

// CheckItem is one check. Which fields apply depends on Kind:
//
//	interface_up   network                      netifd has it up with an address of family
//	default_route  [network]                    a default route of family (through network's L3 device)
//	reach          targets [tcpPort] [via]      one target answers ICMP (or a TCP connect to tcpPort)
//	resolve        name                         the router's resolver answers a fresh label under name (checks.go)
//	wg_handshake   network [publicKey] withinSeconds  a peer (that peer) had a handshake that recently
type CheckItem struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Network  string `json:"network,omitempty"`
	Family   int    `json:"family,omitempty"`
	MustPass bool   `json:"mustPass,omitempty"`
	// Targets are IP literals or "$gateway:<network>".
	Targets       []string `json:"targets,omitempty"`
	TCPPort       int      `json:"tcpPort,omitempty"`
	Via           string   `json:"via,omitempty"`
	Name          string   `json:"name,omitempty"`
	PublicKey     string   `json:"publicKey,omitempty"`
	WithinSeconds int      `json:"withinSeconds,omitempty"`
}

// family is the item's address family, 4 by default.
func (c CheckItem) family() int {
	if c.Family == 6 {
		return 6
	}
	return 4
}

// CheckItemResult is one item's state on the wire. Detail and At are null
// until the item has a result.
type CheckItemResult struct {
	ID     string  `json:"id"`
	State  string  `json:"state"`
	Detail *string `json:"detail"`
	At     *string `json:"at"`
}

// ChecksView is the checks' state: the hello's apply.checks, a result's
// checks, and the data of a checks_pending / checks_failed refusal.
type ChecksView struct {
	State          string            `json:"state"`
	StartedAt      string            `json:"startedAt,omitempty"`
	TimeoutSeconds int               `json:"timeoutSeconds,omitempty"`
	AllSkipped     bool              `json:"allSkipped,omitempty"`
	Items          []CheckItemResult `json:"items"`
}

// ChecksReply is the apply reply's checks: pending, with each item's
// baseline (passed, skipped, or failed for a mustPass item, which is never
// skipped). AgentAdded: the job carried no checks and the agent added its
// own net (checks.go); TimeoutSeconds is the budget granted.
type ChecksReply struct {
	State          string            `json:"state"`
	TimeoutSeconds int               `json:"timeoutSeconds"`
	AgentAdded     bool              `json:"agentAdded,omitempty"`
	Baseline       []CheckItemResult `json:"baseline"`
}

// ChecksNote is the notification gateway.config.checks (agent → server),
// sent on every state change and at most every 5 s while running.
type ChecksNote struct {
	ApplyID        string            `json:"applyId"`
	State          string            `json:"state"`
	StartedAt      string            `json:"startedAt,omitempty"`
	ElapsedSeconds float64           `json:"elapsedSeconds"`
	AllSkipped     bool              `json:"allSkipped,omitempty"`
	Items          []CheckItemResult `json:"items"`
}

var checkIDRe = regexp.MustCompile(`^[a-z0-9:_.-]{1,32}$`)

// hostNameRe is a DNS name to resolve: labels of letters, digits and
// hyphens, dot separated, an optional final dot.
var hostNameRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$`)

// validateChecks checks the wire rules of `checks` (bad_params otherwise).
// An empty items list is valid: the controller's explicit "no checks".
func validateChecks(c *Checks) error {
	if c == nil {
		return nil
	}
	if c.V != ChecksVersion {
		return perr(CodeBadParams, "checks version %d is not supported", c.V)
	}
	if len(c.Items) == 0 {
		return nil
	}
	if len(c.Items) > MaxCheckItems {
		return perr(CodeBadParams, "checks: at most %d items", MaxCheckItems)
	}
	if c.TimeoutSeconds < MinChecksSeconds || c.TimeoutSeconds > MaxChecksSeconds {
		return perr(CodeBadParams, "checks: timeoutSeconds is %d to %d", MinChecksSeconds, MaxChecksSeconds)
	}
	seen := map[string]bool{}
	for i, it := range c.Items {
		where := fmt.Sprintf("checks.items[%d]", i)
		if !checkIDRe.MatchString(it.ID) {
			return perr(CodeBadParams, "%s: invalid id %q", where, it.ID)
		}
		if seen[it.ID] {
			return perr(CodeBadParams, "%s: id %s twice", where, it.ID)
		}
		seen[it.ID] = true
		if it.Family != 0 && it.Family != 4 && it.Family != 6 {
			return perr(CodeBadParams, "%s: family is 4 or 6", where)
		}
		netOK := func(n string, required bool) error {
			if n == "" && !required {
				return nil
			}
			if !uci.ValidName(n) || len(n) > uci.MaxNameLen {
				return perr(CodeBadParams, "%s: invalid network %q", where, n)
			}
			return nil
		}
		switch it.Kind {
		case CheckInterfaceUp:
			if err := netOK(it.Network, true); err != nil {
				return err
			}
		case CheckDefaultRoute:
			if err := netOK(it.Network, false); err != nil {
				return err
			}
		case CheckReach:
			if len(it.Targets) == 0 || len(it.Targets) > 8 {
				return perr(CodeBadParams, "%s: 1 to 8 targets", where)
			}
			for _, t := range it.Targets {
				if n, ok := strings.CutPrefix(t, GatewayTargetPrefix); ok {
					if err := netOK(n, true); err != nil {
						return err
					}
					continue
				}
				if net.ParseIP(t) == nil {
					return perr(CodeBadParams, "%s: target %q is not an IP address or $gateway:<network>", where, t)
				}
			}
			if it.TCPPort < 0 || it.TCPPort > 65535 {
				return perr(CodeBadParams, "%s: tcpPort is 1 to 65535", where)
			}
			if err := netOK(it.Via, false); err != nil {
				return err
			}
		case CheckResolve:
			// The probe asks a fresh label under the name (checks.go), so
			// the name leaves room for it.
			if len(strings.TrimSuffix(it.Name, ".")) > 253-FreshLabelLen || !hostNameRe.MatchString(it.Name) {
				return perr(CodeBadParams, "%s: invalid name %q", where, it.Name)
			}
		case CheckWGHandshake:
			if err := netOK(it.Network, true); err != nil {
				return err
			}
			if it.PublicKey != "" && !validWGKey(it.PublicKey) {
				return perr(CodeBadParams, "%s: publicKey is not a WireGuard key", where)
			}
			if it.WithinSeconds < 30 || it.WithinSeconds > 600 {
				return perr(CodeBadParams, "%s: withinSeconds is 30 to 600", where)
			}
		default:
			return perr(CodeBadParams, "%s: unknown kind %q", where, it.Kind)
		}
	}
	return nil
}

// validWGKey: base64 of 32 bytes (44 characters, one '=' of padding).
func validWGKey(s string) bool {
	if len(s) != 44 || s[43] != '=' {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// CodeUnsupported refuses a new wire feature this build does not implement
// (it never announced it in gateway.capabilities features).
const CodeUnsupported = "unsupported"

// checkUnsupported refuses what this build decodes but does not implement:
// the controller only sends it when the matching feature is announced, so
// reaching here means a controller that ignored the features.
func checkUnsupported(a *ApplyParams) error {
	for i, op := range a.Ops {
		if op.Op == OpService {
			return perr(CodeUnsupported, "ops[%d]: the service op is not supported by this build (feature %s)", i, FeatureServiceV1)
		}
		for name, v := range op.Options {
			if v.Generate != "" {
				return perr(CodeUnsupported, "ops[%d]: option %s: generated values are not supported by this build (feature %s)", i, name, FeatureGenerateWGKey)
			}
		}
	}
	return nil
}
