// Package gwconfig is the router side of the Perch config plane (plan 1 of
// the managed gateway, docs/gateway/ in the controller): it reads the
// router's UCI configuration for the controller, with secrets redacted,
// notices changes (procd's reload trigger plus polling) and says who likely
// made them, and reports what the router is (OpenWrt release, firewall,
// packages, storage). The owner of the router opts in: `config_access`
// none (default), read or write in /etc/config/perch-collector, and only
// the configs on its allowlist are ever read.
//
// With config_access 'write' the controller also writes: the apply engine
// (engine.go) stages the changes in a private rpcd session, commits them in
// apply order, reconnects, and restores its flash snapshot unless the
// controller confirms on the fresh connection. Writes need verified TLS, or
// the router's config_allow_insecure opt-in plus signed requests (sign.go).
package gwconfig

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/pkgdb"
	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Protocol is the config plane protocol version in the hello.
const Protocol = 1

// Access levels (config_access).
const (
	AccessNone  = "none"
	AccessRead  = "read"
	AccessWrite = "write"
)

// SupportedAccess is the highest access this build implements.
const SupportedAccess = AccessWrite

// LedgerConfig is the sync ledger (plan 1 section 9): written only by the
// agent, readable whenever access allows reading.
const LedgerConfig = "perch-managed"

// Denylist are configs never read or written through the plane, whatever the
// allowlist says (gateway README section 3.4): the agent's own config (so the
// controller can never flip the opt-in or re-point it), the AP daemon's, and
// what keeps the router reachable and administrable.
var Denylist = []string{"perch-collector", "perch-apd", "rpcd", "uhttpd", "dropbear", "luci"}

// DefaultAllowlist is the package default of managed_config.
var DefaultAllowlist = []string{"network", "dhcp", "firewall"}

// Denied reports whether a config is on the denylist.
func Denied(name string) bool {
	for _, d := range Denylist {
		if name == d {
			return true
		}
	}
	return false
}

// Options configure a Plane.
type Options struct {
	// Access is config_access: none, read or write.
	Access string
	// Allowlist is managed_config; denylisted names are dropped.
	Allowlist []string
	// AllowInsecure is config_allow_insecure: writes over an unverified
	// transport are accepted when signed.
	AllowInsecure bool
	// ConfirmMax is config_confirm_max in seconds (reported).
	ConfirmMax int
	// TransportOK: server_url is https with certificate verification on.
	TransportOK bool
	// APIKey keys the secret fingerprints (the controller has it too). It
	// never signs config writes (owner decision 29: it is the Bearer token
	// a plain-HTTP listener sees); SignKey or the pairing's key does.
	APIKey string
	// SignKey is config_sign_key: an HMAC key for signed writes that the
	// admin enters on both ends (it never crosses the wire). When set it
	// signs instead of a pairing (pair.go), and pairing is refused.
	SignKey string
	// ServerURL is the controller; its address gives the management path.
	ServerURL string
	// PackageAllow extends InstallAllowlist (list package_allow).
	PackageAllow []string
	// SiblingsOff is managed_config_auto '0': installed sibling packages
	// (siblings.go) do not bring their config onto the allowlist.
	SiblingsOff bool
	// SiblingExclude is list managed_config_exclude: sibling configs that
	// stay off the allowlist although their package is installed.
	SiblingExclude []string
	// StoragePath is the path for the agent's local state (README section
	// 7.18); only detected and reported here.
	StoragePath string
	// CaptureNetwork and CaptureDevice describe what the collector captures.
	CaptureNetwork string
	CaptureDevice  string
	// CapturedNetworks, when set, is the live capture of a multi-network
	// collector (capture_networks): device → UCI network. It replaces the
	// two fields above in gateway.capabilities.
	CapturedNetworks func() map[string]string

	// Root prefixes every path ("" = /; tests).
	Root string
	// Ubus is the ubus client (session list, backend detection); nil =
	// ubus.New().
	Ubus *ubus.Client
	// LookPath finds binaries (backend detection); nil = exec.LookPath.
	LookPath func(string) (string, error)
	// Now is the clock; nil = time.Now (or Clock's).
	Now func() time.Time
	// Clock drives the apply engine's deadlines; nil = the real one.
	Clock Clock
	// Backend writes configs; nil = rpcd when it serves `uci`, else files.
	Backend Backend
	// Run runs commands (ip, opkg, apk); nil = ubus.ExecRunner.
	Run ubus.Runner
	// LookupHost resolves the controller's name; nil = the default resolver.
	LookupHost func(ctx context.Context, host string) ([]string, error)
	// Features are more features the daemon serves outside the plane
	// (runtime RPCs, observation parts), announced with the plane's own in
	// gateway.capabilities.
	Features []string
	// CheckDial connects a reach check's TCP fallback (device "" = by the
	// routing table); nil = net.Dialer bound to the device (tests).
	CheckDial func(ctx context.Context, network, addr, device string) error
	// CheckResolve resolves a resolve check's name; nil = the pure Go
	// resolver over /etc/resolv.conf (tests).
	CheckResolve func(ctx context.Context, network, host string) ([]net.IP, error)
}

// RedactExtra are secret option names beyond the kit's: a mobile WAN's SIM
// PIN and PUK (gateway-sync protocol 5), which its suffix rules miss.
var RedactExtra = []string{"pincode", "pukcode"}

// NewRedactor is the plane's redactor: fingerprints keyed by the api_key,
// the kit's secret names plus RedactExtra. The boot guard uses it too.
func NewRedactor(apiKey string) uci.Redactor {
	return uci.Redactor{Key: []byte(apiKey), Extra: append([]string(nil), RedactExtra...)}
}

// Plane serves the config plane. Safe for concurrent use.
type Plane struct {
	o       Options
	files   uci.Files
	ubus    *ubus.Client
	redact  uci.Redactor
	allowed []string

	mu sync.Mutex
	w  watchState
	// poke wakes Run: a trigger or a configure.
	poke chan struct{}

	clock       Clock
	backend     Backend
	backendOnce sync.Once
	nonces      nonceCache
	pair        pairState
	ap          applier
	hooks       Hooks

	sibMu sync.Mutex
	sib   siblingCache

	// chk holds the pending apply's running checks (checks.go); lock order
	// ap.mu before chk.mu.
	chk checksHolder

	// genValue makes {"$generate"} values (generate.go); tests replace it.
	genValue keyGen
}

// New prepares a plane.
func New(o Options) *Plane {
	if o.Clock == nil {
		o.Clock = realClock{}
	}
	if o.Now == nil {
		o.Now = o.Clock.Now
	}
	if o.Ubus == nil {
		o.Ubus = ubus.New()
	}
	switch o.Access {
	case AccessRead, AccessWrite:
	default:
		o.Access = AccessNone
	}
	p := &Plane{
		o:        o,
		files:    uci.Files{Dir: rooted(o.Root, uci.DefaultDir)},
		ubus:     o.Ubus,
		redact:   NewRedactor(o.APIKey),
		poke:     make(chan struct{}, 1),
		clock:    o.Clock,
		genValue: generateValue,
	}
	p.ap.state = StateIdle
	if o.Backend != nil {
		p.backend = o.Backend
	} else {
		p.backend = &lazyBackend{p: p}
	}
	seen := map[string]bool{}
	for _, c := range o.Allowlist {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] || Denied(c) || c == LedgerConfig || !uci.ValidConfigName(c) {
			continue
		}
		seen[c] = true
		p.allowed = append(p.allowed, c)
	}
	sort.Strings(p.allowed)
	p.w.init()
	return p
}

func rooted(root, p string) string {
	if root == "" || root == "/" {
		return p
	}
	return filepath.Join(root, p)
}

// Access is the effective access: the configured one, capped at what this
// build implements.
func (p *Plane) Access() string {
	if p.o.Access == AccessWrite && SupportedAccess != AccessWrite {
		return AccessRead
	}
	return p.o.Access
}

// ConfiguredAccess is config_access as configured.
func (p *Plane) ConfiguredAccess() string { return p.o.Access }

// Allowed is the effective allowlist, sorted: managed_config after the
// denylist, plus the configs of installed sibling packages (siblings.go,
// README 7.7) unless the owner opted out.
func (p *Plane) Allowed() []string { return p.effectiveAllowlist() }

// Readable are the configs reads and change detection cover: the allowlist
// and the ledger; none without read access.
func (p *Plane) Readable() []string {
	if p.Access() == AccessNone {
		return nil
	}
	return append(p.Allowed(), LedgerConfig)
}

func (p *Plane) readable(name string) bool {
	for _, c := range p.Readable() {
		if c == name {
			return true
		}
	}
	return false
}

// Errors of the plane's RPC methods (plan 1 section 4: -32000 with
// data.error).
var (
	ErrNotManaged       = errors.New("not_managed")
	ErrConfigNotAllowed = errors.New("config_not_allowed")
	ErrInsecure         = errors.New("insecure_transport")
	ErrTooLarge         = errors.New("read_too_large")
)

// AccessError is a refusal by access level.
type AccessError struct {
	Code    error
	Message string
	Configs []string
}

func (e *AccessError) Error() string { return e.Message }

// Unwrap returns the code.
func (e *AccessError) Unwrap() error { return e.Code }

// RequireAccess is the shared guard for anything that needs a level of
// access (plan 1 section 7: live operations of later features call it too).
// write over an unverified transport needs config_allow_insecure and a
// signed request: callers that unwrap signed params use RequireWrite.
func (p *Plane) RequireAccess(level string) error {
	have := p.Access()
	switch level {
	case AccessRead:
		if have == AccessNone {
			return &AccessError{Code: ErrNotManaged, Message: "the router does not allow config access (config_access 'none' in /etc/config/perch-collector)"}
		}
		return nil
	case AccessWrite:
		if p.o.Access != AccessWrite {
			return &AccessError{Code: ErrNotManaged, Message: fmt.Sprintf("the router allows %s access only (config_access)", have)}
		}
		return p.writeGate(false)
	}
	return fmt.Errorf("gwconfig: unknown access level %q", level)
}

// Hashes returns the file hash of every readable config that exists.
func (p *Plane) Hashes() map[string]string {
	out := map[string]string{}
	for _, c := range p.Readable() {
		if h, err := p.files.Hash(c); err == nil {
			out[c] = h
		}
	}
	return out
}

// RequireWrite is RequireAccess(write) for a request whose params may be
// signed: signed tells whether they were (Plane.Unwrap).
func (p *Plane) RequireWrite(signed bool) error { return p.writeGate(signed) }

// ApplyState is the hello's apply block: idle, applying, pending_confirm
// (with the deadline) or rolling_back.
type ApplyState struct {
	State     string `json:"state"`
	ApplyID   string `json:"applyId,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Deadline  string `json:"deadline,omitempty"`
	Protected bool   `json:"protected,omitempty"`
	// Checks: the pending apply's checks (gateway-sync protocol 1.5).
	Checks *ChecksView `json:"checks,omitempty"`
}

// Hello is the gatewayConfig block of collector.hello (plan 1 section 4).
type Hello struct {
	Protocol int    `json:"protocol"`
	Access   string `json:"access"`
	// AccessConfigured is config_access when it differs from Access (write
	// configured, read effective).
	AccessConfigured string            `json:"accessConfigured,omitempty"`
	TransportOK      bool              `json:"transportOk"`
	Hashes           map[string]string `json:"hashes,omitempty"`
	Apply            ApplyState        `json:"apply"`
	// Results are apply outcomes not acknowledged yet (gateway.config.ack).
	Results []Result `json:"results"`
	// Signing says how this session's writes are signed (write access only).
	Signing *Signing `json:"signing,omitempty"`
	// Management is the path to the controller (README 3.8), read now.
	Management *ManagementPath `json:"management,omitempty"`
}

// Hello builds the hello block and makes its hashes the baseline change
// notifications are judged against: the controller compares a new
// session's hello with what it last saw, and every later change is
// notified. challenge is the session's signing challenge.
func (p *Plane) Hello(ctx context.Context, challenge string) *Hello {
	h := &Hello{
		Protocol:    Protocol,
		Access:      p.Access(),
		TransportOK: p.o.TransportOK,
		Apply:       p.ApplyState(),
		Results:     p.Results(),
	}
	if p.o.Access == AccessWrite {
		h.Signing = p.SigningFor(challenge)
		h.Management = p.ManagementPath(ctx)
	}
	if h.Access != p.o.Access {
		h.AccessConfigured = p.o.Access
	}
	if h.Access != AccessNone {
		h.Hashes = p.Hashes()
		p.mu.Lock()
		p.w.rebase(h.Hashes)
		p.mu.Unlock()
	}
	return h
}

// ctxTimeout bounds one ubus call made for the plane.
const ctxTimeout = 5 * time.Second

func (p *Plane) callCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, ctxTimeout)
}

// packageDB is the package database under the plane's root.
func (p *Plane) packageDB() pkgdb.DB { return pkgdb.DB{Root: p.o.Root} }
