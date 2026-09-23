package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/capthndsme/perch-agentkit/rpc"
)

// Settings are the controller's portal tunables the router enforces
// (system_settings key portal, docs/gateway/portal.md §8).
type Settings struct {
	EnforceIntervalSeconds          int   `json:"enforceIntervalSeconds"`
	UsageIntervalSeconds            int   `json:"usageIntervalSeconds"`
	GuestFailuresPerDevicePerMinute int   `json:"guestFailuresPerDevicePerMinute"`
	GuestFailuresPerDevicePerHour   int   `json:"guestFailuresPerDevicePerHour"`
	GuestFailuresPerPortalPerMinute int   `json:"guestFailuresPerPortalPerMinute"`
	PreauthDNSPerDevicePerMinute    int   `json:"preauthDnsPerDevicePerMinute"`
	OfflineRedemption               *bool `json:"offlineRedemption"`
	// RelayRequestsPerClientPerMinute bounds the router-side relay per
	// client address (decision 22); 0 = 60.
	RelayRequestsPerClientPerMinute int `json:"relayRequestsPerClientPerMinute"`
}

// normalized clamps every setting like the controller's settings service.
func (s Settings) normalized() Settings {
	def := func(v, d, lo, hi int) int {
		if v == 0 {
			return d
		}
		return clampInt(v, lo, hi)
	}
	s.EnforceIntervalSeconds = def(s.EnforceIntervalSeconds, 5, 2, 60)
	s.UsageIntervalSeconds = def(s.UsageIntervalSeconds, 30, 10, 300)
	s.GuestFailuresPerDevicePerMinute = def(s.GuestFailuresPerDevicePerMinute, 5, 1, 60)
	s.GuestFailuresPerDevicePerHour = def(s.GuestFailuresPerDevicePerHour, 20, 1, 600)
	s.GuestFailuresPerPortalPerMinute = def(s.GuestFailuresPerPortalPerMinute, 60, 10, 600)
	s.PreauthDNSPerDevicePerMinute = def(s.PreauthDNSPerDevicePerMinute, 120, 10, 6000)
	s.RelayRequestsPerClientPerMinute = def(s.RelayRequestsPerClientPerMinute, 60, 1, 6000)
	if s.OfflineRedemption == nil {
		t := true
		s.OfflineRedemption = &t
	}
	return s
}

// Methods are a portal's sign-in methods.
type Methods struct {
	Voucher  bool `json:"voucher"`
	Password bool `json:"password"`
	// Payment: checkout at a coin terminal (Paid Hotspot, §14).
	Payment bool `json:"payment"`
	// ClickThrough: accept the terms for a free, limited grant (decision 32).
	ClickThrough bool `json:"clickThrough"`
}

// PortalConfig is one portal of portal.configure.
type PortalConfig struct {
	PortalID int64  `json:"portalId"`
	Name     string `json:"name"`
	// Network is the UCI network the portal sits on; Device overrides the
	// device netifd reports for it.
	Network        string   `json:"network"`
	Device         string   `json:"device,omitempty"`
	Enabled        bool     `json:"enabled"`
	Methods        Methods  `json:"methods"`
	TemplateSHA256 string   `json:"templateSha256"`
	CSPConnectSrc  []string `json:"cspConnectSrc"`
	PrivacyNotice  string   `json:"privacyNotice"`
	GatewayName    string   `json:"gatewayName"`
	// WalledGarden: host names (dnsmasq nftset) and IP addresses / CIDRs.
	WalledGarden []string `json:"walledGarden"`
	// IPBinding: forward IPv4 only for the MAC with its learned address.
	IPBinding bool `json:"ipBinding,omitempty"`
	// Relay serves /portal/v1/authorizations for integrations (decision 22).
	Relay bool `json:"relay,omitempty"`
	// Payment is the checkout method's terminals and price tables (present
	// when Methods.Payment); ClickThrough the click-through limits.
	Payment      *PaymentConfig      `json:"payment,omitempty"`
	ClickThrough *ClickThroughConfig `json:"clickThrough,omitempty"`
	// Bypass are MACs that pass the portal without a grant: members of
	// the gateway's device groups with a portal bypass. Authorised like a
	// grant's device, never counted against anything, never ended.
	Bypass []string `json:"bypass,omitempty"`
}

// StorageOverride are the gateway's storage settings (decision 18).
type StorageOverride struct {
	Path                 string `json:"path,omitempty"`
	FlushIntervalSeconds int    `json:"flushIntervalSeconds,omitempty"`
	ExpectMount          string `json:"expectMount,omitempty"`
}

// ConfigureKeys hands the router its gatewayKey (when its epoch differs).
type ConfigureKeys struct {
	Epoch      int64  `json:"epoch"`
	GatewayKey string `json:"gatewayKey"`
}

// Config is portal.configure's params: the complete desired portal set of
// this gateway. A portal not listed is removed.
type Config struct {
	Revision  int64            `json:"revision"`
	GatewayID int64            `json:"gatewayId"`
	Keys      *ConfigureKeys   `json:"keys,omitempty"`
	Settings  Settings         `json:"settings"`
	Storage   *StorageOverride `json:"storage,omitempty"`
	Portals   []PortalConfig   `json:"portals"`
}

// PortalStatus is one portal's state in the configure result.
type PortalStatus struct {
	PortalID int64    `json:"portalId"`
	Device   string   `json:"device"`
	State    string   `json:"state"` // active | disabled | waiting_device | error
	Listen   string   `json:"listen,omitempty"`
	Counting bool     `json:"counting"`
	Issues   []string `json:"issues"`
}

// Enforcement is what the router can do.
type Enforcement struct {
	Nft bool `json:"nft"`
	// Egress: the flowtable fast path's download is counted (netdev
	// egress hook, kernel 5.16+). Without it only flow offloading's
	// download goes uncounted.
	Egress bool `json:"egress"`
	// Ingress: the fast path's upload is counted before the flowtable
	// (inet ingress hook, kernel 5.10+).
	Ingress bool `json:"ingress"`
	// Fw4Include: ok | missing (fw4 did not pick up the drop-in) | none (no fw4).
	Fw4Include string `json:"fw4Include"`
	// Nftset: dnsmasq fills the walled garden by name; without it the
	// collector resolves the names itself every few minutes.
	Nftset    bool `json:"nftset"`
	Conntrack bool `json:"conntrack"`
	// Quota: data quotas are cut by the kernel (named nft quotas and
	// object maps); without it the tick alone enforces them.
	Quota bool `json:"quota"`
}

// ConfigureResult is portal.configure's result.
type ConfigureResult struct {
	Revision         int64          `json:"revision"`
	KeyEpoch         *int64         `json:"keyEpoch"`
	MissingTemplates []string       `json:"missingTemplates"`
	Portals          []PortalStatus `json:"portals"`
	Enforcement      Enforcement    `json:"enforcement"`
	Storage          StorageInfo    `json:"storage"`
	Issues           []string       `json:"issues"`
}

// Hello is the hello's `portal` object (capability details).
type Hello struct {
	Version        int         `json:"version"`
	KeyEpoch       *int64      `json:"keyEpoch"`
	ConfigRevision *int64      `json:"configRevision"`
	Enforcement    Enforcement `json:"enforcement"`
	Storage        StorageInfo `json:"storage"`
	Port           int         `json:"port"`
	MaxPortals     int         `json:"maxPortals"`
	// Hotspot: 1 = checkouts, coin terminals and click-through (§14).
	Hotspot int `json:"hotspot"`
}

// MaxPortals bounds the portals of one gateway.
const MaxPortals = 16

// Options configure an Engine.
type Options struct {
	System  System
	Store   *Store
	Storage StorageInfo
	// StorageConfig is the operator's UCI setting (the base a configure
	// override is resolved against).
	StorageConfig StorageConfig
	Port          int
	Log           *slog.Logger
	Clock         *Clock
	// Leases names a MAC from the DHCP leases (nil = no names).
	Leases func(mac string) string
}

// portalRuntime is a configured portal as it runs.
type portalRuntime struct {
	cfg      PortalConfig
	device   string
	counting bool
	addrs    []netip.Prefix
	csp      []string
	issues   []string
	state    string
	names    []string // walled garden host names
	nets4    []string
	nets6    []string
	dhcpv6   bool
}

// Agent is the controller session, while there is one.
type Agent interface {
	Call(ctx context.Context, method string, params, result any) error
	Notify(method string, params any) error
}

// Engine is the router side of the portal.
type Engine struct {
	mu    sync.Mutex
	sys   System
	store *Store
	log   *slog.Logger
	clock *Clock
	port  int

	storageCfg StorageConfig
	storage    StorageInfo

	cfg      *Config
	keys     *Keys
	settings Settings
	portals  map[int64]*portalRuntime

	grants            map[int64]*Grant
	nextLID           int64
	groups            map[string]*Group
	vouchers          map[int64]*Voucher
	voucherByVerifier map[string]int64
	// voucherSeries is the serverNow of the offline list part 1 last
	// replaced the held list with; its later parts carry the same.
	voucherSeries   int64
	events          []Event
	lastSeq         int64
	ended           []endedUsage
	nonces          []string
	newestServerNow int64

	// applied is what the kernel holds per portal (after the last
	// successful apply); the tick compares the live sets with it.
	applied     map[int64]map[string]bool
	structural  bool // a full re-render is due
	enf         Enforcement
	dnsmasqConf string

	externals map[string]*External // portal|mac → still present

	// The kernel's data cut (quota.go): group key → quota object, portal →
	// MAC → object name, the generation counter, and groups whose object is
	// re-seeded with the next apply.
	kq       map[string]*kernelQuota
	kqMap    map[int64]map[string]string
	kqGen    int64
	kqReseed map[string]bool
	// kqAddr: portal → address → object name (the download direction's
	// maps, kept like kqMap).
	kqAddr map[int64]map[string]string

	// Download by address (tick.go): each address's last counter value
	// (portal|address → bytes, persisted with the counters) and who used
	// each address last (portal → address → MAC, from the last read).
	addrCtr   map[string]int64
	addrOwner map[int64]map[string]string

	agentMu sync.Mutex
	agent   Agent

	// listener opens and closes the guest pages' listeners (FAS.Sync).
	listener func([]netip.Addr)

	lastTick     time.Time
	lastSessions time.Time
	lastResolve  time.Time
	tickNow      func() time.Time

	// failure limiters (guest pages).
	leases func(mac string) string

	failMin, failHour, failPortal *Window
	relayLimit, relayPortal       *Window

	hotspotState
}

// Maximum journal length (docs: ring of 1000).
const journalMax = 1000

// nonceMemory is how many envelope nonces are remembered.
const nonceMemory = 256

// freshness is how much older than the newest accepted envelope one may be.
const freshness = 10 * 60 * 1000

// New builds an engine and loads its state from the store.
func New(o Options) (*Engine, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Port == 0 {
		o.Port = 2080
	}
	e := &Engine{
		sys: o.System, store: o.Store, log: o.Log, port: o.Port,
		storageCfg: o.StorageConfig, storage: o.Storage,
		portals: map[int64]*portalRuntime{}, grants: map[int64]*Grant{}, groups: map[string]*Group{},
		vouchers: map[int64]*Voucher{}, voucherByVerifier: map[string]int64{},
		applied: map[int64]map[string]bool{}, externals: map[string]*External{},
		kq: map[string]*kernelQuota{}, kqMap: map[int64]map[string]string{}, kqAddr: map[int64]map[string]string{},
		addrCtr: map[string]int64{}, addrOwner: map[int64]map[string]string{},
		tickNow: time.Now, leases: o.Leases,
		failMin: NewWindow(5, time.Minute), failHour: NewWindow(20, time.Hour), failPortal: NewWindow(60, time.Minute),
		relayLimit: NewWindow(60, time.Minute), relayPortal: NewWindow(600, time.Minute),
		hotspotState: newHotspotState(),
	}
	if err := e.loadState(); err != nil {
		return nil, fmt.Errorf("portal state: %w", err)
	}
	e.clock = o.Clock
	if e.clock == nil {
		var saved, skew int64
		fmt.Sscan(o.Store.Meta("savedAt"), &saved)
		fmt.Sscan(o.Store.Meta("clockSkew"), &skew)
		e.clock = NewClock(saved, skew)
	}
	e.settings = Settings{}.normalized()
	if e.cfg != nil {
		e.settings = e.cfg.Settings.normalized()
	}
	e.applyLimiterSettings()
	return e, nil
}

func (e *Engine) applyLimiterSettings() {
	e.failMin.SetLimit(e.settings.GuestFailuresPerDevicePerMinute)
	e.failHour.SetLimit(e.settings.GuestFailuresPerDevicePerHour)
	e.failPortal.SetLimit(e.settings.GuestFailuresPerPortalPerMinute)
	e.relayLimit.SetLimit(e.settings.RelayRequestsPerClientPerMinute)
	e.relayPortal.SetLimit(e.settings.RelayRequestsPerClientPerMinute * 10)
}

// Probe finds out what the router can do (once, at start).
func (e *Engine) Probe(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enf.Nft = e.sys.Apply("table inet perch_portal_probe\ndelete table inet perch_portal_probe\n") == nil
	e.enf.Egress = e.enf.Nft && ProbeEgress(e.sys, "lo")
	e.enf.Ingress = e.enf.Nft && ProbeIngress(e.sys, "lo")
	e.enf.Quota = e.enf.Nft && ProbeQuota(e.sys)
	if out, err := e.sys.Command(ctx, "dnsmasq", "--version"); err == nil {
		e.enf.Nftset = DnsmasqHasNftset(string(out))
	}
	e.enf.Fw4Include = "none"
	if _, err := e.sys.ListJSON("table", "inet", "fw4"); err == nil {
		e.enf.Fw4Include = "pending"
	}
	_, err := e.sys.FlushConntrack(nil)
	// An empty list is refused by validation, which proves the flusher
	// exists; "unavailable" means it does not.
	e.enf.Conntrack = err == nil || !strings.Contains(err.Error(), "unavailable")
}

// Hello is the capability details for collector.hello.
func (e *Engine) Hello() Hello {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := Hello{Version: 1, Enforcement: e.enf, Storage: e.storage, Port: e.port, MaxPortals: MaxPortals, Hotspot: 1}
	if e.keys != nil {
		v := e.keys.Epoch
		h.KeyEpoch = &v
	}
	if e.cfg != nil {
		v := e.cfg.Revision
		h.ConfigRevision = &v
	}
	return h
}

// SetAgent sets (or clears, nil) the controller session.
func (e *Engine) SetAgent(a Agent) {
	e.agentMu.Lock()
	e.agent = a
	e.agentMu.Unlock()
}

// SetListener sets the function that makes the guest pages listen on the
// enforcing portals' router addresses (FAS.Sync); it is called at once and
// whenever the portals or their addresses may have changed (configure,
// start, every tick).
func (e *Engine) SetListener(f func([]netip.Addr)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listener = f
	e.syncListenLocked()
}

// ListenAddrs are the addresses the guest pages listen on: the router's
// addresses on each enforcing portal's device (IPv6 link-local left out:
// the port-80 redirect never lands on one). None without a portal.
func (e *Engine) ListenAddrs() []netip.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.listenAddrsLocked()
}

func (e *Engine) listenAddrsLocked() []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, p := range e.enforcing() {
		for _, pfx := range p.addrs {
			a := pfx.Addr().Unmap()
			if a.IsLinkLocalUnicast() || a.IsUnspecified() || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func (e *Engine) syncListenLocked() {
	if e.listener != nil {
		e.listener(e.listenAddrsLocked())
	}
}

func (e *Engine) currentAgent() Agent {
	e.agentMu.Lock()
	defer e.agentMu.Unlock()
	return e.agent
}

// Start re-applies the persisted portals at once (no DHCP, no controller
// needed) and returns; Run keeps the tick going.
func (e *Engine) Start(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resolvePortalsLocked(ctx)
	e.syncSystemLocked(ctx)
	e.structural = true
	e.applyStructuralLocked()
	e.syncListenLocked()
	n := 0
	for _, g := range e.grants {
		if g.Live() {
			n++
		}
	}
	if len(e.portals) > 0 {
		e.log.Info(fmt.Sprintf("portal: %d portals, %d grants re-applied", len(e.portals), n))
	}
}

// Run runs the enforcement tick and the snapshots until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	for {
		e.mu.Lock()
		every := e.nextTickLocked()
		e.mu.Unlock()
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			e.Shutdown()
			return
		case <-t.C:
		}
		e.Tick(ctx)
	}
}

// Shutdown snapshots the state. The nft tables stay: guests keep their
// access while the collector restarts.
func (e *Engine) Shutdown() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.saveClockLocked()
	if err := e.store.Flush(true); err != nil {
		e.log.Warn("portal: final snapshot failed", "err", err)
	}
}

func (e *Engine) saveClockLocked() {
	_, _ = e.store.db.Exec(`INSERT OR REPLACE INTO meta (k, v) VALUES ('savedAt', ?), ('clockSkew', ?)`,
		fmt.Sprint(e.clock.Now()), fmt.Sprint(e.clock.Skew()))
}

// snapshotIfDue writes a snapshot when one is due.
func (e *Engine) snapshotIfDue() {
	flush := time.Duration(e.storage.FlushSeconds) * time.Second
	if !e.store.Due(time.Now(), flush) {
		return
	}
	e.saveClockLocked()
	if err := e.store.Flush(false); err != nil {
		e.log.Warn("portal: snapshot failed", "path", e.store.Path(), "err", err)
	}
}

// ---------------------------------------------------------------------------
// portal.configure
// ---------------------------------------------------------------------------

// errRPC builds a JSON-RPC error with data.error.
func errRPC(code int, errCode, format string, args ...any) error {
	e := rpc.Errorf(code, format, args...)
	e.Data = map[string]any{"error": errCode}
	return e
}

const (
	codeInvalidParams = -32602
	codeFailed        = -32000
)

// Configure applies portal.configure.
func (e *Engine) Configure(ctx context.Context, c Config) (ConfigureResult, error) {
	if c.GatewayID < 1 {
		return ConfigureResult{}, errRPC(codeInvalidParams, "invalid_params", "gatewayId is required")
	}
	if len(c.Portals) > MaxPortals {
		return ConfigureResult{}, errRPC(codeInvalidParams, "too_many_portals", "at most %d portals", MaxPortals)
	}
	seen := map[int64]bool{}
	for _, p := range c.Portals {
		if p.PortalID < 1 || seen[p.PortalID] {
			return ConfigureResult{}, errRPC(codeInvalidParams, "invalid_params", "portal ids must be positive and unique")
		}
		seen[p.PortalID] = true
		if p.Network == "" && p.Device == "" {
			return ConfigureResult{}, errRPC(codeInvalidParams, "invalid_params", "portal %d needs a network or a device", p.PortalID)
		}
		if (p.Network != "" && !ValidIfname(p.Network)) || (p.Device != "" && !ValidIfname(p.Device)) {
			return ConfigureResult{}, errRPC(codeInvalidParams, "invalid_params", "portal %d: bad network or device name", p.PortalID)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var issues []string
	if c.Keys != nil {
		raw, err := DecodeGatewayKey(c.Keys.GatewayKey)
		if err != nil {
			return ConfigureResult{}, errRPC(codeInvalidParams, "invalid_key", "%v", err)
		}
		keys, err := KeysFrom(raw, c.GatewayID, c.Keys.Epoch)
		if err != nil {
			return ConfigureResult{}, errRPC(codeInvalidParams, "invalid_key", "%v", err)
		}
		if e.keys == nil || e.keys.Epoch != keys.Epoch || e.keys.GatewayID != keys.GatewayID || string(e.keys.GatewayKey) != string(keys.GatewayKey) {
			e.keys = keys
			e.saveMetaJSON("keys", storedKeys{GatewayID: keys.GatewayID, Epoch: keys.Epoch, GatewayKey: c.Keys.GatewayKey})
			// Nonces were checked under the old key.
			e.nonces = nil
			_ = e.store.Exec(ClassGrant, `DELETE FROM nonces`)
			e.log.Info("portal: gateway key updated", "epoch", keys.Epoch)
		}
	} else if e.keys != nil && e.keys.GatewayID != c.GatewayID {
		issues = append(issues, "the held key belongs to another gateway id; send keys")
	}
	stored := c
	stored.Keys = nil
	e.cfg = &stored
	e.saveMetaJSON("config", stored)
	e.settings = c.Settings.normalized()
	e.applyLimiterSettings()
	if !*e.settings.OfflineRedemption {
		e.dropVouchersLocked()
	}
	if c.Storage != nil {
		e.moveStorageLocked(*c.Storage)
	}
	e.resolvePortalsLocked(ctx)
	e.syncSystemLocked(ctx)
	e.structural = true
	if err := e.applyStructuralLocked(); err != nil {
		issues = append(issues, err.Error())
	}
	e.hotspotConfiguredLocked()
	// A new walled garden is resolved on the next tick (without nftset).
	e.lastResolve = time.Time{}
	e.syncListenLocked()
	return e.configureResultLocked(issues), nil
}

func (e *Engine) configureResultLocked(issues []string) ConfigureResult {
	res := ConfigureResult{Enforcement: e.enf, Storage: e.storage, Issues: issues, MissingTemplates: []string{}}
	if res.Issues == nil {
		res.Issues = []string{}
	}
	if e.cfg != nil {
		res.Revision = e.cfg.Revision
	}
	if e.keys != nil {
		v := e.keys.Epoch
		res.KeyEpoch = &v
	}
	ids := e.portalIDs()
	missing := map[string]bool{}
	for _, id := range ids {
		p := e.portals[id]
		st := PortalStatus{PortalID: id, Device: p.device, State: p.state, Counting: p.counting, Issues: p.issues}
		if st.Issues == nil {
			st.Issues = []string{}
		}
		if p.state == "active" {
			for _, a := range p.addrs {
				if a.Addr().Is4() {
					st.Listen = fmt.Sprintf("%s:%d", a.Addr(), e.port)
					break
				}
			}
		}
		sha := strings.ToLower(p.cfg.TemplateSHA256)
		if sha != "" && sha != EmptySetSHA256 && !e.hasTemplate(sha) {
			missing[sha] = true
		}
		res.Portals = append(res.Portals, st)
	}
	for sha := range missing {
		res.MissingTemplates = append(res.MissingTemplates, sha)
	}
	sort.Strings(res.MissingTemplates)
	if res.Portals == nil {
		res.Portals = []PortalStatus{}
	}
	return res
}

func (e *Engine) portalIDs() []int64 {
	ids := make([]int64, 0, len(e.portals))
	for id := range e.portals {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	return ids
}

func (e *Engine) moveStorageLocked(o StorageOverride) {
	cfg := e.storageCfg
	if o.Path != "" {
		cfg.Path = o.Path
	}
	if o.FlushIntervalSeconds > 0 {
		cfg.FlushSeconds = o.FlushIntervalSeconds
	}
	if o.ExpectMount != "" {
		cfg.ExpectMount = o.ExpectMount
	}
	info := ResolveStorage(cfg, ReadMounts(), PathExists, e.settings.EnforceIntervalSeconds)
	if info.Path != e.storage.Path {
		e.log.Info("portal: state moves", "from", e.storage.Path, "to", info.Path)
		e.store.SetPath(info.Path)
	}
	if info.Warning != "" && info.Warning != e.storage.Warning {
		e.log.Warn("portal: " + info.Warning)
	}
	e.storage = info
}

// resolvePortalsLocked turns the configured portals into running ones:
// device, addresses, walled garden. Portals that are gone lose their
// grants' enforcement (their grants stay held; the controller's full set
// decides about them).
func (e *Engine) resolvePortalsLocked(ctx context.Context) {
	next := map[int64]*portalRuntime{}
	if e.cfg == nil {
		e.portals = next
		return
	}
	for _, pc := range e.cfg.Portals {
		p := &portalRuntime{cfg: pc, state: "active"}
		if !pc.Enabled {
			p.state = "disabled"
			next[pc.PortalID] = p
			continue
		}
		dev := pc.Device
		if dev == "" {
			d, err := ResolveNetworkDevice(ctx, e.sys, pc.Network)
			if err != nil {
				p.state = "waiting_device"
				p.issues = append(p.issues, fmt.Sprintf("network %s: %v", pc.Network, err))
			}
			dev = d
		}
		if dev != "" && !ValidIfname(dev) {
			p.state = "error"
			p.issues = append(p.issues, fmt.Sprintf("device name %q is not usable", dev))
			dev = ""
		}
		p.device = dev
		if dev != "" {
			addrs, ok := e.sys.DeviceAddrs(dev)
			p.addrs = addrs
			p.counting = ok && e.enf.Nft
			if !ok {
				p.issues = append(p.issues, fmt.Sprintf("device %s does not exist yet", dev))
				if p.state == "active" {
					p.state = "waiting_device"
				}
			}
			if e.enf.Nft && !e.enf.Egress {
				p.issues = append(p.issues, "the kernel has no netdev egress hook (5.16+): downloads that flow offloading moves past the firewall are not counted")
			}
			if e.enf.Nft && !e.enf.Quota {
				p.issues = append(p.issues, "the kernel has no nft quota objects (nft_quota, nft_objref): data quotas are enforced by the tick only and may overshoot by one tick")
			}
		}
		if !e.enf.Nft {
			p.state = "error"
			p.issues = append(p.issues, "nftables (nft) is not available")
		}
		ok, dropped := CleanCSPSources(pc.CSPConnectSrc)
		p.csp = ok
		for _, d := range dropped {
			p.issues = append(p.issues, fmt.Sprintf("cspConnectSrc %q ignored: not an origin", d))
		}
		for _, w := range pc.WalledGarden {
			w = strings.TrimSpace(strings.ToLower(w))
			if w == "" {
				continue
			}
			if pfx, err := netip.ParsePrefix(w); err == nil {
				if pfx.Addr().Is4() {
					p.nets4 = append(p.nets4, pfx.Masked().String())
				} else {
					p.nets6 = append(p.nets6, pfx.Masked().String())
				}
				continue
			}
			if a, err := netip.ParseAddr(w); err == nil {
				if a.Is4() {
					p.nets4 = append(p.nets4, a.String())
				} else {
					p.nets6 = append(p.nets6, a.String())
				}
				continue
			}
			if validHostname(w) {
				p.names = append(p.names, strings.TrimSuffix(w, "."))
				continue
			}
			p.issues = append(p.issues, fmt.Sprintf("walled garden entry %q ignored", w))
		}
		if pc.Network != "" {
			if out, err := e.sys.Command(ctx, "uci", "-q", "get", "dhcp."+pc.Network+".dhcpv6"); err == nil {
				v := strings.TrimSpace(string(out))
				p.dhcpv6 = v == "server" || v == "relay" || v == "hybrid"
			}
		}
		next[pc.PortalID] = p
	}
	e.portals = next
}

func validHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// enforcing are the portals whose rules are rendered (enabled with a device).
func (e *Engine) enforcing() []*portalRuntime {
	var out []*portalRuntime
	for _, id := range e.portalIDs() {
		p := e.portals[id]
		if p.cfg.Enabled && p.device != "" && e.enf.Nft && p.state != "error" {
			out = append(out, p)
		}
	}
	return out
}

// desiredAuth is the MAC set of one portal: its live grants' MACs.
func (e *Engine) desiredAuth(portalID int64) map[string]bool {
	out := map[string]bool{}
	for _, g := range e.grants {
		if g.PortalID == portalID && g.Live() {
			out[g.MAC] = true
		}
	}
	for mac := range e.bypassOf(portalID) {
		out[mac] = true
	}
	return out
}

// bypassOf is a portal's bypass MACs (normalised).
func (e *Engine) bypassOf(portalID int64) map[string]bool {
	out := map[string]bool{}
	if p := e.portals[portalID]; p != nil {
		for _, raw := range p.cfg.Bypass {
			if mac := NormalizeMAC(raw); mac != "" {
				out[mac] = true
			}
		}
	}
	return out
}

// syncSystemLocked writes the fw4 drop-in and the dnsmasq nftset file for
// the current portals, reloading fw4 / restarting dnsmasq only on change.
func (e *Engine) syncSystemLocked(ctx context.Context) {
	var devices []string
	names := map[int64][]string{}
	dhcpv6 := false
	for _, p := range e.enforcing() {
		devices = append(devices, p.device)
		if len(p.names) > 0 {
			names[p.cfg.PortalID] = p.names
		}
		dhcpv6 = dhcpv6 || p.dhcpv6
	}
	if e.enf.Fw4Include != "none" {
		inc := RenderFw4Include(devices, []int{e.port}, dhcpv6)
		var changed bool
		var err error
		if inc == "" {
			changed, err = e.sys.RemoveFile(Fw4IncludePath)
		} else {
			changed, err = e.sys.WriteFile(Fw4IncludePath, []byte(inc), 0o644)
		}
		if err != nil {
			e.log.Warn("portal: fw4 drop-in", "err", err)
		}
		if changed {
			if _, err := e.sys.Command(ctx, "fw4", "-q", "reload"); err != nil {
				e.log.Warn("portal: fw4 reload", "err", err)
			}
		}
		e.checkFw4Locked(len(devices) > 0)
	}
	conf := ""
	if e.enf.Nftset {
		conf = RenderDnsmasqNftset(names)
	}
	if conf != e.dnsmasqConf || conf == "" {
		restart := false
		for _, dir := range DnsmasqConfDirs() {
			path := dir + "/" + DnsmasqConfName
			var changed bool
			var err error
			if conf == "" {
				changed, err = e.sys.RemoveFile(path)
			} else {
				changed, err = e.sys.WriteFile(path, []byte(conf), 0o644)
			}
			if err != nil {
				e.log.Warn("portal: dnsmasq walled garden", "err", err)
			}
			restart = restart || changed
		}
		if restart {
			if _, err := e.sys.Command(ctx, "/etc/init.d/dnsmasq", "restart"); err != nil {
				e.log.Warn("portal: dnsmasq restart", "err", err)
			}
		}
		e.dnsmasqConf = conf
	}
}

// checkFw4Locked verifies fw4 carries the drop-in (auto_includes may be off).
func (e *Engine) checkFw4Locked(want bool) {
	if !want {
		e.enf.Fw4Include = "ok"
		return
	}
	out, err := e.sys.ListJSON("chain", "inet", "fw4", "input")
	if err != nil {
		e.enf.Fw4Include = "missing"
		return
	}
	if strings.Contains(string(out), "!perch-portal") {
		e.enf.Fw4Include = "ok"
	} else {
		e.enf.Fw4Include = "missing"
	}
}

// countingOf is which counting sets a portal has.
func (e *Engine) countingOf(p *portalRuntime) Counting {
	if p == nil {
		return Counting{}
	}
	return Counting{Acct: p.counting, Fast: p.counting && e.enf.Egress}
}

func (e *Engine) routerAddrs() (v4, v6 []string) {
	for _, a := range e.sys.LocalAddrs() {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else if !a.IsLinkLocalUnicast() {
			v6 = append(v6, a.String())
		}
	}
	return v4, v6
}

// applyStructuralLocked re-renders both tables from the current state.
// Counters are folded into the grants first (a replaced table starts at
// zero), and the walled garden's resolved addresses are carried over.
func (e *Engine) applyStructuralLocked() error {
	if !e.structural {
		return nil
	}
	portals := e.enforcing()
	if len(portals) == 0 {
		if !e.enf.Nft {
			e.structural = false
			return nil
		}
		err := e.sys.Apply(RenderDeleteAll())
		if err != nil {
			return fmt.Errorf("removing the portal tables: %w", err)
		}
		e.applied = map[int64]map[string]bool{}
		e.kq, e.kqMap, e.kqReseed = map[string]*kernelQuota{}, map[int64]map[string]string{}, nil
		e.kqAddr = map[int64]map[string]string{}
		e.resetAddrCountersLocked()
		e.structural = false
		return nil
	}
	now := e.clock.Now()
	// Fold what the old counters hold since the last read (the netdev
	// counting table of an older collector, the first time).
	if c, err := e.readCountersLocked(); err == nil {
		e.foldCountersLocked(c, now, 0)
	} else if isMissing(err) {
		e.foldLegacyCountersLocked(now)
	}
	carried := map[string][]string{}
	if data, err := e.sys.ListJSON("table", "inet", TableInet); err == nil {
		if sets, err := ParseTableJSON(data); err == nil {
			for name, s := range sets {
				if strings.HasSuffix(name, "_wg4") || strings.HasSuffix(name, "_wg6") {
					carried[name] = s.Elements
				}
			}
		}
	}
	v4, v6 := e.routerAddrs()
	spec := RulesetSpec{Local4: v4, Local6: v6, Egress: e.enf.Egress, Ingress: e.enf.Ingress, Quota: e.enf.Quota}
	// The data cut, seeded with what each group has left after the fold.
	var quotaMap, quotaAddr map[int64]map[string]string
	var quotaObjs map[string]*kernelQuota
	if spec.Quota {
		spec.Quotas, quotaMap, quotaAddr, quotaObjs = e.quotaSpecLocked()
	}
	for _, p := range portals {
		id := p.cfg.PortalID
		auth := e.desiredAuth(id)
		ps := PortalSpec{ID: id, Device: p.device, Counting: p.counting, Port: e.port,
			IPBinding: p.cfg.IPBinding, WalledNets4: p.nets4, WalledNets6: p.nets6,
			WG4: carried[setName(id, "wg4")], WG6: carried[setName(id, "wg6")],
			DNSPerMinute: e.settings.PreauthDNSPerDevicePerMinute, DHCPv6: p.dhcpv6}
		for mac := range auth {
			ps.Auth = append(ps.Auth, mac)
		}
		ps.Quota = quotaMap[id]
		ps.QuotaAddrs = quotaAddr[id]
		for _, ip := range sortedKeys(e.addrOwner[id]) {
			if mac := e.addrOwner[id][ip]; auth[mac] {
				ps.Learned = append(ps.Learned, MACIP{MAC: mac, IP: ip})
			}
		}
		if p.cfg.IPBinding {
			for _, g := range e.grants {
				if g.PortalID == id && g.Live() && g.Bound != "" {
					ps.Bind = append(ps.Bind, MACIP{MAC: g.MAC, IP: g.Bound})
				}
			}
		}
		spec.Portals = append(spec.Portals, ps)
	}
	script := RenderInet(spec) + RenderAcct(spec) + RenderFast(spec)
	if err := e.sys.Apply(script); err != nil {
		e.log.Error("portal: applying the nftables ruleset failed", "err", err)
		return fmt.Errorf("applying the portal ruleset: %w", err)
	}
	e.applied = map[int64]map[string]bool{}
	for _, p := range portals {
		e.applied[p.cfg.PortalID] = e.desiredAuth(p.cfg.PortalID)
	}
	e.kq, e.kqMap, e.kqReseed = map[string]*kernelQuota{}, map[int64]map[string]string{}, nil
	e.kqAddr = map[int64]map[string]string{}
	if spec.Quota {
		e.kq, e.kqMap, e.kqAddr = quotaObjs, quotaMap, quotaAddr
	}
	// Fresh tables count from zero.
	for _, g := range e.grants {
		g.CtrUp, g.CtrDown = 0, 0
	}
	e.resetAddrCountersLocked()
	e.structural = false
	return nil
}

// Status is a short state line for logs and tests.
func (e *Engine) Status() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	live := 0
	for _, g := range e.grants {
		if g.Live() {
			live++
		}
	}
	return fmt.Sprintf("portals=%d grants=%d live=%d vouchers=%d lastSeq=%d", len(e.portals), len(e.grants), live, len(e.vouchers), e.lastSeq)
}

// ErrOffline: no controller session.
var ErrOffline = errors.New("controller unreachable")

// marshal is json.Marshal for notifications.
func marshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
