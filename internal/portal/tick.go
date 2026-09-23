package portal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/capthndsme/perch-collector/internal/observe"
)

// The enforcement tick (every enforceIntervalSeconds, default 5):
//
//  1. read the counting table and the authorised sets; a table that is gone
//     (nft flush, reboot, someone deleted it) is re-rendered at once, which
//     is not a deauth;
//  2. a MAC in a set that no Perch grant holds was added outside Perch: it
//     is removed and journaled (external_auth, decision 25); a Perch MAC
//     missing from its set was removed outside Perch: the grant ends
//     (router_deauth), which is respected and never undone;
//  3. counter deltas go to each device's current grant; a group that moved
//     traffic is charged the tick's time once, on its lowest-order grant;
//  4. neighbours: a pending grant whose device shows up becomes active;
//     addresses are learned (conntrack flush, IP binding);
//  5. exhausted groups (time, active time, data) end every device, with a
//     conntrack flush; a data quota the kernel cut (quota.go) counts as
//     used up, and a kernel quota that drifted is re-seeded;
//  6. offline-queued entitlements are promoted while the controller is away;
//  7. portal.sessions every usageIntervalSeconds; snapshots when due.

// readCountersLocked reads the counting table's sets and quota objects
// (one dump).
func (e *Engine) readCountersLocked() (map[string]SetContents, map[string]QuotaUse, error) {
	data, err := e.sys.ListJSON("table", "netdev", TableNetdev)
	if err != nil {
		return nil, nil, err
	}
	sets, err := ParseTableJSON(data)
	if err != nil {
		return nil, nil, err
	}
	quotas, err := ParseQuotasJSON(data)
	if err != nil {
		return nil, nil, err
	}
	return sets, quotas, nil
}

// currentGrants maps portal|mac to the device's current live grant (first
// in consumption order): the one its bytes are counted on.
func (e *Engine) currentGrantsLocked() map[string]*Grant {
	byDev := map[string][]*Grant{}
	for _, g := range e.grants {
		if g.Live() {
			k := devKey(g.PortalID, g.MAC)
			byDev[k] = append(byDev[k], g)
		}
	}
	out := map[string]*Grant{}
	for k, list := range byDev {
		out[k] = e.firstInOrder(list)
	}
	return out
}

func (e *Engine) entitlementOf(g *Grant) Entitlement {
	var l Limits
	if grp := e.groups[g.GroupKey]; grp != nil {
		l = GrantLimits(grp.EffectiveLimits(), g.ExpiresAt)
	}
	return Entitlement{Order: g.Order(), Limits: l, CreatedAt: g.CreatedAt}
}

func (e *Engine) firstInOrder(list []*Grant) *Grant {
	sort.Slice(list, func(a, b int) bool {
		return CompareEntitlements(e.entitlementOf(list[a]), e.entitlementOf(list[b])) < 0
	})
	return list[0]
}

func devKey(portalID int64, mac string) string { return fmt.Sprintf("%d|%s", portalID, mac) }

// foldCountersLocked adds counter deltas to the current grants and returns
// the grants that moved traffic.
func (e *Engine) foldCountersLocked(sets map[string]SetContents, now int64, elapsedMs int64) map[int64]bool {
	moved := map[int64]bool{}
	current := e.currentGrantsLocked()
	for _, g := range current {
		p := e.portals[g.PortalID]
		if p == nil || !p.counting {
			continue
		}
		up, okUp := sets[setName(g.PortalID, "up")].Counters[g.MAC]
		down, okDown := sets[setName(g.PortalID, "down")].Counters[g.MAC]
		var dUp, dDown int64
		if okUp {
			dUp = counterDelta(up.Bytes, g.CtrUp)
			g.CtrUp = up.Bytes
		}
		if okDown {
			dDown = counterDelta(down.Bytes, g.CtrDown)
			g.CtrDown = down.Bytes
		}
		// The device's other live grants share the MAC's counters: keep
		// their baselines in step so none of these bytes is counted twice.
		for _, o := range e.grants {
			if o != g && o.Live() && o.PortalID == g.PortalID && o.MAC == g.MAC {
				o.CtrUp, o.CtrDown = g.CtrUp, g.CtrDown
			}
		}
		if dUp == 0 && dDown == 0 {
			continue
		}
		g.BytesUp += dUp
		g.BytesDown += dDown
		moved[g.LID] = true
		t := now
		g.LastSeenAt = &t
		e.saveGrant(g, ClassCounter)
	}
	return moved
}

// counterDelta: a counter below its baseline was reset (element re-added,
// table re-created after a reboot): all of it is new.
func counterDelta(cur, prev int64) int64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// groupUsageLocked is a group's usage: its base, the router's live grants,
// and ended grants the base does not include yet.
func (e *Engine) groupUsageLocked(key string) Usage {
	grp := e.groups[key]
	var u Usage
	if grp != nil {
		u.TimeUsedSeconds, u.BytesUsed = grp.BaseTimeUsedSeconds, grp.BaseBytesUsed
	}
	for _, g := range e.grants {
		if g.GroupKey == key && g.Live() {
			u.TimeUsedSeconds += g.ActiveSeconds()
			u.BytesUsed += g.BytesUp + g.BytesDown
		}
	}
	for _, x := range e.ended {
		if x.GroupKey == key && (grp == nil || x.Seq > grp.AckedSeq) {
			u.TimeUsedSeconds += x.TimeUsed
			u.BytesUsed += x.Bytes
		}
	}
	return u
}

// Tick runs one enforcement pass.
func (e *Engine) Tick(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	wall := e.tickNow()
	now := e.clock.Now()
	elapsed := int64(0)
	if !e.lastTick.IsZero() {
		elapsed = wall.Sub(e.lastTick).Milliseconds()
		if max := int64(e.settings.EnforceIntervalSeconds) * 3000; elapsed > max {
			elapsed = max // a stalled process is not charged for its stall
		}
	}
	e.lastTick = wall
	ops := &ElementOps{}

	portals := e.enforcing()
	if len(portals) > 0 && e.enf.Nft {
		// Devices come and go (a VLAN brought up late).
		e.refreshDevicesLocked(ctx)
		sets, quotas, cerr := e.readCountersLocked()
		auth, aerr := e.readAuthLocked()
		if isMissing(cerr) || isMissing(aerr) || e.structural {
			if isMissing(cerr) || isMissing(aerr) {
				e.log.Warn("portal: enforcement tables are gone; re-applying")
			}
			e.structural = true
			if err := e.applyStructuralLocked(); err != nil {
				e.log.Error("portal: re-apply failed", "err", err)
			}
		} else if cerr == nil && aerr == nil {
			e.reconcileSetsLocked(auth, now, ops)
			moved := e.foldCountersLocked(sets, now, elapsed)
			e.chargeTimeLocked(moved, elapsed)
			e.checkKernelQuotasLocked(quotas)
		}
	}
	e.observeNeighborsLocked(now, ops)
	e.enforceLimitsLocked(now, ops)
	if e.currentAgent() == nil {
		e.promoteQueuedLocked(now, ops)
	}
	e.applyOpsLocked(ops)
	e.resolveWalledGardenLocked(ctx, wall)
	e.sendSessionsLocked(wall, now)
	e.snapshotIfDue()
}

func isMissing(err error) bool {
	var le *ListError
	return errors.As(err, &le) && le.Missing
}

// readAuthLocked reads each enforcing portal's authorised set.
func (e *Engine) readAuthLocked() (map[int64]map[string]bool, error) {
	data, err := e.sys.ListJSON("table", "inet", TableInet)
	if err != nil {
		return nil, err
	}
	sets, err := ParseTableJSON(data)
	if err != nil {
		return nil, err
	}
	out := map[int64]map[string]bool{}
	for _, p := range e.enforcing() {
		s, ok := sets[setName(p.cfg.PortalID, "auth")]
		if !ok {
			return nil, &ListError{Missing: true, Msg: "auth set missing"}
		}
		m := map[string]bool{}
		for _, v := range s.Elements {
			if mac := NormalizeMAC(v); mac != "" {
				m[mac] = true
			}
		}
		out[p.cfg.PortalID] = m
	}
	return out, nil
}

// reconcileSetsLocked compares the kernel's sets with what Perch applied.
func (e *Engine) reconcileSetsLocked(kernel map[int64]map[string]bool, now int64, ops *ElementOps) {
	present := map[string]bool{}
	for id, macs := range kernel {
		applied := e.applied[id]
		pid := id
		for mac := range macs {
			if applied[mac] {
				continue
			}
			// Added outside Perch: undone within this tick (decision 25).
			key := devKey(id, mac)
			present[key] = true
			if _, seen := e.externals[key]; !seen {
				t := now
				x := &External{PortalID: &pid, MAC: mac, Since: &t}
				if ip := e.neighborIPLocked(id, mac); ip != "" {
					x.IP = &ip
				}
				e.externals[key] = x
				ev := Event{Type: EvExternalAuth, PortalID: &pid, MAC: mac, IP: x.IP}
				e.journalLocked(ev, now)
				e.log.Warn("portal: authorisation made outside Perch undone", "portal", id, "mac", mac)
			}
			p := e.portals[id]
			ops.Deauthorize(id, mac, p != nil && p.counting)
		}
		for mac := range applied {
			if macs[mac] {
				continue
			}
			// Removed outside Perch: a deauth, respected.
			for _, g := range e.sortedGrants() {
				if g.PortalID == id && g.MAC == mac && g.Live() {
					e.log.Info("portal: grant ended by a deauth outside Perch", "portal", id, "mac", mac)
					e.endGrantLocked(g, EndRouterDeauth, now, ops)
				}
			}
		}
		e.applied[id] = e.desiredAuth(id)
	}
	// Externals that are gone no longer count as present.
	for key := range e.externals {
		if !present[key] {
			delete(e.externals, key)
		}
	}
}

// chargeTimeLocked charges each group that moved traffic once, on the
// lowest-order live grant of the group that moved (docs §4.3).
func (e *Engine) chargeTimeLocked(moved map[int64]bool, elapsedMs int64) {
	if elapsedMs <= 0 || len(moved) == 0 {
		return
	}
	byGroup := map[string][]*Grant{}
	for lid := range moved {
		if g := e.grants[lid]; g != nil {
			byGroup[g.GroupKey] = append(byGroup[g.GroupKey], g)
		}
	}
	for _, list := range byGroup {
		sort.Slice(list, func(a, b int) bool { return list[a].Order() < list[b].Order() })
		g := list[0]
		g.ActiveMs += elapsedMs
		e.saveGrant(g, ClassCounter)
	}
}

// refreshDevicesLocked notices devices that appeared or vanished.
func (e *Engine) refreshDevicesLocked(ctx context.Context) {
	changed := false
	for _, p := range e.portals {
		if !p.cfg.Enabled || p.device == "" {
			continue
		}
		addrs, ok := e.sys.DeviceAddrs(p.device)
		if ok != p.counting && e.enf.Nft {
			changed = true
		}
		p.addrs = addrs
	}
	if changed {
		e.resolvePortalsLocked(ctx)
		e.structural = true
	}
}

// neighborIPLocked is a device's IPv4 address on a portal (or any).
func (e *Engine) neighborIPLocked(portalID int64, mac string) string {
	p := e.portals[portalID]
	if p == nil {
		return ""
	}
	list, err := e.sys.Neighbors()
	if err != nil {
		return ""
	}
	best := ""
	for _, n := range list {
		if n.Device == p.device && strings.EqualFold(n.MAC, mac) {
			if a, err := netip.ParseAddr(n.IP); err == nil && a.Is4() {
				return n.IP
			}
			if best == "" {
				best = n.IP
			}
		}
	}
	return best
}

// observeNeighborsLocked: pending grants whose device is on the link
// become active; addresses are learned.
func (e *Engine) observeNeighborsLocked(now int64, ops *ElementOps) {
	var list []observe.Neighbor
	if len(e.grants) > 0 {
		var err error
		if list, err = e.sys.Neighbors(); err != nil {
			list = nil
		}
	}
	type seen struct {
		ips []string
		v4  string
	}
	byDev := map[string]*seen{}
	devPortal := map[string][]int64{}
	for _, p := range e.enforcing() {
		devPortal[p.device] = append(devPortal[p.device], p.cfg.PortalID)
	}
	for _, n := range list {
		for _, pid := range devPortal[n.Device] {
			mac := NormalizeMAC(n.MAC)
			if mac == "" {
				continue
			}
			k := devKey(pid, mac)
			s := byDev[k]
			if s == nil {
				s = &seen{}
				byDev[k] = s
			}
			s.ips = append(s.ips, n.IP)
			if a, err := netip.ParseAddr(n.IP); err == nil && a.Is4() && (s.v4 == "" || n.Reachable) {
				s.v4 = n.IP
			}
		}
	}
	for _, g := range e.sortedGrants() {
		if !g.Live() {
			continue
		}
		s := byDev[devKey(g.PortalID, g.MAC)]
		if s == nil {
			continue
		}
		changed := false
		ips := sortedCopy(append(append([]string(nil), g.IPs...), s.ips...))
		if len(ips) > 8 {
			ips = ips[len(ips)-8:]
		}
		if strings.Join(ips, ",") != strings.Join(g.IPs, ",") {
			g.IPs, changed = ips, true
		}
		if s.v4 != "" && (g.IP == nil || *g.IP != s.v4) {
			v := s.v4
			g.IP, changed = &v, true
		}
		if p := e.portals[g.PortalID]; p != nil && p.cfg.IPBinding && s.v4 != "" && g.Bound != s.v4 {
			if g.Bound != "" {
				ops.Unbind(g.PortalID, g.MAC, g.Bound)
			}
			ops.Bind(g.PortalID, g.MAC, s.v4)
			g.Bound, changed = s.v4, true
		}
		if g.State == StatePending {
			e.activateLocked(g, now)
			changed = true
		}
		if changed {
			e.saveGrant(g, ClassGrant)
		}
	}
	// A pending grant whose device moved traffic is active too.
	for _, g := range e.grants {
		if g.State == StatePending && g.BytesUp+g.BytesDown > 0 {
			e.activateLocked(g, now)
			e.saveGrant(g, ClassGrant)
		}
	}
}

func (e *Engine) activateLocked(g *Grant, now int64) {
	g.State = StateActive
	t := now
	if g.StartedAt == nil {
		g.StartedAt = &t
	}
	g.SessionStartedAt = &t
	g.LastSeenAt = &t
	pid := g.PortalID
	e.startGroupClockLocked(g, now)
	e.journalLocked(Event{Type: EvGrantActive, PortalID: &pid, MAC: g.MAC, GrantID: g.GrantID, LocalRef: g.LocalRef, IP: g.IP}, now)
}

// enforceLimitsLocked ends grants whose group (or own deadline) ran out.
func (e *Engine) enforceLimitsLocked(now int64, ops *ElementOps) {
	for _, g := range e.sortedGrants() {
		if !g.Live() {
			continue
		}
		grp := e.groups[g.GroupKey]
		if grp == nil {
			continue
		}
		usage := e.groupUsageLocked(g.GroupKey)
		reason := Exhaustion(GrantLimits(grp.EffectiveLimits(), g.ExpiresAt), usage, now)
		if reason == "" {
			continue
		}
		e.log.Info("portal: grant ended", "portal", g.PortalID, "mac", g.MAC, "reason", reason,
			"bytesUp", g.BytesUp, "bytesDown", g.BytesDown)
		e.endGrantLocked(g, reason, now, ops)
	}
}

// promoteQueuedLocked: while the controller is away, a device whose current
// entitlement ended starts its next offline-queued one.
func (e *Engine) promoteQueuedLocked(now int64, ops *ElementOps) {
	queued := map[string][]*Grant{}
	live := map[string]bool{}
	for _, g := range e.grants {
		k := devKey(g.PortalID, g.MAC)
		if g.State == StateQueued {
			queued[k] = append(queued[k], g)
		} else if g.Live() {
			live[k] = true
		}
	}
	for k, list := range queued {
		if live[k] {
			continue
		}
		g := e.firstInOrder(list)
		g.State = StatePending
		if v := e.voucherOfLocked(g.GroupKey); v != nil {
			e.startVoucherClockLocked(v, now)
		}
		e.authorizeMACLocked(g.PortalID, g.MAC, ops)
		e.saveGrant(g, ClassGrant)
	}
}

// sendSessionsLocked sends portal.sessions every usageIntervalSeconds
// while any client is authorised.
func (e *Engine) sendSessionsLocked(wall time.Time, now int64) {
	a := e.currentAgent()
	if a == nil || wall.Sub(e.lastSessions) < time.Duration(e.settings.UsageIntervalSeconds)*time.Second {
		return
	}
	p := SessionsParams{CollectedAt: now, Clients: []SessionClient{}, Portals: []PortalCount{}}
	count := map[int64]*PortalCount{}
	for _, id := range e.portalIDs() {
		count[id] = &PortalCount{PortalID: id}
	}
	for _, g := range e.sortedGrants() {
		if !g.Live() {
			continue
		}
		p.Clients = append(p.Clients, SessionClient{GrantUsage: e.usageOfLocked(g), Hostname: g.Hostname, SessionStartedAt: g.SessionStartedAt})
		if c := count[g.PortalID]; c != nil {
			c.Authenticated++
		}
	}
	if len(p.Clients) == 0 {
		return
	}
	if list, err := e.sys.Neighbors(); err == nil {
		seen := map[string]bool{}
		for _, pr := range e.enforcing() {
			auth := e.desiredAuth(pr.cfg.PortalID)
			for _, n := range list {
				mac := NormalizeMAC(n.MAC)
				k := devKey(pr.cfg.PortalID, mac)
				if n.Device == pr.device && mac != "" && !auth[mac] && !seen[k] {
					seen[k] = true
					count[pr.cfg.PortalID].Preauth++
					p.PreauthCount++
				}
			}
		}
	}
	for _, id := range e.portalIDs() {
		p.Portals = append(p.Portals, *count[id])
	}
	e.lastSessions = wall
	go func() { _ = a.Notify("portal.sessions", p) }()
}

// resolveWalledGardenLocked: without dnsmasq nftset the collector resolves
// the walled garden's names itself every five minutes.
func (e *Engine) resolveWalledGardenLocked(ctx context.Context, wall time.Time) {
	if e.enf.Nftset || wall.Sub(e.lastResolve) < 5*time.Minute {
		return
	}
	ops := &ElementOps{}
	names := 0
	for _, p := range e.enforcing() {
		names += len(p.names)
	}
	if names == 0 {
		return
	}
	e.lastResolve = wall
	for _, p := range e.enforcing() {
		for _, name := range p.names {
			addrs, err := e.sys.Resolve(ctx, name)
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ops.WalledAddress(p.cfg.PortalID, a.Unmap())
			}
		}
	}
	if !ops.Empty() {
		if err := e.sys.Apply(ops.Script()); err != nil {
			e.log.Warn("portal: walled garden addresses", "err", err)
		}
	}
}
