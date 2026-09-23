package portal

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Exact data quotas (kernel cut).
//
// The tick counts bytes every enforceIntervalSeconds, so a quota enforced
// by the tick alone overshoots by whatever a device moves in one tick
// (30 MB at 52 Mbit/s and 5 s). The kernel therefore cuts the device off
// itself: every group with a data quota that has a device on a counting
// portal gets one named nft quota object in the counting table,
// `over <bytes the group has left>`, and the portal's MAC → quota map
// points each of the group's devices at it. The rule sits before the
// counters in both directions, so the quota counts exactly what the
// counters count (upload + download, like the group's quota) and a dropped
// packet is not usage.
//
// The tick stays the bookkeeper: it folds the counters, notices a quota the
// kernel reports used up, ends the grants (deauth, conntrack flush,
// grant_ended to the controller), and re-seeds a quota object whose
// remaining bytes drifted from the bookkeeping (the controller moved the
// group's base, another router used some of a shared voucher). A quota
// object's limit cannot change in place, so a re-seed creates the next
// generation (q<group>_<gen>), repoints the MACs and deletes the old one in
// one transaction. Every full re-render (collector start, tables gone)
// seeds the objects with the remaining bytes, so a restart neither loses
// nor forgives any.

// quotaDriftBytes is how far the kernel's remaining bytes may be from the
// bookkeeping's before the object is re-seeded (the counters and the quota
// objects are read in one dump, but not atomically).
const quotaDriftBytes = 256 << 10

// quotaNearFraction: a group this close to its quota (10 %) is checked
// every quotaNearInterval instead of every enforceIntervalSeconds.
const (
	quotaNearFraction = 10
	quotaNearInterval = time.Second
)

// kernelQuota is a quota object the kernel holds for a group.
type kernelQuota struct {
	Name  string
	Bytes int64 // its limit: the group's remaining bytes when created
}

// quotaName is a group's quota object name at a generation: q + the group
// key without its colon (v:17 → qv17_4).
func quotaName(groupKey string, gen int64) string {
	var b strings.Builder
	b.WriteByte('q')
	for _, r := range groupKey {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	fmt.Fprintf(&b, "_%d", gen)
	return b.String()
}

// groupRemainingLocked is what a group with a data quota has left (can be
// negative), and whether it has a quota at all.
func (e *Engine) groupRemainingLocked(key string) (int64, bool) {
	grp := e.groups[key]
	if grp == nil || grp.QuotaBytes == nil {
		return 0, false
	}
	return *grp.QuotaBytes - e.groupUsageLocked(key).BytesUsed, true
}

// quotaTargetsLocked is the kernel cut wanted now: per counting portal the
// MACs whose current grant's group has a data quota, with that group's key.
func (e *Engine) quotaTargetsLocked() map[int64]map[string]string {
	out := map[int64]map[string]string{}
	counting := map[int64]bool{}
	for _, p := range e.enforcing() {
		if p.counting {
			counting[p.cfg.PortalID] = true
			out[p.cfg.PortalID] = map[string]string{}
		}
	}
	for _, g := range e.currentGrantsLocked() {
		if !counting[g.PortalID] {
			continue
		}
		if grp := e.groups[g.GroupKey]; grp == nil || grp.QuotaBytes == nil {
			continue
		}
		out[g.PortalID][g.MAC] = g.GroupKey
	}
	return out
}

// quotaOpsLocked works out the kernel changes that bring the quota objects
// and maps to the wanted state: objects to create go into pre, map changes
// and objects to delete into post (pre + element ops + post is one
// transaction). reseed names groups whose object is replaced. It returns
// the state the kernel holds once the transaction commits.
func (e *Engine) quotaOpsLocked(pre, post *ElementOps, reseed map[string]bool) (map[string]*kernelQuota, map[int64]map[string]string) {
	targets := e.quotaTargetsLocked()
	next := map[string]*kernelQuota{}
	for _, pid := range sortedIDs(targets) {
		for _, mac := range sortedKeys(targets[pid]) {
			key := targets[pid][mac]
			if next[key] != nil {
				continue
			}
			if cur := e.kq[key]; cur != nil && !reseed[key] {
				next[key] = cur
				continue
			}
			left, _ := e.groupRemainingLocked(key)
			e.kqGen++
			q := &kernelQuota{Name: quotaName(key, e.kqGen), Bytes: nonNegative(left)}
			pre.AddQuota(q.Name, q.Bytes)
			next[key] = q
		}
	}
	nextMap := map[int64]map[string]string{}
	for pid, macs := range targets {
		nextMap[pid] = map[string]string{}
		for mac, key := range macs {
			nextMap[pid][mac] = next[key].Name
		}
	}
	var maps ElementOps
	for _, pid := range sortedIDs(e.kqMap) {
		want, counted := nextMap[pid]
		if !counted {
			continue // the portal's chains are gone with a re-render
		}
		for _, mac := range sortedKeys(e.kqMap[pid]) {
			if want[mac] != e.kqMap[pid][mac] {
				post.UnmapQuota(pid, mac)
			}
		}
	}
	for _, pid := range sortedIDs(nextMap) {
		have := e.kqMap[pid]
		for _, mac := range sortedKeys(nextMap[pid]) {
			if name := nextMap[pid][mac]; have[mac] != name {
				maps.MapQuota(pid, mac, name)
			}
		}
	}
	post.Append(&maps)
	for _, key := range sortedKeys(e.kq) {
		if n := next[key]; n == nil || n.Name != e.kq[key].Name {
			post.DeleteQuota(e.kq[key].Name)
		}
	}
	return next, nextMap
}

// quotaSpecLocked is the full-render form of the cut: fresh objects seeded
// with each group's remaining bytes.
func (e *Engine) quotaSpecLocked() ([]QuotaSpec, map[int64]map[string]string, map[string]*kernelQuota) {
	targets := e.quotaTargetsLocked()
	objs := map[string]*kernelQuota{}
	nextMap := map[int64]map[string]string{}
	var specs []QuotaSpec
	for _, pid := range sortedIDs(targets) {
		nextMap[pid] = map[string]string{}
		for _, mac := range sortedKeys(targets[pid]) {
			key := targets[pid][mac]
			q := objs[key]
			if q == nil {
				left, _ := e.groupRemainingLocked(key)
				e.kqGen++
				q = &kernelQuota{Name: quotaName(key, e.kqGen), Bytes: nonNegative(left)}
				objs[key] = q
				specs = append(specs, QuotaSpec{Name: q.Name, Bytes: q.Bytes})
			}
			nextMap[pid][mac] = q.Name
		}
	}
	return specs, nextMap, objs
}

// checkKernelQuotasLocked compares the kernel's quota objects (read in the
// same dump as the counters just folded) with the bookkeeping. A group the
// kernel cut off is used up: what is left under one packet is charged to
// its current grant so the controller sees the quota used, and the limits
// pass ends it. A group whose remaining bytes drifted is re-seeded.
func (e *Engine) checkKernelQuotasLocked(use map[string]QuotaUse) {
	if !e.enf.Quota || use == nil {
		return
	}
	for _, key := range sortedKeys(e.kq) {
		q := e.kq[key]
		u, ok := use[q.Name]
		if !ok {
			// Someone removed it (it cannot go while the map points at it
			// unless the table was rebuilt): render everything again.
			e.log.Warn("portal: a quota object is gone; re-applying", "quota", q.Name)
			e.structural = true
			return
		}
		left, has := e.groupRemainingLocked(key)
		if !has {
			continue // the next apply removes it
		}
		kernelLeft := q.Bytes - u.Used
		if u.Over() && left <= quotaDriftBytes {
			if left > 0 {
				if g := e.quotaChargeTargetLocked(key); g != nil {
					g.BytesDown += left
					e.saveGrant(g, ClassCounter)
				}
			}
			e.log.Info("portal: data quota used up (kernel cut)", "group", key, "quota", q.Name, "charged", nonNegative(left))
			continue
		}
		if d := kernelLeft - left; d > quotaDriftBytes || d < -quotaDriftBytes {
			if e.kqReseed == nil {
				e.kqReseed = map[string]bool{}
			}
			e.kqReseed[key] = true
			e.log.Debug("portal: quota re-seeded", "group", key, "kernelLeft", kernelLeft, "left", left)
		}
	}
}

// quotaChargeTargetLocked is the group's current grant with the lowest order.
func (e *Engine) quotaChargeTargetLocked(key string) *Grant {
	var best *Grant
	for _, g := range e.currentGrantsLocked() {
		if g.GroupKey == key && (best == nil || g.Order() < best.Order()) {
			best = g
		}
	}
	return best
}

// nextTickLocked is the wait before the next tick: enforceIntervalSeconds,
// or quotaNearInterval while any group with devices here is within 10 % of
// its data quota (belt and braces next to the kernel cut, and the only cut
// where the kernel has none).
func (e *Engine) nextTickLocked() time.Duration {
	every := time.Duration(e.settings.EnforceIntervalSeconds) * time.Second
	if every <= quotaNearInterval {
		return every
	}
	seen := map[string]bool{}
	for _, g := range e.grants {
		if !g.Live() || seen[g.GroupKey] {
			continue
		}
		seen[g.GroupKey] = true
		grp := e.groups[g.GroupKey]
		if grp == nil || grp.QuotaBytes == nil || *grp.QuotaBytes <= 0 {
			continue
		}
		left, _ := e.groupRemainingLocked(g.GroupKey)
		if left*quotaNearFraction <= *grp.QuotaBytes {
			return quotaNearInterval
		}
	}
	return every
}

func sortedIDs[V any](m map[int64]V) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return sortedCopy(out)
}
