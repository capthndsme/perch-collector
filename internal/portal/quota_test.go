package portal

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/capthndsme/perch-collector/internal/observe"
)

func authorizeQuota(t *testing.T, e *Engine, c *controllerSide, key string, quota, base int64, grants ...WireGrant) {
	t.Helper()
	g := dataGroup(key, quota)
	g.BaseBytesUsed = base
	g.MaxDevices = int64(len(grants))
	var signed []SignedGrant
	for _, gr := range grants {
		signed = append(signed, c.grant(gr))
	}
	if _, err := e.Authorize(context.Background(), c.authorize(true, 0, []SignedGroup{c.group(g)}, signed)); err != nil {
		t.Fatal(err)
	}
}

func TestKernelQuotaCutsExactly(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	if !e.enf.Quota {
		t.Fatal("quota probe failed on the fake kernel")
	}
	gid := int64(42)
	// The device is on the link (it just signed in).
	sys.neighbors = []observe.Neighbor{{IP: "192.168.20.111", MAC: macG1, Device: "guest", Reachable: true}}
	authorizeQuota(t, e, c, "v:17", 1000, 0, WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "v:17", MAC: macG1, Revision: 1})
	// Cut from the first byte, both ways: the authorising transaction
	// carries the MAC's and its address's map entries.
	name, q := sys.quotaOf(3, macG1)
	if q == nil || name != "qv17_1" || q.over != 1000 {
		t.Fatalf("quota %s %+v", name, q)
	}
	if n := sys.quotaOfAddr(3, "192.168.20.111"); n != "qv17_1" {
		t.Fatalf("address not cut: %q", n)
	}
	sys.count("p3_up", macG1, 300)
	sys.count("p3_down", macG1, 400)
	e.Tick(ctx)
	g := e.findGrantLocked(&gid, nil)
	if g == nil || g.BytesUp != 300 || g.BytesDown != 400 {
		t.Fatalf("grant %+v", g)
	}
	// 400 more would cross 1000: the kernel drops it, the counters never see it.
	sys.count("p3_down", macG1, 400)
	if _, q := sys.quotaOf(3, macG1); q.used != 1100 {
		t.Fatalf("kernel quota %+v", q)
	}
	e.Tick(ctx)
	if e.findGrantLocked(&gid, nil) != nil || sys.has("inet", "p3_auth", macG1) {
		t.Fatal("grant not ended at the kernel cut")
	}
	ended := eventsOf(e, EvGrantEnded)
	// Exactly the quota: 700 counted + the 300 under one packet charged.
	if len(ended) != 1 || ended[0].Reason != EndQuota || *ended[0].BytesUp+*ended[0].BytesDown != 1000 {
		t.Fatalf("ended %+v", ended)
	}
	if len(sys.flushed) != 1 {
		t.Fatalf("flush %v", sys.flushed)
	}
	// The map entry and the object are gone with the grant.
	if name, q := sys.quotaOf(3, macG1); q != nil || len(sys.quotas) != 0 {
		t.Fatalf("left behind: %s %+v %v", name, q, sys.quotas)
	}
}

func TestKernelQuotaSharedGroupAndReseed(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	a, b := int64(1), int64(2)
	grants := []WireGrant{
		{GrantID: &a, PortalID: 3, GroupKey: "v:9", MAC: macG1, Revision: 1},
		{GrantID: &b, PortalID: 3, GroupKey: "v:9", MAC: macG2, Revision: 1},
	}
	sys.neighbors = []observe.Neighbor{
		{IP: "192.168.20.111", MAC: macG1, Device: "guest", Reachable: true},
		{IP: "192.168.20.112", MAC: macG2, Device: "guest", Reachable: true},
	}
	authorizeQuota(t, e, c, "v:9", 10_000_000, 1_000_000, grants...)
	n1, q1 := sys.quotaOf(3, macG1)
	n2, _ := sys.quotaOf(3, macG2)
	if q1 == nil || n1 != n2 || q1.over != 9_000_000 {
		t.Fatalf("one object for the group: %s %s %+v", n1, n2, q1)
	}
	sys.count("p3_up", macG1, 2_000_000)
	sys.count("p3_up", macG2, 1_000_000)
	sys.count("p3_down", macG2, 2_000_000)
	e.Tick(ctx)
	if _, q := sys.quotaOf(3, macG1); q.over != 9_000_000 || q.used != 5_000_000 {
		t.Fatalf("no re-seed without drift: %+v", q)
	}
	// Another router used 3 MB of the shared voucher: the controller's next
	// full set raises the base, the tick re-seeds with what is left.
	authorizeQuota(t, e, c, "v:9", 10_000_000, 4_000_000, grants...)
	e.Tick(ctx)
	name, q := sys.quotaOf(3, macG1)
	if q == nil || name == n1 || q.over != 10_000_000-4_000_000-5_000_000 || q.used != 0 {
		t.Fatalf("re-seed %s %+v", name, q)
	}
	if n, _ := sys.quotaOf(3, macG2); n != name || sys.quotaOfAddr(3, "192.168.20.112") != name {
		t.Fatal("second device not repointed")
	}
	if len(sys.quotas) != 1 {
		t.Fatalf("old object kept: %v", sys.quotas)
	}
	// Within 10 %: the tick runs every second.
	if d := e.nextTickLocked(); d != quotaNearInterval {
		t.Fatalf("interval %v at 10 %% left", d)
	}
	// One device leaves: the other keeps the object.
	if _, err := e.Deauthorize(ctx, c.deauthorize([]int64{1}, "revoked")); err != nil {
		t.Fatal(err)
	}
	if n, _ := sys.quotaOf(3, macG1); n != "" || sys.quotaOfAddr(3, "192.168.20.111") != "" {
		t.Fatal("ended device still mapped")
	}
	if n, _ := sys.quotaOf(3, macG2); n != name {
		t.Fatal("remaining device lost its cut")
	}
}

func TestKernelQuotaSurvivesRestart(t *testing.T) {
	sys := newFakeSystem()
	path := filepath.Join(t.TempDir(), "state.db")
	e, _ := newTestEngine(t, sys, path)
	c := newController(t)
	ctx := context.Background()
	if _, err := e.Configure(ctx, c.configure(guestPortal(3))); err != nil {
		t.Fatal(err)
	}
	gid := int64(7)
	sys.neighbors = []observe.Neighbor{{IP: "192.168.20.111", MAC: macG1, Device: "guest", Reachable: true}}
	authorizeQuota(t, e, c, "v:7", 100_000, 0, WireGrant{GrantID: &gid, PortalID: 3, GroupKey: "v:7", MAC: macG1, Revision: 1})
	sys.count("p3_up", macG1, 0) // a request out: the kernel learns the address
	sys.count("p3_down", macG1, 30_000)
	e.Tick(ctx)
	// Traffic after the last tick, then the collector stops (the tables stay).
	sys.count("p3_down", macG1, 20_000)
	e.Shutdown()
	e2, _ := newTestEngine(t, sys, path)
	e2.Start(ctx)
	g := e2.findGrantLocked(&gid, nil)
	if g == nil || g.BytesDown != 50_000 {
		t.Fatalf("bytes lost over the restart: %+v", g)
	}
	_, q := sys.quotaOf(3, macG1)
	if q == nil || q.over != 50_000 || q.used != 0 {
		t.Fatalf("not seeded with the remaining bytes: %+v", q)
	}
	// The learned address came along: download counts and cuts at once.
	if !sys.has("acct", "p3_a4", "192.168.20.111 . "+macG1) || sys.quotaOfAddr(3, "192.168.20.111") == "" {
		t.Fatal("learned address not carried over the re-render")
	}
	// And it cuts there.
	sys.count("p3_down", macG1, 49_000)
	sys.count("p3_down", macG1, 1_500)
	e2.Tick(ctx)
	if e2.findGrantLocked(&gid, nil) != nil {
		t.Fatal("not ended at the quota")
	}
}

func TestQuotaOpsOrderAndGolden(t *testing.T) {
	e, sys, c, _ := configured(t)
	a := int64(1)
	authorizeQuota(t, e, c, "v:5", 5000, 0, WireGrant{GrantID: &a, PortalID: 3, GroupKey: "v:5", MAC: macG1, Revision: 1})
	golden(t, "quota-authorize.nft", sys.scripts[len(sys.scripts)-1])
	e.kqReseed = map[string]bool{"v:5": true}
	e.applyOpsLocked(&ElementOps{})
	golden(t, "quota-reseed.nft", sys.scripts[len(sys.scripts)-1])
}

func TestNextTickInterval(t *testing.T) {
	e, _, c, _ := configured(t)
	if d := e.nextTickLocked(); d != 5*time.Second {
		t.Fatalf("%v", d)
	}
	a := int64(1)
	authorizeQuota(t, e, c, "v:5", 1000, 850, WireGrant{GrantID: &a, PortalID: 3, GroupKey: "v:5", MAC: macG1, Revision: 1})
	if d := e.nextTickLocked(); d != 5*time.Second {
		t.Fatalf("15 %% left: %v", d)
	}
	authorizeQuota(t, e, c, "v:5", 1000, 901, WireGrant{GrantID: &a, PortalID: 3, GroupKey: "v:5", MAC: macG1, Revision: 1})
	if d := e.nextTickLocked(); d != time.Second {
		t.Fatalf("9.9 %% left: %v", d)
	}
}

func TestParseQuotaAndMapJSON(t *testing.T) {
	// nft 1.1.6, `nft -j list table netdev ...` with a quota and a map.
	data := []byte(`{"nftables": [{"metainfo": {"version": "1.1.6"}}, {"quota": {"family": "netdev", "name": "qv17_1", "table": "perch_portal_acct", "handle": 2, "bytes": 31457280, "used": 1234, "inv": true}}, {"map": {"family": "netdev", "name": "p3_quota", "table": "perch_portal_acct", "type": "ether_addr", "handle": 3, "map": "quota", "elem": [["02:00:00:00:20:11", "qv17_1"]]}}]}`)
	q, err := ParseQuotasJSON(data)
	if err != nil || q["qv17_1"].Bytes != 31457280 || q["qv17_1"].Used != 1234 || q["qv17_1"].Over() {
		t.Fatalf("%+v %v", q, err)
	}
	sets, err := ParseTableJSON(data)
	if err != nil || sets["p3_quota"].Values["02:00:00:00:20:11"] != "qv17_1" {
		t.Fatalf("%+v %v", sets, err)
	}
}

// TestRenderedRulesetNftCheck runs the rendered tables and the incremental
// quota ops through the real nft (-c: parsed and checked by the kernel, not
// committed) in a throwaway network namespace, when this machine has nft
// and unprivileged user namespaces.
func TestRenderedRulesetNftCheck(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("no nft")
	}
	if exec.Command("unshare", "-rn", "true").Run() != nil {
		t.Skip("no unprivileged network namespaces")
	}
	spec := goldenQuotaSpec()
	dir := t.TempDir()
	full := filepath.Join(dir, "full.nft")
	if err := os.WriteFile(full, []byte(RenderInet(spec)+RenderAcct(spec)+RenderFast(spec)), 0o644); err != nil {
		t.Fatal(err)
	}
	var ops ElementOps
	ops.AddQuota("qv17_2", 1000)
	ops.Authorize(3, "02:00:00:00:20:13", Counting{Acct: true, Fast: true})
	ops.UnmapQuota(3, "02:00:00:00:20:11")
	ops.UnmapQuota(3, "02:00:00:00:20:12")
	ops.UnmapQuotaAddr(3, "192.168.20.111")
	ops.UnmapQuotaAddr(3, "192.168.20.112")
	ops.UnmapQuotaAddr(3, "2001:db8:20::11")
	ops.MapQuota(3, "02:00:00:00:20:11", "qv17_2")
	ops.MapQuota(3, "02:00:00:00:20:12", "qv17_2")
	ops.MapQuota(3, "02:00:00:00:20:13", "qv17_2")
	ops.MapQuotaAddr(3, "192.168.20.111", "qv17_2")
	ops.DeleteQuota("qv17_1")
	delta := filepath.Join(dir, "ops.nft")
	if err := os.WriteFile(delta, []byte(ops.Script()), 0o644); err != nil {
		t.Fatal(err)
	}
	script := strings.Join([]string{
		"set -e",
		"ip link add guest type dummy",
		"ip link add br-trunk.110 type dummy",
		"ip link add br-trunk.120 type dummy",
		nft + " -c -f " + full,
		nft + " -f " + full,
		nft + " -c -f " + delta,
		nft + " -f " + delta,
		nft + " list map inet perch_portal_acct p3_quota",
		nft + " list map inet perch_portal_acct p3_quota4",
		"! " + nft + " list quota inet perch_portal_acct qv17_1 2>/dev/null",
		// A second full render replaces everything (and the old netdev table).
		"nft add table netdev perch_portal_acct",
		nft + " -f " + full,
		"! " + nft + " list table netdev perch_portal_acct 2>/dev/null",
	}, "\n")
	out, err := exec.Command("unshare", "-rn", "sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("nft refused the ruleset: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `02:00:00:00:20:13 : "qv17_2"`) {
		t.Fatalf("map after the ops:\n%s", out)
	}
}
