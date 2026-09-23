package portal

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeCode(t *testing.T) {
	cases := map[string]string{
		"K7Q2M9XH4D":        "K7Q2M9XH4D",
		"k7q2m-9xh4d":       "K7Q2M9XH4D",
		" k7q2m 9xh4d ":     "K7Q2M9XH4D",
		"K7Q2M.9XH4D":       "K7Q2M9XH4D",
		"iloIL0OO":          "11011000",
		"K7Q2M9XH4U":        "",
		"SHORT":             "",
		"ABCDEFGHJKMNPQRST": "",
		"K7Q2M 9XH4D":       "K7Q2M9XH4D", // NBSP is \s in JavaScript
		"ABCDEFGß":          "ABCDEFGSS",  // ß upper-cases to SS
		"K7Q2M9XH4D!":       "",
	}
	for in, want := range cases {
		if got := NormalizeCode(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	long := ""
	for i := 0; i < 65; i++ {
		long += "-"
	}
	if NormalizeCode(long+"K7Q2M9XH4D") != "" {
		t.Error("over-long input accepted")
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"02-00-00-AA-BB-CC": "02:00:00:aa:bb:cc",
		"0200.00aa.bbcc":    "02:00:00:aa:bb:cc",
		"020000aabbcc":      "02:00:00:aa:bb:cc",
		"01:00:5e:00:00:01": "", // multicast
		"ff:ff:ff:ff:ff:ff": "",
		"00:00:00:00:00:00": "",
		"02:00:00:aa:bb":    "",
		"zz:00:00:aa:bb:cc": "",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestExhaustionOrderAndRemaining(t *testing.T) {
	exp, q, d := int64(1000), int64(100), int64(60)
	l := Limits{DurationMode: ModeWallClock, ExpiresAt: &exp, QuotaBytes: &q}
	if Exhaustion(l, Usage{BytesUsed: 200}, 1000) != EndExpired {
		t.Fatal("time must come first")
	}
	if Exhaustion(l, Usage{BytesUsed: 100}, 999) != EndQuota {
		t.Fatal("quota")
	}
	at := Limits{DurationMode: ModeActiveTime, DurationSeconds: &d}
	if Exhaustion(at, Usage{TimeUsedSeconds: 60}, 0) != EndExpired {
		t.Fatal("active time")
	}
	s, b := Remaining(Limits{DurationMode: ModeWallClock, DurationSeconds: &d}, Usage{}, 0)
	if s == nil || *s != 60 || b != nil {
		t.Fatal("unstarted wall clock reports its duration")
	}
	grant := int64(500)
	if got := GrantLimits(l, &grant); *got.ExpiresAt != 500 {
		t.Fatal("grant deadline must tighten")
	}
}

func TestEntitlementOrderAndPlacement(t *testing.T) {
	q, d, e1 := int64(10), int64(60), int64(5000)
	data := Entitlement{Order: 1, Limits: Limits{QuotaBytes: &q}, CreatedAt: 1}
	timed := Entitlement{Order: 2, Limits: Limits{DurationSeconds: &d}, CreatedAt: 2}
	running := Entitlement{Order: 3, Limits: Limits{DurationSeconds: &d, ExpiresAt: &e1}, CreatedAt: 3}
	if CompareEntitlements(timed, data) >= 0 || CompareEntitlements(running, timed) >= 0 {
		t.Fatal("order: running time, time, data")
	}
	if PlaceBehindCurrent(data.Limits, timed.Limits) != "swap" || PlaceBehindCurrent(timed.Limits, data.Limits) != "queue" {
		t.Fatal("placement")
	}
	ev := EvictOldest([]SlotHolder{{Ref: "b", StartedAt: 20}, {Ref: "a", StartedAt: 10}}, 2)
	if len(ev) != 1 || ev[0] != "a" {
		t.Fatalf("%v", ev)
	}
	if len(EvictOldest([]SlotHolder{{Ref: "a"}}, 2)) != 0 {
		t.Fatal("room left")
	}
}

func TestStorageResolve(t *testing.T) {
	flash := []byte("/dev/root /rom squashfs ro 0 0\n/dev/mtdblock6 /overlay jffs2 rw 0 0\noverlayfs:/overlay / overlay rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n")
	info := ResolveStorage(StorageConfig{}, flash, nil, 5)
	if info.Kind != StorageFlash || info.FlushSeconds != FlushFlashDefault || info.WriteThrough || info.Path != DefaultStoragePath {
		t.Fatalf("%+v", info)
	}
	emmc := []byte("/dev/mmcblk0p2 / ext4 rw 0 0\n")
	if info := ResolveStorage(StorageConfig{}, emmc, nil, 5); info.Kind != StorageEMMC || info.FlushSeconds != 5 || !info.WriteThrough {
		t.Fatalf("%+v", info)
	}
	usb := append(append([]byte{}, flash...), []byte("/dev/sda1 /mnt/usb ext4 rw 0 0\n")...)
	if info := ResolveStorage(StorageConfig{Path: "/mnt/usb/perch/state.db", ExpectMount: "/mnt/usb"}, usb, nil, 5); info.Kind != StorageDisk || info.Fallback {
		t.Fatalf("%+v", info)
	}
	// The USB disk is not mounted: never write onto the empty mount point.
	info = ResolveStorage(StorageConfig{Path: "/mnt/usb/perch/state.db", ExpectMount: "/mnt/usb"}, flash, nil, 5)
	if !info.Fallback || info.Path != DefaultStoragePath || info.Warning == "" {
		t.Fatalf("%+v", info)
	}
	info = ResolveStorage(StorageConfig{Path: "/mnt/usb/perch/state.db"}, flash, nil, 5)
	if !info.Fallback {
		t.Fatalf("unmounted /mnt path accepted: %+v", info)
	}
	// A marker file vouches for a mount the table names differently.
	info = ResolveStorage(StorageConfig{Path: "/mnt/usb/s.db", ExpectMount: "/mnt/usb"}, flash, func(p string) bool { return p == "/mnt/usb/"+StorageMarker }, 5)
	if info.Fallback {
		t.Fatalf("%+v", info)
	}
	if info := ResolveStorage(StorageConfig{Path: "/tmp/portal.db"}, flash, nil, 5); info.Kind != StorageRAM || info.Persistent || info.Warning == "" {
		t.Fatalf("%+v", info)
	}
	if info := ResolveStorage(StorageConfig{FlushSeconds: 60}, flash, nil, 5); info.FlushSeconds != 60 {
		t.Fatalf("%+v", info)
	}
}

func TestStoreSnapshotAndCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.db")
	s, _, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Due(time.Now(), time.Hour) {
		t.Fatal("nothing changed yet")
	}
	_ = s.SetMeta(ClassCounter, "x", "1")
	if s.Due(time.Now(), time.Hour) != true { // first snapshot: lastSnapshot zero
		t.Fatal("counter never snapshotted")
	}
	if err := s.Flush(false); err != nil {
		t.Fatal(err)
	}
	_ = s.SetMeta(ClassCounter, "x", "2")
	if s.Due(time.Now(), time.Hour) {
		t.Fatal("counters are batched")
	}
	_ = s.SetMeta(ClassGrant, "y", "3")
	if !s.Due(time.Now(), time.Hour) {
		t.Fatal("grants are written at once")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, warn, err := OpenStore(path)
	if err != nil || warn != "" || s2.Meta("x") != "2" || s2.Meta("y") != "3" {
		t.Fatalf("%v %q %q %q", err, warn, s2.Meta("x"), s2.Meta("y"))
	}
	s2.db.Close()
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3, warn, err := OpenStore(path)
	if err != nil || warn == "" || s3.Meta("x") != "" {
		t.Fatalf("%v %q", err, warn)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatal("corrupt file not kept aside")
	}
	s3.db.Close()
}

func TestClockFloorAndSkew(t *testing.T) {
	now := time.UnixMilli(1000)
	c := &Clock{now: func() time.Time { return now }, floor: 5000}
	c.started = now
	if c.Now() != 5000 {
		t.Fatalf("floor: %d", c.Now())
	}
	now = now.Add(2 * time.Second)
	if c.Now() != 7000 {
		t.Fatalf("floor + monotonic: %d", c.Now())
	}
	c.Observe(100000)
	if c.Now() != 100000 {
		t.Fatalf("skew: %d", c.Now())
	}
	c.Observe(now.UnixMilli() + 1000)
	if c.Skew() != 0 {
		t.Fatal("small skew applied")
	}
}

func TestWindowBounded(t *testing.T) {
	w := NewWindow(2, time.Minute)
	now := time.Unix(0, 0)
	w.Hit("a", now)
	w.Hit("a", now)
	if b, retry := w.Blocked("a", now); !b || retry <= 0 {
		t.Fatal("limit")
	}
	if b, _ := w.Blocked("a", now.Add(61*time.Second)); b {
		t.Fatal("window slides")
	}
	w.maxKeys = 3
	for _, k := range []string{"b", "c", "d", "e"} {
		w.Hit(k, now)
	}
	if w.Len() > 3 {
		t.Fatal("unbounded")
	}
}

func TestTemplateChecks(t *testing.T) {
	if _, err := CheckTemplateFile("login.html", []byte("{{nope}}")); err == nil {
		t.Fatal("unknown variable accepted")
	}
	if _, err := CheckTemplateFile("../x.html", []byte("x")); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := CheckTemplateFile("a.png", []byte("not a png")); err == nil {
		t.Fatal("fake png accepted")
	}
	if err := CheckTemplateSet([]TemplateFileData{{Name: "a.css", Data: []byte("x")}}); err == nil {
		t.Fatal("set without login.html accepted")
	}
	// The builtin set hashes like the controller's empty set.
	if EmptySetSHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal(EmptySetSHA256)
	}
	out := string(RenderPage([]byte(`{{ portal_name }}|{{status_json}}|{{login_form}}`), map[string]string{"portal_name": "<b>"}, map[string]string{"x": "</script>"}, false, false))
	if out != "&lt;b&gt;|{\"x\":\"\\u003c/script\\u003e\"}|" {
		t.Fatalf("%q", out)
	}
}
