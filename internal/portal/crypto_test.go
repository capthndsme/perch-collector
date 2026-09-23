package portal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Pinned vectors of the controller (tests/unit/services/portal/crypto.spec.ts,
// docs/gateway/portal.md §6.3): APP_KEY "perch-test-app-key-0123456789abcdef",
// gateway 7, epoch 1, code K7Q2M9XH4D.
const (
	vecAppKey     = "perch-test-app-key-0123456789abcdef"
	vecGatewayKey = "5xWg3o-mXyuxbPvlpxL3dGgcnUXrgB-JeSJjxfHfySU"
	vecCode       = "K7Q2M9XH4D"
	vecVerifier   = "0026473bc23eeae443961e14eb2db086f0870607cedb8ea0225eca9106112af6"
)

func i64(v int64) *int64   { return &v }
func str(v string) *string { return &v }
func vecKeys(t testing.TB) *Keys {
	t.Helper()
	raw, err := DecodeGatewayKey(vecGatewayKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := KeysFrom(raw, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var vecGrant = WireGrant{GrantID: i64(42), PortalID: 3, GroupKey: "v:17", MAC: "02:00:00:aa:bb:cc", Revision: 2}

var vecGroup = WireGroup{
	GroupKey: "v:17", DurationMode: ModeWallClock, ExpiresAt: i64(1790000000000), DurationSeconds: i64(3600),
	QuotaBytes: i64(500000000), BaseTimeUsedSeconds: 0, BaseBytesUsed: 1234, MaxDevices: 1, Revision: 3,
}

func vecVoucher() WireOfflineVoucher {
	return WireOfflineVoucher{
		VoucherID: 17, Verifier: vecVerifier, PortalIDs: []int64{3}, GroupKey: "v:17",
		DurationMode: ModeActiveTime, StartMode: StartFirstUse, DurationSeconds: i64(7200),
		DownKbps: i64(5000), UpKbps: i64(1000), MaxDevices: 2, RedeemBy: i64(1791000000000), Revision: 1,
	}
}

// hkdf is RFC 5869 HKDF-SHA256 for one 32-byte block: an independent check
// that the gateway key the vectors pin is what the controller derives.
func hkdf(ikm, salt, info string) []byte {
	ext := hmac.New(sha256.New, []byte(salt))
	ext.Write([]byte(ikm))
	prk := ext.Sum(nil)
	exp := hmac.New(sha256.New, prk)
	exp.Write([]byte(info))
	exp.Write([]byte{1})
	return exp.Sum(nil)
}

func TestVectorKeys(t *testing.T) {
	k := vecKeys(t)
	if got := base64.RawURLEncoding.EncodeToString(hkdf(vecAppKey, "perch-portal-v1", "gateway:7:1")); got != vecGatewayKey {
		t.Fatalf("HKDF gateway key %s", got)
	}
	if got := hex.EncodeToString(hkdf(vecAppKey, "perch-portal-v1", "voucher-lookup")); got != "df9107c705d83bbc11aa97dc6b6443d3cfa0d71d346d58043034fbf06893e4a9" {
		t.Fatalf("lookup key %s", got)
	}
	if got := hex.EncodeToString(k.VoucherKey); got != "77c9f47a3aa4c958b236c4805831b6090a0e9a44db4dfe8fe7ada0618c009703" {
		t.Fatalf("voucherKey %s", got)
	}
	if got := hex.EncodeToString(k.SignKey); got != "82c4ea733b93eed127a9a15ea6f09751eae22970c0d9a631357cf79b906989de" {
		t.Fatalf("signKey %s", got)
	}
	if got := k.Verifier(vecCode); got != vecVerifier {
		t.Fatalf("verifier %s", got)
	}
}

func TestVectorGrant(t *testing.T) {
	k := vecKeys(t)
	c, err := k.CanonicalGrant(vecGrant)
	if err != nil || c != "perch-portal-grant-v1\n7\n1\n42\n\n3\nv:17\n02:00:00:aa:bb:cc\n\n2" {
		t.Fatalf("canonical %q %v", c, err)
	}
	if s, _ := k.SignGrant(vecGrant); s != "fcGv3MNx9X1ku6Egf23WIq_MHxQkC6PcgobSjfLs7VY" {
		t.Fatalf("sig %s", s)
	}
}

func TestVectorGroup(t *testing.T) {
	k := vecKeys(t)
	c, err := k.CanonicalGroup(vecGroup)
	if err != nil || c != "perch-portal-group-v1\n7\n1\nv:17\nwall_clock\n1790000000000\n3600\n500000000\n0\n1234\n\n\n1\n3" {
		t.Fatalf("canonical %q %v", c, err)
	}
	if s, _ := k.SignGroup(vecGroup); s != "-OY5PsYD9P4oVsTi-rr9xIozfwJT0ojy06e2XtuhipQ" {
		t.Fatalf("sig %s", s)
	}
}

func TestVectorVoucher(t *testing.T) {
	k := vecKeys(t)
	c, err := k.CanonicalOfflineVoucher(vecVoucher())
	// firstUsedAt (null here) is the last line: the canonical form ends in "\n".
	want := "perch-portal-voucher-v1\n7\n1\n17\n0026473bc23eeae443961e14eb2db086f0870607cedb8ea0225eca9106112af6\n3\nv:17\nactive_time\nfirst_use\n7200\n\n5000\n1000\n2\n1791000000000\n\n0\n0\n1\n"
	if err != nil || c != want {
		t.Fatalf("canonical %q %v", c, err)
	}
	if s, _ := k.SignOfflineVoucher(vecVoucher()); s != "fF58SkU0g5C47axcdZN2dLM0sGtvRKWO0ksDlD1kaY8" {
		t.Fatalf("sig %s", s)
	}
	used := vecVoucher()
	used.FirstUsedAt = i64(1790000000000)
	if c, _ := k.CanonicalOfflineVoucher(used); c != want+"1790000000000" {
		t.Fatalf("canonical with firstUsedAt %q", c)
	}
	if s, _ := k.SignOfflineVoucher(used); s != "AMBsGy99v8xLEJ_uEq9C2LFi2cVgrIzUBYewJLuzLMo" {
		t.Fatalf("sig with firstUsedAt %s", s)
	}
	// Portal lists are sorted.
	v := vecVoucher()
	v.PortalIDs = []int64{5, 3}
	w := vecVoucher()
	w.PortalIDs = []int64{3, 5}
	a, _ := k.SignOfflineVoucher(v)
	b, _ := k.SignOfflineVoucher(w)
	if a != b {
		t.Fatal("portal order changed the signature")
	}
}

func TestVectorEnvelope(t *testing.T) {
	k := vecKeys(t)
	gs, _ := k.SignGroup(vecGroup)
	ts, _ := k.SignGrant(vecGrant)
	e := Envelope{
		Kind: "authorize", Full: true, ServerNow: 1790000000123, Nonce: "AAAAAAAAAAAAAAAAAAAAAA",
		ItemSignatures: []string{gs, ts}, AckedEventSeq: 9,
		Externals: []ExternalRef{{PortalID: i64(3), MAC: "02:00:00:00:00:09"}},
	}
	c, err := k.CanonicalEnvelope(e)
	want := "perch-portal-authorize-v1\n7\n1\n1\n1790000000123\nAAAAAAAAAAAAAAAAAAAAAA\n9\n\n\n2\n1\n" +
		"-OY5PsYD9P4oVsTi-rr9xIozfwJT0ojy06e2XtuhipQ\nfcGv3MNx9X1ku6Egf23WIq_MHxQkC6PcgobSjfLs7VY\n" +
		"ext:3:02:00:00:00:00:09"
	if err != nil || c != want {
		t.Fatalf("canonical %q %v", c, err)
	}
	if s, _ := k.SignEnvelope(e); s != "cARMzBOVvRS3e43pF1xkGJl3Zg_640uqJ6OFPhourAU" {
		t.Fatalf("sig %s", s)
	}
}

func TestCanonicalRefusals(t *testing.T) {
	k := vecKeys(t)
	bad := []WireGrant{
		{GrantID: i64(1), LocalRef: str("a\nb"), PortalID: 3, GroupKey: "v:17", MAC: "02:00:00:aa:bb:cc", Revision: 1},
		{GrantID: i64(1), PortalID: 3, GroupKey: "v:17", MAC: "02:00:00:AA:BB:CC", Revision: 1},
		{GrantID: i64(1), PortalID: 3, GroupKey: "x:1", MAC: "02:00:00:aa:bb:cc", Revision: 1},
		{GrantID: i64(1), PortalID: 3, GroupKey: "v:17", MAC: "02:00:00:aa:bb:cc", Revision: -1},
		{PortalID: 3, GroupKey: "v:17", MAC: "02:00:00:aa:bb:cc", Revision: 1},
	}
	for i, g := range bad {
		if _, err := k.CanonicalGrant(g); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := k.CanonicalEnvelope(Envelope{Kind: "authorize", Nonce: "short"}); err == nil {
		t.Error("short nonce accepted")
	}
	if _, err := k.CanonicalEnvelope(Envelope{Kind: "authorize", Nonce: "AAAAAAAAAAAAAAAAAAAAAA", ItemSignatures: []string{"x"}}); err == nil {
		t.Error("bad item signature accepted")
	}
	if _, err := KeysFrom(make([]byte, 16), 1, 1); err == nil {
		t.Error("16-byte key accepted")
	}
}

func TestDeauthorizeEnvelopeSortsIDs(t *testing.T) {
	k := vecKeys(t)
	r := "revoked"
	a, _ := k.SignEnvelope(Envelope{Kind: "deauthorize", ServerNow: 1, Nonce: "AAAAAAAAAAAAAAAAAAAAAA", GrantIDs: []int64{3, 1, 2}, Reason: &r})
	b, _ := k.SignEnvelope(Envelope{Kind: "deauthorize", ServerNow: 1, Nonce: "AAAAAAAAAAAAAAAAAAAAAA", GrantIDs: []int64{1, 2, 3}, Reason: &r})
	if a != b {
		t.Fatal("grant id order changed the signature")
	}
}
