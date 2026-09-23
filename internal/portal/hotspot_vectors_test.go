package portal

import (
	"strings"
	"testing"
)

// Vectors pinned by the controller's tests/unit/services/portal/hotspot.spec.ts.

func vectorTable() PriceTable {
	return PriceTable{PriceTableID: 2, Revision: 3, Name: "Coins", Currency: "PHP", Decimals: 0, DurationMode: ModeWallClock,
		Entries: []PriceEntry{
			{Amount: 1, Minutes: 10},
			{Amount: 5, Minutes: 60, DownKbps: i64(5000), UpKbps: i64(2000)},
			{Amount: 20, Minutes: 300, DownKbps: i64(10000), UpKbps: i64(5000)},
		}}
}

func vectorRecord() CheckoutRecord {
	return CheckoutRecord{CheckoutRef: "ck-0123456789abcdef", PortalID: 3, TerminalID: 4, MAC: "02:00:00:aa:bb:cc",
		Amount: 7, Currency: "PHP", PriceTableID: 2, PriceRevision: 3, DurationMode: ModeWallClock, DurationSeconds: 4800,
		DownKbps: i64(5000), UpKbps: i64(2000), OpenedAt: 1790000000000, FinalizedAt: 1790000042000, Reason: ReasonDone,
		LocalRef: "k5-a1b2c3d4", UnusedAmount: 0, CoinCount: 3}
}

func TestPriceEntitlementVectors(t *testing.T) {
	tab := vectorTable()
	r := PriceEntitlement(tab, 7)
	if r.DurationSeconds != 4800 || r.QuotaBytes != nil || *r.DownKbps != 5000 || *r.UpKbps != 2000 || r.UnusedAmount != 0 || r.Amount != 7 {
		t.Fatalf("7: %+v", r)
	}
	if r := PriceEntitlement(tab, 47); r.DurationSeconds != (600+60+20)*60 || *r.DownKbps != 10000 {
		t.Fatalf("47: %+v", r)
	}
	if r := PriceEntitlement(tab, 1); r.DurationSeconds != 600 || r.DownKbps != nil {
		t.Fatalf("1: %+v", r)
	}
	only := tab
	only.Entries = []PriceEntry{tab.Entries[1]}
	if r := PriceEntitlement(only, 3); r.DurationSeconds != 0 || r.UnusedAmount != 3 || r.DownKbps != nil {
		t.Fatalf("3: %+v", r)
	}
	if r := PriceEntitlement(only, 12); r.UnusedAmount != 2 {
		t.Fatalf("12: %+v", r)
	}
	if r := PriceEntitlement(only, -5); r.Amount != 0 || r.DurationSeconds != 0 {
		t.Fatalf("-5: %+v", r)
	}
	q := tab
	q.Entries = []PriceEntry{{Amount: 10, Minutes: 60, QuotaBytes: i64(500_000_000)}, {Amount: 50, Minutes: 1440, QuotaBytes: i64(5_000_000_000)}}
	if r := PriceEntitlement(q, 70); *r.QuotaBytes != 6_000_000_000 || r.DurationSeconds != (1440+120)*60 {
		t.Fatalf("70: %+v", r)
	}
	big := tab
	big.Entries = []PriceEntry{{Amount: 1, Minutes: 525600}}
	if r := PriceEntitlement(big, 3); r.DurationSeconds != 525600*60 {
		t.Fatalf("cap: %+v", r)
	}
}

func TestCheckoutRecordVectors(t *testing.T) {
	k := vecKeys(t)
	text, err := k.CanonicalCheckout(vectorRecord())
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"perch-portal-checkout-v1", "7", "1", "ck-0123456789abcdef", "3", "4", "02:00:00:aa:bb:cc",
		"7", "PHP", "2", "3", "wall_clock", "4800", "", "5000", "2000", "1790000000000", "1790000042000", "done",
		"k5-a1b2c3d4", "0", "3"}, "\n")
	if text != want {
		t.Fatalf("canonical:\n%s", text)
	}
	sig, _ := k.SignCheckout(vectorRecord())
	if sig != "addRWmtev4ux-XcOWgh524P90PI5NMkRip7TT-If_Ow" {
		t.Fatalf("sig %s", sig)
	}
	code, _ := k.CheckoutReferenceCode(vectorRecord())
	if code != "GE6RH9AQ1S" || NormalizeCode(code) != code || FormatCode(code) != "GE6RH-9AQ1S" {
		t.Fatalf("code %s", code)
	}
	bad := vectorRecord()
	bad.Currency = "php"
	if _, err := k.CanonicalCheckout(bad); err == nil {
		t.Fatal("lower-case currency accepted")
	}
	bad = vectorRecord()
	bad.Reason = "other"
	if _, err := k.SignCheckout(bad); err == nil {
		t.Fatal("bad reason accepted")
	}
	other := vectorRecord()
	other.Amount = 8
	if s, _ := k.SignCheckout(other); s == sig {
		t.Fatal("amount not bound")
	}
}

func TestTerminalSignatureVector(t *testing.T) {
	body := `{"checkoutRef":"ck-0123456789abcdef","eventId":"b1-7","amount":5}`
	s := TerminalSigningString("post", "/portal/v1/terminal/coins", 4, "Zm9vYmFyYmF6cXV4MTIzNA", 12,
		"18f89dad2df98792fd8af9ecc7476adccfeeb6833e0ab4f160abd8553eabd629")
	if s != "perch-terminal-v1\nPOST\n/portal/v1/terminal/coins\n4\nZm9vYmFyYmF6cXV4MTIzNA\n12\n18f89dad2df98792fd8af9ecc7476adccfeeb6833e0ab4f160abd8553eabd629" {
		t.Fatalf("%q", s)
	}
	got := SignTerminalRequest("perch_pt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "POST", "/portal/v1/terminal/coins", 4,
		"Zm9vYmFyYmF6cXV4MTIzNA", 12, []byte(body))
	if got != "j-IqTTtDgwOwIyJZOYnyPQKsmZS_cvs-iOIo7RAOcWM" {
		t.Fatalf("sig %s", got)
	}
}

func TestHotspotTexts(t *testing.T) {
	cases := map[string]string{
		MoneyText(5, "PHP", 0):     "PHP 5",
		MoneyText(525, "PHP", 2):   "PHP 5.25",
		MoneyText(5, "USD", 2):     "USD 0.05",
		DurationText(0):            "0 min",
		DurationText(61):           "2 min",
		DurationText(3600):         "1 h",
		DurationText(4800):         "1 h 20 min",
		DurationText(86400 + 7200): "1 d 2 h",
		BytesText(999):             "999 B",
		BytesText(500_000_000):     "500 MB",
		BytesText(1_500_000_000):   "1.5 GB",
		SpeedText(5000):            "5 Mbit/s",
		SpeedText(512):             "512 kbit/s",
		EntitlementText(4800, i64(500_000_000), i64(5000)): "1 h 20 min · 500 MB · 5 Mbit/s down",
		ReceiptTimeText(1790000042000):                     "2026-09-21 14:14 UTC",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
	r := PriceEntitlement(vectorTable(), 0)
	if PreviewText(r, "PHP", 0) != "Insert coins" {
		t.Fatal(PreviewText(r, "PHP", 0))
	}
	only := vectorTable()
	only.Entries = only.Entries[1:2]
	if s := PreviewText(PriceEntitlement(only, 3), "PHP", 0); s != "Not enough for a rate yet" {
		t.Fatal(s)
	}
	if s := PreviewText(PriceEntitlement(only, 7), "PHP", 0); s != "1 h · 5 Mbit/s down (PHP 2 unused)" {
		t.Fatal(s)
	}
}
