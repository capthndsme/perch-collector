//go:build ndpi
// +build ndpi

package classifier

import "testing"

// Runs only with `-tags ndpi`: the category table must come out of the real
// library with our label namespace applied.
func TestNDPIProtocolCategories(t *testing.T) {
	c, err := NewNDPIClassifier(1000, 60)
	if err != nil {
		t.Skipf("nDPI unavailable: %v", err)
	}
	defer c.Close()

	list := c.ProtocolCategories()
	if len(list) < 100 {
		t.Fatalf("expected the library's protocol table, got %d entries", len(list))
	}
	got := make(map[string]string, len(list))
	for _, pc := range list {
		if pc.Protocol == "" || pc.Category == "" {
			t.Fatalf("empty label or category in %+v", pc)
		}
		if _, dup := got[pc.Protocol]; dup {
			t.Fatalf("duplicate label %q", pc.Protocol)
		}
		got[pc.Protocol] = pc.Category
	}
	// Our label namespace, not nDPI's ("https" not "tls"), with the
	// library's own category for it.
	for _, label := range []string{"https", "http", "dns", "youtube", "netflix", "ssh", "bittorrent"} {
		if _, ok := got[label]; !ok {
			t.Errorf("label %q missing from the category table", label)
		}
	}
	if got["dns"] != "network" {
		t.Errorf("dns category = %q, want network", got["dns"])
	}
	if got["https"] != "web" {
		t.Errorf("https category = %q, want web", got["https"])
	}
	if got["ssh"] != "remote-access" {
		t.Errorf("ssh category = %q, want remote-access", got["ssh"])
	}
	t.Logf("%d labels; youtube=%s netflix=%s bittorrent=%s", len(list), got["youtube"], got["netflix"], got["bittorrent"])
}
