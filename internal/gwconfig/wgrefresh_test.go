package gwconfig

import (
	"strings"
	"testing"
	"time"
)

func ifups(e *env, iface string) int {
	n := 0
	for _, c := range e.router.log() {
		if c == "/sbin/ifup "+iface {
			n++
		}
	}
	return n
}

// A peer is its own section, which netifd's reload does not compare: the
// plane sets its interface up again after the commit and after a rollback.
func TestPeerChangesSetTheInterfaceUpAgain(t *testing.T) {
	e := newEnv(t)
	js := `{"applyId":"w1","base":` + mustJSON(e.base("network")) + `,"ops":[{"op":"put","config":"network","section":"perch_p1",
	  "type":"wireguard_wg0","options":{"public_key":"` + strings.Repeat("x", 42) + `E=","allowed_ips":["10.7.0.2/32"]}}],
	  "ledger":{"set":[{"perchId":"p1","config":"network","section":"perch_p1","domain":"wireguard"}]}}`
	if _, err := e.apply(js); err != nil {
		t.Fatal(err)
	}
	e.waitReconnect()
	if n := ifups(e, "wg0"); n != 1 {
		t.Fatalf("ifup wg0 after the commit: %d\n%s", n, strings.Join(e.router.log(), "\n"))
	}
	// Not confirmed: the rollback takes the peer away, and wg0 is set up again.
	e.clock.Advance(91 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for ifups(e, "wg0") < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := ifups(e, "wg0"); n != 2 {
		t.Fatalf("ifup wg0 after the rollback: %d", n)
	}

	// An apply without peers leaves every interface alone.
	e2 := newEnv(t)
	if _, err := e2.apply(reservationJSON(e2, "a1")); err != nil {
		t.Fatal(err)
	}
	e2.waitReconnect()
	for _, c := range e2.router.log() {
		if strings.HasPrefix(c, "/sbin/ifup") {
			t.Fatal(c)
		}
	}
}
