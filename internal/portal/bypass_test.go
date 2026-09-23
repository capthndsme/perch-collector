package portal

import (
	"context"
	"testing"
)

// Device-group members with a portal bypass (controller
// docs/gateway/device-groups.md section 6): authorised without a grant,
// never external, put back when removed outside Perch, gone when the
// controller drops them.
func TestBypassMACs(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	p := guestPortal(3)
	p.Bypass = []string{"02:00:00:00:20:12", "not-a-mac"}
	cfg := c.configure(p)
	cfg.Revision = 2
	if _, err := e.Configure(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if !sys.has("inet", "p3_auth", macG2) || !sys.has("acct", "p3_ok", macG2) {
		t.Fatal("bypass MAC not authorised")
	}
	e.Tick(ctx)
	if len(eventsOf(e, EvExternalAuth)) != 0 {
		t.Fatal("a bypass MAC read as an outside authorisation")
	}
	// Removed by hand on the router: back in on the next tick.
	sys.setElem("inet", "p3_auth", macG2, false)
	e.Tick(ctx)
	if !sys.has("inet", "p3_auth", macG2) {
		t.Fatal("bypass MAC not put back")
	}
	// The controller drops it.
	cfg = c.configure(guestPortal(3))
	cfg.Revision = 3
	if _, err := e.Configure(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if sys.has("inet", "p3_auth", macG2) {
		t.Fatal("dropped bypass MAC still authorised")
	}
}
