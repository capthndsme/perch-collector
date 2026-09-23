package portal

import (
	"context"
	"fmt"
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

// Decision 31: a portal user's sign-in that moved the device into its
// device group's own network carries no grant; the guest page says the
// device is moving, and nothing is authorised here.
func TestLoginBoundToGroupNetwork(t *testing.T) {
	e, sys, c, _ := configured(t)
	ctx := context.Background()
	p := guestPortal(3)
	p.Methods.Password = true
	cfg := c.configure(p)
	cfg.Revision = 2
	if _, err := e.Configure(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.SetAgent(&fakeAgent{handler: func(method string, params, result any) error {
		if method != "portal.login" {
			return fmt.Errorf("unexpected %s", method)
		}
		*(result.(*RedeemResult)) = RedeemResult{Bound: &BoundGroup{GroupID: 5, GroupName: "Unit 101", Moved: true}}
		return nil
	}})
	out := e.Login(ctx, Client{PortalID: 3, MAC: macG1, IP: "192.168.20.111"}, "tenant", "secret-pass", false)
	if !out.OK || out.Code != "moving" {
		t.Fatalf("outcome %+v", out)
	}
	if sys.has("inet", "p3_auth", macG1) {
		t.Fatal("a moved device was authorised on the onboarding portal")
	}
}
