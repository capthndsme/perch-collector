package portal

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/capthndsme/perch-agentkit/rpc"
)

// Capability is the hello capability of the portal.
const Capability = "portal"

// Register adds the portal's requests to the collector's dispatcher
// (controller → collector):
//
//	portal.configure   Config          → ConfigureResult
//	portal.template    TemplateParams  → {stored: true}
//	portal.authorize   AuthorizeParams → AuthorizeResult
//	portal.deauthorize DeauthorizeParams → DeauthorizeResult
//	portal.vouchers    VouchersParams  → VouchersResult
//	portal.sync        SyncParams      → SyncResult
//
// The collector's requests to the controller are portal.redeem,
// portal.login and portal.relay; its notifications portal.event and
// portal.sessions.
func (e *Engine) Register(d *rpc.Dispatcher) {
	d.Register("portal.configure", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p Config
		if err := rpc.Params(raw, &p); err != nil {
			return nil, err
		}
		return e.Configure(ctx, p)
	})
	d.Register("portal.template", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p TemplateParams
		if err := rpc.Params(raw, &p); err != nil {
			return nil, err
		}
		return e.StoreTemplate(ctx, p)
	})
	d.Register("portal.authorize", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p AuthorizeParams
		if err := rpc.Params(raw, &p); err != nil {
			return nil, err
		}
		return e.Authorize(ctx, p)
	})
	d.Register("portal.deauthorize", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p DeauthorizeParams
		if err := rpc.Params(raw, &p); err != nil {
			return nil, err
		}
		return e.Deauthorize(ctx, p)
	})
	d.Register("portal.vouchers", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p VouchersParams
		if err := rpc.Params(raw, &p); err != nil {
			return nil, err
		}
		return e.Vouchers(ctx, p)
	})
	d.Register("portal.sync", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p SyncParams
		if err := rpc.Params(raw, &p); err != nil {
			return nil, err
		}
		return e.Sync(ctx, p)
	})
}

// LeaseHostnames reads host names from a dnsmasq leases file
// (/tmp/dhcp.leases): "<expiry> <mac> <ip> <hostname> <client-id>".
func LeaseHostnames(path string) func(mac string) string {
	return func(mac string) string {
		f, err := os.Open(path)
		if err != nil {
			return ""
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 4 && strings.EqualFold(fields[1], mac) && fields[3] != "*" {
				h := fields[3]
				if len(h) > 64 {
					h = h[:64]
				}
				return h
			}
		}
		return ""
	}
}
