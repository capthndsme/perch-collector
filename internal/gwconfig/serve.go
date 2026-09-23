package gwconfig

import (
	"context"
	"encoding/json"
	"fmt"
)

// Write methods of the config plane (plan 1 section 4; the package job from
// README 7.7).
const (
	MethodApply          = "gateway.config.apply"
	MethodConfirm        = "gateway.config.confirm"
	MethodRollback       = "gateway.config.rollback"
	MethodAck            = "gateway.config.ack"
	MethodPackageInstall = "gateway.package.install"
	// NotifyResult is the agent's gateway.config.result notification.
	NotifyResult = "gateway.config.result"
)

// WriteMethods are the methods ServeWrite handles.
var WriteMethods = []string{MethodApply, MethodConfirm, MethodRollback, MethodAck, MethodPackageInstall}

// ServeWrite runs one write method: unwrap a signed envelope, check the
// write gate (access write; verified TLS, or the router's opt-in and a
// valid signature), decode the params and run the method.
func (p *Plane) ServeWrite(ctx context.Context, method string, raw json.RawMessage, sess SessionRef) (any, error) {
	// Refusals by the router's settings come before any signature check.
	if p.o.Access != AccessWrite || (!p.o.TransportOK && !p.o.AllowInsecure) {
		if err := p.writeGate(false); err != nil {
			return nil, err
		}
	}
	params, signed, err := p.Unwrap(method, raw, sess)
	if err != nil {
		return nil, err
	}
	if err := p.RequireWrite(signed); err != nil {
		return nil, err
	}
	decode := func(v any) error {
		if len(params) == 0 || string(params) == "null" {
			return perr(CodeBadParams, "params are required")
		}
		if err := json.Unmarshal(params, v); err != nil {
			return perr(CodeBadParams, "params: %v", err)
		}
		return nil
	}
	switch method {
	case MethodApply:
		var a ApplyParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.Apply(ctx, &a, sess, p.o.TransportOK)
	case MethodConfirm:
		var a ApplyIDParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.Confirm(a.ApplyID, sess)
	case MethodRollback:
		var a ApplyIDParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.RollbackNow(a.ApplyID)
	case MethodAck:
		var a AckParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.Ack(a.ApplyIDs)
	case MethodPackageInstall:
		var a PackageInstallParams
		if err := decode(&a); err != nil {
			return nil, err
		}
		return p.InstallPackages(ctx, &a, sess)
	}
	return nil, fmt.Errorf("gwconfig: %s is not a write method", method)
}
