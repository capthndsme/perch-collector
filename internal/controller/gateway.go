package controller

// The managed gateway's observation channel and runtime actions on the
// collector socket (gateway plan 2 sections 3 and 4.3; docs in
// ARCHITECTURE.md "Observation channel"):
//
//   - collector.push carries `observe`, one key per part, each present only
//     when its fingerprint changed, in a session's first push and every
//     refresh (observe.Pacer);
//   - gateway.observe {parts?} answers the same section on demand, fresh;
//   - net.conntrack_flush {ips, proto?, dryRun?} deletes conntrack entries;
//   - gateway.backup {redact?} returns a sysupgrade -b archive.
//
// Kept apart from controller.go so the config plane's additions to the
// hello and the dispatcher stay separate.

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/gatewayops"
	"github.com/capthndsme/perch-collector/internal/observe"
)

// Capabilities of this file's features.
const (
	CapabilityGatewayObserve = "gateway.observe"
	CapabilityConntrackFlush = "net.conntrack_flush"
	CapabilityGatewayBackup  = "gateway.backup"
)

// JSON-RPC error codes (section 3.2's convention: -32000 with data.error).
const (
	codeInvalidParams = -32602
	codeNotSupported  = -32001
	codeFailed        = -32000
)

// Observation is what the push reads the parts from; *observe.Observer.
type Observation interface {
	Parts() []observe.Part
	Read(p observe.Part, fresh bool) (observe.Item, bool)
}

// dhcpOnly adapts the older Source.DHCP function.
type dhcpOnly func() (*observe.DHCP, string)

func (d dhcpOnly) Parts() []observe.Part { return []observe.Part{observe.PartDHCP} }

func (d dhcpOnly) Read(p observe.Part, _ bool) (observe.Item, bool) {
	if p != observe.PartDHCP {
		return observe.Item{}, false
	}
	v, fp := d()
	if v == nil {
		return observe.Item{}, false
	}
	return observe.Item{Value: v, FP: fp}, true
}

// observation is the source of the parts: Source.Observe, else the DHCP
// function alone, else nil.
func (c *Client) observation() Observation {
	if c.o.Source.Observe != nil {
		return c.o.Source.Observe
	}
	if c.o.Source.DHCP != nil {
		return dhcpOnly(c.o.Source.DHCP)
	}
	return nil
}

// gatewayCapabilities are the hello's capabilities of this file.
func (c *Client) gatewayCapabilities() []string {
	var caps []string
	if obs := c.observation(); obs != nil {
		for _, p := range obs.Parts() {
			caps = append(caps, p.Capability())
		}
		if c.o.Source.Observe != nil {
			caps = append(caps, CapabilityGatewayObserve)
		}
	}
	if c.o.Conntrack != nil {
		caps = append(caps, CapabilityConntrackFlush)
	}
	if c.o.Backup != nil {
		caps = append(caps, CapabilityGatewayBackup)
	}
	return caps
}

// registerGateway adds this file's requests to the dispatcher.
func (c *Client) registerGateway() {
	c.pacer = &observe.Pacer{Refresh: c.o.ObserveRefresh, RefreshOf: map[observe.Part]time.Duration{}}
	dhcp := c.o.DHCPRefresh
	if dhcp <= 0 {
		dhcp = DefaultDHCPRefresh
	}
	c.pacer.RefreshOf[observe.PartDHCP] = dhcp
	if c.o.Source.Observe != nil {
		c.dispatcher.Register("gateway.observe", c.handleObserve)
	}
	if c.o.Conntrack != nil {
		c.dispatcher.Register("net.conntrack_flush", c.handleConntrackFlush)
	}
	if c.o.Backup != nil {
		c.dispatcher.Register("gateway.backup", c.handleBackup)
	}
}

// observeFor builds the `observe` section of a push of session gen, and a
// commit to call once the push went out; nil when no part is due.
func (c *Client) observeFor(gen uint64) (*observe.Section, func()) {
	obs := c.observation()
	if obs == nil {
		return nil, nil
	}
	now := time.Now()
	sec := &observe.Section{}
	type due struct {
		part observe.Part
		fp   string
	}
	var sent []due
	all := true
	for _, p := range obs.Parts() {
		item, ok := obs.Read(p, false)
		if !ok {
			continue // nothing to report: absent, the controller keeps its data
		}
		if !c.pacer.Due(gen, p, item.FP, now) {
			all = false
			continue
		}
		sec.Set(p, item.Value)
		sent = append(sent, due{p, item.FP})
	}
	if len(sent) == 0 {
		return nil, nil
	}
	sec.Full = all
	return sec, func() {
		for _, d := range sent {
			c.pacer.Sent(gen, d.part, d.fp, now)
		}
	}
}

type observeParams struct {
	Parts []string `json:"parts"`
}

func (c *Client) handleObserve(_ context.Context, raw json.RawMessage) (any, error) {
	var p observeParams
	if len(raw) > 0 && string(raw) != "null" {
		if err := rpc.Params(raw, &p); err != nil {
			return nil, rpc.Errorf(codeInvalidParams, "bad params: %v", err)
		}
	}
	var parts []observe.Part
	if p.Parts != nil {
		parts = []observe.Part{}
		for _, s := range p.Parts {
			// Unknown parts are ignored: a newer controller may ask for
			// parts this collector does not have.
			if part, ok := observe.ParsePart(s); ok {
				parts = append(parts, part)
			}
		}
	}
	obs, ok := c.o.Source.Observe.(interface {
		Section(parts []observe.Part, fresh bool) *observe.Section
	})
	var sec *observe.Section
	if ok {
		sec = obs.Section(parts, true)
	} else {
		sec = &observe.Section{}
		for _, part := range c.o.Source.Observe.Parts() {
			if parts == nil || containsPart(parts, part) {
				if item, ok := c.o.Source.Observe.Read(part, true); ok {
					sec.Set(part, item.Value)
				}
			}
		}
		sec.Full = parts == nil
	}
	sec.CollectedAt = time.Now().UTC().Format(time.RFC3339)
	return sec, nil
}

func containsPart(list []observe.Part, p observe.Part) bool {
	for _, q := range list {
		if q == p {
			return true
		}
	}
	return false
}

func (c *Client) handleConntrackFlush(_ context.Context, raw json.RawMessage) (any, error) {
	var p gatewayops.FlushParams
	if err := rpc.Params(raw, &p); err != nil {
		return nil, rpc.Errorf(codeInvalidParams, "bad params: %v", err)
	}
	res, err := c.o.Conntrack.Flush(p)
	if err != nil {
		var pe *gatewayops.ParamError
		if errors.As(err, &pe) {
			e := rpc.Errorf(codeInvalidParams, "%s", pe.Message)
			e.Data = map[string]any{"error": pe.Code}
			return nil, e
		}
		return nil, rpc.Errorf(codeFailed, "%v", err)
	}
	if res.Flushed && !res.DryRun {
		c.log.Info("conntrack flushed", "ips", len(p.IPs), "deleted", res.Deleted, "skipped", res.Skipped)
	}
	return res, nil
}

func (c *Client) handleBackup(ctx context.Context, raw json.RawMessage) (any, error) {
	var p gatewayops.BackupParams
	if len(raw) > 0 && string(raw) != "null" {
		if err := rpc.Params(raw, &p); err != nil {
			return nil, rpc.Errorf(codeInvalidParams, "bad params: %v", err)
		}
	}
	res, err := c.o.Backup.Backup(ctx, p)
	if err != nil {
		var be *gatewayops.BackupError
		if errors.As(err, &be) {
			e := rpc.Errorf(codeFailed, "%s", be.Message)
			e.Data = map[string]any{"error": be.Code}
			return nil, e
		}
		return nil, rpc.Errorf(codeFailed, "%v", err)
	}
	c.log.Info("backup taken", "bytes", res.Size, "redacted", res.Redacted)
	return res, nil
}

// connectionEndpoints are the local and remote address of the current
// controller connection, for the conntrack flush's self-protection.
func (c *Client) connectionEndpoints() (netip.AddrPort, netip.AddrPort) {
	if c.dialer == nil {
		return netip.AddrPort{}, netip.AddrPort{}
	}
	return c.dialer.endpoints()
}
