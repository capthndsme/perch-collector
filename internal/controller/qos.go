package controller

// Traffic shaping on the collector socket (gateway plan 3 section 6,
// metrics-be docs/gateway/qos.md; details in ARCHITECTURE.md "Traffic
// shaping"):
//
//   - hello capability "qos" while perch-qos is installed;
//   - qos.probe → what the router can do (kernel features by trial, sqm,
//     conflicts, flow offload, the LANs);
//   - qos.devices.set {revision, devices} → {revision, accepted, rejected};
//   - qos.status → the push section plus the last apply;
//   - collector.push carries `qos` (absent = not reported);
//   - the agent notifies qos.event {type, at, mac?, detail?}.

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/capthndsme/perch-agentkit/link"
	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/qos"
)

// CapabilityQoS is announced while perch-qos is installed.
const CapabilityQoS = "qos"

// codeQoSNotActive is qos.devices.set's refusal while perch-qos is not
// set up on this router (plan 3 section 6).
const codeQoSNotActive = -32010

// QoS is the shaper the socket serves; *qos.Engine.
type QoS interface {
	Configured() bool
	Probe(ctx context.Context) qos.ProbeResult
	SetDevices(p qos.DevicesSetParams) (qos.DevicesSetResult, error)
	Section() *qos.Section
	StatusReport() qos.Status
	Notify() <-chan struct{}
	DrainEvents() []qos.Event
}

func (c *Client) qosOn() bool {
	if c.o.QoS == nil {
		return false
	}
	if c.o.QoSAllowed != nil && !c.o.QoSAllowed() {
		return false
	}
	return c.o.QoS.Configured()
}

func (c *Client) registerQoS() {
	if c.o.QoS == nil {
		return
	}
	c.dispatcher.Register("qos.probe", c.handleQoSProbe)
	c.dispatcher.Register("qos.devices.set", c.handleQoSDevicesSet)
	c.dispatcher.Register("qos.status", c.handleQoSStatus)
}

func qosNotActive() error {
	e := rpc.Errorf(codeQoSNotActive, "traffic shaping is not set up on this router (perch-qos is not installed, or not allowed)")
	e.Data = map[string]any{"error": "qos_not_active"}
	return e
}

func (c *Client) handleQoSProbe(ctx context.Context, _ json.RawMessage) (any, error) {
	if c.o.QoSAllowed != nil && !c.o.QoSAllowed() {
		return nil, qosNotActive()
	}
	return c.o.QoS.Probe(ctx), nil
}

func (c *Client) handleQoSDevicesSet(_ context.Context, raw json.RawMessage) (any, error) {
	if !c.qosOn() {
		return nil, qosNotActive()
	}
	var p qos.DevicesSetParams
	if err := rpc.Params(raw, &p); err != nil {
		return nil, rpc.Errorf(codeInvalidParams, "bad params: %v", err)
	}
	if p.Devices == nil {
		return nil, rpc.Errorf(codeInvalidParams, "devices is required")
	}
	res, err := c.o.QoS.SetDevices(p)
	if errors.Is(err, qos.ErrNotActive) {
		return nil, qosNotActive()
	}
	if err != nil {
		return nil, rpc.Errorf(codeInvalidParams, "%v", err)
	}
	c.log.Info("qos device set", "revision", res.Revision, "accepted", res.Accepted, "rejected", len(res.Rejected))
	return res, nil
}

func (c *Client) handleQoSStatus(context.Context, json.RawMessage) (any, error) {
	if !c.qosOn() {
		return nil, qosNotActive()
	}
	return c.o.QoS.StatusReport(), nil
}

// qosSection is the push's `qos`, nil when not reported.
func (c *Client) qosSection() *qos.Section {
	if !c.qosOn() {
		return nil
	}
	return c.o.QoS.Section()
}

// forwardQoSEvents sends the shaper's events on the session until it ends.
// Events raised while no session was open wait in the engine's queue.
func (c *Client) forwardQoSEvents(ctx context.Context, s *link.Session) {
	if c.o.QoS == nil {
		return
	}
	send := func() {
		for _, ev := range c.o.QoS.DrainEvents() {
			if err := s.Notify("qos.event", ev); err != nil {
				c.log.Debug("qos.event not sent", "type", ev.Type, "err", err)
			}
		}
	}
	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.o.QoS.Notify():
			send()
		}
	}
}
