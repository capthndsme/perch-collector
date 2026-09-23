package controller

// The config plane on the collector socket (plan 1 section 4 of the managed
// gateway; ARCHITECTURE.md "Config plane"): the gateway_config capability,
// the hello's gatewayConfig block, agent.configure's gatewayConfig, the
// read-only requests gateway.capabilities and gateway.config.read, and the
// gateway.config.changed notification. Everything is additive: an older
// controller drops the unknown hello key, sends no gatewayConfig, and never
// calls the methods.

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/capthndsme/perch-agentkit/link"
	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/gwconfig"
)

// CapabilityGatewayConfig is announced when the collector serves the config
// plane (on OpenWrt; whatever the router's config_access, which the hello
// block states).
const CapabilityGatewayConfig = "gateway_config"

// Config plane methods and notifications.
const (
	MethodGatewayCapabilities = "gateway.capabilities"
	MethodGatewayConfigRead   = "gateway.config.read"
	NotifyGatewayConfigChange = "gateway.config.changed"
)

func (c *Client) registerConfigPlane() {
	if c.o.Config == nil {
		return
	}
	c.dispatcher.Register(MethodGatewayCapabilities, c.handleGatewayCapabilities)
	c.dispatcher.Register(MethodGatewayConfigRead, c.handleGatewayConfigRead)
}

// configCapabilities are the hello capabilities of the config plane.
func (c *Client) configCapabilities() []string {
	if c.o.Config == nil {
		return nil
	}
	return []string{CapabilityGatewayConfig}
}

// configHello is the hello's gatewayConfig block; its hashes become the
// baseline of change notifications for the session.
func (c *Client) configHello() *gwconfig.Hello {
	if c.o.Config == nil {
		return nil
	}
	return c.o.Config.Hello()
}

// startConfigPlane runs the change watcher for the client's lifetime.
func (c *Client) startConfigPlane(ctx context.Context) {
	if c.o.Config == nil {
		return
	}
	go c.o.Config.Run(ctx, c.notifyConfigChanged)
}

// configConfigure applies agent.configure's gatewayConfig block. Absent
// (an older controller) leaves the plane as it is: off until told.
func (c *Client) configConfigure(raw json.RawMessage) {
	if c.o.Config == nil || len(raw) == 0 || string(raw) == "null" {
		return
	}
	var gc gwconfig.Configure
	if err := json.Unmarshal(raw, &gc); err != nil {
		c.log.Warn("bad gatewayConfig in agent.configure", "err", err)
		return
	}
	before := c.o.Config.Mode()
	c.o.Config.Configure(gc)
	if after := c.o.Config.Mode(); after != before {
		log.Printf("controller: gateway config mode %s (router access %s)", after, c.o.Config.Access())
	}
}

// configSessionOpened makes s the session change notifications go to.
func (c *Client) configSessionOpened(gen uint64, s *link.Session) {
	if c.o.Config == nil {
		return
	}
	c.mu.Lock()
	if gen == c.gen {
		c.configSession = s
	}
	c.mu.Unlock()
}

// configSessionEnded forgets the session; the controller's mode for the
// next one comes with its agent.configure.
func (c *Client) configSessionEnded() {
	if c.o.Config == nil {
		return
	}
	c.mu.Lock()
	c.configSession = nil
	c.mu.Unlock()
	c.o.Config.Configure(gwconfig.Configure{Mode: gwconfig.ModeOff})
}

// notifyConfigChanged sends gateway.config.changed on the current session.
func (c *Client) notifyConfigChanged(ch gwconfig.Changed) bool {
	c.mu.Lock()
	s := c.configSession
	c.mu.Unlock()
	if s == nil {
		return false
	}
	if err := s.Notify(NotifyGatewayConfigChange, ch); err != nil {
		c.log.Debug("gateway.config.changed not sent", "err", err)
		return false
	}
	log.Printf("controller: gateway config changed on the router: %v (%s, %s)", ch.Changed, ch.Origin, ch.Author.Kind)
	return true
}

func (c *Client) handleGatewayCapabilities(ctx context.Context, _ json.RawMessage) (any, error) {
	return c.o.Config.Capabilities(ctx), nil
}

type configReadParams struct {
	Configs []string `json:"configs"`
}

func (c *Client) handleGatewayConfigRead(_ context.Context, params json.RawMessage) (any, error) {
	var p configReadParams
	if len(params) > 0 && string(params) != "null" {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "params: %v", err)
		}
	}
	res, err := c.o.Config.Read(p.Configs)
	if err != nil {
		return nil, configRPCError(err)
	}
	return res, nil
}

// configRPCError maps a plane refusal onto -32000 with data.error, the
// hello's convention (collector-agent.md section 3.2).
func configRPCError(err error) error {
	var ae *gwconfig.AccessError
	if errors.As(err, &ae) {
		data := map[string]any{"error": ae.Code.Error()}
		if len(ae.Configs) > 0 {
			data["configs"] = ae.Configs
		}
		return &rpc.Error{Code: rpc.CodeCommandFailed, Message: ae.Message, Data: data}
	}
	return &rpc.Error{Code: rpc.CodeCommandFailed, Message: err.Error(), Data: map[string]any{"error": "read_failed"}}
}
