package controller

// The config plane on the collector socket (plan 1 section 4 of the managed
// gateway; ARCHITECTURE.md "Config plane"): the gateway_config capability,
// the hello's gatewayConfig block, agent.configure's gatewayConfig, the
// requests gateway.capabilities, gateway.config.read and the write methods
// (apply, confirm, rollback, ack, package install), the pairing methods
// (gateway.pair.*, pair.go), and the notifications gateway.config.changed,
// gateway.config.result, gateway.config.checks and gateway.pair.state. Everything is additive:
// an older controller drops the unknown hello key, sends no gatewayConfig,
// and never calls the methods.
//
// An apply ends its session on purpose: once the reload settled, the plane
// asks for a fresh connection (a surviving TCP connection proves nothing
// about DNS, routing, the firewall or TLS), and the controller confirms on
// the new session. While an apply waits for that, and for a while after a
// rollback, the loop redials every applyRedial.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/coder/websocket"

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

// Redial waits around an apply.
const (
	// applyRedialFirst: the first dial after the plane dropped the session.
	applyRedialFirst = 250 * time.Millisecond
	// applyRedial: retries while an apply waits for its confirm (plan 1
	// section 3.4 step 5: every 2 s until the deadline).
	applyRedial = 2 * time.Second
)

func (c *Client) registerConfigPlane() {
	if c.o.Config == nil {
		return
	}
	c.dispatcher.Register(MethodGatewayCapabilities, c.handleGatewayCapabilities)
	c.dispatcher.Register(MethodGatewayConfigRead, c.handleGatewayConfigRead)
	for _, m := range gwconfig.WriteMethods {
		method := m
		c.dispatcher.Register(method, func(ctx context.Context, params json.RawMessage) (any, error) {
			res, err := c.o.Config.ServeWrite(ctx, method, params, c.sessionRef(ctx))
			if err != nil {
				return nil, configRPCError(err)
			}
			return res, nil
		})
	}
	for _, m := range gwconfig.PairMethods {
		method := m
		c.dispatcher.Register(method, func(ctx context.Context, params json.RawMessage) (any, error) {
			res, err := c.o.Config.ServePair(ctx, method, params, c.sessionRef(ctx))
			if err != nil {
				return nil, configRPCError(err)
			}
			return res, nil
		})
	}
	c.o.Config.SetHooks(gwconfig.Hooks{Reconnect: c.reconnectAfterApply, Result: c.notifyResult, PairState: c.notifyPairState,
		Checks: c.notifyChecks})
}

// configCapabilities are the hello capabilities of the config plane.
func (c *Client) configCapabilities() []string {
	if c.o.Config == nil {
		return nil
	}
	return []string{CapabilityGatewayConfig}
}

// configSessionStarting records a session before its hello: requests are
// matched to it by their context (the kit serves them with the session's).
func (c *Client) configSessionStarting(gen uint64, s *link.Session) string {
	if c.o.Config == nil {
		return ""
	}
	challenge := gwconfig.NewChallenge()
	c.mu.Lock()
	if gen == c.gen {
		c.sessCtx, c.sessChallenge = s.Context(), challenge
	}
	c.mu.Unlock()
	return challenge
}

// sessionRef identifies the session a request came in on: its number
// (counting from 1) and signing challenge; zero for a session that ended.
func (c *Client) sessionRef(ctx context.Context) gwconfig.SessionRef {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessCtx != nil && ctx == c.sessCtx {
		return gwconfig.SessionRef{Gen: c.gen + 1, Challenge: c.sessChallenge}
	}
	return gwconfig.SessionRef{}
}

// configHello is the hello's gatewayConfig block; its hashes become the
// baseline of change notifications for the session.
func (c *Client) configHello(ctx context.Context, challenge string) *gwconfig.Hello {
	if c.o.Config == nil {
		return nil
	}
	return c.o.Config.Hello(ctx, challenge)
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

// configSessionOpened makes s the session notifications go to.
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
	c.configSession, c.sessCtx, c.sessChallenge = nil, nil, ""
	c.mu.Unlock()
	c.o.Config.Configure(gwconfig.Configure{Mode: gwconfig.ModeOff})
}

// reconnectAfterApply is the plane's Reconnect hook: close the session
// (1000) and dial a fresh one at once.
func (c *Client) reconnectAfterApply(reason string) {
	c.mu.Lock()
	s := c.configSession
	c.redialNow = true
	c.mu.Unlock()
	if s == nil {
		return // no session: the loop is dialing already
	}
	log.Printf("controller: %s: dropping the session to dial a fresh one", reason)
	s.Close(websocket.StatusNormalClosure, "reconnecting after apply")
}

// applyRedialWait adjusts the wait before the next dial around an apply.
func (c *Client) applyRedialWait(o outcome) outcome {
	if c.o.Config == nil {
		return o
	}
	c.mu.Lock()
	now := c.redialNow
	c.redialNow = false
	c.mu.Unlock()
	if now {
		return outcome{wait: applyRedialFirst, note: "dialing a fresh connection after a config apply"}
	}
	// Refusals that retrying cannot fix keep their slow retry.
	if c.o.Config.RedialFast() && o.wait > applyRedial && o.wait < slowRetry {
		o.wait = applyRedial
	}
	return o
}

// notifyResult is the plane's Result hook: gateway.config.result.
func (c *Client) notifyResult(r gwconfig.Result) bool {
	c.mu.Lock()
	s := c.configSession
	c.mu.Unlock()
	if s == nil {
		return false
	}
	if err := s.Notify(gwconfig.NotifyResult, r); err != nil {
		c.log.Debug("gateway.config.result not sent", "err", err)
		return false
	}
	return true
}

// notifyChecks is the plane's Checks hook: gateway.config.checks.
func (c *Client) notifyChecks(n gwconfig.ChecksNote) bool {
	c.mu.Lock()
	s := c.configSession
	c.mu.Unlock()
	if s == nil {
		return false
	}
	if err := s.Notify(gwconfig.NotifyChecks, n); err != nil {
		c.log.Debug("gateway.config.checks not sent", "err", err)
		return false
	}
	return true
}

// notifyPairState is the plane's PairState hook: gateway.pair.state.
func (c *Client) notifyPairState(n gwconfig.PairStateNote) bool {
	c.mu.Lock()
	s := c.configSession
	c.mu.Unlock()
	if s == nil {
		return false
	}
	if err := s.Notify(gwconfig.NotifyPairState, n); err != nil {
		c.log.Debug("gateway.pair.state not sent", "err", err)
		return false
	}
	return true
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
	return c.o.Config.Capabilities(ctx, c.sessionRef(ctx).Challenge), nil
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
// hello's convention (collector-agent.md section 3.2); bad params are
// -32602.
func configRPCError(err error) error {
	var ae *gwconfig.AccessError
	if errors.As(err, &ae) {
		data := map[string]any{"error": ae.Code.Error()}
		if len(ae.Configs) > 0 {
			data["configs"] = ae.Configs
		}
		return &rpc.Error{Code: rpc.CodeCommandFailed, Message: ae.Message, Data: data}
	}
	var pe *gwconfig.PlaneError
	if errors.As(err, &pe) {
		data := map[string]any{"error": pe.Code}
		for k, v := range pe.Data {
			data[k] = v
		}
		code := rpc.CodeCommandFailed
		if pe.Code == gwconfig.CodeBadParams {
			code = rpc.CodeInvalidParams
		}
		return &rpc.Error{Code: code, Message: pe.Message, Data: data}
	}
	return &rpc.Error{Code: rpc.CodeCommandFailed, Message: err.Error(), Data: map[string]any{"error": "failed"}}
}
