package controller

import (
	"context"

	"github.com/capthndsme/perch-agentkit/rpc"
	"github.com/capthndsme/perch-agentkit/update"
)

// Updater is agent self-update (the kit's update.Updater, wired in
// main_update.go) as the session loop sees it (agent-updates protocol.md
// sections 3-5): the hello's update block and capability, the
// agent.update.* methods, and a sink for its notifications while a session
// is open (unacknowledged results are sent again on each).
type Updater interface {
	Status(ctx context.Context) update.Status
	Capability() string
	Register(d *rpc.Dispatcher)
	SessionOpened(notify func(method string, params any) error)
	SessionClosed()
}

// registerUpdate installs agent.update.* when the collector has an updater.
func (c *Client) registerUpdate() {
	if c.o.Update != nil {
		c.o.Update.Register(c.dispatcher)
	}
}

// updateHello is the hello's update block and capability: the block always
// (its refusal says why nothing can be installed), agent_update only when
// nothing refuses.
func (c *Client) updateHello(ctx context.Context, p *helloParams) {
	if c.o.Update == nil {
		return
	}
	st := c.o.Update.Status(ctx)
	p.Update = &st
	if capability := c.o.Update.Capability(); capability != "" {
		p.Capabilities = append(p.Capabilities, capability)
	}
}

// updateSession gives the updater the session once its hello was accepted
// (results and progress go there); the returned func takes it back.
func (c *Client) updateSession(notify func(method string, params any) error) func() {
	if c.o.Update == nil {
		return func() {}
	}
	c.o.Update.SessionOpened(notify)
	return c.o.Update.SessionClosed
}
