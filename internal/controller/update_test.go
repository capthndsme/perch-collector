package controller

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/capthndsme/perch-agentkit/rpc"
	"github.com/capthndsme/perch-agentkit/update"
)

type fakeUpdater struct {
	capability string

	mu     sync.Mutex
	opened int
	closed int
}

func (f *fakeUpdater) Status(context.Context) update.Status {
	return update.Status{Protocol: 1, Enabled: true, InstallKind: update.InstallUnowned, Methods: []string{update.MethodBinary},
		Arch: "amd64", Results: []update.Result{}}
}
func (f *fakeUpdater) Capability() string { return f.capability }
func (f *fakeUpdater) Register(d *rpc.Dispatcher) {
	d.Register("agent.update.status", func(ctx context.Context, _ json.RawMessage) (any, error) { return f.Status(ctx), nil })
}
func (f *fakeUpdater) SessionOpened(notify func(string, any) error) {
	f.mu.Lock()
	f.opened++
	f.mu.Unlock()
	notify("agent.update.result", map[string]string{"updateId": "u-0000000000000001", "outcome": "rolled_back"})
}
func (f *fakeUpdater) SessionClosed() {
	f.mu.Lock()
	f.closed++
	f.mu.Unlock()
}

// The hello carries the update block and agent_update; once it is accepted
// the updater gets the session (its results go out), agent.update.* is
// served, and the session's end takes it back.
func TestHelloCarriesTheUpdateBlock(t *testing.T) {
	up := &fakeUpdater{capability: update.Capability}
	type helloUpdate struct {
		Capabilities []string       `json:"capabilities"`
		Update       *update.Status `json:"update"`
	}
	got := make(chan helloUpdate, 1)
	results := make(chan string, 1)
	statuses := make(chan string, 1)
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		var h helloUpdate
		json.Unmarshal(hello.Params, &h)
		got <- h
		answerHello(ctx, c, hello, "adopted")
		m, _ := next(t, frames, anyFrame, 3*time.Second)
		if m.Method == "agent.update.result" {
			results <- string(m.Params)
		}
		send(ctx, c, `{"jsonrpc":"2.0","id":7,"method":"agent.update.status","params":{}}`)
		r, _ := next(t, frames, responseFrame, 3*time.Second)
		statuses <- string(r.Result)
		c.Close(websocket.StatusNormalClosure, "done")
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	_, waits, stop := newTestClient(t, srv, func(o *Options) { o.Update = up })
	defer stop()

	h := <-got
	if h.Update == nil || h.Update.InstallKind != update.InstallUnowned || !slices.Contains(h.Capabilities, "agent_update") {
		t.Fatalf("hello %+v", h)
	}
	if r := <-results; r != `{"outcome":"rolled_back","updateId":"u-0000000000000001"}` {
		t.Fatalf("result %s", r)
	}
	var st update.Status
	if json.Unmarshal([]byte(<-statuses), &st) != nil || st.Arch != "amd64" {
		t.Fatal("agent.update.status not served")
	}
	<-waits
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.opened != 1 || up.closed != 1 {
		t.Fatalf("opened %d closed %d", up.opened, up.closed)
	}
}

// A refused updater (self_update off, no key…) still reports its block,
// without the capability; no updater, no block.
func TestHelloUpdateBlockWithoutCapability(t *testing.T) {
	for _, up := range []*fakeUpdater{{capability: ""}, nil} {
		got := make(chan string, 1)
		fc := &fakeController{t: t}
		fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
			got <- string(hello.Params)
			c.Close(websocket.StatusNormalClosure, "done")
		}
		srv := httptest.NewServer(fc)
		_, waits, stop := newTestClient(t, srv, func(o *Options) {
			if up != nil {
				o.Update = up
			}
		})
		var p map[string]any
		json.Unmarshal([]byte(<-got), &p)
		<-waits
		stop()
		srv.Close()
		_, hasBlock := p["update"]
		caps, _ := json.Marshal(p["capabilities"])
		if hasBlock != (up != nil) || slices.Contains(capsOf(caps), "agent_update") {
			t.Fatalf("updater %v: hello %v", up != nil, p)
		}
	}
}

func capsOf(b []byte) []string {
	var out []string
	json.Unmarshal(b, &out)
	return out
}
