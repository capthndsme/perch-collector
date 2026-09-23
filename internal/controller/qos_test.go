package controller

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/qos"
)

type fakeQoS struct {
	mu         sync.Mutex
	configured bool
	sets       []qos.DevicesSetParams
	events     []qos.Event
	notify     chan struct{}
}

func (f *fakeQoS) Configured() bool { return f.configured }
func (f *fakeQoS) Probe(context.Context) qos.ProbeResult {
	return qos.ProbeResult{Kernel: map[string]bool{"htb": true}, Tc: "tc-tiny"}
}
func (f *fakeQoS) SetDevices(p qos.DevicesSetParams) (qos.DevicesSetResult, error) {
	f.mu.Lock()
	f.sets = append(f.sets, p)
	f.mu.Unlock()
	return qos.DevicesSetResult{Revision: p.Revision, Accepted: len(p.Devices), Rejected: []qos.Rejection{}}, nil
}
func (f *fakeQoS) Section() *qos.Section {
	return &qos.Section{Epoch: "e1", State: "active", Classes: []qos.ClassStats{{ID: "1:200", Key: "d:02:00:00:00:00:01", Dir: "down"}}}
}
func (f *fakeQoS) StatusReport() qos.Status { return qos.Status{Summary: "ok"} }
func (f *fakeQoS) Notify() <-chan struct{}  { return f.notify }
func (f *fakeQoS) DrainEvents() []qos.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.events
	f.events = nil
	return out
}
func (f *fakeQoS) raise(ev qos.Event) {
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
	select {
	case f.notify <- struct{}{}:
	default:
	}
}

// With perch-qos installed: the hello names "qos", the push carries `qos`,
// qos.devices.set and qos.probe answer, and queued events are notified.
func TestQoSOnTheSocket(t *testing.T) {
	fq := &fakeQoS{configured: true, notify: make(chan struct{}, 1)}
	fq.raise(qos.Event{Type: qos.EventSQMPaused, At: "2026-09-23T12:00:00Z"}) // before the session
	type seen struct {
		caps        string
		push        map[string]json.RawMessage
		set, probe  rpc.Message
		bad, status rpc.Message
		events      []string
	}
	result := make(chan seen, 1)
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		var s seen
		var hp map[string]json.RawMessage
		json.Unmarshal(hello.Params, &hp)
		s.caps = string(hp["capabilities"])
		answerHello(ctx, c, hello, "adopted")
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0.1,"lifecycle":"adopted"}}`)
		// The event queued before the session comes right after the hello.
		for s.push == nil {
			m, _ := next(t, frames, anyFrame, 2*time.Second)
			switch m.Method {
			case "qos.event":
				var ev qos.Event
				json.Unmarshal(m.Params, &ev)
				s.events = append(s.events, ev.Type)
			case "collector.push":
				json.Unmarshal(m.Params, &s.push)
			}
		}
		send(ctx, c, `{"jsonrpc":"2.0","id":1,"method":"qos.devices.set","params":{"revision":3,"devices":[{"mac":"02:00:00:00:00:01","bucket":null,"downKbit":2000,"upKbit":null,"quota":null,"expiresAt":null}]}}`)
		s.set, _ = next(t, frames, responseFrame, 2*time.Second)
		send(ctx, c, `{"jsonrpc":"2.0","id":2,"method":"qos.probe","params":{}}`)
		s.probe, _ = next(t, frames, responseFrame, 2*time.Second)
		send(ctx, c, `{"jsonrpc":"2.0","id":3,"method":"qos.devices.set","params":{"revision":"x"}}`)
		s.bad, _ = next(t, frames, responseFrame, 2*time.Second)
		send(ctx, c, `{"jsonrpc":"2.0","id":4,"method":"qos.status"}`)
		s.status, _ = next(t, frames, responseFrame, 2*time.Second)
		fq.raise(qos.Event{Type: qos.EventCapHit, MAC: "02:00:00:00:00:01", At: "2026-09-23T12:00:01Z"})
		deadline := time.After(3 * time.Second)
		for len(s.events) < 2 {
			select {
			case data := <-frames:
				var m rpc.Message
				json.Unmarshal(data, &m)
				if m.Method == "qos.event" {
					var ev qos.Event
					json.Unmarshal(m.Params, &ev)
					s.events = append(s.events, ev.Type)
				}
			case <-deadline:
				t.Error("events missing")
				result <- s
				return
			}
		}
		result <- s
		c.Close(4002, "done")
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	_, _, stop := newTestClient(t, srv, func(o *Options) { o.QoS = fq })
	defer stop()
	var s seen
	select {
	case s = <-result:
	case <-time.After(15 * time.Second):
		t.Fatal("no session")
	}
	if !strings.Contains(s.caps, `"qos"`) {
		t.Errorf("capabilities %s", s.caps)
	}
	if !strings.Contains(string(s.push["qos"]), `"epoch":"e1"`) {
		t.Errorf("push qos = %s", s.push["qos"])
	}
	var res qos.DevicesSetResult
	if s.set.Error != nil || json.Unmarshal(s.set.Result, &res) != nil || res.Revision != 3 || res.Accepted != 1 {
		t.Errorf("devices.set = %s %v", s.set.Result, s.set.Error)
	}
	if len(fq.sets) != 1 || *fq.sets[0].Devices[0].DownKbit != 2000 || fq.sets[0].Devices[0].UpKbit != nil {
		t.Errorf("set received %+v", fq.sets)
	}
	if s.probe.Error != nil || !strings.Contains(string(s.probe.Result), `"tc":"tc-tiny"`) {
		t.Errorf("probe = %s %v", s.probe.Result, s.probe.Error)
	}
	if s.bad.Error == nil || s.bad.Error.Code != -32602 {
		t.Errorf("bad set = %+v", s.bad.Error)
	}
	if s.status.Error != nil {
		t.Errorf("status = %v", s.status.Error)
	}
	if strings.Join(s.events, ",") != "sqm_paused,cap_hit" {
		t.Errorf("events %v", s.events)
	}
}

// Without perch-qos the hello has no "qos", the push no `qos`, and
// qos.devices.set is refused with -32010 qos_not_active.
func TestQoSNotActive(t *testing.T) {
	fq := &fakeQoS{configured: false, notify: make(chan struct{}, 1)}
	type seen struct {
		caps string
		push map[string]json.RawMessage
		set  rpc.Message
	}
	result := make(chan seen, 1)
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		var s seen
		var hp map[string]json.RawMessage
		json.Unmarshal(hello.Params, &hp)
		s.caps = string(hp["capabilities"])
		answerHello(ctx, c, hello, "adopted")
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0.1,"lifecycle":"adopted"}}`)
		m, _ := next(t, frames, pushFrame, 2*time.Second)
		json.Unmarshal(m.Params, &s.push)
		send(ctx, c, `{"jsonrpc":"2.0","id":1,"method":"qos.devices.set","params":{"revision":1,"devices":[]}}`)
		s.set, _ = next(t, frames, responseFrame, 2*time.Second)
		result <- s
		c.Close(4002, "done")
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	_, _, stop := newTestClient(t, srv, func(o *Options) { o.QoS = fq })
	defer stop()
	s := <-result
	if strings.Contains(s.caps, `"qos"`) || s.push["qos"] != nil {
		t.Errorf("caps %s push qos %s", s.caps, s.push["qos"])
	}
	if e := s.set.Error; e == nil || e.Code != -32010 || !strings.Contains(string(mustJSON(e.Data)), "qos_not_active") {
		t.Errorf("set = %+v", s.set.Error)
	}
}

// The controller connection is marked DSCP CS6.
func TestDialerMarksCS6(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	d := newFallbackDialer("")
	conn, err := d.base.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, _ := conn.(*net.TCPConn).SyscallConn()
	var tos int
	raw.Control(func(fd uintptr) { tos, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS) })
	if tos != dscpCS6 {
		t.Errorf("TOS %#x", tos)
	}
}
