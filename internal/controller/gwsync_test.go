package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/gatewayops"
	"github.com/capthndsme/perch-collector/internal/gwconfig"
)

// The runtime actions of gateway-sync protocol 6.2 on the socket: they sit
// behind the config plane's write gate (access write; verified TLS, or the
// router's opt-in and a signed request) and answer their own refusals with
// data.error.

type opsRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *opsRunner) run(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	return nil, nil, 0, nil
}

func (r *opsRunner) log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func opsRoot(t *testing.T) string {
	t.Helper()
	root := configRoot(t)
	for p, body := range map[string]string{
		"usr/sbin/miniupnpd":                  "",
		"etc/init.d/miniupnpd":                "",
		"var/run/miniupnpd.leases":            "TCP:51413:192.168.1.21:51413:0:app\nUDP:500:192.168.1.22:500:0:vpn\n",
		"usr/lib/ddns/dynamic_dns_updater.sh": "#!/bin/sh\n",
		"etc/config/ddns":                     "\nconfig service 'home'\n\toption enabled '1'\n",
	} {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func opsPlane(root, access string, transportOK bool, signKey string) *gwconfig.Plane {
	noUbus := &ubus.Client{Bin: "ubus", LookPath: func(string) (string, error) { return "/bin/ubus", nil },
		Run: func(context.Context, string, ...string) ([]byte, []byte, int, error) {
			return nil, []byte("Not found"), 4, nil
		}}
	return gwconfig.New(gwconfig.Options{
		Access: access, Allowlist: []string{"network"}, APIKey: "0123456789abcdef0123456789abcdef",
		TransportOK: transportOK, AllowInsecure: !transportOK, SignKey: signKey,
		Root: root, Ubus: noUbus, LookPath: func(string) (string, error) { return "", fmt.Errorf("none") },
		Features: []string{gwconfig.FeatureUPnPDelete, gwconfig.FeatureDDNSUpdate},
	})
}

type opsCall struct {
	method string
	params any
	sign   bool
}

// runOps connects a client with the plane and the actions, sends the calls
// on one session and returns the answers and the hello's capabilities.
func runOps(t *testing.T, pl *gwconfig.Plane, root string, signKey string, calls []opsCall) ([]rpc.Message, []string, *opsRunner) {
	t.Helper()
	runner := &opsRunner{}
	type out struct {
		answers []rpc.Message
		caps    []string
	}
	result := make(chan out, 1)
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		var p struct {
			Capabilities  []string       `json:"capabilities"`
			GatewayConfig gwconfig.Hello `json:"gatewayConfig"`
		}
		json.Unmarshal(hello.Params, &p)
		answerHello(ctx, c, hello, "adopted")
		var o out
		o.caps = p.Capabilities
		for i, call := range calls {
			raw, _ := json.Marshal(call.params)
			if call.sign {
				var err error
				raw, err = gwconfig.Sign([]byte(signKey), call.method, p.GatewayConfig.Signing.Challenge, time.Now().Unix(), fmt.Sprintf("nonce-%010d", i), call.params)
				if err != nil {
					t.Error(err)
				}
			}
			o.answers = append(o.answers, request(t, ctx, c, frames, i+1, call.method, string(raw)))
		}
		result <- o
		c.Close(4002, "done")
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	_, _, stop := newTestClient(t, srv, func(o *Options) {
		o.Config = pl
		o.UPnP = &gatewayops.UPnP{Root: root, Run: runner.run}
		o.DDNS = &gatewayops.DDNS{Root: root, Run: runner.run}
	})
	defer stop()
	select {
	case o := <-result:
		return o.answers, o.caps, runner
	case <-time.After(10 * time.Second):
		t.Fatal("no answers")
	}
	return nil, nil, nil
}

func TestRuntimeActionsOverTLS(t *testing.T) {
	root := opsRoot(t)
	answers, caps, runner := runOps(t, opsPlane(root, "write", true, ""), root, "", []opsCall{
		{method: MethodUPnPDelete, params: map[string]any{"mappings": []any{map[string]any{"proto": "TCP", "extPort": 51413}}}},
		{method: MethodDDNSUpdate, params: map[string]any{"service": "home"}},
		{method: MethodDDNSUpdate, params: map[string]any{"service": "office"}},
		{method: MethodUPnPDelete, params: map[string]any{"mappings": []any{}}},
		{method: "gateway.capabilities", params: map[string]any{}},
	})
	var up gatewayops.UPnPDeleteResult
	if answers[0].Error != nil || json.Unmarshal(answers[0].Result, &up) != nil || up.Deleted != 1 || !up.Restarted {
		t.Fatalf("upnp delete %s %+v", answers[0].Result, answers[0].Error)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "var/run/miniupnpd.leases")); string(b) != "UDP:500:192.168.1.22:500:0:vpn\n" {
		t.Fatalf("leases %q", b)
	}
	if string(answers[1].Result) != `{"started":true}` {
		t.Fatalf("ddns update %s %+v", answers[1].Result, answers[1].Error)
	}
	if e := answers[2].Error; e == nil || e.Code != -32000 || errorCode(e) != "ddns_unknown_service" {
		t.Fatalf("unknown service %+v", e)
	}
	if e := answers[3].Error; e == nil || e.Code != -32602 || errorCode(e) != "bad_params" {
		t.Fatalf("no mappings %+v", e)
	}
	var cp struct {
		Features []string `json:"features"`
	}
	json.Unmarshal(answers[4].Result, &cp)
	f := strings.Join(cp.Features, " ")
	if !strings.Contains(f, "upnp.delete") || !strings.Contains(f, "ddns.update") {
		t.Fatalf("features %v", cp.Features)
	}
	// Announced in gateway.capabilities only, never in the hello (cut at 32).
	for _, c := range caps {
		if c == "upnp.delete" || c == "ddns.update" || strings.HasPrefix(c, "gateway.upnp") || strings.HasPrefix(c, "gateway.ddns") {
			t.Fatalf("hello capabilities %v", caps)
		}
	}
	calls := runner.log()
	if len(calls) != 2 || calls[0] != "miniupnpd restart" || !strings.HasPrefix(calls[1], "start-stop-daemon -S -b -x ") || !strings.HasSuffix(calls[1], " -- -v 0 -S home -- start") {
		t.Fatalf("calls %v", calls)
	}
}

func TestRuntimeActionsSignedOverPlainHTTP(t *testing.T) {
	root := opsRoot(t)
	key := "a-shared-sign-key-0001"
	answers, _, runner := runOps(t, opsPlane(root, "write", false, key), root, key, []opsCall{
		{method: MethodDDNSUpdate, params: map[string]any{"service": "home"}},
		{method: MethodDDNSUpdate, params: map[string]any{"service": "home"}, sign: true},
		{method: MethodUPnPDelete, params: map[string]any{"mappings": []any{map[string]any{"proto": "UDP", "extPort": 500}}}, sign: true},
	})
	if e := answers[0].Error; e == nil || errorCode(e) != "signature_required" {
		t.Fatalf("unsigned %+v", e)
	}
	if string(answers[1].Result) != `{"started":true}` {
		t.Fatalf("signed %s %+v", answers[1].Result, answers[1].Error)
	}
	var up gatewayops.UPnPDeleteResult
	if answers[2].Error != nil || json.Unmarshal(answers[2].Result, &up) != nil || up.Deleted != 1 {
		t.Fatalf("signed upnp %s %+v", answers[2].Result, answers[2].Error)
	}
	if len(runner.log()) != 2 {
		t.Fatalf("calls %v", runner.log())
	}
}

func TestRuntimeActionsNeedWriteAccess(t *testing.T) {
	root := opsRoot(t)
	answers, _, runner := runOps(t, opsPlane(root, "read", true, ""), root, "", []opsCall{
		{method: MethodUPnPDelete, params: map[string]any{"mappings": []any{map[string]any{"proto": "TCP", "extPort": 51413}}}},
		{method: MethodDDNSUpdate, params: map[string]any{"service": "home"}},
	})
	for i, a := range answers {
		if a.Error == nil || errorCode(a.Error) != "not_managed" {
			t.Fatalf("%d: %s %+v", i, a.Result, a.Error)
		}
	}
	if len(runner.log()) != 0 {
		t.Fatalf("calls %v", runner.log())
	}
}
