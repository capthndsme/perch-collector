package controller

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/rpc"

	"github.com/capthndsme/perch-collector/internal/gwconfig"
)

// configRoot is a small OpenWrt tree: two allowlisted configs (one with a
// Wi-Fi key), the agent's own config, and the release file.
func configRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"etc/config/network":         "\nconfig interface 'lan'\n\toption device 'br-lan'\n\toption proto 'static'\n\toption ipaddr '192.168.1.1/24'\n\nconfig bridge-vlan\n\toption device 'br-lan'\n\toption vlan '1'\n\tlist ports 'lan1:u*'\n",
		"etc/config/wireless":        "\nconfig wifi-iface 'default_radio0'\n\toption ssid 'home'\n\toption key 'correct horse'\n",
		"etc/config/perch-collector": "\nconfig collector 'main'\n\toption api_key 'secret-key-here'\n",
		"etc/openwrt_release":        "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.8'\n",
	}
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func testPlane(root string, access string) *gwconfig.Plane {
	noUbus := &ubus.Client{Bin: "ubus", LookPath: func(string) (string, error) { return "/bin/ubus", nil },
		Run: func(context.Context, string, ...string) ([]byte, []byte, int, error) {
			return nil, []byte("Not found"), 4, nil
		}}
	return gwconfig.New(gwconfig.Options{
		Access: access, Allowlist: []string{"network", "wireless", "dhcp"}, APIKey: "0123456789abcdef0123456789abcdef",
		Root: root, Ubus: noUbus, LookPath: func(string) (string, error) { return "/sbin/uci", nil },
		CaptureNetwork: "lan", CaptureDevice: "br-lan",
	})
}

func request(t *testing.T, ctx context.Context, c *websocket.Conn, frames <-chan []byte, id int, method, params string) rpc.Message {
	t.Helper()
	frame := `{"jsonrpc":"2.0","id":` + string(rune('0'+id)) + `,"method":"` + method + `"`
	if params != "" {
		frame += `,"params":` + params
	}
	send(ctx, c, frame+"}")
	for {
		m, _ := next(t, frames, responseFrame, 3*time.Second)
		if string(m.ID) == string(rune('0'+id)) {
			return m
		}
	}
}

func TestConfigPlaneOnTheSocket(t *testing.T) {
	root := configRoot(t)
	pl := testPlane(root, "write")
	result := make(chan struct{})
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		defer close(result)
		var p struct {
			Capabilities  []string        `json:"capabilities"`
			GatewayConfig json.RawMessage `json:"gatewayConfig"`
		}
		json.Unmarshal(hello.Params, &p)
		if !reflect.DeepEqual(p.Capabilities, []string{"gateway_stats", "gateway_config"}) {
			t.Errorf("capabilities %v", p.Capabilities)
		}
		var gc gwconfig.Hello
		json.Unmarshal(p.GatewayConfig, &gc)
		if gc.Protocol != 1 || gc.Access != "write" || gc.TransportOK || gc.Apply.State != "idle" || len(gc.Hashes) != 2 || gc.Hashes["network"] == "" ||
			gc.Signing == nil || !gc.Signing.Required || len(gc.Signing.Challenge) != 32 {
			t.Errorf("gatewayConfig %s", p.GatewayConfig)
		}
		answerHello(ctx, c, hello, "adopted")
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0,"lifecycle":"adopted","gatewayConfig":{"mode":"observe","authoritative":false,"watchSeconds":10,"debounceSeconds":1}}}`)

		caps := request(t, ctx, c, frames, 1, "gateway.capabilities", "{}")
		var cp map[string]any
		json.Unmarshal(caps.Result, &cp)
		if caps.Error != nil || cp["access"] != "write" || cp["backend"] != "uci-cli" {
			t.Errorf("capabilities %s %+v", caps.Result, caps.Error)
		}
		if ow, _ := json.Marshal(cp["openwrt"]); string(ow) != `{"release":"24.10.8"}` {
			t.Errorf("openwrt %s", ow)
		}

		read := request(t, ctx, c, frames, 2, "gateway.config.read", `{"configs":["wireless","network"]}`)
		if read.Error != nil || strings.Contains(string(read.Result), "correct horse") || !strings.Contains(string(read.Result), `"secrets":{"key":"hmac:`) ||
			!strings.Contains(string(read.Result), `"name":"cfg02a1b0"`) {
			t.Errorf("read %s %+v", read.Result, read.Error)
		}
		all := request(t, ctx, c, frames, 3, "gateway.config.read", "")
		var res gwconfig.ReadResult
		json.Unmarshal(all.Result, &res)
		if len(res.Configs) != 4 || res.Configs[0].Name != "dhcp" || !res.Configs[0].Missing {
			t.Errorf("read all %s", all.Result)
		}
		denied := request(t, ctx, c, frames, 4, "gateway.config.read", `{"configs":["perch-collector"]}`)
		if denied.Error == nil || denied.Error.Code != rpc.CodeCommandFailed {
			t.Errorf("denied %+v", denied)
		} else if d, _ := json.Marshal(denied.Error.Data); string(d) != `{"configs":["perch-collector"],"error":"config_not_allowed"}` {
			t.Errorf("denied data %s", d)
		}
		bad := request(t, ctx, c, frames, 5, "gateway.config.read", `{"configs":"network"}`)
		if bad.Error == nil || bad.Error.Code != rpc.CodeInvalidParams {
			t.Errorf("bad params %+v", bad)
		}
		// Writes over plain HTTP without the router's opt-in: refused.
		apply := request(t, ctx, c, frames, 6, "gateway.config.apply", `{}`)
		if apply.Error == nil || apply.Error.Code != rpc.CodeCommandFailed {
			t.Errorf("apply %+v", apply)
		} else if d, _ := json.Marshal(apply.Error.Data); string(d) != `{"error":"insecure_transport"}` {
			t.Errorf("apply data %s", d)
		}

		// A `uci set … && uci commit` on the router: the next poll or the
		// trigger reports it.
		os.WriteFile(filepath.Join(root, "etc/config/network"), []byte("\nconfig interface 'lan'\n\toption device 'br-lan'\n\toption proto 'dhcp'\n"), 0o600)
		later := time.Now().Add(time.Hour)
		os.Chtimes(filepath.Join(root, "etc/config/network"), later, later)
		pl.Trigger()
		deadline := time.After(5 * time.Second)
		for {
			var m rpc.Message
			select {
			case data := <-frames:
				json.Unmarshal(data, &m)
			case <-deadline:
				t.Error("no gateway.config.changed")
				return
			}
			if m.Method != "gateway.config.changed" {
				continue
			}
			var ch gwconfig.Changed
			json.Unmarshal(m.Params, &ch)
			if m.ID != nil || !reflect.DeepEqual(ch.Changed, []string{"network"}) || ch.Origin != "router" || ch.Author.Via != "trigger" || ch.Author.Kind != "unknown" {
				t.Errorf("changed %s", m.Params)
			}
			break
		}
		c.Close(websocket.StatusNormalClosure, "done")
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	_, waits, stop := newTestClient(t, srv, func(o *Options) { o.Config = pl })
	defer stop()
	<-result
	<-waits // the session is over
	if pl.Mode() != gwconfig.ModeOff {
		t.Fatal("mode kept after the session")
	}
}

// An older controller sends no gatewayConfig: nothing is watched, and a
// collector without the plane keeps its old hello.
func TestConfigPlaneWithOldController(t *testing.T) {
	root := configRoot(t)
	done := make(chan struct{})
	fc := &fakeController{t: t}
	fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
		answerHello(ctx, c, hello, "adopted")
		send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0,"lifecycle":"adopted"}}`)
		time.Sleep(100 * time.Millisecond)
		close(done)
		<-ctx.Done()
	}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	cl, _, st := newTestClient(t, srv, func(o *Options) { o.Config = testPlane(root, "read") })
	defer st()
	<-done
	if cl.o.Config.Mode() != gwconfig.ModeOff {
		t.Fatal("watching without the controller asking")
	}

	plain := &Client{o: Options{Source: testSource()}}
	h := plain.hello(context.Background(), "")
	if h.GatewayConfig != nil || strings.Contains(strings.Join(h.Capabilities, ","), "gateway_config") {
		t.Fatalf("%+v", h)
	}
	b, _ := json.Marshal(h)
	if strings.Contains(string(b), "gatewayConfig") {
		t.Fatal(string(b))
	}
}
