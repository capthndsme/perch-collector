package controller

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/capthndsme/perch-collector/internal/gwconfig"
)

// A fake clock for the plane's deadlines; timers fire when advanced.
type testClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []struct {
		at time.Time
		f  func()
		ok *bool
	}
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := true
	c.timers = append(c.timers, struct {
		at time.Time
		f  func()
		ok *bool
	}{c.now.Add(d), f, &live})
	return func() bool { c.mu.Lock(); defer c.mu.Unlock(); was := live; live = false; return was }
}
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	for _, t := range c.timers {
		if *t.ok && !t.at.After(c.now) {
			*t.ok = false
			due = append(due, t.f)
		}
	}
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}

func managedPlane(t *testing.T, root string, clock *testClock, transportOK bool) *gwconfig.Plane {
	t.Helper()
	noUbus := &ubus.Client{Bin: "ubus", LookPath: func(string) (string, error) { return "/bin/ubus", nil },
		Run: func(context.Context, string, ...string) ([]byte, []byte, int, error) {
			return nil, []byte("Not found"), 4, nil
		}}
	return gwconfig.New(gwconfig.Options{
		Access: "write", Allowlist: []string{"network", "dhcp"}, APIKey: "0123456789abcdef0123456789abcdef",
		TransportOK: transportOK, AllowInsecure: !transportOK, ConfirmMax: 600,
		Root: root, Ubus: noUbus, LookPath: func(string) (string, error) { return "", fmt.Errorf("none") },
		Clock: clock, Backend: &gwconfig.FileBackend{Dir: filepath.Join(root, "etc/config")},
		Run: func(context.Context, string, ...string) ([]byte, []byte, int, error) { return nil, nil, 1, nil },
	})
}

// The whole round trip on the socket: apply on one session, the agent
// drops it and dials a fresh one whose hello says the apply is pending,
// the controller confirms there; a second apply without a confirm is
// restored at the deadline and the result arrives as a notification.
func TestApplyReconnectConfirmOnTheSocket(t *testing.T) {
	for _, signedMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed=%v", signedMode), func(t *testing.T) {
			root := configRoot(t)
			os.WriteFile(filepath.Join(root, "etc/config/dhcp"), []byte("\nconfig dhcp 'lan'\n\toption interface 'lan'\n"), 0o600)
			clock := &testClock{now: time.Now()}
			pl := managedPlane(t, root, clock, !signedMode)
			type sess struct {
				hello gwconfig.Hello
				ctx   context.Context
				c     *websocket.Conn
				fr    <-chan []byte
				done  chan struct{}
			}
			sessions := make(chan *sess, 8)
			fc := &fakeController{t: t}
			fc.session = func(ctx context.Context, c *websocket.Conn, frames <-chan []byte, hello rpc.Message) {
				var p struct {
					GatewayConfig gwconfig.Hello `json:"gatewayConfig"`
				}
				json.Unmarshal(hello.Params, &p)
				answerHello(ctx, c, hello, "adopted")
				send(ctx, c, `{"jsonrpc":"2.0","method":"agent.configure","params":{"metricsIntervalSeconds":0,"lifecycle":"adopted","gatewayConfig":{"mode":"managed"}}}`)
				s := &sess{hello: p.GatewayConfig, ctx: ctx, c: c, fr: frames, done: make(chan struct{})}
				sessions <- s
				select {
				case <-s.done:
				case <-ctx.Done():
				}
			}
			srv := httptest.NewServer(fc)
			defer srv.Close()
			_, _, stop := newTestClient(t, srv, func(o *Options) {
				o.Config = pl
				o.Sleep = func(ctx context.Context, d time.Duration) error {
					if d > 100*time.Millisecond {
						d = 100 * time.Millisecond
					}
					return sleepCtx(ctx, d)
				}
			})
			defer stop()
			nonce := 0
			// Over plain HTTP the controller signs with the key of a pairing
			// (owner decision 29), run on the first session below.
			var signKey []byte
			call := func(s *sess, id int, method string, params any) rpc.Message {
				t.Helper()
				var raw json.RawMessage
				if signedMode {
					nonce++
					var err error
					raw, err = gwconfig.Sign(signKey, method, s.hello.Signing.Challenge, time.Now().Unix(), fmt.Sprintf("nonce-%010d", nonce), params)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					raw, _ = json.Marshal(params)
				}
				return request(t, s.ctx, s.c, s.fr, id, method, string(raw))
			}
			waitSession := func() *sess {
				t.Helper()
				select {
				case s := <-sessions:
					return s
				case <-time.After(5 * time.Second):
					t.Fatal("no session")
				}
				return nil
			}
			hashOf := func(name string) string {
				data, _ := os.ReadFile(filepath.Join(root, "etc/config", name))
				return fmt.Sprintf("%x", sha(data))
			}

			s1 := waitSession()
			if s1.hello.Signing == nil || s1.hello.Signing.Required != signedMode || s1.hello.Apply.State != "idle" {
				t.Fatalf("%+v", s1.hello)
			}
			// Let agent.configure land before the apply.
			time.Sleep(100 * time.Millisecond)
			if signedMode {
				if s1.hello.Signing.Key != "none" {
					t.Fatalf("%+v", s1.hello.Signing)
				}
				// The api_key (the Bearer token) never signs.
				signKey = []byte("0123456789abcdef0123456789abcdef")
				m := call(s1, 8, "gateway.config.apply", map[string]any{"applyId": "g1-x"})
				if errorCode(m.Error) != "not_paired" {
					t.Fatalf("%+v", m.Error)
				}
				signKey = pairOnTheSocket(t, s1.ctx, s1.c, s1.fr, pl)
			}
			apply := map[string]any{"applyId": "g1-a1", "kind": "apply", "confirmTimeoutSeconds": 90,
				"base":   map[string]string{"dhcp": hashOf("dhcp")},
				"ops":    []any{map[string]any{"op": "put", "config": "dhcp", "section": "perch_h1", "type": "host", "options": map[string]any{"name": "cam", "mac": "02:00:00:00:00:20", "ip": "192.168.1.20"}}},
				"ledger": map[string]any{"set": []any{map[string]string{"perchId": "h1", "config": "dhcp", "section": "perch_h1", "domain": "dhcp_hosts"}}}}
			m := call(s1, 1, "gateway.config.apply", apply)
			var res gwconfig.ApplyResult
			json.Unmarshal(m.Result, &res)
			if m.Error != nil || res.State != "pending_confirm" {
				t.Fatalf("%s %+v", m.Result, m.Error)
			}
			// Confirm on the same session: refused.
			m = call(s1, 2, "gateway.config.confirm", map[string]string{"applyId": "g1-a1"})
			if m.Error == nil || errorCode(m.Error) != "not_reconnected" {
				t.Fatalf("%+v", m.Error)
			}
			// The agent drops the session and dials a fresh one.
			s2 := waitSession()
			close(s1.done)
			if s2.hello.Apply.State != "pending_confirm" || s2.hello.Apply.ApplyID != "g1-a1" || (signedMode && s2.hello.Signing.Challenge == s1.hello.Signing.Challenge) {
				t.Fatalf("%+v", s2.hello)
			}
			time.Sleep(100 * time.Millisecond)
			m = call(s2, 3, "gateway.config.confirm", map[string]string{"applyId": "g1-a1"})
			if m.Error != nil || !strings.Contains(string(m.Result), `"state":"confirmed"`) {
				t.Fatalf("%s %+v", m.Result, m.Error)
			}
			if data, _ := os.ReadFile(filepath.Join(root, "etc/config/dhcp")); !strings.Contains(string(data), "config host 'perch_h1'") {
				t.Fatal(string(data))
			}

			// A second apply, never confirmed.
			apply["applyId"] = "g1-a2"
			apply["base"] = map[string]string{"dhcp": hashOf("dhcp")}
			apply["ops"] = []any{map[string]any{"op": "delete", "config": "dhcp", "section": "perch_h1"}}
			apply["ledger"] = map[string]any{"remove": []string{"h1"}}
			m = call(s2, 4, "gateway.config.apply", apply)
			if m.Error != nil {
				t.Fatalf("%+v", m.Error)
			}
			s3 := waitSession()
			close(s2.done)
			time.Sleep(100 * time.Millisecond)
			clock.Advance(91 * time.Second)
			for {
				msg, _ := next(t, s3.fr, anyFrame, 5*time.Second)
				if msg.Method != gwconfig.NotifyResult {
					continue
				}
				var r gwconfig.Result
				json.Unmarshal(msg.Params, &r)
				if r.ApplyID != "g1-a2" || r.Outcome != "rolled_back" || r.Reason != "confirm_timeout" {
					t.Fatalf("%s", msg.Params)
				}
				break
			}
			if data, _ := os.ReadFile(filepath.Join(root, "etc/config/dhcp")); !strings.Contains(string(data), "config host 'perch_h1'") {
				t.Fatal("not restored: " + string(data))
			}
			m = call(s3, 5, "gateway.config.ack", map[string]any{"applyIds": []string{"g1-a2"}})
			if m.Error != nil || string(m.Result) != `{"acked":1}` {
				t.Fatalf("%s %+v", m.Result, m.Error)
			}
			close(s3.done)
		})
	}
}

func sha(b []byte) [32]byte { return sha256.Sum256(b) }

// pairOnTheSocket is the controller's half of a pairing (pairing.ts) over
// the session, with the router's admin confirming locally; it returns the
// key both ends derived.
func pairOnTheSocket(t *testing.T, ctx context.Context, c *websocket.Conn, frames <-chan []byte, pl *gwconfig.Plane) []byte {
	t.Helper()
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cpub := priv.PublicKey().Bytes()
	m := request(t, ctx, c, frames, 6, "gateway.pair.begin", fmt.Sprintf(`{"pairingId":"0011223344556677","gatewayId":3,"controllerPub":"%x"}`, cpub))
	var begin gwconfig.PairBeginResult
	if m.Error != nil || json.Unmarshal(m.Result, &begin) != nil {
		t.Fatalf("%s %+v", m.Result, m.Error)
	}
	cnonce := make([]byte, 32)
	rand.Read(cnonce)
	m = request(t, ctx, c, frames, 7, "gateway.pair.reveal", fmt.Sprintf(`{"pairingId":"0011223344556677","controllerNonce":"%x"}`, cnonce))
	var rev gwconfig.PairRevealResult
	if m.Error != nil || json.Unmarshal(m.Result, &rev) != nil {
		t.Fatalf("%s %+v", m.Result, m.Error)
	}
	rpub, _ := hex.DecodeString(begin.RouterPub)
	rnonce, _ := hex.DecodeString(rev.RouterNonce)
	commit, _ := hex.DecodeString(begin.Commitment)
	if !bytes.Equal(commit, gwconfig.PairCommitment(rnonce, rpub, cpub)) {
		t.Fatal("commitment")
	}
	shared, err := gwconfig.X25519Shared(priv, rpub)
	if err != nil {
		t.Fatal(err)
	}
	tr := gwconfig.PairTranscript{GatewayID: 3, ControllerPub: cpub, RouterPub: rpub, ControllerNonce: cnonce, RouterNonce: rnonce}
	key, sas := gwconfig.PairKey(shared, tr), gwconfig.PairSAS(tr)
	// The router's admin reads the same code and confirms.
	if st := pl.PairLocalStatus(); st.Pending == nil || st.Pending.Code != sas {
		t.Fatalf("router %+v, controller %s", st.Pending, sas)
	}
	if _, err := pl.PairConfirmLocal(sas); err != nil {
		t.Fatal(err)
	}
	for {
		msg, _ := next(t, frames, anyFrame, 3*time.Second)
		if msg.Method != gwconfig.NotifyPairState {
			continue
		}
		want := fmt.Sprintf(`{"pairingId":"0011223344556677","state":"paired","keyId":"%s"}`, gwconfig.PairKeyID(key))
		if string(msg.Params) != want {
			t.Fatalf("%s", msg.Params)
		}
		return key
	}
}

func TestRedialWaitsAroundAnApply(t *testing.T) {
	root := configRoot(t)
	clock := &testClock{now: time.Now()}
	pl := managedPlane(t, root, clock, true)
	c := &Client{o: Options{Config: pl}}
	// Nothing pending: the table's waits stand.
	if o := c.applyRedialWait(outcome{wait: 16 * time.Second}); o.wait != 16*time.Second {
		t.Fatal(o.wait)
	}
	// The plane dropped the session: dial at once.
	c.redialNow = true
	if o := c.applyRedialWait(outcome{wait: 16 * time.Second, state: StateError}); o.wait != applyRedialFirst || o.state != "" || o.note == "" {
		t.Fatalf("%+v", o)
	}
	if c.redialNow {
		t.Fatal("consumed")
	}
	// While an apply waits for its confirm: every 2 s, but a refusal that
	// retrying cannot fix keeps its slow retry.
	pl.Configure(gwconfig.Configure{Mode: gwconfig.ModeManaged})
	os.WriteFile(filepath.Join(root, "etc/config/dhcp"), []byte("\nconfig dhcp 'lan'\n"), 0o600)
	data, _ := os.ReadFile(filepath.Join(root, "etc/config/dhcp"))
	var a gwconfig.ApplyParams
	json.Unmarshal([]byte(fmt.Sprintf(`{"applyId":"x1","base":{"dhcp":"%x"},"ops":[{"op":"put","config":"dhcp","section":"perch_a","type":"host","options":{"name":"a"}}]}`, sha(data))), &a)
	if _, err := pl.Apply(context.Background(), &a, gwconfig.SessionRef{Gen: 1}, true); err != nil {
		t.Fatal(err)
	}
	if o := c.applyRedialWait(outcome{wait: 16 * time.Second}); o.wait != applyRedial {
		t.Fatal(o.wait)
	}
	if o := c.applyRedialWait(outcome{wait: slowRetry}); o.wait != slowRetry {
		t.Fatal(o.wait)
	}
	if o := c.applyRedialWait(outcome{wait: time.Second}); o.wait != time.Second {
		t.Fatal(o.wait)
	}
}
