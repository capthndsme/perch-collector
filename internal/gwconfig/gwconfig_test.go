package gwconfig

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// newRoot copies testdata/root (an OpenWrt 24.10 file tree: configs,
// release, opkg status, firewall binaries, mounts) into a temp dir.
func newRoot(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir("testdata/root", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("testdata/root", p)
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func put(t *testing.T, root, p, body string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeUbus answers `ubus list uci` and `ubus call session list`.
type fakeUbus struct {
	sessions string
	hasUci   bool
	calls    [][]string
}

func (f *fakeUbus) client() *ubus.Client {
	return &ubus.Client{Bin: "ubus", LookPath: func(string) (string, error) { return "/bin/ubus", nil },
		Run: func(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
			f.calls = append(f.calls, args)
			switch strings.Join(args[2:], " ") {
			case "list uci":
				if f.hasUci {
					return []byte("uci\n"), nil, 0, nil
				}
			case "call session list":
				return []byte(f.sessions), nil, 0, nil
			}
			return nil, []byte("Command failed: Not found"), 4, nil
		}}
}

func plane(t *testing.T, root string, o Options) (*Plane, *fakeUbus) {
	t.Helper()
	fu := &fakeUbus{hasUci: true}
	o.Root = root
	o.Ubus = fu.client()
	if o.LookPath == nil {
		o.LookPath = func(string) (string, error) { return "/sbin/uci", nil }
	}
	if o.APIKey == "" {
		o.APIKey = "test-api-key"
	}
	return New(o), fu
}

func TestAccessAndAllowlist(t *testing.T) {
	root := newRoot(t)
	p, _ := plane(t, root, Options{Access: "bogus", Allowlist: []string{"network", "rpcd", "perch-collector", "network", "", "dhcp", "../x", LedgerConfig}})
	if p.Access() != AccessNone || p.Readable() != nil {
		t.Fatalf("unknown access must be none: %s %v", p.Access(), p.Readable())
	}
	if !reflect.DeepEqual(p.Allowed(), []string{"dhcp", "network"}) {
		t.Fatalf("allowlist %v", p.Allowed())
	}
	var ae *AccessError
	if err := p.RequireAccess(AccessRead); !errors.As(err, &ae) || !errors.Is(err, ErrNotManaged) {
		t.Fatalf("%v", err)
	}

	p, _ = plane(t, root, Options{Access: AccessRead, Allowlist: DefaultAllowlist})
	if p.RequireAccess(AccessRead) != nil || !reflect.DeepEqual(p.Readable(), []string{"dhcp", "firewall", "network", LedgerConfig}) {
		t.Fatalf("%v", p.Readable())
	}
	if err := p.RequireAccess(AccessWrite); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("write with read access: %v", err)
	}

	// write over an unverified transport: refused without the router's
	// opt-in, and without a signature even with it.
	p, _ = plane(t, root, Options{Access: AccessWrite, Allowlist: DefaultAllowlist})
	if p.Access() != AccessWrite || p.ConfiguredAccess() != AccessWrite {
		t.Fatal(p.Access())
	}
	if err := p.RequireAccess(AccessWrite); !errors.Is(err, ErrInsecure) {
		t.Fatalf("%v", err)
	}
	p, _ = plane(t, root, Options{Access: AccessWrite, AllowInsecure: true})
	var pe *PlaneError
	if err := p.RequireAccess(AccessWrite); !errors.As(err, &pe) || pe.Code != CodeSignatureRequired {
		t.Fatalf("%v", err)
	}
	if err := p.RequireWrite(true); err != nil {
		t.Fatalf("signed: %v", err)
	}
	p, _ = plane(t, root, Options{Access: AccessWrite, TransportOK: true})
	if err := p.RequireAccess(AccessWrite); err != nil {
		t.Fatalf("%v", err)
	}
	if err := p.RequireAccess("admin"); err == nil {
		t.Fatal("unknown level")
	}
	for _, d := range []string{"perch-collector", "perch-apd", "rpcd", "uhttpd", "dropbear", "luci"} {
		if !Denied(d) {
			t.Error(d)
		}
	}
}

func TestHello(t *testing.T) {
	root := newRoot(t)
	p, _ := plane(t, root, Options{Access: AccessNone, TransportOK: true})
	h := p.Hello(context.Background(), "")
	b, _ := json.Marshal(h)
	if string(b) != `{"protocol":1,"access":"none","transportOk":true,"apply":{"state":"idle"},"results":[]}` {
		t.Fatal(string(b))
	}
	p, _ = plane(t, root, Options{Access: AccessWrite, Allowlist: DefaultAllowlist})
	h = p.Hello(context.Background(), "c1")
	if h.Access != AccessWrite || h.AccessConfigured != "" || h.TransportOK || h.Signing == nil || !h.Signing.Required ||
		h.Signing.Challenge != "c1" || h.Signing.Key != "api_key" {
		t.Fatalf("%+v", h)
	}
	// dhcp is allowlisted but has no file: absent. The ledger counts.
	if len(h.Hashes) != 3 || h.Hashes["dhcp"] != "" || h.Hashes["network"] == "" || h.Hashes[LedgerConfig] == "" {
		t.Fatalf("%v", h.Hashes)
	}
	net, _ := os.ReadFile(filepath.Join(root, "etc/config/network"))
	if h.Hashes["network"] != uci.FileHash(net) {
		t.Fatal("hash is not the file hash")
	}
}

func TestRead(t *testing.T) {
	root := newRoot(t)
	put(t, root, "tmp/.uci/network", "network.lan.ipaddr='192.168.9.1'\n")
	put(t, root, "tmp/.uci/rpcd", "rpcd.x.y='1'\n") // not readable: not reported
	put(t, root, "var/run/rpcd/snapshot-files/network", "x")
	p, _ := plane(t, root, Options{Access: AccessRead, Allowlist: []string{"network", "wireless", "dhcp"},
		Now: func() time.Time { return time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC) }})
	res, err := p.Read(nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range res.Configs {
		names = append(names, c.Name)
	}
	if !reflect.DeepEqual(names, []string{"dhcp", "network", LedgerConfig, "wireless"}) {
		t.Fatalf("%v", names)
	}
	if !res.Configs[0].Missing || res.Configs[0].Hash != "" || len(res.Configs[0].Sections) != 0 {
		t.Fatalf("dhcp %+v", res.Configs[0])
	}
	if res.ReadAt != "2026-09-23T10:00:00Z" || !res.LuciPending || !reflect.DeepEqual(res.Uncommitted, []string{"network"}) {
		t.Fatalf("%+v", res)
	}
	if !reflect.DeepEqual(res.Ledger, []LedgerEntry{{PerchID: "k2v9", Config: "network", Section: "lan", Domain: "networks"}}) {
		t.Fatalf("ledger %+v", res.Ledger)
	}
	// Anonymous sections carry libuci's names; the hash is the redacted
	// content hash.
	netw := res.Configs[1]
	var bv *Section
	for i := range netw.Sections {
		if netw.Sections[i].Type == "bridge-vlan" {
			bv = &netw.Sections[i]
			break
		}
	}
	if bv == nil || bv.Name != "cfg09a1b0" || !bv.Anonymous || bv.Index != 8 {
		t.Fatalf("%+v", bv)
	}
	// Secrets never leave: the key is a fingerprint.
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "correct horse") {
		t.Fatal("secret in the read")
	}
	wl := res.Configs[3].Sections[1]
	if _, ok := wl.Options["key"]; ok || !strings.HasPrefix(wl.Secrets["key"], "hmac:") {
		t.Fatalf("%+v", wl)
	}
	if wl.Secrets["key"] != uci.Fingerprint([]byte("test-api-key"), "wireless", "default_radio0", "key", uci.String("correct horse battery staple")) {
		t.Fatal("fingerprint")
	}
	if !strings.Contains(string(b), `"options":{"device":"radio0","encryption":"sae-mixed","mode":"ap","network":"lan","ssid":"home"}`) {
		t.Fatal(string(b))
	}

	// Named reads, refusals.
	res, err = p.Read([]string{"network", "network"})
	if err != nil || len(res.Configs) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	var ae *AccessError
	_, err = p.Read([]string{"network", "perch-collector", "firewall"})
	if !errors.As(err, &ae) || !errors.Is(err, ErrConfigNotAllowed) || !reflect.DeepEqual(ae.Configs, []string{"firewall", "perch-collector"}) {
		t.Fatalf("%v", err)
	}
	pn, _ := plane(t, root, Options{Access: AccessNone, Allowlist: DefaultAllowlist})
	if _, err := pn.Read(nil); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("%v", err)
	}
	// A broken config is an error, not a partial read.
	put(t, root, "etc/config/network", "config t 's'\n\toption a 'x\n")
	if _, err := p.Read([]string{"network"}); err == nil {
		t.Fatal("broken config read")
	}
	put(t, root, "etc/config/network", "config t 's'\n\toption a '"+strings.Repeat("x", MaxConfigBytes)+"'\n")
	if _, err := p.Read([]string{"network"}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
}

func TestCapabilities(t *testing.T) {
	root := newRoot(t)
	put(t, root, "tmp/.uci/firewall", "firewall.x.y='1'\n")
	p, _ := plane(t, root, Options{Access: AccessRead, Allowlist: DefaultAllowlist, TransportOK: true, ConfirmMax: 600,
		CaptureNetwork: "lan", CaptureDevice: "br-lan", StoragePath: "/etc/perch-collector"})
	c := p.Capabilities(context.Background(), "")
	if c.Access != AccessRead || c.AccessConfigured != AccessRead || !c.TransportOK || c.ConfirmMax != 600 {
		t.Fatalf("%+v", c)
	}
	if c.Backend == nil || *c.Backend != uci.BackendUbus || c.Firewall == nil || *c.Firewall != "fw4" || c.PackageManager == nil || *c.PackageManager != "opkg" {
		t.Fatalf("backend/firewall/manager: %v %v %v", c.Backend, c.Firewall, c.PackageManager)
	}
	if *c.OpenWrt != (OpenWrt{Release: "24.10.8", Revision: "r29233-443ec4032a", Target: "x86/64", Arch: "x86_64", Board: "example-board"}) {
		t.Fatalf("%+v", c.OpenWrt)
	}
	if c.Packages["firewall4"] != "2024.12.18~18fc0ead-r1" || c.Packages["dnsmasq"] != "2.93-r1" || len(c.Packages) != 7 {
		t.Fatalf("%v", c.Packages)
	}
	if !reflect.DeepEqual(c.Configs, []string{"firewall", "network", LedgerConfig}) || len(c.Hashes) != 3 {
		t.Fatalf("%v %v", c.Configs, c.Hashes)
	}
	if !reflect.DeepEqual(c.Uncommitted, []string{"firewall"}) || c.LuciPending {
		t.Fatalf("%v", c.Uncommitted)
	}
	if !reflect.DeepEqual(c.Capture.Networks, []CaptureNetwork{{Network: "lan", Device: "br-lan"}}) {
		t.Fatalf("%+v", c.Capture)
	}
	if c.Storage == nil || c.Storage.Path != "/etc/perch-collector" || c.Storage.Exists || c.Storage.MountPoint != "/" || !c.Storage.OnRoot {
		t.Fatalf("%+v", c.Storage)
	}
	if c.Flash == nil || c.Flash.Path != "/" || c.Flash.TotalBytes == 0 {
		t.Fatalf("%+v", c.Flash)
	}
	b, err := json.Marshal(c)
	if err != nil || !strings.Contains(string(b), `"apply":{"state":"idle"}`) {
		t.Fatal(string(b))
	}

	// fw3 only, no rpcd, no package database, access none: no hashes.
	os.Remove(filepath.Join(root, "sbin/fw4"))
	os.Remove(filepath.Join(root, "sbin/fw3"))
	put(t, root, "sbin/fw3", "")
	os.RemoveAll(filepath.Join(root, "usr/lib/opkg"))
	pn, fu := plane(t, root, Options{Access: AccessNone, LookPath: func(string) (string, error) { return "", errors.New("no") }})
	fu.hasUci = false
	c = pn.Capabilities(context.Background(), "")
	if *c.Firewall != "fw3" || c.Backend != nil || c.PackageManager != nil || len(c.Hashes) != 0 || len(c.Configs) != 0 || c.Storage != nil {
		t.Fatalf("%+v", c)
	}
	os.Remove(filepath.Join(root, "etc/openwrt_release"))
	if pn.Capabilities(context.Background(), "").OpenWrt != nil {
		t.Fatal("openwrt without a release file")
	}
}

func TestSessionUsers(t *testing.T) {
	// `ubus call session list`: one object per session, the unauthenticated
	// one first (OpenWrt 24.10).
	raw := `{
	"ubus_rpc_session": "00000000000000000000000000000000",
	"timeout": 0, "expires": 0,
	"acls": {"access-group": {"unauthenticated": ["read"]}},
	"data": {}
}
{
	"ubus_rpc_session": "5a1b2c3d4e5f60718293a4b5c6d7e8f9",
	"timeout": 300, "expires": 297,
	"acls": {"uci": {"*": ["read", "write"]}},
	"data": {"username": "root", "token": "0123"}
}
`
	users, err := sessionUsers([]byte(raw))
	if err != nil || !reflect.DeepEqual(users, []string{"root"}) {
		t.Fatalf("%v %v", users, err)
	}
	if _, err := sessionUsers([]byte("{bad")); err == nil {
		t.Fatal("bad json")
	}
	if u, err := sessionUsers(nil); err != nil || u != nil {
		t.Fatal("empty")
	}
}
