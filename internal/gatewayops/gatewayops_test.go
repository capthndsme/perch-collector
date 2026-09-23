package gatewayops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ti-mo/conntrack"
)

// ── conntrack ─────────────────────────────────────────────────────────────

type fakeTable struct {
	flows   []conntrack.Flow
	deleted []conntrack.Flow
	dumpErr error
	delErr  map[uint16]error // by original source port
	closed  bool
}

func (f *fakeTable) Dump() ([]conntrack.Flow, error) { return f.flows, f.dumpErr }
func (f *fakeTable) Delete(fl conntrack.Flow) error {
	if err := f.delErr[fl.TupleOrig.Proto.SourcePort]; err != nil {
		return err
	}
	f.deleted = append(f.deleted, fl)
	return nil
}
func (f *fakeTable) Probe() error { return nil }
func (f *fakeTable) Close() error { f.closed = true; return nil }

func flow(proto uint8, src string, sport uint16, dst string, dport uint16, rsrc string, rsport uint16, rdst string, rdport uint16) conntrack.Flow {
	a := netip.MustParseAddr
	return conntrack.Flow{
		TupleOrig: conntrack.Tuple{IP: conntrack.IPTuple{SourceAddress: a(src), DestinationAddress: a(dst)},
			Proto: conntrack.ProtoTuple{Protocol: proto, SourcePort: sport, DestinationPort: dport}},
		TupleReply: conntrack.Tuple{IP: conntrack.IPTuple{SourceAddress: a(rsrc), DestinationAddress: a(rdst)},
			Proto: conntrack.ProtoTuple{Protocol: proto, SourcePort: rsport, DestinationPort: rdport}},
	}
}

func TestConntrackFlush(t *testing.T) {
	const wan = "203.0.113.10"
	table := &fakeTable{flows: []conntrack.Flow{
		// c1 → internet, masqueraded: reply goes to the WAN address.
		flow(6, "192.168.1.21", 40001, "198.51.100.7", 443, "198.51.100.7", 443, wan, 40001),
		flow(17, "192.168.1.21", 40002, "198.51.100.8", 53, "198.51.100.8", 53, wan, 40002),
		// A port forward to c1: the original destination is the WAN address.
		flow(6, "198.51.100.9", 50000, wan, 8080, "192.168.1.21", 80, "198.51.100.9", 50000),
		// c2, untouched.
		flow(6, "192.168.1.22", 40003, "198.51.100.7", 443, "198.51.100.7", 443, wan, 40003),
		// The collector's own socket to a controller at c1's address.
		flow(6, "192.168.1.1", 45555, "192.168.1.21", 12553, "192.168.1.21", 12553, "192.168.1.1", 45555),
		// Gone meanwhile.
		flow(6, "192.168.1.21", 40004, "198.51.100.7", 443, "198.51.100.7", 443, wan, 40004),
	}, delErr: map[uint16]error{40004: syscall.ENOENT}}
	f := &Flusher{
		Dial:       func() (Table, error) { return table, nil },
		LocalAddrs: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr(wan), netip.MustParseAddr("192.168.1.1")} },
		Protected: func() (netip.AddrPort, netip.AddrPort) {
			return netip.MustParseAddrPort("192.168.1.1:45555"), netip.MustParseAddrPort("192.168.1.21:12553")
		},
	}
	// Dry run first.
	res, err := f.Flush(FlushParams{IPs: []string{"192.168.1.21"}, DryRun: true})
	if err != nil || !res.Flushed || res.Matched != 5 || res.Deleted != 0 || res.Skipped != 1 || len(table.deleted) != 0 {
		t.Fatalf("dry run = %+v %v", res, err)
	}
	res, err = f.Flush(FlushParams{IPs: []string{"192.168.1.21", " 192.168.1.21"}})
	if err != nil || res.Matched != 5 || res.Deleted != 3 || res.Skipped != 1 || res.Failed != 0 {
		t.Fatalf("flush = %+v %v", res, err)
	}
	if !table.closed {
		t.Error("table not closed")
	}
	for _, d := range table.deleted {
		if d.TupleOrig.IP.SourceAddress.String() == "192.168.1.22" {
			t.Error("another device's flow deleted")
		}
		if d.TupleReply.IP.SourceAddress.IsValid() {
			t.Error("deletes go by the original tuple only")
		}
	}
	// Protocol filter.
	table.deleted = nil
	res, _ = f.Flush(FlushParams{IPs: []string{"192.168.1.21"}, Proto: "udp"})
	if res.Matched != 1 || res.Deleted != 1 {
		t.Errorf("udp only = %+v", res)
	}
	// A failing delete is counted.
	table.delErr[40001] = errors.New("boom")
	res, _ = f.Flush(FlushParams{IPs: []string{"192.168.1.21"}, Proto: "tcp"})
	if res.Failed != 1 {
		t.Errorf("failed delete = %+v", res)
	}
	// Conntrack unreachable: flushed false with a reason, not an error.
	table.dumpErr = errors.New("operation not permitted")
	res, err = f.Flush(FlushParams{IPs: []string{"192.168.1.21"}})
	if err != nil || res.Flushed || !strings.Contains(res.Reason, "not permitted") {
		t.Errorf("unreachable = %+v %v", res, err)
	}
}

func TestConntrackValidate(t *testing.T) {
	f := &Flusher{LocalAddrs: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.10")} }}
	cases := map[string]FlushParams{
		"conntrack_ips_required":   {},
		"conntrack_ip_invalid":     {IPs: []string{"nope"}},
		"conntrack_router_address": {IPs: []string{"203.0.113.10"}},
		"conntrack_proto_invalid":  {IPs: []string{"192.168.1.2"}, Proto: "bogus"},
	}
	for code, p := range cases {
		_, _, err := f.Validate(p)
		var pe *ParamError
		if !errors.As(err, &pe) || pe.Code != code {
			t.Errorf("%s: got %v", code, err)
		}
	}
	for _, bad := range []string{"127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "fe80::1", "::"} {
		if _, _, err := f.Validate(FlushParams{IPs: []string{bad}}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	many := make([]string, MaxFlushIPs+1)
	for i := range many {
		many[i] = "192.168.1.2"
	}
	if _, _, err := f.Validate(FlushParams{IPs: many}); err == nil {
		t.Error("too many accepted")
	}
	ips, proto, err := f.Validate(FlushParams{IPs: []string{"::ffff:192.168.1.2", "fd00::2"}, Proto: "17"})
	if err != nil || len(ips) != 2 || ips[0].String() != "192.168.1.2" || proto != 17 {
		t.Errorf("valid = %v %d %v", ips, proto, err)
	}
}

// ── backup ────────────────────────────────────────────────────────────────

type file struct {
	name, body string
}

func makeArchive(t *testing.T, files []file) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755})
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(f.body))
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func readArchive(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
	return out
}

const wirelessConf = `config wifi-iface 'default_radio0'
	option device 'radio0'
	option ssid 'Example'
	option encryption 'sae-mixed'
	option key 'correct horse battery staple'
`

const networkConf = `config interface 'wg0'
	option proto 'wireguard'
	option private_key 'aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSByZWFsIGtleQ='
	list addresses '10.0.0.1/24'

config wireguard_wg0
	option public_key 'cHVibGljIGtleSBzdGF5cyB2aXNpYmxl'
	option preshared_key 'c2VjcmV0IHByZXNoYXJlZA=='

config interface 'wan'
	option proto 'pppoe'
	option username 'user@example.com'
	option password 'hunter2'
`

func TestRedactArchive(t *testing.T) {
	in := makeArchive(t, []file{
		{"etc/config/wireless", wirelessConf},
		{"etc/config/network", networkConf},
		{"etc/config/perch-collector", "config perch-collector 'main'\n\toption api_key 'abcdefgh12345678'\n\toption announce_api_key '1'\n\toption server_url 'https://perch.example.com'\n"},
		{"etc/config/uhttpd", "config uhttpd 'main'\n\toption key '/etc/uhttpd.key'\n\toption cert '/etc/uhttpd.crt'\n"},
		{"etc/config/ddns", "config service 'x'\n\toption password 'ddns-pass'\n\toption lookup_host 'example.com'\n"},
		{"etc/shadow", "root:$1$abc$defghijklmnop:19000:0:99999:7:::\ndaemon:*:0:0:99999:7:::\n"},
		{"etc/dropbear/dropbear_ed25519_host_key", "\x00\x00binary"},
		{"etc/uhttpd.key", "-----BEGIN EC PRIVATE KEY-----\nxx\n-----END EC PRIVATE KEY-----\n"},
		{"etc/acme/example.pem", "-----BEGIN PRIVATE KEY-----\nxx\n"},
		{"etc/adguardhome.yaml", "users:\n  - name: admin\n    password: $2y$10$hashhashhash\ndns:\n  port: 53\n"},
		{"etc/dropbear/authorized_keys", "ssh-ed25519 AAAAC3Nza example\n"},
		{"etc/hosts", "127.0.0.1 localhost\n"},
	})
	out, reds, err := RedactArchive(in)
	if err != nil {
		t.Fatal(err)
	}
	files := readArchive(t, out)
	if strings.Contains(files["etc/config/wireless"], "battery") || !strings.Contains(files["etc/config/wireless"], "option key '"+Redacted+"'") ||
		!strings.Contains(files["etc/config/wireless"], "option ssid 'Example'") {
		t.Errorf("wireless:\n%s", files["etc/config/wireless"])
	}
	net := files["etc/config/network"]
	for _, secret := range []string{"aGVsbG8", "c2VjcmV0", "hunter2"} {
		if strings.Contains(net, secret) {
			t.Errorf("network keeps %s:\n%s", secret, net)
		}
	}
	if !strings.Contains(net, "cHVibGljIGtleSBzdGF5cyB2aXNpYmxl") || !strings.Contains(net, "user@example.com") || !strings.Contains(net, "list addresses '10.0.0.1/24'") {
		t.Errorf("network lost non-secrets:\n%s", net)
	}
	if strings.Contains(files["etc/config/perch-collector"], "abcdefgh") || !strings.Contains(files["etc/config/perch-collector"], "server_url") {
		t.Errorf("collector config:\n%s", files["etc/config/perch-collector"])
	}
	if !strings.Contains(files["etc/config/uhttpd"], "option key '/etc/uhttpd.key'") {
		t.Errorf("a key file path is not a secret:\n%s", files["etc/config/uhttpd"])
	}
	if strings.Contains(files["etc/config/ddns"], "ddns-pass") {
		t.Error("ddns password kept")
	}
	if files["etc/shadow"] != "root:*:19000:0:99999:7:::\ndaemon:*:0:0:99999:7:::\n" {
		t.Errorf("shadow = %q", files["etc/shadow"])
	}
	for _, gone := range []string{"etc/dropbear/dropbear_ed25519_host_key", "etc/uhttpd.key", "etc/acme/example.pem"} {
		if _, ok := files[gone]; ok {
			t.Errorf("%s kept", gone)
		}
	}
	if strings.Contains(files["etc/adguardhome.yaml"], "hashhash") || !strings.Contains(files["etc/adguardhome.yaml"], "port: 53") {
		t.Errorf("adguard:\n%s", files["etc/adguardhome.yaml"])
	}
	if files["etc/dropbear/authorized_keys"] != "ssh-ed25519 AAAAC3Nza example\n" || files["etc/hosts"] != "127.0.0.1 localhost\n" {
		t.Error("untouched files changed")
	}
	if _, ok := files["etc/"]; !ok {
		t.Error("directory entries must be kept")
	}
	got := map[string]bool{}
	for _, r := range reds {
		got[r.File+"#"+r.Option] = true
	}
	for _, want := range []string{"/etc/config/wireless#key", "/etc/config/network#private_key", "/etc/config/network#preshared_key",
		"/etc/config/network#password", "/etc/config/perch-collector#api_key", "/etc/shadow#root", "/etc/uhttpd.key#",
		"/etc/adguardhome.yaml#password"} {
		if !got[want] {
			t.Errorf("redactions lack %s: %+v", want, reds)
		}
	}
	if !strings.Contains(files["etc/config/perch-collector"], "option announce_api_key '1'") {
		t.Errorf("a boolean switch is not a secret:\n%s", files["etc/config/perch-collector"])
	}
	if got["/etc/config/network#public_key"] || got["/etc/config/uhttpd#key"] || got["/etc/config/perch-collector#announce_api_key"] {
		t.Errorf("non-secrets listed: %+v", reds)
	}
}

func TestSecretOption(t *testing.T) {
	for _, s := range []string{"key", "key2", "password", "private_key", "preshared_key", "api_key", "secret", "faskey", "sae_password", "auth_secret", "wpa_psk", "token", "PrivateKey", "ssh_private_key"} {
		if !secretOption(s) {
			t.Errorf("%s is a secret", s)
		}
	}
	for _, s := range []string{"public_key", "ssid", "keyfile", "username", "cert", "server_url", "port", "ssh_key", "keys"} {
		if secretOption(s) {
			t.Errorf("%s is not a secret", s)
		}
	}
}

func TestBackup(t *testing.T) {
	archive := makeArchive(t, []file{{"etc/config/wireless", wirelessConf}})
	b := &Backuper{
		Policy:   BackupRedacted,
		Hostname: func() string { return "gate way/1" },
		Release:  func() string { return "OpenWrt 24.10.2" },
		Create: func(_ context.Context, path string) error {
			return os.WriteFile(path, archive, 0o600)
		},
		TempDir: t.TempDir(),
		Now:     func() time.Time { return time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC) },
	}
	res, err := b.Backup(context.Background(), BackupParams{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Filename != "backup-gate-way-1-2026-09-23.tar.gz" || res.CreatedAt != "2026-09-23T10:00:00Z" || !res.Redacted ||
		res.Release != "OpenWrt 24.10.2" || len(res.Redactions) != 1 || len(res.SHA256) != 64 {
		t.Errorf("result = %+v", res)
	}
	data, _ := base64.StdEncoding.DecodeString(res.ContentBase64)
	if len(data) != res.Size || strings.Contains(readArchive(t, data)["etc/config/wireless"], "battery") {
		t.Error("content is not the redacted archive")
	}
	// Full backups need the router's consent.
	no := false
	var be *BackupError
	if _, err := b.Backup(context.Background(), BackupParams{Redact: &no}); !errors.As(err, &be) || be.Code != "backup_redaction_required" {
		t.Errorf("full on a redacted router = %v", err)
	}
	b.Policy = BackupFull
	res, err = b.Backup(context.Background(), BackupParams{Redact: &no})
	if err != nil || res.Redacted {
		t.Fatalf("full = %+v %v", res, err)
	}
	if data, _ := base64.StdEncoding.DecodeString(res.ContentBase64); !bytes.Equal(data, archive) {
		t.Error("a full backup must be the archive as is")
	}
	// Too large, and a failing sysupgrade.
	b.Create = func(_ context.Context, path string) error {
		return os.WriteFile(path, make([]byte, MaxBackupBytes+1), 0o600)
	}
	if _, err := b.Backup(context.Background(), BackupParams{}); !errors.As(err, &be) || be.Code != "backup_too_large" {
		t.Errorf("too large = %v", err)
	}
	b.Create = func(context.Context, string) error { return errors.New("sysupgrade -b: exit status 1") }
	if _, err := b.Backup(context.Background(), BackupParams{}); !errors.As(err, &be) || be.Code != "backup_failed" {
		t.Errorf("failure = %v", err)
	}
	entries, _ := os.ReadDir(b.TempDir)
	if len(entries) != 0 {
		t.Errorf("temporary files left: %v", entries)
	}
}
