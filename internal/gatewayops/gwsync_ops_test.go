package gatewayops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// The runtime actions of gateway-sync protocol 6.2.

type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	code  int
	err   error
	// out answers a command line (name and args joined by spaces).
	out map[string]string
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	if o, ok := f.out[strings.Join(append([]string{name}, args...), " ")]; ok {
		return []byte(o), nil, 0, nil
	}
	if f.err != nil {
		return nil, nil, -1, f.err
	}
	if f.code != 0 {
		return nil, []byte("Command failed\n"), f.code, nil
	}
	return nil, nil, 0, nil
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// miniupnpd 2.x lines, a 1.x line, a line that is no mapping, a CRLF line
// and no newline at the end: everything but the deleted mappings stays
// byte for byte.
const leases = "TCP:51413:192.168.1.21:51413:1790003600:torrent client\n" +
	"UDP:51413:192.168.1.21:51413:1790003600:torrent client\n" +
	"TCP:3074:192.168.1.30:3074:0:console: xbox live\n" +
	"# not a mapping\n" +
	"udp:9308:192.168.1.30:9308:app v1\r\n" +
	"TCP:8080:192.168.1.40:80:0:web"

func upnpRoot(t *testing.T, leaseFile string) string {
	root := t.TempDir()
	files := map[string]string{
		"usr/sbin/miniupnpd":               "",
		"etc/init.d/miniupnpd":             "",
		"etc/config/upnpd":                 "\nconfig upnpd 'config'\n\toption enabled '1'\n\toption upnp_lease_file '" + leaseFile + "'\n",
		strings.TrimPrefix(leaseFile, "/"): leases,
	}
	writeFiles(t, root, files)
	return root
}

func TestUPnPDeleteByContent(t *testing.T) {
	root := upnpRoot(t, "/tmp/upnp.leases")
	r := &fakeRunner{}
	u := &UPnP{Root: root, Run: r.run}
	res, err := u.Delete(context.Background(), UPnPDeleteParams{Mappings: []UPnPMappingRef{
		{Proto: "tcp", ExtPort: 51413}, {Proto: "UDP", ExtPort: 9308}, {Proto: "TCP", ExtPort: 9999}}})
	if err != nil || res.Deleted != 2 || res.NotFound != 1 || !res.Restarted {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "tmp/upnp.leases"))
	want := "UDP:51413:192.168.1.21:51413:1790003600:torrent client\n" +
		"TCP:3074:192.168.1.30:3074:0:console: xbox live\n" +
		"# not a mapping\n" +
		"TCP:8080:192.168.1.40:80:0:web"
	if string(got) != want {
		t.Fatalf("lease file\n%q\nwant\n%q", got, want)
	}
	if len(r.calls) != 1 || filepath.Base(r.calls[0][0]) != "miniupnpd" || r.calls[0][1] != "restart" {
		t.Fatalf("calls %v", r.calls)
	}
	// Again: nothing left to delete, nothing written, no restart.
	res, err = u.Delete(context.Background(), UPnPDeleteParams{Mappings: []UPnPMappingRef{{Proto: "TCP", ExtPort: 51413}}})
	if err != nil || res.Deleted != 0 || res.NotFound != 1 || res.Restarted || len(r.calls) != 1 {
		t.Fatalf("%+v %v %v", res, err, r.calls)
	}
}

// A device just blocked: miniupnpd's restart dropped its mapping from the
// lease file (the new deny refused to re-add it) but left the nftables
// rules, so the port is still open. The delete removes them.
func TestUPnPDeleteRemovesOrphanRules(t *testing.T) {
	root := upnpRoot(t, "/var/run/miniupnpd.leases")
	writeFiles(t, root, map[string]string{
		"usr/sbin/nft": "",
		"var/etc/miniupnpd.conf": "ext_ifname=wan\nupnp_table_name=fw4\nupnp_nat_table_name=fw4\n" +
			"upnp_forward_chain=upnp_forward\nupnp_nat_chain=upnp_prerouting\n",
	})
	r := &fakeRunner{out: map[string]string{
		"nft -a list chain inet fw4 upnp_prerouting": "table inet fw4 {\n\tchain upnp_prerouting {\n" +
			"\t\tiif \"wan\" @nh,72,8 0x6 th dport 45000 dnat ip to 10.99.10.128:5000 # handle 8536\n" +
			"\t\tiif \"wan\" @nh,72,8 0x11 th dport 3074 dnat ip to 192.168.1.30:3074 # handle 8540\n\t}\n}\n",
		"nft -a list chain inet fw4 upnp_forward": "table inet fw4 {\n\tchain upnp_forward {\n" +
			"\t\tiif \"wan\" th dport 5000 @nh,128,32 0xa630a80 @nh,72,8 0x6 accept # handle 8537\n" +
			"\t\tiif \"wan\" th dport 3074 @nh,128,32 0xc0a8011e @nh,72,8 0x11 accept # handle 8541\n\t}\n}\n",
	}}
	u := &UPnP{Root: root, Run: r.run}
	res, err := u.Delete(context.Background(), UPnPDeleteParams{Mappings: []UPnPMappingRef{{Proto: "TCP", ExtPort: 45000}}})
	if err != nil || res.Deleted != 1 || res.NotFound != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	var deletes []string
	for _, c := range r.calls {
		if len(c) > 2 && c[0] == "nft" && c[1] == "delete" {
			deletes = append(deletes, strings.Join(c, " "))
		}
	}
	want := []string{
		"nft delete rule inet fw4 upnp_prerouting handle 8536",
		"nft delete rule inet fw4 upnp_forward handle 8537",
	}
	if strings.Join(deletes, "\n") != strings.Join(want, "\n") {
		t.Fatalf("deletes:\n%s", strings.Join(deletes, "\n"))
	}
}

func TestUPnPDeleteRefusals(t *testing.T) {
	ctx := context.Background()
	u := &UPnP{Root: t.TempDir(), Run: (&fakeRunner{}).run}
	var pe *ParamError
	for _, p := range []UPnPDeleteParams{
		{},
		{Mappings: []UPnPMappingRef{{Proto: "SCTP", ExtPort: 1}}},
		{Mappings: []UPnPMappingRef{{Proto: "TCP", ExtPort: 0}}},
		{Mappings: make([]UPnPMappingRef, MaxUPnPDelete+1)},
	} {
		if _, err := u.Delete(ctx, p); !errors.As(err, &pe) || pe.Code != "bad_params" {
			t.Fatalf("%+v: %v", p, err)
		}
	}
	var ae *ActionError
	if _, err := u.Delete(ctx, UPnPDeleteParams{Mappings: []UPnPMappingRef{{Proto: "TCP", ExtPort: 1}}}); !errors.As(err, &ae) || ae.Code != "upnp_not_installed" {
		t.Fatal(err)
	}
	// A failed restart is upnp_failed with the detail.
	root := upnpRoot(t, "/var/run/miniupnpd.leases")
	os.Remove(filepath.Join(root, "etc/config/upnpd")) // the default lease file
	u = &UPnP{Root: root, Run: (&fakeRunner{code: 1}).run}
	if _, err := u.Delete(ctx, UPnPDeleteParams{Mappings: []UPnPMappingRef{{Proto: "TCP", ExtPort: 8080}}}); !errors.As(err, &ae) || ae.Code != "upnp_failed" || ae.Detail != "Command failed" {
		t.Fatal(err)
	}
	// No lease file at all: nothing found.
	os.Remove(filepath.Join(root, "var/run/miniupnpd.leases"))
	if res, err := u.Delete(ctx, UPnPDeleteParams{Mappings: []UPnPMappingRef{{Proto: "TCP", ExtPort: 8080}}}); err != nil || res.NotFound != 1 || res.Restarted {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestDDNSUpdate(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	r := &fakeRunner{}
	d := &DDNS{Root: root, Run: r.run}
	var ae *ActionError
	if _, err := d.Update(ctx, DDNSUpdateParams{Service: "home"}); !errors.As(err, &ae) || ae.Code != "ddns_not_installed" {
		t.Fatal(err)
	}
	writeFiles(t, root, map[string]string{
		"usr/lib/ddns/dynamic_dns_updater.sh": "#!/bin/sh\n",
		"etc/config/ddns":                     "\nconfig ddns 'global'\n\toption ddns_dateformat '%F %R'\n\nconfig service 'home'\n\toption enabled '1'\n\toption password 'x'\n\nconfig service\n\toption enabled '0'\n",
	})
	var pe *ParamError
	for _, bad := range []string{"", "../x", "a b", "home;reboot"} {
		if _, err := d.Update(ctx, DDNSUpdateParams{Service: bad}); !errors.As(err, &pe) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	for _, unknown := range []string{"office", "global"} {
		if _, err := d.Update(ctx, DDNSUpdateParams{Service: unknown}); !errors.As(err, &ae) || ae.Code != "ddns_unknown_service" {
			t.Fatalf("%s: %v", unknown, err)
		}
	}
	if len(r.calls) != 0 {
		t.Fatal(r.calls)
	}
	res, err := d.Update(ctx, DDNSUpdateParams{Service: "home"})
	if err != nil || !res.Started {
		t.Fatalf("%+v %v", res, err)
	}
	want := "start-stop-daemon -S -b -x " + filepath.Join(root, DDNSUpdaterScript) + " -- -v 0 -S home -- start"
	if len(r.calls) != 1 || strings.Join(r.calls[0], " ") != want {
		t.Fatalf("ran %v\nwant %s", r.calls, want)
	}
	// An anonymous section by its libuci name (what `uci -X show` and the
	// ddns observation call it).
	if res, err := d.Update(ctx, DDNSUpdateParams{Service: uci.AnonymousName(3, "service")}); err != nil || !res.Started {
		t.Fatalf("%+v %v", res, err)
	}
	r.code = 1
	if _, err := d.Update(ctx, DDNSUpdateParams{Service: "home"}); !errors.As(err, &ae) || ae.Code != "ddns_failed" {
		t.Fatal(err)
	}
}
