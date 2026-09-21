package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/capthndsme/perch-agentkit/hoststat"
)

func fixture(t *testing.T, files map[string]string) hoststat.FS {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return hoststat.FS{Root: root}
}

const netdev = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n" +
	"    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n" +
	"  lan0: 5000 1 0 0 0 0 0 0 9000 1 0 0 0 0 0 0\n" +
	"  wan0: 693974698743 5 0 0 0 0 0 0 1697321558462 6 0 0 0 0 0 0\n" +
	"  wan2: 14071637 5 0 0 0 0 0 0 1116436 6 0 0 0 0 0 0\n" +
	"pppoe-wan: 777 1 0 0 0 0 0 0 888 1 0 0 0 0 0 0\n"

// Two IPv4 default routes (dual WAN), a down route that does not count.
const routeV4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"wan0\t00000000\t017100CB\t0003\t0\t0\t1\t00000000\t0\t0\t0\n" +
	"wan2\t00000000\t0102A8C0\t0003\t0\t0\t2\t00000000\t0\t0\t0\n" +
	"lan0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
	"stale0\t00000000\t01010101\t0002\t0\t0\t9\t00000000\t0\t0\t0\n"

// IPv6: unreachable defaults on lo, a reject route, and one real default.
const routeV6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n" +
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000201 blackhole0\n" +
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 pppoe-wan\n"

func full(t *testing.T) hoststat.FS {
	return fixture(t, map[string]string{
		"proc/net/dev":        netdev,
		"proc/net/route":      routeV4,
		"proc/net/ipv6_route": routeV6,
		"proc/loadavg":        "1.44 1.10 1.49 1/2336 3075337\n",
		"proc/meminfo":        "MemTotal:       15271332 kB\nMemFree:  221220 kB\nMemAvailable:   15161130 kB\n",
		"proc/net/snmp": "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs\n" +
			"Tcp: 1 200 120000 -1 650 19565 280 13 2 1459927\n",
		"proc/sys/net/netfilter/nf_conntrack_count": "2495\n",
		"proc/sys/net/netfilter/nf_conntrack_max":   "262144\n",
		"etc/openwrt_release":                       "DISTRIB_ID='OpenWrt'\n",
	})
}

var fixed = func() time.Time { return time.Date(2026, 9, 21, 14, 17, 10, 500, time.UTC) }

func TestReadDualWANWithIPv6Default(t *testing.T) {
	s := Reader{FS: full(t), Now: fixed}.Read()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"collectedAt":"2026-09-21T14:17:10Z","conntrack":{"entries":2495,"limit":262144},"tcpEstablished":2,` +
		`"load":{"load1":1.44,"load5":1.1,"load15":1.49},"memory":{"totalBytes":15637843968,"availableBytes":15524997120},` +
		`"wan":[{"name":"pppoe-wan","rxBytes":777,"txBytes":888},{"name":"wan0","rxBytes":693974698743,"txBytes":1697321558462},` +
		`{"name":"wan2","rxBytes":14071637,"txBytes":1116436}],"wanSource":"default-route"}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestConfiguredInterfacesWin(t *testing.T) {
	s := Reader{FS: full(t), Now: fixed, WANInterfaces: []string{"wan2", "missing0"}}.Read()
	if s.WANSource != SourceConfigured || len(s.WAN) != 1 || s.WAN[0].Name != "wan2" || s.WAN[0].RxBytes != 14071637 {
		t.Fatalf("%+v", s)
	}
}

func TestNothingReadable(t *testing.T) {
	s := Reader{FS: fixture(t, nil), Now: fixed}.Read()
	b, _ := json.Marshal(s)
	if string(b) != `{"collectedAt":"2026-09-21T14:17:10Z","wan":[],"wanSource":"default-route"}` {
		t.Fatalf("%s", b)
	}
	if OnOpenWrt(fixture(t, nil)) {
		t.Fatal("empty tree is OpenWrt")
	}
}

// A router without the conntrack module, without IPv6 and without
// MemAvailable (old kernel): the rest still reports.
func TestPartialHost(t *testing.T) {
	fs := fixture(t, map[string]string{
		"proc/net/dev":   netdev,
		"proc/net/route": routeV4,
		"proc/loadavg":   "0.01 0.02 0.03 1/10 99\n",
		"proc/meminfo":   "MemTotal: 1024 kB\nMemFree: 512 kB\n",
		"proc/sys/net/netfilter/nf_conntrack_max": "4096\n",
	})
	s := Reader{FS: fs, Now: fixed}.Read()
	if s.Conntrack == nil || s.Conntrack.Entries != nil || *s.Conntrack.Limit != 4096 {
		t.Fatalf("conntrack %+v", s.Conntrack)
	}
	if s.TCPEstablished != nil || s.Memory == nil || s.Memory.AvailableBytes != nil || *s.Memory.TotalBytes != 1024*1024 {
		t.Fatalf("%+v %+v", s.TCPEstablished, s.Memory)
	}
	if len(s.WAN) != 2 || s.WAN[0].Name != "wan0" || s.WAN[1].Name != "wan2" {
		t.Fatalf("wan %+v", s.WAN)
	}
	if !OnOpenWrt(full(t)) {
		t.Fatal("openwrt_release not detected")
	}
}
