package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

func fullFiles() map[string]string {
	return map[string]string{
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
	}
}

func full(t *testing.T) hoststat.FS {
	return fixture(t, fullFiles())
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

// addNetdev adds one /sys/class/net entry to a fixture: a directory of
// attribute files, as sysfs shows a netdev.
func addNetdev(files map[string]string, name string, attrs map[string]string) {
	for k, v := range attrs {
		files["sys/class/net/"+name+"/"+k] = v + "\n"
	}
}

// addVeth adds the inside end of a veth: no device link, iflink an index in
// the peer's namespace, 10 Gb/s, link up. What a router in a container has
// instead of ports.
func addVeth(files map[string]string, name string, ifindex, iflink int, mac string) {
	addNetdev(files, name, map[string]string{
		"type": "1", "ifindex": strconv.Itoa(ifindex), "iflink": strconv.Itoa(iflink),
		"flags": "0x1003", "carrier": "1", "carrier_changes": "2", "operstate": "up",
		"speed": "10000", "duplex": "full", "address": mac,
		"uevent": "INTERFACE=" + name + "\nIFINDEX=" + strconv.Itoa(ifindex),
	})
}

// addNoPorts adds what every host has that is not a port: lo, and the ifb
// SQM puts on the WAN (iflink == ifindex).
func addNoPorts(files map[string]string) {
	addNetdev(files, "lo", map[string]string{"type": "772", "ifindex": "1", "iflink": "1", "flags": "0x9", "address": "00:00:00:00:00:00"})
	addNetdev(files, "ifb4wan0", map[string]string{"type": "1", "ifindex": "22", "iflink": "22", "flags": "0x83", "operstate": "unknown", "address": "02:00:00:00:00:22"})
}

// containerGateway is a router in a container with the dual WAN of full():
// veths wan0 and wan2 (the default routes), lan0 and guest, and no board.json
// (in a container it would be the host's anyway).
func containerGateway() map[string]string {
	files := fullFiles()
	addNoPorts(files)
	addVeth(files, "guest", 25, 26, "02:00:00:00:00:25")
	addVeth(files, "lan0", 29, 30, "02:00:00:00:00:29")
	addVeth(files, "wan0", 35, 36, "02:00:00:00:00:35")
	addVeth(files, "wan2", 37, 38, "02:00:00:00:00:37")
	return files
}

func veth(name, role, mac string) string {
	if role != "" {
		role = `"role":"` + role + `",`
	}
	return fmt.Sprintf(`{"name":%q,"label":%q,%s"medium":"virtual","mac":%q,"adminUp":true,"carrier":true,"operstate":"up","speedMbps":10000,"duplex":"full","carrierChanges":2}`, name, name, role, mac)
}

// The ports ride in the report after wanSource; the interfaces the report
// counts as WAN (here the default routes) are role "wan" and come first.
func TestPortsInReport(t *testing.T) {
	fs := fixture(t, containerGateway())
	s := Reader{FS: fs, Now: fixed, Ports: NewPorts(fs)}.Read()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"collectedAt":"2026-09-21T14:17:10Z","conntrack":{"entries":2495,"limit":262144},"tcpEstablished":2,` +
		`"load":{"load1":1.44,"load5":1.1,"load15":1.49},"memory":{"totalBytes":15637843968,"availableBytes":15524997120},` +
		`"wan":[{"name":"pppoe-wan","rxBytes":777,"txBytes":888},{"name":"wan0","rxBytes":693974698743,"txBytes":1697321558462},` +
		`{"name":"wan2","rxBytes":14071637,"txBytes":1116436}],"wanSource":"default-route",` +
		`"ports":[` + veth("wan0", "wan", "02:00:00:00:00:35") + `,` + veth("wan2", "wan", "02:00:00:00:00:37") + `,` +
		veth("guest", "", "02:00:00:00:00:25") + `,` + veth("lan0", "", "02:00:00:00:00:29") + `]}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

// Configured WAN interfaces are what the report counts, so they alone are
// role "wan", even when another interface holds a default route.
func TestPortsWANFromConfiguredInterfaces(t *testing.T) {
	fs := fixture(t, containerGateway())
	r := Reader{FS: fs, Now: fixed, WANInterfaces: []string{"wan2"}, Ports: NewPorts(fs)}
	s := r.Read()
	if s.Ports == nil {
		t.Fatal("no ports")
	}
	if got := roles(*s.Ports); got != "wan2:wan,guest,lan0,wan0" {
		t.Fatalf("ports %s", got)
	}
	if got := roles(r.ReadPorts()); got != "wan2:wan,guest,lan0,wan0" {
		t.Fatalf("ReadPorts %s", got)
	}
}

// Ports off: the key is absent from the report, and nothing under /sys is
// read for it.
func TestPortsOffLeavesTheKeyOut(t *testing.T) {
	r := Reader{FS: fixture(t, containerGateway()), Now: fixed}
	b, _ := json.Marshal(r.Read())
	if strings.Contains(string(b), `"ports"`) {
		t.Fatalf("ports off: %s", b)
	}
	if r.ReadPorts() != nil {
		t.Fatal("ReadPorts with ports off")
	}
}

// A host without ports reports an empty list, which the controller reads
// as "looked and found none".
func TestPortsNoneIsAnEmptyList(t *testing.T) {
	files := fullFiles()
	addNoPorts(files)
	fs := fixture(t, files)
	b, _ := json.Marshal(Reader{FS: fs, Now: fixed, Ports: NewPorts(fs)}.Read())
	if !strings.HasSuffix(string(b), `"wanSource":"default-route","ports":[]}`) {
		t.Fatalf("no ports: %s", b)
	}
}

// When /sys/class/net cannot be listed the key is left out: an empty list
// would tell the controller the ports are gone.
func TestPortsUnlistableLeavesTheKeyOut(t *testing.T) {
	fs := fixture(t, nil)
	b, _ := json.Marshal(Reader{FS: fs, Now: fixed, Ports: NewPorts(fs)}.Read())
	if string(b) != `{"collectedAt":"2026-09-21T14:17:10Z","wan":[],"wanSource":"default-route"}` {
		t.Fatalf("%s", b)
	}
}

// One Reader over time: a default route that moves takes the role with it
// on the next report, and link state is read fresh every time although the
// port facts are cached.
func TestPortsFollowTheRoutesAndTheLink(t *testing.T) {
	files := containerGateway()
	delete(files, "proc/net/ipv6_route")
	root := fixture(t, files)
	r := Reader{FS: root, Now: fixed, Ports: NewPorts(root)}
	if got := roles(*r.Read().Ports); got != "wan0:wan,wan2:wan,guest,lan0" {
		t.Fatalf("before %s", got)
	}

	write := func(p, body string) {
		if err := os.WriteFile(filepath.Join(root.Root, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"wan2\t00000000\t0102A8C0\t0003\t0\t0\t2\t00000000\t0\t0\t0\n")
	write("sys/class/net/wan0/carrier", "0\n")
	write("sys/class/net/wan0/operstate", "lowerlayerdown\n")
	write("sys/class/net/wan0/carrier_changes", "3\n")
	s := r.Read()
	if got := roles(*s.Ports); got != "wan2:wan,guest,lan0,wan0" {
		t.Fatalf("after %s", got)
	}
	w0 := (*s.Ports)[3]
	if w0.Carrier == nil || *w0.Carrier || w0.Operstate != "lowerlayerdown" || w0.CarrierChanges == nil || *w0.CarrierChanges != 3 {
		t.Fatalf("wan0 state not read fresh: %+v", w0)
	}
}

// The push and GET /api/v1/summary build reports at the same time, from
// copies of one Reader that share its Ports, each with the WAN list of its
// moment. Each report must get the roles of its own list (run with -race).
func TestPortsConcurrentReports(t *testing.T) {
	fs := fixture(t, containerGateway())
	shared := NewPorts(fs)
	readers := []Reader{
		{FS: fs, Now: fixed, WANInterfaces: []string{"wan0"}, Ports: shared},
		{FS: fs, Now: fixed, WANInterfaces: []string{"lan0"}, Ports: shared},
	}
	want := []string{"wan0:wan,guest,lan0,wan2", "lan0:wan,guest,wan0,wan2"}
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				k := (g + i) % 2
				s := readers[k].Read()
				if s.Ports == nil {
					errs <- "no ports"
					return
				}
				if got := roles(*s.Ports); got != want[k] {
					errs <- fmt.Sprintf("reader %d got %s, want %s", k, got, want[k])
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// roles renders ports as name[:role] in report order.
func roles(ports []hoststat.Port) string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = p.Name
		if p.Role != "" {
			out[i] += ":" + p.Role
		}
	}
	return strings.Join(out, ",")
}
