package qos

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func loadKernelFixture(t *testing.T) (*Kernel, kernelFixture) {
	t.Helper()
	data, err := os.ReadFile("testdata/kernel-weekday-noon.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx kernelFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	answers, err := parseBatchOutput(fx.Commands, []byte(fx.Stdout), []byte(fx.Stderr))
	if err != nil {
		t.Fatal(err)
	}
	k, err := parseKernel(fx.Commands, answers)
	if err != nil {
		t.Fatal(err)
	}
	return k, fx
}

// TestParseRealKernel reads tc's JSON of an applied plan (captured in a
// namespace by TestNetnsKernelFixture) and finds it equal to the plan.
func TestParseRealKernel(t *testing.T) {
	k, _ := loadKernelFixture(t)
	d := Plan(fixtureInputs(t, time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)), NewState("golden"))
	if b := Diff(d, k, nil); !b.Empty() {
		t.Fatalf("diff against the real kernel:\n%s", b.Text())
	}
	down := k.Ifb[Down]
	if down.RootKind != "htb" || down.RootHandle != "1:" {
		t.Errorf("root %s %s", down.RootKind, down.RootHandle)
	}
	c := down.Classes[0x200]
	if c == nil || c.Parent != RootMinor || c.RateBps != 250000 || c.CeilBps != 250000 || c.Leaf != "200:" {
		t.Fatalf("class 1:200: %+v", c)
	}
	if q := down.Qdiscs["200:"]; q == nil || q.Kind != "fq_codel" {
		t.Errorf("leaf of 1:200: %+v", q)
	}
	if q := down.Qdiscs["112:"]; q == nil || q.Kind != "cake" || q.Options["flowmode"] != "dual-dsthost" {
		t.Errorf("rest leaf: %+v", q)
	}
	lan := k.Devs["lan"]
	if lan == nil || !lan.Clsact || lan.Ingress {
		t.Fatalf("lan: %+v", lan)
	}
	var sawExempt, sawClass, sawDrop bool
	for _, f := range lan.Filters {
		switch {
		case f.Pref == PrefExemptV4 && f.Match == "src_ip=192.168.10.0/24" && f.Action == ActPass && f.Hook == "egress":
			sawExempt = true
		case f.Pref == PrefDevice && f.Match == "dst_mac=02:00:00:00:10:11" && f.Action == "class:200@ifb-pdn":
			sawClass = true
		case f.Pref == PrefDevice && f.Match == "src_mac=02:00:00:00:10:15" && f.Action == ActDrop && f.Hook == "ingress":
			sawDrop = true
		}
	}
	if !sawExempt || !sawClass || !sawDrop {
		t.Errorf("filters: exempt %v class %v drop %v", sawExempt, sawClass, sawDrop)
	}
}

// TestParseSpikeFixtures reads the kernel spike's `tc -s -j` output
// (OpenWrt 24.10, tc-tiny): the shapes the stats reader depends on.
func TestParseSpikeFixtures(t *testing.T) {
	read := func(name string) json.RawMessage {
		data, err := os.ReadFile("testdata/spike/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	cls, err := parseClasses(read("tc-s-j-class-ifb-pdn.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c202 *KClass
	for _, c := range cls {
		if c.Minor == 0x202 {
			c202 = c
		}
	}
	if c202 == nil || c202.Parent != 0x13 || c202.RateBps != 8000 || c202.CeilBps != 500000 || c202.Leaf != "804a:" || c202.Stats.Bytes != 37968013 {
		t.Fatalf("1:202: %+v", c202)
	}
	qs, err := parseQdiscs(read("tc-s-j-qdisc-ifb-pdn.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fq *KQdisc
	for _, q := range qs {
		if q.Handle == "804a:" {
			fq = q
		}
	}
	if fq == nil || fq.Kind != "fq_codel" || fq.Stats.Drops != 351 {
		t.Fatalf("804a: %+v", fq)
	}
	wan, err := parseQdiscs(read("tc-s-j-qdisc-wan2-sqm.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := qdiscStats(wan[0])
	if s.Kind != "cake" || s.BandwidthKbit == nil || *s.BandwidthKbit != 50000 || s.Drops != 173 || *s.PeakDelayUs != 4 {
		t.Errorf("sqm cake: %+v", s)
	}
	fs, err := parseFilters(read("tc-s-j-filter-lan-egress.json"), "egress")
	if err != nil {
		t.Fatal(err)
	}
	var mac *KFilter
	for i := range fs {
		if fs[i].Pref == 10 {
			mac = &fs[i]
		}
	}
	if mac == nil || mac.Match != "dst_mac=02:00:00:99:10:11" || mac.Action != "class:201@ifb-pdn" || mac.Bytes != 3826681 {
		t.Fatalf("pref 10: %+v", mac)
	}
	if fs[0].Kind != "matchall" || fs[0].Action != ActPass || fs[0].Proto != "arp" {
		t.Errorf("arp: %+v", fs[0])
	}
}

func TestParseBatchOutputFailures(t *testing.T) {
	cmds := []string{"qdisc show dev a", "qdisc show dev nosuch", "qdisc show dev b"}
	out := `[{"kind":"noqueue","handle":"0:","root":true}]
[{"kind":"fq_codel","handle":"0:","root":true}]
`
	answers, err := parseBatchOutput(cmds, []byte(out), []byte("Cannot find device \"nosuch\"\nCommand failed -:2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if answers[1] != nil || !strings.Contains(string(answers[2]), "fq_codel") {
		t.Errorf("answers: %q", answers)
	}
	if _, err := parseBatchOutput(cmds, []byte(out), nil); err == nil {
		t.Error("a missing answer went unnoticed")
	}
	msgs := tcErrors([]string{"class add dev x", "filter add dev y"}, []byte("Error: Invalid handle.\nCommand failed -:2\n"))
	if len(msgs) != 1 || msgs[0] != "filter add dev y: Error: Invalid handle." {
		t.Errorf("errors: %q", msgs)
	}
}

func TestCanonicalKeys(t *testing.T) {
	for in, want := range map[string]string{
		`{"eth_type":"ipv4","src_ip":"192.168.1.1"}`:                   "src_ip=192.168.1.1/32",
		`{"eth_type":"ipv6","dst_ip":"FD00:10::/64"}`:                   "dst_ip=fd00:10::/64",
		`{"dst_mac":"01:00:00:00:00:00/01:00:00:00:00:00"}`:             "dst_mac=01:00:00:00:00:00/01:00:00:00:00:00",
		`{}`:                                                             "",
		`{"src_mac":"02:00:00:00:00:0A","eth_type":"arp"}`:              "src_mac=02:00:00:00:00:0a",
	} {
		var keys map[string]any
		if err := json.Unmarshal([]byte(in), &keys); err != nil {
			t.Fatal(err)
		}
		if got := canonicalKeys(keys); got != want {
			t.Errorf("%s → %q, want %q", in, got, want)
		}
	}
}
