package netutil

import (
	"net"
	"strings"
	"testing"
)

func TestParseLEHexIPv4(t *testing.T) {
	cases := []struct {
		hex  string
		want string
	}{
		// /proc/net/route stores host-byte-order, so on LE machines the bytes
		// are reversed relative to dotted-quad notation.
		{"0101A8C0", "192.168.1.1"},
		{"FE14A8C0", "192.168.20.254"},
		{"00000000", "0.0.0.0"},
	}
	for _, c := range cases {
		got, err := parseLEHexIPv4(c.hex)
		if err != nil {
			t.Fatalf("parseLEHexIPv4(%q): %v", c.hex, err)
		}
		if got.String() != c.want {
			t.Errorf("parseLEHexIPv4(%q) = %s, want %s", c.hex, got, c.want)
		}
	}
}

func TestParseLEHexIPv4Invalid(t *testing.T) {
	if _, err := parseLEHexIPv4("XX"); err == nil {
		t.Error("expected error for short input")
	}
	if _, err := parseLEHexIPv4("ZZZZZZZZ"); err == nil {
		t.Error("expected error for non-hex input")
	}
}

func TestParseCIDRs(t *testing.T) {
	got, err := ParseCIDRs([]string{"10.0.0.0/8", "", "fe80::/10"})
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 nets, got %d", len(got))
	}
	if got[0].String() != "10.0.0.0/8" {
		t.Errorf("got[0]=%s", got[0])
	}
	if got[1].String() != "fe80::/10" {
		t.Errorf("got[1]=%s", got[1])
	}

	if _, err := ParseCIDRs([]string{"not-a-cidr"}); err == nil {
		t.Error("expected error for malformed CIDR")
	}
}

func TestMergeSubnets(t *testing.T) {
	a, _ := ParseCIDRs([]string{"10.0.0.0/8", "172.16.0.0/12"})
	b, _ := ParseCIDRs([]string{"10.0.0.0/8", "192.168.0.0/16"})
	merged := MergeSubnets(a, b)
	if len(merged) != 3 {
		t.Fatalf("expected 3 deduped nets, got %d", len(merged))
	}
}

func TestIsLocal(t *testing.T) {
	subnets, _ := ParseCIDRs([]string{"192.168.0.0/16", "fe80::/10"})
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.5", true},
		{"172.21.0.1", false},
		{"fe80::1234", true},
		{"2001:db8::1", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		got := IsLocal(net.ParseIP(c.ip), subnets)
		if got != c.want {
			t.Errorf("IsLocal(%s)=%v, want %v", c.ip, got, c.want)
		}
	}
}

func TestParseDefaultInterface(t *testing.T) {
	const header = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	cases := []struct {
		name  string
		table string
		want  string
	}{
		{
			name: "single default route",
			table: header +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "lowest metric wins even when listed second",
			table: header +
				"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
				"br-lan\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
			want: "br-lan",
		},
		{
			name: "down route is skipped",
			table: header +
				"eth1\t00000000\t0101A8C0\t0002\t0\t0\t0\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
	}
	for _, c := range cases {
		got, err := parseDefaultInterface(strings.NewReader(c.table))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseDefaultInterfaceNone(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	if _, err := parseDefaultInterface(strings.NewReader(table)); err == nil {
		t.Error("expected error when no default route is present")
	}
}
