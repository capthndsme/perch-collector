package gwconfig

import (
	"fmt"
	"testing"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

func parseFix(t *testing.T, name, body string) *uci.Config {
	t.Helper()
	c, err := uci.Parse(name, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidateSQMFloor(t *testing.T) {
	sqm := func(enabled, down, up string) string {
		return fmt.Sprintf("config queue 'wan'\n\toption enabled '%s'\n\toption interface 'eth1'\n\toption download '%s'\n\toption upload '%s'\n", enabled, down, up)
	}
	floor := "config globals 'globals'\n\toption min_wan_kbit '5000'\n"
	for _, tc := range []struct {
		name, sqm, perchQoS string
		touched             []string
		want                string
	}{
		{"above default floor", sqm("1", "50000", "10000"), "", []string{"sqm"}, ""},
		{"below default floor", sqm("1", "500", "10000"), "", []string{"sqm"}, CodeInvalidConfig},
		{"0 = not shaped", sqm("1", "0", "0"), "", []string{"sqm"}, ""},
		{"disabled queue", sqm("0", "500", "500"), "", []string{"sqm"}, ""},
		{"below a raised floor", sqm("1", "50000", "4000"), floor, []string{"sqm"}, CodeInvalidConfig},
		{"perch-qos raises the floor over live sqm", sqm("1", "50000", "4000"), floor, []string{"perch-qos"}, CodeInvalidConfig},
		{"untouched configs are not checked", sqm("1", "500", "500"), "", []string{"dhcp"}, ""},
	} {
		configs := map[string]*uci.Config{"sqm": parseFix(t, "sqm", tc.sqm)}
		if tc.perchQoS != "" {
			configs["perch-qos"] = parseFix(t, "perch-qos", tc.perchQoS)
		}
		err := validateApply(tc.touched, func(n string) *uci.Config { return configs[n] })
		if code(err) != tc.want {
			t.Errorf("%s: %v", tc.name, err)
		}
		if err != nil && data(err)["section"] != "wan" {
			t.Errorf("%s: data %v", tc.name, data(err))
		}
	}
	if err := validateApply([]string{"sqm"}, func(string) *uci.Config { return nil }); err != nil {
		t.Errorf("no sqm: %v", err)
	}
}

// Through the engine: an sqm put below the floor is refused before
// anything is staged.
func TestApplyRefusesSQMBelowFloor(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Allowlist = append(append([]string{}, DefaultAllowlist...), "sqm") })
	put(t, e.root, "etc/config/sqm", "config queue 'wan'\n\toption enabled '1'\n\toption download '50000'\n\toption upload '10000'\n")
	before := e.file("sqm")
	_, err := e.apply(fmt.Sprintf(`{"applyId":"q1","base":%s,"ops":[
	  {"op":"put","config":"sqm","section":"perch_q1","type":"queue","options":{"enabled":"1","download":"50000","upload":"300"}}]}`, mustJSON(e.base("sqm"))))
	if code(err) != CodeInvalidConfig {
		t.Fatalf("got %v", err)
	}
	if e.file("sqm") != before {
		t.Fatal("sqm changed")
	}
	res, err := e.apply(fmt.Sprintf(`{"applyId":"q2","dryRun":true,"base":%s,"ops":[
	  {"op":"put","config":"sqm","section":"perch_q1","type":"queue","options":{"enabled":"1","download":"50000","upload":"2000"}}]}`, mustJSON(e.base("sqm"))))
	if err != nil || res.State != StateDryRun {
		t.Fatalf("%+v %v", res, err)
	}
}
