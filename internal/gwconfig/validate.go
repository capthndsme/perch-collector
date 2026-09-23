package gwconfig

import (
	"strconv"
	"strings"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"

	"github.com/capthndsme/perch-collector/internal/qos"
)

// CodeInvalidConfig refuses an apply whose result breaks a rule of the
// router's own (a config validator below); data {config, section?, detail}.
const CodeInvalidConfig = "invalid_config"

// configLookup returns a config as the apply would leave it (touched) or as
// it is now; nil when the router has none.
type configLookup func(name string) *uci.Config

// validators run on the simulated result before anything is staged. Each is
// keyed by the configs whose change triggers it.
var validators = []struct {
	configs []string
	check   func(get configLookup) *PlaneError
}{
	{[]string{"sqm", "perch-qos"}, validateSQMFloor},
}

// validateApply runs the validators whose configs the apply touches.
func validateApply(touched []string, get configLookup) error {
	in := map[string]bool{}
	for _, c := range touched {
		in[c] = true
	}
	for _, v := range validators {
		hit := false
		for _, c := range v.configs {
			hit = hit || in[c]
		}
		if !hit {
			continue
		}
		if err := v.check(get); err != nil {
			return err
		}
	}
	return nil
}

// validateSQMFloor: no enabled sqm queue may shape below perch-qos
// globals.min_wan_kbit (gateway plan 3 section 8, qos.CheckSQMFloor). The
// agent never rewrites sqm itself; the edit is refused here instead.
func validateSQMFloor(get configLookup) *PlaneError {
	sqm := get("sqm")
	if sqm == nil {
		return nil
	}
	var perchQoS []byte
	if c := get("perch-qos"); c != nil {
		perchQoS = uci.Render(c)
	}
	floor := qos.MinWanKbit(perchQoS)
	for _, s := range sqm.OfType("queue") {
		enabled := uciBool(s, "enabled", true)
		down := uciInt(s, "download")
		up := uciInt(s, "upload")
		if err := qos.CheckSQMFloor(enabled, down, up, floor); err != nil {
			e := perr(CodeInvalidConfig, "sqm.%s: %v", s.Name, err)
			e.Data = map[string]any{"config": "sqm", "section": s.Name, "detail": "sqm_below_floor", "minWanKbit": floor}
			return e
		}
	}
	return nil
}

func uciBool(s *uci.Section, name string, def bool) bool {
	v, ok := s.Get(name)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v.Str())) {
	case "1", "on", "true", "yes", "enabled":
		return true
	case "0", "off", "false", "no", "disabled":
		return false
	}
	return def
}

func uciInt(s *uci.Section, name string) int64 {
	v, ok := s.Get(name)
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v.Str()), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
