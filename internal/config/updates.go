package config

import (
	"fmt"
	"os"
)

// Updates is the router owner's say on agent self-update (agent-updates
// design, device.md 10.2): whether the controller may install signed Perch
// releases of this collector, and which release keys it trusts besides the
// ones built in. Like ConfigPlane it lives in the collector's own config,
// which neither the config plane nor the updater ever writes, so only
// someone with access to the router can change it.
type Updates struct {
	// SelfUpdate lets the controller update this collector (default true):
	// only releases signed with a trusted key, every file checked here, the
	// previous version restored unless the new one is confirmed.
	SelfUpdate bool `yaml:"self_update"`
	// UpdateKeys are extra trusted release keys: signify/usign public key
	// lines ("RW…"), e.g. a lab's test key.
	UpdateKeys []string `yaml:"update_keys"`
}

func defaultUpdates() Updates { return Updates{SelfUpdate: true} }

func (u *Updates) readEnv(env *envReader) {
	env.boolean("SELF_UPDATE", &u.SelfUpdate)
	if list, ok := env.list("UPDATE_KEYS"); ok {
		u.UpdateKeys = list
	}
}

// ownPackages are the collector's own packages: they are updated only by the
// updater (agent.update.*), never through gateway.package.install, whatever
// package_allow lists (agent-updates README section 3).
var ownPackages = map[string]bool{"perch-collector": true, "perch-qos": true, "perch-apd": true}

func (c *Config) validateUpdates() {
	c.UpdateKeys = cleanList(c.UpdateKeys)
	var allow []string
	for _, name := range c.PackageAllow {
		if ownPackages[name] {
			fmt.Fprintf(os.Stderr, "WARNING: package_allow %q: Perch's own packages are updated from Settings → Updates, never installed as a gateway package; ignored.\n", name)
			continue
		}
		allow = append(allow, name)
	}
	c.PackageAllow = allow
}
