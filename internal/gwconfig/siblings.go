package gwconfig

import (
	"sort"
	"time"
)

// Sibling packages (gateway README 7.7, owner decision 7): a package Perch
// drives through the config plane brings its config onto the allowlist by
// being installed. sqm-scripts → sqm (WAN queues), perch-qos → perch-qos
// (the shaper's package). The router owner opts out with UCI
// (managed_config_auto '0' for all of them, list managed_config_exclude for
// one); the denylist always wins, whatever is installed.

// Sibling is one package whose config joins the allowlist once installed.
type Sibling struct {
	Package string
	Config  string
}

// Siblings are the sibling packages this build knows.
var Siblings = []Sibling{
	{Package: "sqm-scripts", Config: "sqm"},
	{Package: "perch-qos", Config: "perch-qos"},
}

func siblingPackages() []string {
	out := make([]string, 0, len(Siblings))
	for _, s := range Siblings {
		out = append(out, s.Package)
	}
	return out
}

// Reasons of a sibling's allowlist state (gateway.capabilities siblingConfigs).
const (
	SiblingListed       = "listed"        // in managed_config anyway
	SiblingInstalled    = "installed"     // joined by being installed
	SiblingNotInstalled = "not_installed" // joins once installed
	SiblingOptedOut     = "opted_out"     // managed_config_auto '0' or managed_config_exclude
)

// SiblingConfig is one sibling's state in gateway.capabilities.
type SiblingConfig struct {
	Config    string `json:"config"`
	Package   string `json:"package"`
	Installed bool   `json:"installed"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
}

// siblingTTL bounds how stale the installed-package view may be (a package
// installed by hand shows up within it; an install job refreshes at once).
const siblingTTL = 30 * time.Second

type siblingCache struct {
	at        time.Time
	installed map[string]bool
}

// installedSiblings returns which sibling packages are installed, cached for
// siblingTTL. No package database (not OpenWrt) = none.
func (p *Plane) installedSiblings() map[string]bool {
	now := p.clock.Now()
	p.sibMu.Lock()
	defer p.sibMu.Unlock()
	if p.sib.installed != nil && now.Sub(p.sib.at) < siblingTTL && !now.Before(p.sib.at) {
		return p.sib.installed
	}
	out := map[string]bool{}
	if all, err := p.packageDB().Installed(); err == nil {
		for _, s := range Siblings {
			if _, ok := all[s.Package]; ok {
				out[s.Package] = true
			}
		}
	}
	p.sib = siblingCache{at: now, installed: out}
	return out
}

// refreshSiblings drops the cache (after a package job).
func (p *Plane) refreshSiblings() {
	p.sibMu.Lock()
	p.sib = siblingCache{}
	p.sibMu.Unlock()
}

func (p *Plane) siblingExcluded(config string) bool {
	if p.o.SiblingsOff {
		return true
	}
	for _, c := range p.o.SiblingExclude {
		if c == config {
			return true
		}
	}
	return false
}

// SiblingConfigs is every sibling's allowlist state now.
func (p *Plane) SiblingConfigs() []SiblingConfig {
	installed := p.installedSiblings()
	out := make([]SiblingConfig, 0, len(Siblings))
	for _, s := range Siblings {
		sc := SiblingConfig{Config: s.Config, Package: s.Package, Installed: installed[s.Package]}
		switch {
		case Denied(s.Config):
			sc.Reason = SiblingOptedOut
		case p.listed(s.Config):
			sc.Allowed, sc.Reason = true, SiblingListed
		case p.siblingExcluded(s.Config):
			sc.Reason = SiblingOptedOut
		case sc.Installed:
			sc.Allowed, sc.Reason = true, SiblingInstalled
		default:
			sc.Reason = SiblingNotInstalled
		}
		out = append(out, sc)
	}
	return out
}

func (p *Plane) listed(config string) bool {
	for _, c := range p.allowed {
		if c == config {
			return true
		}
	}
	return false
}

// effectiveAllowlist is managed_config plus the installed siblings' configs
// the owner did not opt out, sorted.
func (p *Plane) effectiveAllowlist() []string {
	out := append([]string(nil), p.allowed...)
	for _, sc := range p.SiblingConfigs() {
		if sc.Reason == SiblingInstalled {
			out = append(out, sc.Config)
		}
	}
	sort.Strings(out)
	return out
}
