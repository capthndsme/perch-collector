package gwconfig

import (
	"sort"
	"time"
)

// Sibling packages (gateway README 7.7, owner decision 7; gateway-sync
// protocol 5, decision D11): a package Perch drives through the config
// plane brings its config onto the allowlist by being installed.
// sqm-scripts → sqm (WAN queues), perch-qos → perch-qos (the shaper's
// package), miniupnpd → upnpd, ddns-scripts → ddns. mwan3 and pbr join
// read-only (decision 12: multi-WAN is read only): their config is read and
// watched, never written, unless the router's owner lists it in
// managed_config. The owner opts out with UCI (managed_config_auto '0' for
// all of them, list managed_config_exclude for one); the denylist always
// wins, whatever is installed.

// Sibling is one config that joins the allowlist once one of its packages
// is installed.
type Sibling struct {
	// Packages that bring the config (alternatives: miniupnpd comes as
	// miniupnpd-nftables, miniupnpd or miniupnpd-iptables).
	Packages []string
	Config   string
	// ReadOnly: joins readable only; writable when listed in managed_config.
	ReadOnly bool
}

// Siblings are the sibling configs this build knows.
var Siblings = []Sibling{
	{Packages: []string{"sqm-scripts"}, Config: "sqm"},
	{Packages: []string{"perch-qos"}, Config: "perch-qos"},
	{Packages: []string{"miniupnpd-nftables", "miniupnpd", "miniupnpd-iptables"}, Config: "upnpd"},
	{Packages: []string{"ddns-scripts"}, Config: "ddns"},
	{Packages: []string{"mwan3"}, Config: "mwan3", ReadOnly: true},
	{Packages: []string{"pbr"}, Config: "pbr", ReadOnly: true},
}

// siblingPackages are every sibling package (the watched packages of
// gateway.capabilities).
func siblingPackages() []string {
	var out []string
	for _, s := range Siblings {
		out = append(out, s.Packages...)
	}
	return out
}

// Reasons of a sibling's allowlist state (gateway.capabilities siblingConfigs).
const (
	SiblingListed            = "listed"              // in managed_config anyway (writable)
	SiblingInstalled         = "installed"           // joined by being installed (writable)
	SiblingInstalledReadOnly = "installed_read_only" // joined readable only (a ReadOnly sibling)
	SiblingNotInstalled      = "not_installed"       // joins once installed
	SiblingOptedOut          = "opted_out"           // managed_config_auto '0' or managed_config_exclude
)

// SiblingConfig is one sibling's state in gateway.capabilities.
type SiblingConfig struct {
	Config string `json:"config"`
	// Package is the installed package that brings it, else the first one
	// that would.
	Package   string `json:"package"`
	Installed bool   `json:"installed"`
	// Allowed: readable (on allowedConfigs).
	Allowed bool `json:"allowed"`
	// ReadOnly: never written (a ReadOnly sibling not listed in
	// managed_config); writable = Allowed && !ReadOnly.
	ReadOnly bool   `json:"readOnly"`
	Reason   string `json:"reason"`
}

// siblingTTL bounds how stale the installed-package view may be (a package
// installed by hand shows up within it; an install job refreshes at once).
const siblingTTL = 30 * time.Second

type siblingCache struct {
	at time.Time
	// installed maps a sibling config to the package that brings it.
	installed map[string]string
}

// installedSiblings returns, per sibling config, the installed package that
// brings it, cached for siblingTTL. No package database (not OpenWrt) =
// none.
func (p *Plane) installedSiblings() map[string]string {
	now := p.clock.Now()
	p.sibMu.Lock()
	defer p.sibMu.Unlock()
	if p.sib.installed != nil && now.Sub(p.sib.at) < siblingTTL && !now.Before(p.sib.at) {
		return p.sib.installed
	}
	out := map[string]string{}
	if all, err := p.packageDB().Installed(); err == nil {
		for _, s := range Siblings {
			for _, pkg := range s.Packages {
				if _, ok := all[pkg]; ok {
					out[s.Config] = pkg
					break
				}
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
		pkg, ok := installed[s.Config]
		if !ok {
			pkg = s.Packages[0]
		}
		sc := SiblingConfig{Config: s.Config, Package: pkg, Installed: ok, ReadOnly: s.ReadOnly}
		switch {
		case Denied(s.Config):
			sc.Reason = SiblingOptedOut
		case p.listed(s.Config):
			sc.Allowed, sc.ReadOnly, sc.Reason = true, false, SiblingListed
		case p.siblingExcluded(s.Config):
			sc.Reason = SiblingOptedOut
		case sc.Installed && s.ReadOnly:
			sc.Allowed, sc.Reason = true, SiblingInstalledReadOnly
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
// the owner did not opt out (read-only ones included: readable), sorted.
func (p *Plane) effectiveAllowlist() []string {
	out := append([]string(nil), p.allowed...)
	for _, sc := range p.SiblingConfigs() {
		if sc.Reason == SiblingInstalled || sc.Reason == SiblingInstalledReadOnly {
			out = append(out, sc.Config)
		}
	}
	sort.Strings(out)
	return out
}

// writableAllowlist: managed_config plus the installed siblings that are not
// read-only.
func (p *Plane) writableAllowlist() map[string]bool {
	out := map[string]bool{}
	for _, c := range p.allowed {
		out[c] = true
	}
	for _, sc := range p.SiblingConfigs() {
		if sc.Reason == SiblingInstalled {
			out[sc.Config] = true
		}
	}
	return out
}
