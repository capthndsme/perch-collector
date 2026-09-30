package gatewayops

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// UPnP mapping delete (gateway.upnp.delete, gateway-sync protocol 6.2): a
// runtime action, not config. miniupnpd keeps its mappings in a lease file
// and installs what the file holds when it starts, so a mapping is deleted
// the way LuCI does it: drop its line from the file and restart miniupnpd
// once. Lines are matched by content (protocol and external port), never
// by position (LuCI's index-based delete races with miniupnpd rewriting the
// file); every other line stays byte for byte. The new file replaces the
// old one atomically (a temporary file beside it, then rename).

// MaxUPnPDelete bounds one request.
const MaxUPnPDelete = 64

// UPnP files and commands.
const (
	UPnPBinary           = "/usr/sbin/miniupnpd"
	UPnPInit             = "/etc/init.d/miniupnpd"
	DefaultUPnPLeaseFile = "/var/run/miniupnpd.leases"
)

// UPnPMappingRef names one mapping: its protocol and external port.
type UPnPMappingRef struct {
	Proto   string `json:"proto"`
	ExtPort int    `json:"extPort"`
}

// UPnPDeleteParams are gateway.upnp.delete's params.
type UPnPDeleteParams struct {
	Mappings []UPnPMappingRef `json:"mappings"`
}

// UPnPDeleteResult is gateway.upnp.delete's result. Deleted and NotFound
// count the requested mappings; Restarted: miniupnpd was restarted (only
// when something was deleted).
type UPnPDeleteResult struct {
	Deleted   int  `json:"deleted"`
	NotFound  int  `json:"notFound"`
	Restarted bool `json:"restarted"`
}

// ActionError is a refusal or failure of a runtime action (-32000 with
// data.error = Code; Detail, when set, goes into data.detail).
type ActionError struct {
	Code    string
	Message string
	Detail  string
}

func (e *ActionError) Error() string { return e.Message }

// UPnP deletes miniupnpd port mappings.
type UPnP struct {
	// Root prefixes every path ("" = /; tests).
	Root string
	// Run runs the init script; nil = ubus.ExecRunner.
	Run ubus.Runner

	mu sync.Mutex // one delete at a time
}

func rootPath(root, p string) string {
	if root == "" || root == "/" {
		return p
	}
	return filepath.Join(root, p)
}

// Installed reports whether miniupnpd is installed.
func (u *UPnP) Installed() bool {
	for _, p := range []string{UPnPBinary, UPnPInit} {
		if _, err := os.Stat(rootPath(u.Root, p)); err == nil {
			return true
		}
	}
	return false
}

// LeaseFile is upnpd.config.upnp_lease_file (the first `upnpd` section's),
// or the default.
func (u *UPnP) LeaseFile() string {
	l, err := uci.Files{Dir: rootPath(u.Root, uci.DefaultDir)}.Load("upnpd")
	if err == nil {
		for _, s := range l.Config.Sections {
			if s.Type != "upnpd" {
				continue
			}
			if v, ok := s.Get("upnp_lease_file"); ok && strings.HasPrefix(v.Str(), "/") {
				return filepath.Clean(v.Str())
			}
			break
		}
	}
	return DefaultUPnPLeaseFile
}

func validateUPnP(p UPnPDeleteParams) (map[string]bool, error) {
	if len(p.Mappings) == 0 || len(p.Mappings) > MaxUPnPDelete {
		return nil, &ParamError{"bad_params", fmt.Sprintf("mappings: 1 to %d entries", MaxUPnPDelete)}
	}
	want := map[string]bool{}
	for i, m := range p.Mappings {
		proto := strings.ToUpper(strings.TrimSpace(m.Proto))
		if proto != "TCP" && proto != "UDP" {
			return nil, &ParamError{"bad_params", fmt.Sprintf("mappings[%d]: proto is TCP or UDP", i)}
		}
		if m.ExtPort < 1 || m.ExtPort > 65535 {
			return nil, &ParamError{"bad_params", fmt.Sprintf("mappings[%d]: extPort is 1 to 65535", i)}
		}
		want[mappingKey(proto, m.ExtPort)] = true
	}
	return want, nil
}

func mappingKey(proto string, port int) string { return proto + ":" + strconv.Itoa(port) }

// leaseKey is a lease line's protocol and external port ("" for a line
// that is not a mapping: it is kept as it is).
func leaseKey(line []byte) string {
	f := strings.SplitN(strings.TrimRight(string(line), "\r"), ":", 3)
	if len(f) < 3 {
		return ""
	}
	port, err := strconv.Atoi(f[1])
	if err != nil {
		return ""
	}
	return mappingKey(strings.ToUpper(strings.TrimSpace(f[0])), port)
}

// Delete drops the mappings from the lease file and restarts miniupnpd
// once. Idempotent: a mapping that is not there counts as notFound, and
// nothing found means nothing is written or restarted.
func (u *UPnP) Delete(ctx context.Context, p UPnPDeleteParams) (res *UPnPDeleteResult, _ error) {
	want, err := validateUPnP(p)
	if err != nil {
		return nil, err
	}
	if !u.Installed() {
		return nil, &ActionError{Code: "upnp_not_installed", Message: "miniupnpd is not installed on this router"}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	path := rootPath(u.Root, u.LeaseFile())
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, &ActionError{Code: "upnp_failed", Message: "cannot read the lease file", Detail: err.Error()}
	}
	res = &UPnPDeleteResult{}
	found := map[string]bool{}
	var kept bytes.Buffer
	rest := data
	for len(rest) > 0 {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i+1], rest[i+1:]
		} else {
			rest = nil
		}
		if k := leaseKey(bytes.TrimRight(line, "\n")); k != "" && want[k] {
			found[k] = true
			continue
		}
		kept.Write(line)
	}
	run := u.Run
	if run == nil {
		run = ubus.ExecRunner
	}
	// Whatever happens to the lease file, rules left for a requested mapping
	// go (upnp_nft.go), counted as deleted.
	defer func() {
		if res == nil {
			return
		}
		orphans := u.removeOrphanRules(ctx, run, want)
		for k := range orphans {
			if !found[k] {
				found[k] = true
				res.Deleted++
				res.NotFound--
			}
		}
		// miniupnpd still lists what it read from the rules at its start:
		// one restart makes its list match.
		if len(orphans) > 0 && !res.Restarted {
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if _, _, code, err := run(cctx, rootPath(u.Root, UPnPInit), "restart"); err == nil && code == 0 {
				res.Restarted = true
			}
		}
	}()
	res.Deleted = len(found)
	res.NotFound = len(want) - len(found)
	if res.Deleted == 0 {
		return res, nil
	}
	if err := replaceFile(path, kept.Bytes()); err != nil {
		return nil, &ActionError{Code: "upnp_failed", Message: "cannot write the lease file", Detail: err.Error()}
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, stderr, code, err := run(cctx, rootPath(u.Root, UPnPInit), "restart")
	if err != nil || code != 0 {
		detail := strings.TrimSpace(string(stderr))
		if err != nil {
			detail = err.Error()
		} else if detail == "" {
			detail = fmt.Sprintf("exit status %d", code)
		}
		return nil, &ActionError{Code: "upnp_failed", Message: "the mappings were removed from the lease file, but restarting miniupnpd failed", Detail: detail}
	}
	res.Restarted = true
	return res, nil
}

// replaceFile writes data to path atomically, keeping the file's mode.
func replaceFile(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".perch-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
