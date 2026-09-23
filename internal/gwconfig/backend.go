package gwconfig

import (
	"context"
	"encoding/json"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Backend is how the apply engine writes configs and has services reload.
// The router's is rpcd (a private session) or the uci CLI; tests use a fake.
type Backend interface {
	// Name is "ubus" or "uci-cli" (capabilities' backend).
	Name() string
	// Stager opens a private staging area with write access to configs.
	Stager(ctx context.Context, configs []string, applyID string) (uci.Stager, error)
	// CommitReloads: a commit makes procd reload the config's services by
	// itself (rpcd's commit emits config.change). Otherwise the engine calls
	// Reload after committing.
	CommitReloads() bool
	// Reload has procd reload the services of configs, in this order: one
	// config.change event each, what rpcd's commit sends. Used after a
	// rollback, whose files are restored directly.
	Reload(ctx context.Context, configs []string) error
	// Settle waits until the reload of a commit has run: netifd has no
	// interface left pending (max SettleMax).
	Settle(ctx context.Context) error
}

// Settle bounds (plan 1 section 3.4 step 5). procd runs a reload trigger
// about a second after the commit (PROCD_RELOAD_DELAY), so the wait starts
// with SettleMin.
const (
	SettleMin = 2 * time.Second
	SettleMax = 20 * time.Second
)

// routerBackend is the real one: rpcd when it serves the uci object, else
// Go-rendered files (fileStager) plus reload events.
type routerBackend struct {
	kind string // uci.BackendUbus, or "file"
	ub   *ubus.Client
	run  ubus.Runner
	// confDir is /etc/config under the plane's root.
	confDir string
}

// BackendFile is the fallback write path's name.
const BackendFile = "file"

func (b *routerBackend) Name() string { return b.kind }

func (b *routerBackend) Stager(ctx context.Context, configs []string, applyID string) (uci.Stager, error) {
	if b.kind != uci.BackendUbus {
		return newFileStager(b.confDir, configs), nil
	}
	s, err := uci.NewSession(ctx, b.ub, configs, true)
	if err != nil {
		return nil, err
	}
	// Tag the session, so a watcher looking at rpcd sessions can tell ours
	// (uci-settle amendment section 1). Best effort.
	_ = b.ub.Call(ctx, "session", "set", map[string]any{"ubus_rpc_session": s.ID, "values": map[string]string{"perch": applyID}}, nil)
	return s, nil
}

func (b *routerBackend) CommitReloads() bool { return b.kind == uci.BackendUbus }

func (b *routerBackend) Reload(ctx context.Context, configs []string) error {
	if b.ub != nil && b.ub.Available() {
		var firstErr error
		for _, c := range configs {
			ev := map[string]any{"type": "config.change", "data": map[string]string{"package": c}}
			if err := b.ub.Call(ctx, "service", "event", ev, nil); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	return uci.ReloadConfig(ctx, b.run)
}

func (b *routerBackend) Settle(ctx context.Context) error {
	t := time.NewTimer(SettleMin)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
	}
	deadline := time.Now().Add(SettleMax - SettleMin)
	for time.Now().Before(deadline) {
		if b.ub == nil {
			return nil
		}
		raw, err := b.ub.CallRaw(ctx, "network.interface", "dump", nil)
		if err != nil || !anyPending(raw) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}

// anyPending reports an interface netifd is still bringing up.
func anyPending(raw []byte) bool {
	var dump struct {
		Interface []struct {
			Pending bool `json:"pending"`
		} `json:"interface"`
	}
	if json.Unmarshal(raw, &dump) != nil {
		return false
	}
	for _, i := range dump.Interface {
		if i.Pending {
			return true
		}
	}
	return false
}

// FileBackend writes whole config files (the fallback's stager) and reports
// reloads to OnReload instead of procd: for tests, and for tools that run
// the engine against a copy of a router's tree.
type FileBackend struct {
	// Dir is the config directory.
	Dir      string
	OnReload func(configs []string)
}

func (b *FileBackend) Name() string { return BackendFile }
func (b *FileBackend) Stager(_ context.Context, configs []string, _ string) (uci.Stager, error) {
	return newFileStager(b.Dir, configs), nil
}
func (b *FileBackend) CommitReloads() bool { return false }
func (b *FileBackend) Reload(_ context.Context, configs []string) error {
	if b.OnReload != nil {
		b.OnReload(configs)
	}
	return nil
}
func (b *FileBackend) Settle(context.Context) error { return nil }
