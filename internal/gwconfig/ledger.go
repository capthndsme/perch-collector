package gwconfig

import (
	"context"
	"errors"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// The sync ledger (/etc/config/perch-managed, plan 1 section 9, README
// 3.1): `config synced '<perchId>'` with options config, section and
// domain, one per section Perch syncs. Only the agent writes it, as a whole
// file (it is Perch's own config, not staged through rpcd), and never marks
// anything inside the foreign configs.

// readLedger returns the ledger's entries; none when the file is missing.
func (p *Plane) readLedger() ([]LedgerEntry, error) {
	l, err := p.files.Load(LedgerConfig)
	if errors.Is(err, uci.ErrNoConfig) {
		return []LedgerEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	return ledger(l.Config), nil
}

// writeLedger replaces the ledger and records the write as the plane's own.
func (p *Plane) writeLedger(entries []LedgerEntry, applyID string) error {
	data := renderLedger(entries)
	if err := writeFileSync(p.files.Path(LedgerConfig), data, 0o644); err != nil {
		return err
	}
	p.RecordOwn(LedgerConfig, uci.FileHash(data), applyID)
	return nil
}

// writable: a config the controller may write (allowlisted, never the
// denylist or the ledger).
func (p *Plane) writable(config string) bool {
	if Denied(config) || config == LedgerConfig {
		return false
	}
	for _, c := range p.Allowed() {
		if c == config {
			return true
		}
	}
	return false
}

// lazyBackend picks the router's write path on first use: rpcd's private
// sessions when it serves the uci object, else Go-rendered files.
type lazyBackend struct {
	p *Plane
	b Backend
}

func (l *lazyBackend) get() Backend {
	l.p.backendOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
		kind := BackendFile
		if uci.Detect(ctx, l.p.ubus, func(string) (string, error) { return "", errors.New("no CLI fallback") }) == uci.BackendUbus {
			kind = uci.BackendUbus
		}
		cancel()
		l.b = &routerBackend{kind: kind, ub: l.p.ubus, run: l.p.o.Run, confDir: l.p.files.Dir}
	})
	return l.b
}

func (l *lazyBackend) Name() string { return l.get().Name() }
func (l *lazyBackend) Stager(ctx context.Context, configs []string, id string) (uci.Stager, error) {
	return l.get().Stager(ctx, configs, id)
}
func (l *lazyBackend) CommitReloads() bool { return l.get().CommitReloads() }
func (l *lazyBackend) Reload(ctx context.Context, configs []string) error {
	return l.get().Reload(ctx, configs)
}
func (l *lazyBackend) Settle(ctx context.Context) error { return l.get().Settle(ctx) }
