package gwconfig

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/ubus"
	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// The overdue watchdog (gateway-sync protocol 7): a pending apply is
// restored by the daemon at its deadline, by the daemon at start, or by the
// boot guard after a reboot. None of them helps while the daemon is down
// (procd gave up on a crash loop, someone stopped it) and the router keeps
// running: `perch-collector config-guard --overdue`, run by cron every
// minute, restores such an apply once its deadline is OverdueGrace behind.
//
// Who owns an apply is decided by a lock: the daemon holds an exclusive
// flock on PlaneLock for its whole life (HoldPlaneLock, before Plane.Start
// reads pending.json), and the watchdog and the boot guard act only when
// they can take it themselves, holding it while they restore. A daemon that
// is stopped (SIGSTOP) still holds it, so the watchdog leaves its apply
// alone; one that exited released it with its file descriptors.

// PlaneLock is the daemon's lock file, on tmpfs (a reboot drops it; the
// boot guard covers that case).
const PlaneLock = RunDir + "/plane.lock"

// OverdueGrace is how long past its deadline an apply must be before the
// watchdog restores it: the daemon's own timer always comes first.
const OverdueGrace = 60 * time.Second

// OverdueDetail is the detail of a result the watchdog wrote.
const OverdueDetail = "restored by the overdue watchdog"

// ErrLockHeld: another process holds the plane lock.
var ErrLockHeld = errors.New("the config plane lock is held by another process")

// PlaneLockFile is the lock taken: release it with Release.
type PlaneLockFile struct {
	f *os.File
}

// Release drops the lock (the daemon never does: it holds it until exit).
func (l *PlaneLockFile) Release() {
	if l != nil && l.f != nil {
		unlockFile(l.f)
		l.f.Close()
		l.f = nil
	}
}

func openLock(root string) (*os.File, error) {
	path := rooted(root, PlaneLock)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

// TryPlaneLock takes the lock without waiting; ErrLockHeld when another
// process (or another open file of this one) holds it.
func TryPlaneLock(root string) (*PlaneLockFile, error) {
	f, err := openLock(root)
	if err != nil {
		return nil, err
	}
	held, err := tryLockFile(f)
	if err != nil || held {
		f.Close()
		if err == nil {
			err = ErrLockHeld
		}
		return nil, err
	}
	return &PlaneLockFile{f: f}, nil
}

// daemonLock is the daemon's lock, referenced for the process's life (a
// collected *os.File would close the descriptor and drop the lock).
var daemonLock *PlaneLockFile

// HoldPlaneLock takes the lock for the rest of the daemon's life, waiting
// while a config-guard holds it (a restore takes seconds). Call it before
// Plane.Start. logf reports the wait (nil = log.Printf).
func HoldPlaneLock(root string, logf func(string, ...any)) error {
	if logf == nil {
		logf = log.Printf
	}
	var waited time.Duration
	for {
		l, err := TryPlaneLock(root)
		if err == nil {
			daemonLock = l
			if waited > 0 {
				logf("config plane: got the plane lock after %s", waited.Round(time.Second))
			}
			return nil
		}
		if !errors.Is(err, ErrLockHeld) {
			return err
		}
		if waited%(30*time.Second) == 0 {
			logf("config plane: %s is held (a config-guard restoring, or another perch-collector); waiting", rooted(root, PlaneLock))
		}
		time.Sleep(250 * time.Millisecond)
		waited += 250 * time.Millisecond
	}
}

// OverdueOptions configure Overdue.
type OverdueOptions struct {
	// Root prefixes every path ("" = /; tests).
	Root string
	// Run runs the package manager for a package job's rollback and ubus
	// for the reload; nil = ubus.ExecRunner.
	Run ubus.Runner
	// Now is the time; zero = time.Now().
	Now time.Time
	// Redact fingerprints discarded router edits (NewRedactor).
	Redact uci.Redactor
	// Reload has procd reload the restored configs' services, in this
	// order; nil = one `ubus call service event` config.change per config
	// over Ubus, what the daemon's rollback sends (reload_config without
	// ubus).
	Reload func(ctx context.Context, configs []string) error
	// Ubus is the ubus client of the default reload; nil = ubus.New()
	// running through Run.
	Ubus *ubus.Client
}

// Overdue is `perch-collector config-guard --overdue`: it restores a
// pending apply whose deadline is OverdueGrace behind while no daemon holds
// the plane lock, has procd reload what it restored, and records the result
// for the controller (the daemon reports it at its next hello). The reason
// is what the daemon would have said: confirm_timeout, or reboot / commit_
// failed for an apply the boot guard or the daemon would have caught;
// detail OverdueDetail. It returns nil when there was nothing to do: no
// pending apply, the daemon holds the lock, or the deadline is not far
// enough behind.
func Overdue(o OverdueOptions) (*Result, error) {
	st := store{root: o.Root}
	rec, err := st.readPending()
	if err != nil || rec == nil {
		return nil, err
	}
	lock, err := TryPlaneLock(o.Root)
	if errors.Is(err, ErrLockHeld) {
		return nil, nil // the daemon owns it
	}
	if err != nil {
		return nil, fmt.Errorf("plane lock: %w", err)
	}
	defer lock.Release()
	// Again under the lock: a daemon may have finished it meanwhile.
	if rec, err = st.readPending(); err != nil || rec == nil {
		return nil, err
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !now.After(rec.Deadline.Add(OverdueGrace)) {
		return nil, nil
	}
	run := o.Run
	if run == nil {
		run = ubus.ExecRunner
	}
	reason := ReasonConfirmTimeout
	switch {
	case !st.hasMarker(rec.ApplyID):
		reason = ReasonReboot
	case !rec.Committed:
		reason = ReasonCommitFailed
	}
	res := restore(st, rec, reason, OverdueDetail, o.Redact, o.Root, run, now)
	var cfgs []string
	for _, c := range res.restored {
		if c != LedgerConfig {
			cfgs = append(cfgs, c)
		}
	}
	if len(cfgs) > 0 {
		reload := o.Reload
		if reload == nil {
			ub := o.Ubus
			if ub == nil {
				ub = ubus.New()
				ub.Run = run
			}
			reload = (&routerBackend{ub: ub, run: run}).Reload
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		if err := reload(ctx, cfgs); err != nil {
			res.Result.Detail += "; reload: " + err.Error()
		}
		cancel()
	}
	hashes := map[string]string{}
	for _, c := range rec.Configs {
		if h := st.currentHash(c); h != "" {
			hashes[c] = h
		}
	}
	res.Result.Hashes = hashes
	if err := st.addResult(res.Result); err != nil {
		return &res.Result, err
	}
	if res.failed {
		st.keepFailed(rec.ApplyID)
	} else {
		st.finish(rec.ApplyID)
	}
	return &res.Result, nil
}
