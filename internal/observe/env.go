package observe

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Env is where the readers of this package look: a filesystem root, the
// system tools and a clock. The zero value is the real router.
type Env struct {
	// Root prefixes every path ("" = the real filesystem; fixture trees).
	Root string
	// Run runs uci and ubus; nil = ExecRunner.
	Run Runner
	// Now is the clock; nil = time.Now.
	Now func() time.Time
}

func (e *Env) now() time.Time {
	if e != nil && e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) path(p string) string {
	if e == nil || e.Root == "" {
		return p
	}
	return filepath.Join(e.Root, p)
}

func (e *Env) read(p string) ([]byte, error) {
	return os.ReadFile(e.path(p))
}

func (e *Env) exists(p string) bool {
	_, err := os.Stat(e.path(p))
	return err == nil
}

// stamp is a file's identity for change detection: size and mtime, or "-"
// when it does not exist.
func (e *Env) stamp(p string) string {
	st, err := os.Stat(e.path(p))
	if err != nil {
		return "-"
	}
	return strconv.FormatInt(st.Size(), 10) + "@" + strconv.FormatInt(st.ModTime().UnixNano(), 10)
}

func (e *Env) run(name string, args ...string) ([]byte, error) {
	run := ExecRunner
	if e != nil && e.Run != nil {
		run = e.Run
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return run(ctx, name, args...)
}

// uciShow runs `uci -q show <pkg>` and parses it; ok is false when uci
// failed (not installed, or no such package).
func (e *Env) uciShow(pkg string) ([]UCISection, bool) {
	out, err := e.run("uci", "-q", "show", pkg)
	if err != nil {
		return nil, false
	}
	return ParseUCIShow(pkg, out), true
}

// serviceEnabled is what `/etc/init.d/<name> enabled` answers: a start
// link in /etc/rc.d.
func (e *Env) serviceEnabled(name string) bool {
	matches, _ := filepath.Glob(e.path("/etc/rc.d/S[0-9][0-9]" + name))
	return len(matches) > 0
}

// processRunning reports whether a process whose comm is name runs (a
// /proc scan; comm is at most 15 bytes).
func (e *Env) processRunning(name string) bool {
	if len(name) > 15 {
		name = name[:15]
	}
	entries, err := os.ReadDir(e.path("/proc"))
	if err != nil {
		return false
	}
	for _, d := range entries {
		if !isPID(d.Name()) {
			continue
		}
		comm, err := e.read("/proc/" + d.Name() + "/comm")
		if err == nil && trimNL(string(comm)) == name {
			return true
		}
	}
	return false
}

func isPID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
