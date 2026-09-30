package gwconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/capthndsme/perch-agentkit/openwrt/uci"
)

// Where the apply engine keeps its state. The rollback directory is on the
// root flash on purpose (not storage_path, which may be a USB stick that is
// not mounted yet when the boot guard runs): a pending apply must survive
// a reboot. The marker lives on tmpfs, so a missing marker next to a
// pending record means the router rebooted during the confirm window.
const (
	StateDir    = "/etc/perch-collector"
	RollbackDir = "/etc/perch-collector/rollback"
	RunDir      = "/var/run/perch-collector"
)

// MaxResults bounds the unacknowledged outcomes kept for the hello.
const MaxResults = 32

// pendingRecord is rollback/pending.json: an apply that is not confirmed.
// It is written (fsync'ed) after the snapshot and before anything is
// committed, so its existence always means "the snapshot is complete and
// the files may differ from it".
type pendingRecord struct {
	ApplyID   string    `json:"applyId"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"createdAt"`
	Deadline  time.Time `json:"deadline"`
	// ConfirmSeconds is the granted window.
	ConfirmSeconds int  `json:"confirmSeconds"`
	Protected      bool `json:"protected,omitempty"`
	// Configs are the snapshotted configs in apply order (the ledger last).
	Configs []string `json:"configs"`
	// HashesBefore: file hashes at the snapshot; "" = the file did not exist.
	HashesBefore map[string]string `json:"hashesBefore"`
	// HashesAfter: file hashes right after the commit (Committed).
	HashesAfter map[string]string `json:"hashesAfter,omitempty"`
	Committed   bool              `json:"committed"`
	Packages    *packageRecord    `json:"packages,omitempty"`
	// Checks are the apply's effective checks (the controller's, or the
	// agent's own net) and CheckState their last recorded state
	// (checks.go): a restarted daemon re-runs what has not passed with what
	// is left of the budget. Both optional: an older binary ignores them and
	// restores at the deadline.
	Checks     *Checks           `json:"checks,omitempty"`
	CheckState *checkStateRecord `json:"checkState,omitempty"`
	// Generated are the public halves of the job's generated values
	// (generate.go), for a retried apply's reply; never a private value.
	Generated []Generated `json:"generated,omitempty"`
}

// packageRecord is the package part of a package job.
type packageRecord struct {
	Manager   string   `json:"manager"`
	Requested []string `json:"requested"`
	// Before: every package installed before the job.
	Before []string `json:"before"`
	// Installed: what the job installed (known after the install).
	Installed []string `json:"installed,omitempty"`
}

// store reads and writes the engine's files under a root ("" = /).
type store struct {
	root string
}

func (s store) path(p string) string { return rooted(s.root, p) }
func (s store) configPath(c string) string {
	return filepath.Join(s.path(uci.DefaultDir), c)
}
func (s store) applyDir(id string) string { return filepath.Join(s.path(RollbackDir), id) }
func (s store) pendingPath() string       { return filepath.Join(s.path(RollbackDir), "pending.json") }
func (s store) resultsPath() string       { return filepath.Join(s.path(RollbackDir), "results.json") }
func (s store) markerPath(id string) string {
	return filepath.Join(s.path(RunDir), "apply-"+id)
}

// writeFileSync writes data to path atomically (a temporary file beside
// it, fsync, rename, fsync of the directory).
func writeFileSync(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".perch-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Some file systems refuse fsync on a directory; the rename is done.
	_ = d.Sync()
	return nil
}

// fileMode is the mode of an existing file, 0644 otherwise.
func fileMode(path string) fs.FileMode {
	if st, err := os.Stat(path); err == nil {
		return st.Mode().Perm()
	}
	return 0o644
}

// snapshot copies the configs' files into the apply's directory under
// sub ("before" or "after") and returns their hashes ("" = no file).
func (s store) snapshot(id, sub string, configs []string) (map[string]string, error) {
	hashes := map[string]string{}
	dir := filepath.Join(s.applyDir(id), sub)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for _, c := range configs {
		src := s.configPath(c)
		data, err := os.ReadFile(src)
		if errors.Is(err, os.ErrNotExist) {
			hashes[c] = ""
			os.Remove(filepath.Join(dir, c))
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := writeFileSync(filepath.Join(dir, c), data, fileMode(src)); err != nil {
			return nil, err
		}
		hashes[c] = uci.FileHash(data)
	}
	return hashes, syncDir(dir)
}

// snapshotData returns a snapshotted file's content; nil when the config
// did not exist then.
func (s store) snapshotData(id, sub, config string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.applyDir(id), sub, config))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// restore puts one config back as it was in the "before" snapshot: the
// file atomically, or removed when it did not exist.
func (s store) restore(id, config, hashBefore string) error {
	dst := s.configPath(config)
	if hashBefore == "" {
		err := os.Remove(dst)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(dst))
	}
	src := filepath.Join(s.applyDir(id), "before", config)
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("snapshot of %s: %w", config, err)
	}
	if uci.FileHash(data) != hashBefore {
		return fmt.Errorf("snapshot of %s does not match its recorded hash", config)
	}
	return writeFileSync(dst, data, fileMode(src))
}

// currentHash is the hash of a config file now ("" = no file).
func (s store) currentHash(config string) string {
	data, err := os.ReadFile(s.configPath(config))
	if err != nil {
		return ""
	}
	return uci.FileHash(data)
}

func (s store) readPending() (*pendingRecord, error) {
	data, err := os.ReadFile(s.pendingPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r pendingRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", s.pendingPath(), err)
	}
	if !ValidApplyID(r.ApplyID) {
		return nil, fmt.Errorf("%s: bad apply id %q", s.pendingPath(), r.ApplyID)
	}
	return &r, nil
}

func (s store) writePending(r *pendingRecord) error {
	data, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	return writeFileSync(s.pendingPath(), data, 0o600)
}

// setMarker creates the tmpfs marker of an apply.
func (s store) setMarker(id string) error {
	return writeFileSync(s.markerPath(id), []byte(id+"\n"), 0o600)
}

func (s store) hasMarker(id string) bool {
	_, err := os.Stat(s.markerPath(id))
	return err == nil
}

// finish removes an apply's record, snapshot and marker.
func (s store) finish(id string) {
	os.Remove(s.pendingPath())
	os.RemoveAll(s.applyDir(id))
	os.Remove(s.markerPath(id))
	syncDir(s.path(RollbackDir))
}

// keepFailed moves a snapshot that could not be restored aside, for a
// human, and drops the record so nothing loops on it.
func (s store) keepFailed(id string) {
	os.Remove(s.pendingPath())
	os.Rename(s.applyDir(id), filepath.Join(s.path(RollbackDir), "failed-"+id))
	os.Remove(s.markerPath(id))
	syncDir(s.path(RollbackDir))
}

// cleanStale removes snapshot directories no pending record refers to
// (a crash between snapshot and record).
func (s store) cleanStale(keep string) {
	entries, err := os.ReadDir(s.path(RollbackDir))
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() || n == keep || len(n) > 7 && n[:7] == "failed-" {
			continue
		}
		os.RemoveAll(filepath.Join(s.path(RollbackDir), n))
	}
}

func (s store) readResults() []Result {
	data, err := os.ReadFile(s.resultsPath())
	if err != nil {
		return []Result{}
	}
	var out []Result
	if json.Unmarshal(data, &out) != nil || out == nil {
		return []Result{}
	}
	return out
}

func (s store) writeResults(list []Result) error {
	if len(list) > MaxResults {
		list = list[len(list)-MaxResults:]
	}
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return writeFileSync(s.resultsPath(), data, 0o600)
}

func (s store) addResult(r Result) error {
	list := s.readResults()
	kept := list[:0]
	for _, x := range list {
		if x.ApplyID != r.ApplyID {
			kept = append(kept, x)
		}
	}
	return s.writeResults(append(kept, r))
}

// ack drops acknowledged results and returns how many were dropped.
func (s store) ack(ids []string) (int, error) {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	list := s.readResults()
	kept := []Result{}
	for _, r := range list {
		if !drop[r.ApplyID] {
			kept = append(kept, r)
		}
	}
	n := len(list) - len(kept)
	if n == 0 {
		return 0, nil
	}
	return n, s.writeResults(kept)
}

func (s store) findResult(id string) *Result {
	for _, r := range s.readResults() {
		if r.ApplyID == id {
			r := r
			return &r
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
