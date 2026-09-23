package portal

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite, linked statically (cgo)
)

// Store is the portal's local state (owner decision 18): a SQLite database
// held in RAM and snapshotted to a file with VACUUM INTO. The engine keeps
// its working set in Go and writes every change through to the database;
// two write classes decide when a snapshot follows:
//
//   - ClassGrant (a redeemed voucher, a paid authorisation, a journal event,
//     keys, configuration): snapshot at once (coalesced over SnapshotDelay);
//   - ClassCounter (byte and time counters): snapshot every flush interval,
//     so a power cut loses at most one interval of usage.
//
// A snapshot is written to <path>.tmp, synced, renamed over <path> and the
// directory synced: a crash leaves the old or the new file, never half of one.
type Store struct {
	db   *sql.DB
	mu   sync.Mutex
	path string // "" = RAM only

	dirtyGrant   bool
	dirtyCounter bool
	lastSnapshot time.Time
	snapErr      error
}

// Write classes.
const (
	ClassGrant   = 1
	ClassCounter = 2
)

// SnapshotDelay coalesces bursts of grant writes (a full authorize of many
// grants) into one snapshot.
const SnapshotDelay = time.Second

const storeSchemaVersion = "1"

var storeTables = []string{
	`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS groups (group_key TEXT PRIMARY KEY, data TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS grants (lid INTEGER PRIMARY KEY, data TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, data TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS vouchers (voucher_id INTEGER PRIMARY KEY, data TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, at INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS templates (sha TEXT NOT NULL, name TEXT NOT NULL, content_type TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY (sha, name))`,
	`CREATE TABLE IF NOT EXISTS ended_usage (id INTEGER PRIMARY KEY, group_key TEXT NOT NULL, seq INTEGER NOT NULL, time_used INTEGER NOT NULL, bytes_used INTEGER NOT NULL)`,
}

var tableNames = []string{"meta", "groups", "grants", "events", "vouchers", "nonces", "templates", "ended_usage"}

// OpenStore opens the RAM database and loads the snapshot at path, if any.
// A snapshot that cannot be read is moved aside (<path>.corrupt) and the
// store starts empty; the returned warning says so.
func OpenStore(path string) (*Store, string, error) {
	db, err := sql.Open("sqlite3", "file:perch-portal?mode=memory&cache=private&_foreign_keys=0")
	if err != nil {
		return nil, "", err
	}
	// One connection for the life of the store: a :memory: database lives
	// and dies with its connection.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	for _, q := range storeTables {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, "", fmt.Errorf("store schema: %w", err)
		}
	}
	s := &Store{db: db, path: path}
	warning := ""
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			if err := s.load(path); err != nil {
				bad := path + ".corrupt"
				_ = os.Rename(path, bad)
				warning = fmt.Sprintf("portal state %s could not be read (%v); moved to %s, starting empty", path, err, bad)
				for _, t := range tableNames {
					_, _ = db.Exec("DELETE FROM " + t)
				}
			}
		}
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO meta (k, v) VALUES ('schema', ?)`, storeSchemaVersion); err != nil {
		db.Close()
		return nil, "", err
	}
	return s, warning, nil
}

func (s *Store) load(path string) error {
	if _, err := s.db.Exec(`ATTACH DATABASE ? AS disk`, "file:"+path+"?mode=ro"); err != nil {
		return err
	}
	defer s.db.Exec(`DETACH DATABASE disk`) //nolint:errcheck
	var check string
	if err := s.db.QueryRow(`PRAGMA disk.quick_check`).Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return fmt.Errorf("quick_check: %s", check)
	}
	var schema string
	if err := s.db.QueryRow(`SELECT v FROM disk.meta WHERE k = 'schema'`).Scan(&schema); err != nil {
		return fmt.Errorf("no schema version: %w", err)
	}
	if schema != storeSchemaVersion {
		return fmt.Errorf("schema version %s, expected %s", schema, storeSchemaVersion)
	}
	for _, t := range tableNames {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM disk.sqlite_master WHERE type = 'table' AND name = ?`, t).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if _, err := s.db.Exec(fmt.Sprintf(`INSERT OR REPLACE INTO main.%s SELECT * FROM disk.%s`, t, t)); err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
	}
	return nil
}

// Close snapshots pending changes and closes the database.
func (s *Store) Close() error {
	err := s.Flush(true)
	s.db.Close()
	return err
}

// Path is the snapshot file ("" = RAM only).
func (s *Store) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// SetPath moves the snapshot target; the next snapshot writes there.
func (s *Store) SetPath(path string) {
	s.mu.Lock()
	if s.path != path {
		s.path = path
		s.dirtyGrant = true
	}
	s.mu.Unlock()
}

func (s *Store) mark(class int) {
	s.mu.Lock()
	if class == ClassGrant {
		s.dirtyGrant = true
	} else {
		s.dirtyCounter = true
	}
	s.mu.Unlock()
}

// Exec runs a write of the given class.
func (s *Store) Exec(class int, q string, args ...any) error {
	_, err := s.db.Exec(q, args...)
	if err == nil {
		s.mark(class)
	}
	return err
}

// Query runs a read.
func (s *Store) Query(q string, args ...any) (*sql.Rows, error) { return s.db.Query(q, args...) }

// QueryRow runs a one-row read.
func (s *Store) QueryRow(q string, args ...any) *sql.Row { return s.db.QueryRow(q, args...) }

// Tx runs fn in a transaction of the given class.
func (s *Store) Tx(class int, fn func(tx sqlTx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.mark(class)
	return nil
}

// Due reports whether a snapshot should be written now: grant changes at
// once (after SnapshotDelay), counter changes once flushEvery passed.
func (s *Store) Due(now time.Time, flushEvery time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return false
	}
	if s.dirtyGrant {
		return true
	}
	return s.dirtyCounter && now.Sub(s.lastSnapshot) >= flushEvery
}

// Flush writes a snapshot when something changed (force: even counters
// that are not due yet).
func (s *Store) Flush(force bool) error {
	s.mu.Lock()
	path := s.path
	dirty := s.dirtyGrant || s.dirtyCounter
	s.mu.Unlock()
	if path == "" || (!dirty && !force) {
		return nil
	}
	if !dirty {
		return nil
	}
	err := s.snapshot(path)
	s.mu.Lock()
	s.snapErr = err
	if err == nil {
		s.dirtyGrant, s.dirtyCounter = false, false
		s.lastSnapshot = time.Now()
	}
	s.mu.Unlock()
	return err
}

// LastError is the last snapshot's error (nil = fine).
func (s *Store) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapErr
}

func (s *Store) snapshot(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if _, err := s.db.Exec(`VACUUM INTO ?`, tmp); err != nil {
		return fmt.Errorf("vacuum into: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	serr := f.Sync()
	_ = f.Chmod(0o600)
	f.Close()
	if serr != nil {
		return serr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Meta reads one meta value ("" when unset).
func (s *Store) Meta(k string) string {
	var v string
	if err := s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(&v); err != nil {
		return ""
	}
	return v
}

// SetMeta writes one meta value.
func (s *Store) SetMeta(class int, k, v string) error {
	return s.Exec(class, `INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)`, k, v)
}

// sqlTx is the transaction handed to Tx's function.
type sqlTx = *sql.Tx

// errNoRows is sql.ErrNoRows, for callers.
var errNoRows = sql.ErrNoRows

func isNoRows(err error) bool { return errors.Is(err, errNoRows) }
