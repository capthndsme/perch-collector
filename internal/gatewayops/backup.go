package gatewayops

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Backup limits.
const (
	// MaxBackupBytes caps the archive (raw, before base64): plan 2 §4.5.
	MaxBackupBytes = 8 << 20
	// maxUnpacked caps what a redaction pass unpacks.
	maxUnpacked   = 64 << 20
	maxRedactions = 256
	backupTimeout = 60 * time.Second
)

// Backup policies (UCI gateway_backup / PERCH_COLLECTOR_GATEWAY_BACKUP).
const (
	BackupOff      = "off"
	BackupRedacted = "redacted"
	BackupFull     = "full"
)

// Redacted replaces a secret's value.
const Redacted = "REDACTED-BY-PERCH"

// BackupParams are gateway.backup's params.
type BackupParams struct {
	// Redact defaults to true. false (the whole archive, secrets included)
	// is refused unless the router's policy is "full".
	Redact *bool `json:"redact,omitempty"`
}

// BackupResult is gateway.backup's result.
type BackupResult struct {
	Filename  string `json:"filename"`
	CreatedAt string `json:"createdAt"`
	Release   string `json:"release,omitempty"`
	Size      int    `json:"size"`
	// SHA256 is the hex digest of the archive as returned (after redaction).
	SHA256     string      `json:"sha256"`
	Redacted   bool        `json:"redacted"`
	Redactions []Redaction `json:"redactions"`
	// ContentBase64 is the tar.gz archive.
	ContentBase64 string `json:"contentBase64"`
}

// Redaction says what a redacted archive lost: an option of a UCI file, a
// line key of another text file, or a whole file (Option "").
type Redaction struct {
	File   string `json:"file"`
	Option string `json:"option,omitempty"`
	// Removed: the file was left out of the archive.
	Removed bool `json:"removed,omitempty"`
}

// Backuper takes sysupgrade -b archives.
type Backuper struct {
	// Policy is BackupRedacted (default) or BackupFull.
	Policy string
	// Hostname and Release name the archive (display only).
	Hostname func() string
	Release  func() string
	// Create writes the archive to path; nil = `sysupgrade -b path`.
	Create func(ctx context.Context, path string) error
	// TempDir for the archive; "" = os.TempDir() (/tmp, RAM on OpenWrt).
	TempDir string
	Now     func() time.Time

	mu sync.Mutex // one backup at a time
}

// BackupError is a failure with a data.error code for the controller.
type BackupError struct {
	Code    string // backup_failed, backup_too_large, backup_redaction_required
	Message string
}

func (e *BackupError) Error() string { return e.Message }

// SysupgradeAvailable reports whether `sysupgrade` is on the PATH.
func SysupgradeAvailable() bool {
	_, err := exec.LookPath("sysupgrade")
	return err == nil
}

func sysupgradeBackup(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, "sysupgrade", "-b", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("sysupgrade -b: %v %s", err, msg)
	}
	return nil
}

// Backup takes one archive.
func (b *Backuper) Backup(ctx context.Context, p BackupParams) (*BackupResult, error) {
	redact := p.Redact == nil || *p.Redact
	if !redact && b.Policy != BackupFull {
		return nil, &BackupError{"backup_redaction_required", "this router only hands out redacted backups (gateway_backup 'redacted'); set it to 'full' on the router to allow complete ones"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	create := b.Create
	if create == nil {
		create = sysupgradeBackup
	}
	dir, err := os.MkdirTemp(b.TempDir, "perch-backup-")
	if err != nil {
		return nil, &BackupError{"backup_failed", "temporary directory: " + err.Error()}
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "backup.tar.gz")
	cctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	if err := create(cctx, file); err != nil {
		return nil, &BackupError{"backup_failed", err.Error()}
	}
	st, err := os.Stat(file)
	if err != nil {
		return nil, &BackupError{"backup_failed", "no archive: " + err.Error()}
	}
	if st.Size() > MaxBackupBytes {
		return nil, &BackupError{"backup_too_large", fmt.Sprintf("the archive is %d bytes, more than %d", st.Size(), MaxBackupBytes)}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, &BackupError{"backup_failed", err.Error()}
	}
	res := &BackupResult{Redacted: redact, Redactions: []Redaction{}}
	if redact {
		out, reds, err := RedactArchive(data)
		if err != nil {
			return nil, &BackupError{"backup_failed", "redaction: " + err.Error()}
		}
		data, res.Redactions = out, reds
		if len(data) > MaxBackupBytes {
			return nil, &BackupError{"backup_too_large", fmt.Sprintf("the archive is %d bytes, more than %d", len(data), MaxBackupBytes)}
		}
	}
	t := now().UTC()
	host := "router"
	if b.Hostname != nil {
		if h := safeName(b.Hostname()); h != "" {
			host = h
		}
	}
	if b.Release != nil {
		res.Release = b.Release()
	}
	sum := sha256.Sum256(data)
	res.Filename = fmt.Sprintf("backup-%s-%s.tar.gz", host, t.Format("2006-01-02"))
	res.CreatedAt = t.Format(time.RFC3339)
	res.Size = len(data)
	res.SHA256 = hex.EncodeToString(sum[:])
	res.ContentBase64 = base64.StdEncoding.EncodeToString(data)
	return res, nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s string) string {
	s = unsafeName.ReplaceAllString(strings.TrimSpace(s), "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return strings.Trim(s, "-.")
}

// ── redaction (plan 2 P10) ───────────────────────────────────────────────

// secretOption reports whether a UCI option or a "key = value" line key
// holds a secret: passwords, pre-shared and private keys, API keys and
// tokens (Wi-Fi `key`, WireGuard `private_key` / `preshared_key`, PPPoE and
// DDNS `password`, the collector's `api_key`, perch-apd's `secret`,
// openNDS's `faskey`). Public keys and key file paths are not secrets.
func secretOption(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "key", "key1", "key2", "key3", "key4", "psk", "pass", "passwd", "token", "faskey",
		"api_key", "apikey", "sae_password", "priv_key_pwd", "auth_secret", "acct_secret", "secret",
		"privatekey", "presharedkey", "wpa_passphrase", "wpa_psk", "password_hash":
		return true
	case "public_key", "publickey", "keyfile", "key_file", "ssh_key", "authorized_keys", "keys":
		return false
	}
	for _, s := range []string{"password", "passphrase", "secret", "private_key", "preshared_key", "_psk", "token"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return strings.HasSuffix(n, "_key") && !strings.HasSuffix(n, "public_key") && !strings.HasSuffix(n, "_keyfile")
}

var (
	uciLine   = regexp.MustCompile(`^(\s*(?:option|list)\s+)(['"]?)([A-Za-z0-9_.-]+)(['"]?)(\s+)(.*)$`)
	kvLine    = regexp.MustCompile(`^(\s*-?\s*)([A-Za-z0-9_.-]+)(\s*[:=]\s*)(\S.*)$`)
	privBlock = []byte("PRIVATE KEY-----")
)

// removedFile reports files a redacted archive leaves out: host keys and
// any private key file.
func removedFile(name string, content []byte) bool {
	base := path.Base(name)
	if strings.Contains(base, "host_key") || strings.HasSuffix(base, ".key") {
		return true
	}
	if strings.HasPrefix(name, "etc/wireguard/") {
		return true
	}
	return bytes.Contains(content, privBlock)
}

// isPathValue: a UCI value naming a file (uhttpd's `key '/etc/uhttpd.key'`)
// is not itself a secret.
func isPathValue(v string) bool {
	v = strings.Trim(strings.TrimSpace(v), `'"`)
	return strings.HasPrefix(v, "/") && !strings.ContainsAny(v, " \t")
}

func isText(b []byte) bool {
	if len(b) > 0 && bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	return true
}

// redactText rewrites one text file; the redactions name file.
func redactText(name string, content []byte) ([]byte, []Redaction) {
	var out bytes.Buffer
	var reds []Redaction
	seen := map[string]bool{}
	note := func(opt string) {
		if !seen[opt] {
			seen[opt] = true
			reds = append(reds, Redaction{File: "/" + name, Option: opt})
		}
	}
	isUCI := strings.HasPrefix(name, "etc/config/")
	isShadow := name == "etc/shadow"
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	first := true
	for sc.Scan() {
		if !first {
			out.WriteByte('\n')
		}
		first = false
		line := sc.Text()
		switch {
		case isShadow:
			f := strings.SplitN(line, ":", 3)
			if len(f) == 3 && f[1] != "" && f[1] != "*" && f[1] != "!" && f[1] != "x" && !strings.HasPrefix(f[1], "!") {
				line = f[0] + ":*:" + f[2]
				note(f[0])
			}
		case isUCI:
			if m := uciLine.FindStringSubmatch(line); m != nil && secretOption(m[3]) && !isPathValue(m[6]) {
				line = m[1] + m[2] + m[3] + m[4] + m[5] + "'" + Redacted + "'"
				note(m[3])
			}
		default:
			if m := kvLine.FindStringSubmatch(line); m != nil && secretOption(m[2]) {
				line = m[1] + m[2] + m[3] + Redacted
				note(m[2])
			}
		}
		out.WriteString(line)
	}
	if bytes.HasSuffix(content, []byte("\n")) {
		out.WriteByte('\n')
	}
	return out.Bytes(), reds
}

// RedactArchive rewrites a tar.gz: secrets in text files replaced by
// Redacted, private key files left out. It returns the new archive and
// what was redacted.
func RedactArchive(data []byte) ([]byte, []Redaction, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	tr := tar.NewReader(zr)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	reds := []Redaction{}
	add := func(r ...Redaction) {
		for _, x := range r {
			if len(reds) < maxRedactions {
				reds = append(reds, x)
			}
		}
	}
	total := int64(0)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		name := strings.TrimPrefix(path.Clean(strings.TrimPrefix(h.Name, "./")), "/")
		if h.Typeflag != tar.TypeReg {
			if err := tw.WriteHeader(h); err != nil {
				return nil, nil, err
			}
			continue
		}
		total += h.Size
		if total > maxUnpacked {
			return nil, nil, fmt.Errorf("archive unpacks to more than %d bytes", maxUnpacked)
		}
		content, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, nil, err
		}
		if removedFile(name, content) {
			add(Redaction{File: "/" + name, Removed: true})
			continue
		}
		if isText(content) {
			var r []Redaction
			content, r = redactText(name, content)
			add(r...)
		}
		nh := *h
		nh.Size = int64(len(content))
		if err := tw.WriteHeader(&nh); err != nil {
			return nil, nil, err
		}
		if _, err := tw.Write(content); err != nil {
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), reds, nil
}
