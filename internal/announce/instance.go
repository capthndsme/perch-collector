package announce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// idPattern is the shape the server accepts for an instance id
// (app/validators/collectors.ts). Everything this package produces is 32 hex
// characters; the pattern is what an operator-supplied id has to satisfy.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// machineIDPaths are the stable per-installation identifiers this package
// derives from, most authoritative first. systemd writes the first; the dbus
// one predates it. A variable so tests can take them away.
var machineIDPaths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}

// macOnlyOnce keeps the "no machine id here" notice to a single line.
var macOnlyOnce sync.Once

// ResolveInstanceID returns the identity this collector announces under. It
// is the one value that must survive restarts, reinstalls and address
// changes: the server keys a collector row on it, so a daemon that comes
// back with a new id arrives as a *new* pending row that has to be adopted
// again.
//
// Order of preference:
//
//  1. an explicit `instance_id` from the config (what OpenWrt passes, where
//     UCI is the persistence layer and the filesystem may be read-only);
//  2. the id previously persisted in `path`;
//  3. an id DERIVED from this machine — the machine id and the capture
//     interface's MAC — which needs no state on disk at all, so a container
//     recreated without a volume keeps the identity it had as long as it
//     still sees the same host NIC. It is written to `path` anyway when that
//     works, which pins it against a later NIC change; a failed write is not
//     an error, it is just the container case;
//  4. a fresh random id, persisted to `path`;
//  5. a random id that lives only as long as the process.
//
// The returned id is always usable. A non-nil error is advisory — the caller
// should log it and carry on — and only (5) means the collector will have to
// be adopted again after a restart.
func ResolveInstanceID(explicit, path, iface string) (string, error) {
	var warn error

	// 1. Explicit configuration wins, always.
	if id := strings.TrimSpace(explicit); id != "" {
		if validID(id) {
			return id, nil
		}
		warn = fmt.Errorf("ignoring instance_id %q: expected 8-64 characters of [A-Za-z0-9_-]", id)
	}

	// 2. Whatever a previous run persisted.
	//
	// A file that cannot be read at all (no such directory, no permission)
	// is the container case and is only worth reporting if we end up needing
	// that file, so it is kept apart from `warn` until then.
	var fileWarn error
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if id := strings.TrimSpace(string(data)); validID(id) {
				return id, warn
			}
			warn = errors.Join(warn, fmt.Errorf("%s does not contain a usable instance id; replacing it", path))
		case !os.IsNotExist(err):
			fileWarn = fmt.Errorf("reading %s: %w", path, err)
		}
	}

	// 3. Derive one from the machine itself. This is the normal path for a
	// first start, and the reason an unvolumed container stays recognisable.
	machineID := readMachineID()
	mac := interfaceMAC(iface)
	if id, ok := deriveStableID(machineID, mac); ok {
		if machineID == "" {
			macOnlyOnce.Do(func() {
				log.Printf("announce: no machine id on this host (%s); deriving the instance id from the %s MAC alone",
					strings.Join(machineIDPaths, ", "), ifaceLabel(iface))
			})
		}
		// Best effort: pin it so a NIC swap later cannot change our identity.
		// Failing to write it is exactly the container case and not an error.
		if path != "" {
			_ = persistID(path, id)
		}
		return id, warn
	}

	// 4. Nothing stable to derive from: generate and persist. From here on
	// the id file matters, so anything that went wrong with it is reported.
	warn = errors.Join(warn, fileWarn)
	if path != "" {
		id, genErr := generateID()
		if genErr != nil {
			warn = errors.Join(warn, fmt.Errorf("generating an instance id: %w", genErr))
		} else if persistErr := persistID(path, id); persistErr != nil {
			warn = errors.Join(warn, fmt.Errorf("persisting the instance id to %s: %w", path, persistErr))
		} else {
			return id, warn
		}
	}

	// 5. Nowhere to persist and nothing to derive from.
	id, err := generateID()
	if err != nil {
		return "", errors.Join(warn, fmt.Errorf("generating an instance id: %w", err))
	}
	return id, errors.Join(warn, errors.New(
		"instance id is in memory only: this machine has no machine id and no interface MAC to derive one from, "+
			"and it could not be persisted, so the collector will have to be adopted again after a restart; "+
			"set instance_id / PERCH_COLLECTOR_INSTANCE_ID"))
}

// validID reports whether id is one the server will accept.
func validID(id string) bool {
	return idPattern.MatchString(id)
}

// generateID returns 32 hex characters from crypto/rand — the same shape the
// OpenWrt init script generates for the API key.
func generateID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// persistID writes id to path, creating the directory if needed. It goes
// through a temp file and a rename so a half-written file can never be read
// back as an identity, and so an older 0644 file ends up 0600: the id is not
// a secret the way the API key is, but nothing else needs to read it.
func persistID(path, id string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0o600); err != nil {
		return err
	}
	// WriteFile only applies the mode when it creates the file, and the umask
	// can trim it; say it explicitly.
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// deriveStableID hashes whatever stable facts about this machine we could
// find into an id. It reports false only when there was nothing to hash, in
// which case the caller has to settle for a random id.
//
// The hash means neither the machine id (which is meant to stay local) nor
// the MAC leaves the box in a recoverable form.
func deriveStableID(machineID, mac string) (string, bool) {
	machineID = strings.TrimSpace(machineID)
	mac = strings.ToLower(strings.TrimSpace(mac))
	if machineID == "" && mac == "" {
		return "", false
	}
	// The salt keeps the pre-rename name on purpose: changing it would give
	// every collector that derives its id a new identity.
	sum := sha256.Sum256([]byte("go-collector instance id|" + machineID + "|" + mac))
	return hex.EncodeToString(sum[:])[:32], true
}

// readMachineID returns the first machine id this host exposes, or "".
func readMachineID() string {
	for _, p := range machineIDPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}
	return ""
}

// interfaceMAC returns the hardware address of the capture interface, or ""
// when there is none to read (a pseudo-interface such as "any", a name that
// no longer exists, a container without CAP_NET_ADMIN).
func interfaceMAC(iface string) string {
	if iface == "" || iface == "any" {
		return ""
	}
	ni, err := net.InterfaceByName(iface)
	if err != nil || len(ni.HardwareAddr) == 0 {
		return ""
	}
	return ni.HardwareAddr.String()
}

// ifaceLabel is what to call the capture interface in a log line.
func ifaceLabel(iface string) string {
	if iface == "" {
		return "capture interface"
	}
	return iface
}
