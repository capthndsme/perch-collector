package announce

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withoutMachineID points the machine-id lookup at nothing, so a test can
// exercise the Debian-slim shape on a host that has /etc/machine-id.
func withoutMachineID(t *testing.T) {
	t.Helper()
	prev := machineIDPaths
	machineIDPaths = []string{filepath.Join(t.TempDir(), "no-machine-id")}
	t.Cleanup(func() { machineIDPaths = prev })
}

// anInterfaceWithAMAC returns the name of a real interface that has a
// hardware address, or "" when this host has none.
func anInterfaceWithAMAC(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ni := range ifaces {
		if len(ni.HardwareAddr) > 0 {
			return ni.Name
		}
	}
	return ""
}

func TestResolveInstanceIDPersistsWhatItResolved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "instance-id")

	first, err := ResolveInstanceID("", path, "")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if !validID(first) {
		t.Fatalf("id %q is not one the server would accept", first)
	}
	if len(first) != 32 {
		t.Errorf("id %q has %d characters, want 32", first, len(first))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the id file was not created: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("id file mode = %o, want 600", mode)
	}

	// Stable across restarts: that is the whole point of the file.
	second, err := ResolveInstanceID("", path, "")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second != first {
		t.Errorf("id changed across calls: %q then %q", first, second)
	}
}

// L2: the write is atomic and tightens the mode of a file that was already
// there with looser permissions.
func TestPersistIDIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "instance-id")
	if err := os.WriteFile(path, []byte("older-and-world-readable\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := persistID(path, "aaaabbbbccccddddeeeeffff00001111"); err != nil {
		t.Fatalf("persistID: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("id file mode = %o, want 600 even though the old file was 644", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "aaaabbbbccccddddeeeeffff00001111" {
		t.Errorf("file holds %q", strings.TrimSpace(string(data)))
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temp file was left behind")
	}
}

func TestResolveInstanceIDExplicitWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance-id")

	id, err := ResolveInstanceID("  uci-supplied-id  ", path, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "uci-supplied-id" {
		t.Errorf("id = %q, want the trimmed explicit value", id)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the id file was written although the id came from the config (OpenWrt's overlay may be read-only)")
	}

	// An explicit id also wins over one already on disk.
	if err := os.WriteFile(path, []byte("file-supplied-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err = ResolveInstanceID("uci-supplied-id", path, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "uci-supplied-id" {
		t.Errorf("id = %q, want the explicit value to beat the file", id)
	}
}

func TestResolveInstanceIDReadsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance-id")
	if err := os.WriteFile(path, []byte("  persisted-instance-id \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := ResolveInstanceID("", path, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "persisted-instance-id" {
		t.Errorf("id = %q, want the persisted value", id)
	}
}

// Garbage in the file (a truncated write, a half-filled disk) is replaced
// rather than announced.
func TestResolveInstanceIDReplacesGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance-id")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := ResolveInstanceID("", path, "")
	if err == nil {
		t.Error("want an advisory error saying the file was replaced")
	}
	if !validID(id) || id == "short" {
		t.Fatalf("id = %q, want a freshly generated one", id)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("reading back: %v", readErr)
	}
	if strings.TrimSpace(string(data)) != id {
		t.Errorf("file holds %q, want the new id %q", strings.TrimSpace(string(data)), id)
	}
}

// An explicit id the server would reject is ignored, loudly, instead of
// producing announces that 422 forever.
func TestResolveInstanceIDRejectsInvalidExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance-id")

	id, err := ResolveInstanceID("no", path, "")
	if err == nil || !strings.Contains(err.Error(), "ignoring instance_id") {
		t.Errorf("err = %v, want it to report the ignored value", err)
	}
	if !validID(id) || id == "no" {
		t.Errorf("id = %q, want a usable replacement", id)
	}
}

// M1: the derived id comes BEFORE a random one, and is written to the file
// as a pin rather than being invented there.
func TestResolveInstanceIDPrefersDerivedOverRandom(t *testing.T) {
	want, ok := deriveStableID(readMachineID(), interfaceMAC(""))
	if !ok {
		t.Skip("this host has neither a machine id nor a usable MAC")
	}
	path := filepath.Join(t.TempDir(), "instance-id")

	got, err := ResolveInstanceID("", path, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != want {
		t.Errorf("id = %q, want the derived %q rather than a random one", got, want)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("the derived id was not pinned to the file: %v", readErr)
	}
	if strings.TrimSpace(string(data)) != want {
		t.Errorf("file holds %q, want the derived id", strings.TrimSpace(string(data)))
	}
}

// M1: no /etc/machine-id (a Debian-slim container) still derives, from the
// capture interface's MAC alone — the case that keeps a recreated container
// off the pending list.
func TestResolveInstanceIDDerivesFromMACAlone(t *testing.T) {
	iface := anInterfaceWithAMAC(t)
	if iface == "" {
		t.Skip("no interface with a hardware address on this host")
	}
	withoutMachineID(t)

	want, ok := deriveStableID("", interfaceMAC(iface))
	if !ok {
		t.Fatalf("interface %s has no MAC after all", iface)
	}
	path := filepath.Join(t.TempDir(), "instance-id")

	got, err := ResolveInstanceID("", path, iface)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != want {
		t.Errorf("id = %q, want %q derived from the MAC alone", got, want)
	}
}

// M1: a path that cannot be written is the container case, not an error —
// the id is still derived and still stable across restarts.
func TestResolveInstanceIDDerivesWhenUnwritable(t *testing.T) {
	want, ok := deriveStableID(readMachineID(), interfaceMAC(""))
	if !ok {
		t.Skip("this host has neither a machine id nor a usable MAC")
	}

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "instance-id") // parent is a file → ENOTDIR

	first, err := ResolveInstanceID("", path, "")
	if err != nil {
		t.Errorf("failing to pin the derived id must not be an error, got %v", err)
	}
	if first != want {
		t.Errorf("id = %q, want the derived %q", first, want)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("something was written to an unwritable path")
	}

	if second, _ := ResolveInstanceID("", path, ""); second != first {
		t.Errorf("derived id is not stable across restarts: %q then %q", first, second)
	}
}

// M1: a random id only when there is nothing to derive from at all. Without
// a file to persist it to, it is ephemeral and the daemon says so.
func TestResolveInstanceIDRandomOnlyAsLastResort(t *testing.T) {
	withoutMachineID(t)
	path := filepath.Join(t.TempDir(), "instance-id")

	first, err := ResolveInstanceID("", path, "") // no iface → no MAC either
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !validID(first) {
		t.Fatalf("id = %q, want a usable random one", first)
	}
	if derived, ok := deriveStableID("", ""); ok && first == derived {
		t.Error("nothing should have been derivable")
	}
	// Persisted, so the next start reads it back instead of inventing another.
	if second, _ := ResolveInstanceID("", path, ""); second != first {
		t.Errorf("random id was not persisted: %q then %q", first, second)
	}

	// Nowhere to persist it: ephemeral, and the operator is told.
	id, err := ResolveInstanceID("", "", "")
	if err == nil || !strings.Contains(err.Error(), "in memory only") {
		t.Errorf("err = %v, want a warning that the id is ephemeral", err)
	}
	if !validID(id) {
		t.Errorf("id = %q, want a usable one anyway", id)
	}
}

func TestDeriveStableID(t *testing.T) {
	a, ok := deriveStableID("machine-id-aaa", "aa:bb:cc:dd:ee:ff")
	if !ok {
		t.Fatal("deriveStableID reported nothing to derive from")
	}
	if len(a) != 32 || !validID(a) {
		t.Errorf("derived id = %q, want 32 acceptable characters", a)
	}
	if again, _ := deriveStableID("machine-id-aaa", "aa:bb:cc:dd:ee:ff"); again != a {
		t.Error("deriveStableID is not deterministic")
	}
	if strings.Contains(a, "machine-id-aaa") || strings.Contains(a, "aabbccddeeff") {
		t.Error("the derived id exposes its inputs")
	}

	// Different machine, or the same machine on a different interface.
	if other, _ := deriveStableID("machine-id-bbb", "aa:bb:cc:dd:ee:ff"); other == a {
		t.Error("two machines derive the same id")
	}
	if other, _ := deriveStableID("machine-id-aaa", "11:22:33:44:55:66"); other == a {
		t.Error("two interfaces derive the same id")
	}

	// Case and padding in a MAC must not matter.
	if other, _ := deriveStableID("machine-id-aaa", " AA:BB:CC:DD:EE:FF "); other != a {
		t.Error("MAC formatting changes the derived id")
	}

	// Either input on its own is still something.
	if _, ok := deriveStableID("machine-id-aaa", ""); !ok {
		t.Error("a machine id alone should be enough")
	}
	if _, ok := deriveStableID("", "aa:bb:cc:dd:ee:ff"); !ok {
		t.Error("a MAC alone should be enough")
	}
	if _, ok := deriveStableID("  ", " "); ok {
		t.Error("nothing at all should not be derivable")
	}
}

func TestValidID(t *testing.T) {
	tests := map[string]bool{
		"9d4c1a0f6b2e47c8a15d3e9f7b0c2a68":   true,
		"abcdefgh":                           true,
		"with-dashes_and_underscores":        true,
		"short":                              false,
		"":                                   false,
		"has spaces in it":                   false,
		"has/a/slash/in/it":                  false,
		strings.Repeat("a", 64):              true,
		strings.Repeat("a", 65):              false,
		"9d4c1a0f6b2e47c8a15d3e9f7b0c2a68\n": false,
	}
	for in, want := range tests {
		if got := validID(in); got != want {
			t.Errorf("validID(%q) = %v, want %v", in, got, want)
		}
	}
}
