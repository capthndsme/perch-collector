package portal

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Storage placement of the portal state (owner decision 18). The operator
// picks the path and the flush interval; the collector finds out what backs
// the path and reports it, and never writes onto the router's own flash
// through an empty mount point.

// Storage kinds.
const (
	StorageFlash   = "flash"   // SPI/NAND flash (mtd, ubi, jffs2, ubifs)
	StorageEMMC    = "emmc"    // eMMC / SD (mmcblk)
	StorageDisk    = "disk"    // USB or SATA/NVMe disk, virtual disk
	StorageRAM     = "ram"     // tmpfs / ramfs: lost on reboot
	StorageUnknown = "unknown" // anything else
)

// DefaultStoragePath is where the state lives when nothing else is set: the
// router's overlay, which survives a reboot.
const DefaultStoragePath = "/etc/perch-collector/portal/state.db"

// StorageMarker is the file a dedicated mount may carry to prove it is the
// expected medium (optional; an expected mount point is checked either way).
const StorageMarker = ".perch-portal-storage"

// Flush interval defaults (seconds): batched on flash, write-through (every
// enforcement tick) on eMMC and disks.
const (
	FlushFlashDefault = 300
	FlushMin          = 5
	FlushMax          = 3600
)

// StorageConfig is what the operator set.
type StorageConfig struct {
	// Path of the snapshot ("" = DefaultStoragePath).
	Path string
	// FlushSeconds for counters; 0 = by storage kind.
	FlushSeconds int
	// ExpectMount is the mount point the path must be on ("" = only the
	// built-in check: a path under /mnt, /media or /srv must not be on the
	// root file system).
	ExpectMount string
}

// StorageInfo is what the collector found (hello capability details).
type StorageInfo struct {
	Path         string `json:"path"`
	Kind         string `json:"kind"`
	FSType       string `json:"fsType,omitempty"`
	Device       string `json:"device,omitempty"`
	MountPoint   string `json:"mountPoint,omitempty"`
	Persistent   bool   `json:"persistent"`
	FlushSeconds int    `json:"flushIntervalSeconds"`
	WriteThrough bool   `json:"writeThrough"`
	// Fallback: the configured path failed the mount check; the state is
	// kept in RAM and snapshotted to DefaultStoragePath instead.
	Fallback bool   `json:"fallback,omitempty"`
	Warning  string `json:"warning,omitempty"`
}

type mountEntry struct {
	device, point, fstype string
}

func parseMounts(data []byte) []mountEntry {
	var out []mountEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		out = append(out, mountEntry{device: unescapeMount(f[0]), point: unescapeMount(f[1]), fstype: f[2]})
	}
	return out
}

// unescapeMount undoes /proc/mounts' octal escapes (\040 = space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v int
			if _, err := fmt.Sscanf(s[i+1:i+4], "%o", &v); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountOf is the longest mount point containing path (the last mount on a
// point wins, like the kernel's view).
func mountOf(mounts []mountEntry, path string) (mountEntry, bool) {
	best := -1
	var found mountEntry
	for _, m := range mounts {
		p := m.point
		if p == "/" || path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			if len(p) >= best {
				best, found = len(p), m
			}
		}
	}
	return found, best >= 0
}

func classify(m mountEntry, mounts []mountEntry) (kind string, persistent bool) {
	switch m.fstype {
	case "tmpfs", "ramfs":
		return StorageRAM, false
	case "jffs2", "ubifs", "yaffs2":
		return StorageFlash, true
	case "overlay":
		// OpenWrt's root: the upper layer is /overlay.
		if up, ok := mountOf(mounts, "/overlay"); ok && up.point == "/overlay" {
			return classify(up, nil)
		}
		return StorageUnknown, true
	}
	dev := m.device
	switch {
	case strings.HasPrefix(dev, "/dev/mtdblock"), strings.HasPrefix(dev, "ubi"), strings.HasPrefix(dev, "/dev/ubi"):
		return StorageFlash, true
	case strings.HasPrefix(dev, "/dev/mmcblk"):
		return StorageEMMC, true
	case strings.HasPrefix(dev, "/dev/sd"), strings.HasPrefix(dev, "/dev/nvme"), strings.HasPrefix(dev, "/dev/vd"),
		strings.HasPrefix(dev, "/dev/hd"), strings.HasPrefix(dev, "/dev/xvd"), strings.HasPrefix(dev, "/dev/loop"),
		strings.HasPrefix(dev, "/dev/dm-"), strings.HasPrefix(dev, "/dev/mapper/"):
		return StorageDisk, true
	}
	switch m.fstype {
	case "ext4", "ext3", "ext2", "f2fs", "btrfs", "xfs", "vfat", "exfat", "ntfs", "ntfs3", "zfs":
		return StorageDisk, true
	}
	return StorageUnknown, true
}

// ResolveStorage decides where the state is snapshotted. mounts is the
// content of /proc/mounts; exists tells whether a path exists.
func ResolveStorage(cfg StorageConfig, mounts []byte, exists func(string) bool, tick int) StorageInfo {
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		path = DefaultStoragePath
	}
	path = filepath.Clean(path)
	list := parseMounts(mounts)
	info := StorageInfo{Path: path}

	fallback := func(why string) StorageInfo {
		fb := resolveAt(DefaultStoragePath, list, cfg.FlushSeconds, tick)
		fb.Fallback = true
		fb.Warning = why + "; keeping the portal state in RAM and snapshotting to " + DefaultStoragePath
		return fb
	}
	if !filepath.IsAbs(path) {
		return fallback(fmt.Sprintf("storage path %q is not absolute", cfg.Path))
	}
	m, ok := mountOf(list, path)
	if !ok {
		return fallback("cannot read the mount table")
	}
	if want := strings.TrimSpace(cfg.ExpectMount); want != "" {
		want = filepath.Clean(want)
		// Either the kernel shows the mount there, or the medium carries
		// the marker file (a mount the table names differently).
		marked := exists != nil && exists(filepath.Join(want, StorageMarker))
		if m.point != want && !marked {
			return fallback(fmt.Sprintf("%s is not mounted (the path is on %s)", want, m.point))
		}
		if path != want && !strings.HasPrefix(path, want+"/") {
			return fallback(fmt.Sprintf("storage path %s is not under %s", path, want))
		}
	} else if underDataDir(path) && (m.point == "/" || m.point == "/overlay" || m.point == "/rom") {
		// A path under /mnt with nothing mounted there would land on the
		// router's own flash, the one thing decision 18 rules out.
		return fallback(fmt.Sprintf("nothing is mounted for %s (it would land on the root file system)", path))
	}
	info = resolveAt(path, list, cfg.FlushSeconds, tick)
	return info
}

func underDataDir(path string) bool {
	for _, p := range []string{"/mnt/", "/media/", "/srv/", "/data/"} {
		if strings.HasPrefix(path+"/", p) && path+"/" != p {
			return true
		}
	}
	return false
}

func resolveAt(path string, mounts []mountEntry, flush, tick int) StorageInfo {
	info := StorageInfo{Path: path, Kind: StorageUnknown, Persistent: true}
	if m, ok := mountOf(mounts, path); ok {
		info.FSType, info.Device, info.MountPoint = m.fstype, m.device, m.point
		info.Kind, info.Persistent = classify(m, mounts)
	}
	if tick < FlushMin {
		tick = FlushMin
	}
	switch {
	case flush > 0:
		info.FlushSeconds = clampInt(flush, FlushMin, FlushMax)
	case info.Kind == StorageFlash || info.Kind == StorageUnknown:
		info.FlushSeconds = FlushFlashDefault
	default:
		info.FlushSeconds = tick
	}
	info.WriteThrough = info.FlushSeconds <= tick
	if !info.Persistent {
		info.Warning = fmt.Sprintf("%s is in RAM (%s): the portal state is lost on reboot", path, info.FSType)
	}
	return info
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ReadMounts reads /proc/mounts.
func ReadMounts() []byte {
	b, _ := os.ReadFile("/proc/mounts")
	return b
}

// PathExists is os.Stat's yes/no.
func PathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
