package gwconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/capthndsme/perch-agentkit/openwrt/pkgdb"
)

// Storage media (gateway README section 7.18): what backs a path decides how
// often local state is written there (batched on SPI/NAND flash,
// write-through on eMMC, SD, USB or SATA).
const (
	MediumFlash   = "flash" // raw SPI/NAND flash: mtdblock, UBI, jffs2, ubifs
	MediumEMMC    = "emmc"
	MediumSD      = "sd"
	MediumUSB     = "usb"
	MediumSATA    = "sata"
	MediumNVMe    = "nvme"
	MediumDisk    = "disk" // another block device (virtio, xen, SCSI without USB)
	MediumRAM     = "ram"  // tmpfs, ramfs, zram
	MediumNetwork = "network"
	MediumUnknown = "unknown"
)

// Storage describes what backs a configured path. Detection only: nothing
// is written there by this version.
type Storage struct {
	Path string `json:"path"`
	// Exists: the path itself exists (the rest describes its nearest
	// existing parent otherwise).
	Exists     bool   `json:"exists"`
	MountPoint string `json:"mountPoint,omitempty"`
	FSType     string `json:"fsType,omitempty"`
	Device     string `json:"device,omitempty"`
	Medium     string `json:"medium"`
	// OnRoot: the path is on the router's own root file system (/ or the
	// /overlay behind it), not on a mount of its own. For a path meant to be
	// on a USB stick or an SD card this means the card is not mounted and
	// writing there would fill the router's flash (the mount check of README
	// section 7.18).
	OnRoot     bool   `json:"onRoot"`
	ReadOnly   bool   `json:"readOnly"`
	TotalBytes uint64 `json:"totalBytes,omitempty"`
	FreeBytes  uint64 `json:"freeBytes,omitempty"`
}

// devOf returns the device number (major, minor) of the file system holding
// path; ok false where it cannot tell (tests replace it).
var devOf = statDev

// DetectStorage describes the storage of path on the system under root.
func DetectStorage(root, path string) *Storage {
	path = filepath.Clean("/" + path)
	s := &Storage{Path: path, Medium: MediumUnknown}
	existing := path
	for {
		if _, err := os.Stat(rooted(root, existing)); err == nil {
			break
		}
		if existing == "/" {
			break
		}
		existing = filepath.Dir(existing)
	}
	s.Exists = existing == path
	mounts, err := pkgdb.Mounts(root)
	if err != nil {
		return s
	}
	// The mount is looked up by the path itself: a mount point covers it
	// whether or not the directory exists yet.
	m, ok := pkgdb.MountFor(mounts, path)
	if !ok {
		return s
	}
	s.MountPoint, s.FSType, s.Device, s.ReadOnly = m.MountPoint, m.FSType, m.Device, m.ReadOnly()
	s.OnRoot = m.MountPoint == "/" || m.MountPoint == "/overlay" || m.FSType == "overlay"
	// The device is read from the mount point (it exists while mounted),
	// else from the nearest existing parent.
	statPath := existing
	if _, err := os.Stat(rooted(root, m.MountPoint)); err == nil {
		statPath = m.MountPoint
	}
	s.Medium = mediumOf(root, mounts, m, statPath, 0)
	if sp, err := pkgdb.FreeSpace(rooted(root, existing)); err == nil {
		s.TotalBytes, s.FreeBytes = sp.TotalBytes, sp.FreeBytes
	}
	return s
}

// mediumOf classifies a mount: by file system type first, then by the block
// device behind it (sysfs), then by the device name.
func mediumOf(root string, mounts []pkgdb.Mount, m pkgdb.Mount, path string, depth int) string {
	switch fs := m.FSType; {
	case fs == "tmpfs" || fs == "ramfs":
		return MediumRAM
	case fs == "jffs2" || fs == "ubifs" || fs == "squashfs" && strings.Contains(m.Device, "mtd"):
		return MediumFlash
	case strings.HasPrefix(fs, "nfs") || fs == "cifs" || fs == "smb3" || fs == "9p" || strings.Contains(fs, "sshfs"):
		return MediumNetwork
	case fs == "overlay":
		// OpenWrt's root: the writable half is the /overlay mount.
		if depth == 0 {
			for _, o := range mounts {
				if filepath.Clean(o.MountPoint) == "/overlay" {
					return mediumOf(root, mounts, o, "/overlay", depth+1)
				}
			}
		}
		return MediumUnknown
	}
	if major, minor, ok := devOf(rooted(root, path)); ok && major != 0 {
		if link, err := filepath.EvalSymlinks(rooted(root, fmt.Sprintf("/sys/dev/block/%d:%d", major, minor))); err == nil {
			if med := mediumOfSysfs(root, link); med != MediumUnknown {
				return med
			}
		}
	}
	return mediumOfName(root, strings.TrimPrefix(m.Device, "/dev/"))
}

// mediumOfSysfs classifies a /sys/devices/... path of a block device.
func mediumOfSysfs(root, sysPath string) string {
	p := filepath.ToSlash(sysPath)
	switch {
	case strings.Contains(p, "/usb"):
		return MediumUSB
	case strings.Contains(p, "/virtual/mtd") || strings.Contains(p, "/mtdblock") || strings.Contains(p, "/ubiblock"):
		return MediumFlash
	case strings.Contains(p, "/zram") || strings.Contains(p, "/ram"):
		return MediumRAM
	}
	// The whole-disk name is the path element after .../block/.
	parts := strings.Split(p, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "block" {
			return mediumOfName(root, parts[i+1])
		}
	}
	return mediumOfName(root, filepath.Base(p))
}

// mediumOfName classifies by device name: mmcblkN (eMMC or SD by the card's
// type in sysfs), nvme, sdX/hdX, vdX/xvdX, mtdblock/ubi.
func mediumOfName(root, name string) string {
	switch {
	case name == "":
		return MediumUnknown
	case strings.HasPrefix(name, "mmcblk"):
		disk := name
		if i := strings.Index(name[len("mmcblk"):], "p"); i >= 0 {
			disk = name[:len("mmcblk")+i]
		}
		t, _ := os.ReadFile(rooted(root, "/sys/block/"+disk+"/device/type"))
		switch strings.TrimSpace(string(t)) {
		case "MMC":
			return MediumEMMC
		case "SD":
			return MediumSD
		}
		return MediumUnknown
	case strings.HasPrefix(name, "nvme"):
		return MediumNVMe
	case strings.HasPrefix(name, "mtdblock") || strings.HasPrefix(name, "ubi"):
		return MediumFlash
	case strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "hd"):
		// USB mass storage is also sdX: sysfs tells (mediumOfSysfs); by name
		// alone, look at the disk's sysfs link.
		disk := strings.TrimRightFunc(name, func(r rune) bool { return r >= '0' && r <= '9' })
		if link, err := filepath.EvalSymlinks(rooted(root, "/sys/block/"+disk)); err == nil && strings.Contains(filepath.ToSlash(link), "/usb") {
			return MediumUSB
		}
		return MediumSATA
	case strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd"):
		return MediumDisk
	case strings.HasPrefix(name, "zram"):
		return MediumRAM
	}
	return MediumUnknown
}
