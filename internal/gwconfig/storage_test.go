package gwconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// storageRoot builds /proc/mounts and a sysfs with the given block device
// links (/sys/dev/block/M:m -> ../../devices/...), and fakes the device
// number of each mount point.
func storageRoot(t *testing.T, mounts string, links map[string]string, devs map[string][2]uint32, types map[string]string) string {
	t.Helper()
	root := t.TempDir()
	put(t, root, "proc/mounts", mounts)
	for devnum, target := range links {
		full := filepath.Join(root, "sys/devices", target)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "sys/dev/block"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("../../devices", target), filepath.Join(root, "sys/dev/block", devnum)); err != nil {
			t.Fatal(err)
		}
	}
	for disk, typ := range types {
		put(t, root, "sys/block/"+disk+"/device/type", typ+"\n")
	}
	old := devOf
	devOf = func(p string) (uint32, uint32, bool) {
		rel, _ := filepath.Rel(root, p)
		rel = filepath.Clean("/" + rel)
		for mp, d := range devs {
			if rel == mp || len(rel) > len(mp) && rel[:len(mp)+1] == mp+"/" {
				return d[0], d[1], true
			}
		}
		return 0, 0, false
	}
	t.Cleanup(func() { devOf = old })
	return root
}

func TestStorageMedia(t *testing.T) {
	cases := []struct {
		name, mounts, path string
		links              map[string]string
		devs               map[string][2]uint32
		types              map[string]string
		mkdir              []string
		medium             string
		onRoot, exists     bool
		mountPoint         string
	}{
		{
			name: "squashfs router, state on the overlay (NAND/UBI)",
			mounts: "/dev/root /rom squashfs ro,relatime 0 0\n/dev/ubi0_1 /overlay ubifs rw,noatime 0 0\n" +
				"overlayfs:/overlay / overlay rw,noatime,lowerdir=/,upperdir=/overlay/upper 0 0\ntmpfs /tmp tmpfs rw 0 0\n",
			path: "/etc/perch-collector", medium: MediumFlash, onRoot: true, mountPoint: "/",
		},
		{
			name: "squashfs router with a jffs2 overlay on SPI NOR",
			mounts: "/dev/root /rom squashfs ro 0 0\n/dev/mtdblock6 /overlay jffs2 rw,noatime 0 0\n" +
				"overlayfs:/overlay / overlay rw 0 0\n",
			path: "/etc/perch-collector", medium: MediumFlash, onRoot: true, mountPoint: "/",
		},
		{
			name:   "tmpfs",
			mounts: "/dev/root / ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n",
			path:   "/tmp/perch", medium: MediumRAM, mountPoint: "/tmp",
		},
		{
			name:   "eMMC data partition",
			mounts: "/dev/root / squashfs ro 0 0\n/dev/mmcblk0p5 /mnt/data ext4 rw 0 0\n",
			links:  map[string]string{"179:5": "platform/soc/11230000.mmc/mmc_host/mmc0/mmc0:0001/block/mmcblk0/mmcblk0p5"},
			devs:   map[string][2]uint32{"/mnt/data": {179, 5}},
			types:  map[string]string{"mmcblk0": "MMC"},
			mkdir:  []string{"mnt/data/perch"},
			path:   "/mnt/data/perch", medium: MediumEMMC, exists: true, mountPoint: "/mnt/data",
		},
		{
			name:   "SD card, by name only",
			mounts: "/dev/mmcblk1p1 /mnt/sd vfat rw 0 0\n",
			types:  map[string]string{"mmcblk1": "SD"},
			path:   "/mnt/sd/perch", medium: MediumSD, mountPoint: "/mnt/sd",
		},
		{
			name:   "USB stick",
			mounts: "/dev/root / squashfs ro 0 0\n/dev/sda1 /mnt/usb ext4 rw 0 0\n",
			links:  map[string]string{"8:1": "platform/soc/usb3/xhci-hcd.0/usb1/1-1/1-1:1.0/host0/target0:0:0/0:0:0:0/block/sda/sda1"},
			devs:   map[string][2]uint32{"/mnt/usb": {8, 1}},
			mkdir:  []string{"mnt/usb"}, // a mount point exists while mounted
			path:   "/mnt/usb/perch", medium: MediumUSB, mountPoint: "/mnt/usb",
		},
		{
			name:   "SATA disk of an x86 router, ext4 root",
			mounts: "/dev/root / ext4 rw,noatime 0 0\n",
			links:  map[string]string{"8:2": "pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda/sda2"},
			devs:   map[string][2]uint32{"/": {8, 2}},
			path:   "/etc/perch-collector", medium: MediumSATA, onRoot: true, mountPoint: "/",
		},
		{
			name:   "NVMe",
			mounts: "/dev/nvme0n1p2 / ext4 rw 0 0\n",
			path:   "/srv", medium: MediumNVMe, onRoot: true, mountPoint: "/",
		},
		{
			name:   "virtio disk",
			mounts: "/dev/vda2 / ext4 rw 0 0\n",
			path:   "/etc", medium: MediumDisk, onRoot: true, mountPoint: "/",
		},
		{
			name:   "NFS",
			mounts: "/dev/root / ext4 rw 0 0\n192.168.1.5:/export /mnt/nfs nfs4 rw 0 0\n",
			path:   "/mnt/nfs/x", medium: MediumNetwork, mountPoint: "/mnt/nfs",
		},
		{
			name:   "USB stick not mounted: the path is on the root",
			mounts: "/dev/root /rom squashfs ro 0 0\n/dev/ubi0_1 /overlay ubifs rw 0 0\noverlayfs:/overlay / overlay rw 0 0\n",
			path:   "/mnt/usb/perch", medium: MediumFlash, onRoot: true, mountPoint: "/",
		},
		{
			name:   "unknown device",
			mounts: "/dev/weird0 / ext4 rw 0 0\n",
			path:   "/x", medium: MediumUnknown, onRoot: true, mountPoint: "/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := storageRoot(t, tc.mounts, tc.links, tc.devs, tc.types)
			for _, d := range tc.mkdir {
				if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			s := DetectStorage(root, tc.path)
			if s.Medium != tc.medium || s.OnRoot != tc.onRoot || s.Exists != tc.exists || s.MountPoint != tc.mountPoint || s.Path != tc.path {
				t.Fatalf("%+v", s)
			}
		})
	}
}

func TestStorageWithoutMounts(t *testing.T) {
	s := DetectStorage(t.TempDir(), "relative/dir")
	if s.Path != "/relative/dir" || s.Medium != MediumUnknown || s.MountPoint != "" {
		t.Fatalf("%+v", s)
	}
}

func TestStorageReadOnly(t *testing.T) {
	root := storageRoot(t, "/dev/sda1 /mnt/ro ext4 ro 0 0\n", nil, nil, nil)
	if s := DetectStorage(root, "/mnt/ro/x"); !s.ReadOnly || s.Medium != MediumSATA {
		t.Fatalf("%+v", s)
	}
}
