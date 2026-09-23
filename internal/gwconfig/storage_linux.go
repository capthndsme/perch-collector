//go:build linux

package gwconfig

import "syscall"

func statDev(path string) (major, minor uint32, ok bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, 0, false
	}
	dev := uint64(st.Dev)
	// Linux's encoding of dev_t (glibc and musl gnu_dev_major/minor).
	major = uint32((dev>>32)&0xfffff000) | uint32((dev>>8)&0x00000fff)
	minor = uint32((dev>>12)&0xffffff00) | uint32(dev&0x000000ff)
	return major, minor, true
}
