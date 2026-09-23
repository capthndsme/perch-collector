//go:build !linux

package gwconfig

func statDev(string) (uint32, uint32, bool) { return 0, 0, false }
