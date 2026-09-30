//go:build !unix

package gwconfig

import "os"

// Without flock nothing can hold the lock (the plane runs on OpenWrt only).
func tryLockFile(*os.File) (bool, error) { return false, nil }

func unlockFile(*os.File) {}
