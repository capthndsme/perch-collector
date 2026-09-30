//go:build unix

package gwconfig

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFile takes an exclusive flock without waiting; held reports that
// someone else has it. flock locks belong to the open file description, so
// a stopped (SIGSTOP) holder keeps it and an exited one has released it.
func tryLockFile(f *os.File) (held bool, err error) {
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}

func unlockFile(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
