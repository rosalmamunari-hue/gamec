//go:build windows

package flock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows locks are mandatory for the bytes they cover, so lock one byte far past any real file end: other
// handles can still read and append, and the lock only excludes other lockers, as flock does on Linux.
func lock(f *os.File, wait bool) error {
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if !wait {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	at := &windows.Overlapped{Offset: 0xFFFFFFFE, OffsetHigh: 0x7FFFFFFF}
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, at)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrBusy
	}
	return err
}
