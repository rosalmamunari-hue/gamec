//go:build unix

package flock

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lock(f *os.File, wait bool) error {
	how := unix.LOCK_EX
	if !wait {
		how |= unix.LOCK_NB
	}
	for {
		err := unix.Flock(int(f.Fd()), how)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EWOULDBLOCK):
			return ErrBusy
		}
		return err
	}
}
