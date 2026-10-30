// Package flock takes exclusive locks on files, so the panel's command-line tools and the running server do
// not write the same data files at the same time. The locks are advisory on Linux: every writer must take them.
package flock

import (
	"errors"
	"os"
)

// ErrBusy means another process holds the lock.
var ErrBusy = errors.New("locked by another process")

// Lock waits until f is locked exclusively. Closing f releases it.
func Lock(f *os.File) error { return lock(f, true) }

// TryLock locks f exclusively, or returns ErrBusy at once.
func TryLock(f *os.File) error { return lock(f, false) }
