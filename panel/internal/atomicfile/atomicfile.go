// Package atomicfile replaces a file so that after a crash or power loss it holds either the old contents
// or the new ones, never an empty or half-written file. The vault is the only copy of the signing keys.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write puts data at path: a temporary file next to it, flushed to disk, renamed over path, and the
// directory flushed so the rename itself survives.
func Write(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync() // not possible on every system (Windows); the file itself is already on disk
		d.Close()
	}
	return nil
}
