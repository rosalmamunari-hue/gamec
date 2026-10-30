package flock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestASecondHolderIsTurnedAwayUntilTheFirstLetsGo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.lock")
	open := func() *os.File {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	a, b := open(), open()
	defer b.Close()
	if err := TryLock(a); err != nil {
		t.Fatal(err)
	}
	if err := TryLock(b); !errors.Is(err, ErrBusy) {
		t.Fatalf("second lock: %v", err)
	}
	a.Close()
	if err := TryLock(b); err != nil {
		t.Fatalf("after the first holder closed: %v", err)
	}
}
