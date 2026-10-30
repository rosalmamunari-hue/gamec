package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLog(t *testing.T) (*Log, string) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return l, p
}

func fill(t *testing.T, l *Log, n int) {
	for i := 0; i < n; i++ {
		if err := l.Append(Entry{User: "admin", IP: "10.0.0.1", Action: "publish", Detail: strings.Repeat("x", i+1), OK: true}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifies(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 5)
	n, err := Verify(p)
	if err != nil || n != 5 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestModifiedEntryIsDetected(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 4)
	b, _ := os.ReadFile(p)
	b = []byte(strings.Replace(string(b), `"user":"admin"`, `"user":"mallory"`, 1))
	os.WriteFile(p, b, 0o600)
	if _, err := Verify(p); err == nil {
		t.Fatal("an edited entry must be detected")
	}
}

func TestRemovedEntryIsDetected(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 4)
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	os.WriteFile(p, []byte(strings.Join(append(lines[:1], lines[2:]...), "\n")+"\n"), 0o600)
	if _, err := Verify(p); err == nil {
		t.Fatal("a removed entry must be detected")
	}
}

func TestReorderedEntriesAreDetected(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 4)
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	lines[1], lines[2] = lines[2], lines[1]
	os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	if _, err := Verify(p); err == nil {
		t.Fatal("reordering must be detected")
	}
}

func TestChainContinuesAfterRestart(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 3)
	l2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	fill(t, l2, 2)
	if n, err := Verify(p); err != nil || n != 5 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestDamagedLogIsNotSilentlyExtended(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 3)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), `"action":"publish"`, `"action":"nothing"`, 1)), 0o600)
	if _, err := Open(p); err == nil {
		t.Fatal("opening a tampered log must fail instead of appending to it")
	}
}

func TestTailIsNewestFirst(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 6)
	es, err := Tail(p, 3)
	if err != nil || len(es) != 3 {
		t.Fatalf("%v %v", es, err)
	}
	if len(es[0].Detail) != 6 || len(es[2].Detail) != 4 {
		t.Fatalf("order wrong: %d %d", len(es[0].Detail), len(es[2].Detail))
	}
	if es, err := Tail(filepath.Join(t.TempDir(), "none"), 3); err != nil || es != nil {
		t.Fatalf("missing file: %v %v", es, err)
	}
}

func TestEmptyLogVerifies(t *testing.T) {
	_, p := newLog(t)
	if _, err := os.Stat(p); err == nil {
		if n, err := Verify(p); err != nil || n != 0 {
			t.Fatal(n, err)
		}
	}
}
