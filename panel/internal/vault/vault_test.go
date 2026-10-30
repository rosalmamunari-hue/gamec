package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func init() { scryptN = 1 << 10 } // fast for tests

const pass = "correct horse battery staple"

func newVault(t *testing.T) (*Vault, string) {
	p := filepath.Join(t.TempDir(), "vault.json")
	v, err := Create(p, pass)
	if err != nil {
		t.Fatal(err)
	}
	return v, p
}

func TestRoundTripAcrossRestart(t *testing.T) {
	v, p := newVault(t)
	if err := v.Set("cluster/a/signing_key", "TOP-SECRET-KEY"); err != nil {
		t.Fatal(err)
	}
	w, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Sealed() {
		t.Fatal("a freshly opened vault must be sealed")
	}
	if _, _, err := w.Get("cluster/a/signing_key"); err != ErrSealed {
		t.Fatalf("sealed vault must refuse reads, got %v", err)
	}
	if err := w.Unseal(pass); err != nil {
		t.Fatal(err)
	}
	got, ok, err := w.Get("cluster/a/signing_key")
	if err != nil || !ok || got != "TOP-SECRET-KEY" {
		t.Fatalf("got %q %v %v", got, ok, err)
	}
}

func TestFileNeverHoldsPlaintext(t *testing.T) {
	v, p := newVault(t)
	v.Set("name-that-is-also-sensitive", "VALUE-THAT-MUST-NOT-LEAK")
	raw, _ := os.ReadFile(p)
	for _, leak := range []string{"VALUE-THAT-MUST-NOT-LEAK", "name-that-is-also-sensitive", pass} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("%q is visible in the vault file", leak)
		}
	}
}

func TestWrongPassphraseIsRefused(t *testing.T) {
	_, p := newVault(t)
	w, _ := Open(p)
	if err := w.Unseal("not the passphrase at all"); err != ErrBadPassphrase {
		t.Fatalf("got %v", err)
	}
	if !w.Sealed() {
		t.Fatal("a failed unseal must leave the vault sealed")
	}
}

func TestTamperedFileIsDetected(t *testing.T) {
	v, p := newVault(t)
	v.Set("k", "v")
	raw, _ := os.ReadFile(p)
	i := bytes.Index(raw, []byte(`"ct":"`)) + 8
	raw[i] ^= 1
	os.WriteFile(p, raw, 0o600)
	w, _ := Open(p)
	if err := w.Unseal(pass); err == nil {
		t.Fatal("a modified vault must not unseal")
	}
}

func TestSealForgetsEverything(t *testing.T) {
	v, _ := newVault(t)
	v.Set("k", "v")
	v.Seal()
	if !v.Sealed() {
		t.Fatal("still unsealed")
	}
	if _, _, err := v.Get("k"); err != ErrSealed {
		t.Fatalf("got %v", err)
	}
	if err := v.Set("x", "y"); err != ErrSealed {
		t.Fatalf("writes must be refused while sealed, got %v", err)
	}
}

func TestEachSaveUsesAFreshNonce(t *testing.T) {
	v, p := newVault(t)
	v.Set("a", "1")
	first, _ := os.ReadFile(p)
	v.Set("a", "1")
	second, _ := os.ReadFile(p)
	if bytes.Equal(first, second) {
		t.Fatal("same ciphertext twice means the nonce was reused")
	}
}

func TestWeakPassphraseAndOverwriteAreRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(filepath.Join(dir, "v"), "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	v, p := newVault(t)
	_ = v
	if _, err := Create(p, pass); err != ErrExists {
		t.Fatalf("overwriting a vault must be refused, got %v", err)
	}
}

func TestNamesNeverReturnValues(t *testing.T) {
	v, _ := newVault(t)
	v.Set("b", "2")
	v.Set("a", "1")
	names, err := v.Names()
	if err != nil || len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("%v %v", names, err)
	}
}

func TestFileIsPrivate(t *testing.T) {
	_, p := newVault(t)
	st, _ := os.Stat(p)
	if st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("vault file is readable by others: %v", st.Mode())
	}
}
