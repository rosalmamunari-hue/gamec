// Package vault keeps the panel's secrets (signing keys, token secrets, DNS and SSH credentials) in one file
// that is encrypted with a key derived from a passphrase. The file on disk never holds a plaintext secret.
// The vault starts sealed; an administrator unseals it with the passphrase, which is never stored. While
// sealed, nothing can be read, so a stolen disk or backup reveals nothing.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"golang.org/x/crypto/scrypt"
)

var (
	ErrSealed        = errors.New("vault is sealed")
	ErrBadPassphrase = errors.New("wrong passphrase, or the vault file was modified")
	ErrExists        = errors.New("vault already exists")
)

// scrypt cost. Raised for real use; tests lower it.
var (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

const aad = "gamec-panel-vault-v1"

type file struct {
	V     int    `json:"v"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

type Vault struct {
	mu      sync.RWMutex
	path    string
	hdr     file
	key     []byte // nil while sealed
	secrets map[string]string
}

func derive(pass string, salt []byte, n, r, p int) ([]byte, error) {
	return scrypt.Key([]byte(pass), salt, n, r, p, 32)
}

// Create makes a new, empty, unsealed vault. It refuses to overwrite an existing file.
func Create(path, passphrase string) (*Vault, error) {
	if len(passphrase) < 12 {
		return nil, errors.New("passphrase must be at least 12 characters")
	}
	if _, err := os.Stat(path); err == nil {
		return nil, ErrExists
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := derive(passphrase, salt, scryptN, scryptR, scryptP)
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, key: key, secrets: map[string]string{},
		hdr: file{V: 1, N: scryptN, R: scryptR, P: scryptP, Salt: salt}}
	if err := v.save(); err != nil {
		return nil, err
	}
	return v, nil
}

// Open reads the file but leaves the vault sealed.
func Open(path string) (*Vault, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var h file
	if err := json.Unmarshal(b, &h); err != nil || h.V != 1 {
		return nil, errors.New("not a vault file")
	}
	return &Vault{path: path, hdr: h}, nil
}

func (v *Vault) Sealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.key == nil
}

// Unseal derives the key from the passphrase and decrypts the secrets into memory.
func (v *Vault) Unseal(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	key, err := derive(passphrase, v.hdr.Salt, v.hdr.N, v.hdr.R, v.hdr.P)
	if err != nil {
		return err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	plain, err := gcm.Open(nil, v.hdr.Nonce, v.hdr.CT, []byte(aad))
	if err != nil {
		return ErrBadPassphrase
	}
	m := map[string]string{}
	if err := json.Unmarshal(plain, &m); err != nil {
		return ErrBadPassphrase
	}
	v.key, v.secrets = key, m
	return nil
}

// Seal forgets the key and the secrets.
func (v *Vault) Seal() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.key {
		v.key[i] = 0
	}
	v.key, v.secrets = nil, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (v *Vault) Get(name string) (string, bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.key == nil {
		return "", false, ErrSealed
	}
	s, ok := v.secrets[name]
	return s, ok, nil
}

func (v *Vault) Set(name, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrSealed
	}
	old, had := v.secrets[name]
	v.secrets[name] = value
	if err := v.save(); err != nil {
		if had {
			v.secrets[name] = old
		} else {
			delete(v.secrets, name)
		}
		return err
	}
	return nil
}

func (v *Vault) Delete(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrSealed
	}
	delete(v.secrets, name)
	return v.save()
}

// Names lists the secret names (never the values).
func (v *Vault) Names() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.key == nil {
		return nil, ErrSealed
	}
	out := make([]string, 0, len(v.secrets))
	for k := range v.secrets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// save encrypts with a fresh nonce and replaces the file atomically. Caller holds the lock.
func (v *Vault) save() error {
	gcm, err := newGCM(v.key)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(v.secrets)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	h := v.hdr
	h.Nonce = nonce
	h.CT = gcm.Seal(nil, nonce, plain, []byte(aad))
	out, err := json.Marshal(h)
	if err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, v.path); err != nil {
		return fmt.Errorf("replace vault file: %w", err)
	}
	v.hdr = h
	return nil
}
