// Package auth handles who may use the panel: argon2id password hashes, TOTP second factor, lockout after
// repeated failures, and server-side sessions with idle and absolute expiry.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// argon2id cost; tests lower it.
var (
	argonTime    uint32 = 2
	argonMemKiB  uint32 = 32 * 1024
	argonThreads uint8  = 2
)

const (
	MaxFailures  = 5
	LockDuration = 15 * time.Minute
	MinPassword  = 12
)

var (
	// ErrInvalid is returned for an unknown user, wrong password or wrong code alike, so the answer does not
	// reveal which part was wrong.
	ErrInvalid = errors.New("invalid credentials")
	ErrLocked  = errors.New("too many failed attempts; try again later")
)

// ---------------------------------------------------------------- passwords

func HashPassword(pw string) (string, error) {
	if len(pw) < MinPassword {
		return "", fmt.Errorf("password must be at least %d characters", MinPassword)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(pw), salt, argonTime, argonMemKiB, argonThreads, 32)
	return fmt.Sprintf("argon2id$%d$%d$%d$%s$%s", argonTime, argonMemKiB, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h)), nil
}

func CheckPassword(encoded, pw string) bool {
	f := strings.Split(encoded, "$")
	if len(f) != 6 || f[0] != "argon2id" {
		return false
	}
	var t, m uint32
	var p uint8
	var pp uint32
	if _, err := fmt.Sscanf(f[1]+" "+f[2]+" "+f[3], "%d %d %d", &t, &m, &pp); err != nil {
		return false
	}
	p = uint8(pp)
	salt, err1 := base64.RawStdEncoding.DecodeString(f[4])
	want, err2 := base64.RawStdEncoding.DecodeString(f[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---------------------------------------------------------------- TOTP (RFC 6238, SHA-1, 6 digits, 30 s)

func NewTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func totpAt(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

func TOTPCode(secret string, t time.Time) (string, error) { return totpAt(secret, t.Unix()/30) }

// VerifyTOTP accepts the code for the current 30 s step or the one on either side (clock drift) and returns
// the step that matched, so the caller can refuse to accept the same step twice.
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	cur := now.Unix() / 30
	for _, s := range []int64{cur, cur - 1, cur + 1} {
		want, err := totpAt(secret, s)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

func TOTPURI(issuer, account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer), url.PathEscape(account), secret, url.QueryEscape(issuer))
}

// ---------------------------------------------------------------- users

type Role string

const (
	Admin  Role = "admin"
	Viewer Role = "viewer"
)

type User struct {
	Name        string    `json:"name"`
	Role        Role      `json:"role"`
	PwHash      string    `json:"pw"`
	TOTP        string    `json:"totp"`
	Failed      int       `json:"failed"`
	LockedUntil time.Time `json:"locked_until"`
	LastStep    int64     `json:"last_step"`
	Created     time.Time `json:"created"`
}

type Users struct {
	mu   sync.Mutex
	path string
	list []*User
}

// a hash to compare against when the user does not exist, so timing does not reveal who exists
var dummyHash, _ = HashPassword("this is not anybody's password")

func OpenUsers(path string) (*Users, error) {
	u := &Users{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return u, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &u.list); err != nil {
		return nil, fmt.Errorf("users file: %w", err)
	}
	return u, nil
}

func (u *Users) save() error {
	b, err := json.MarshalIndent(u.list, "", "  ")
	if err != nil {
		return err
	}
	tmp := u.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, u.path)
}

func (u *Users) find(name string) *User {
	for _, x := range u.list {
		if x.Name == name {
			return x
		}
	}
	return nil
}

// Add creates a user and returns the TOTP secret to enrol in an authenticator app.
func (u *Users) Add(name string, role Role, password string, now time.Time) (string, error) {
	if name == "" || len(name) > 40 || strings.ContainsAny(name, " \t\r\n\"'<>&/\\") {
		return "", errors.New("user name must be 1-40 characters without spaces or special characters")
	}
	if role != Admin && role != Viewer {
		return "", errors.New("role must be admin or viewer")
	}
	h, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.find(name) != nil {
		return "", errors.New("user already exists")
	}
	secret := NewTOTPSecret()
	u.list = append(u.list, &User{Name: name, Role: role, PwHash: h, TOTP: secret, Created: now})
	if err := u.save(); err != nil {
		u.list = u.list[:len(u.list)-1]
		return "", err
	}
	return secret, nil
}

// Authenticate checks password and TOTP code together. Every failure returns ErrInvalid (or ErrLocked once
// the account is locked); five failures lock the account for 15 minutes. A locked account still lets in the
// right password with a fresh code: otherwise anyone who knows the name could keep the admins out (and the
// vault sealed) with five bad tries every 15 minutes. A wrong guess while locked is refused as before, and
// learns nothing, because password and code are only ever judged together.
func (u *Users) Authenticate(name, password, code string, now time.Time) (*User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	usr := u.find(name)
	if usr == nil {
		CheckPassword(dummyHash, password)
		return nil, ErrInvalid
	}
	pwOK := CheckPassword(usr.PwHash, password)
	step, codeOK := VerifyTOTP(usr.TOTP, code, now)
	replay := codeOK && step <= usr.LastStep // a code may be used once
	if now.Before(usr.LockedUntil) && !(pwOK && codeOK && !replay) {
		return nil, ErrLocked
	}
	if !pwOK || !codeOK || replay {
		usr.Failed++
		if usr.Failed >= MaxFailures {
			usr.LockedUntil = now.Add(LockDuration)
			usr.Failed = 0
		}
		u.save()
		return nil, ErrInvalid
	}
	usr.Failed = 0
	usr.LockedUntil = time.Time{}
	usr.LastStep = step
	u.save()
	cp := *usr
	return &cp, nil
}

func (u *Users) SetPassword(name, password string) error {
	h, err := HashPassword(password)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	usr := u.find(name)
	if usr == nil {
		return errors.New("no such user")
	}
	usr.PwHash = h
	return u.save()
}

func (u *Users) Delete(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	admins := 0
	for _, x := range u.list {
		if x.Role == Admin {
			admins++
		}
	}
	for i, x := range u.list {
		if x.Name == name {
			if x.Role == Admin && admins == 1 {
				return errors.New("cannot delete the last administrator")
			}
			u.list = append(u.list[:i], u.list[i+1:]...)
			return u.save()
		}
	}
	return errors.New("no such user")
}

// Info is a user without any secret.
type Info struct {
	Name    string
	Role    Role
	Locked  bool
	Created time.Time
}

func (u *Users) List(now time.Time) []Info {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]Info, 0, len(u.list))
	for _, x := range u.list {
		out = append(out, Info{x.Name, x.Role, now.Before(x.LockedUntil), x.Created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (u *Users) Count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.list)
}

// ---------------------------------------------------------------- sessions

type Session struct {
	Token   string
	User    string
	Role    Role
	CSRF    string
	Created time.Time
	Last    time.Time
}

type Sessions struct {
	mu   sync.Mutex
	m    map[string]*Session
	idle time.Duration
	abs  time.Duration
}

func NewSessions(idle, abs time.Duration) *Sessions {
	return &Sessions{m: map[string]*Session{}, idle: idle, abs: abs}
}

func token() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Sessions) Create(user string, role Role, now time.Time) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := &Session{Token: token(), User: user, Role: role, CSRF: token(), Created: now, Last: now}
	s.m[x.Token] = x
	return x
}

// Get returns a live session and refreshes its idle timer.
func (s *Sessions) Get(tok string, now time.Time) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[tok]
	if !ok {
		return nil, false
	}
	if now.Sub(x.Last) > s.idle || now.Sub(x.Created) > s.abs {
		delete(s.m, tok)
		return nil, false
	}
	x.Last = now
	cp := *x
	return &cp, true
}

func (s *Sessions) Destroy(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tok)
}

// DestroyUser ends every session of a user (after a password change or deletion).
func (s *Sessions) DestroyUser(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, x := range s.m {
		if x.User == name {
			delete(s.m, k)
		}
	}
}

// CheckCSRF compares in constant time.
func CheckCSRF(want, got string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
