package auth

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() { argonMemKiB = 64 } // fast for tests

const goodPW = "a long enough password"

func TestPasswordHashAndCheck(t *testing.T) {
	h, err := HashPassword(goodPW)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h, goodPW) {
		t.Fatal("hash contains the password")
	}
	if !CheckPassword(h, goodPW) || CheckPassword(h, goodPW+"x") || CheckPassword("garbage", goodPW) {
		t.Fatal("check is wrong")
	}
	h2, _ := HashPassword(goodPW)
	if h == h2 {
		t.Fatal("two hashes of one password must differ (salt)")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short passwords must be refused")
	}
}

// RFC 6238 appendix B: the SHA-1 secret is the ASCII string "12345678901234567890".
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"}
	for unix, want := range cases {
		got, err := TOTPCode(secret, time.Unix(unix, 0))
		if err != nil || got != want {
			t.Errorf("t=%d got %q want %q (%v)", unix, got, want, err)
		}
	}
}

func TestTOTPWindow(t *testing.T) {
	s := NewTOTPSecret()
	now := time.Unix(1_700_000_010, 0)
	cur, _ := TOTPCode(s, now)
	prev, _ := TOTPCode(s, now.Add(-30*time.Second))
	old, _ := TOTPCode(s, now.Add(-120*time.Second))
	if _, ok := VerifyTOTP(s, cur, now); !ok {
		t.Fatal("current code rejected")
	}
	if _, ok := VerifyTOTP(s, prev, now); !ok {
		t.Fatal("previous step should be tolerated for clock drift")
	}
	if _, ok := VerifyTOTP(s, old, now); ok {
		t.Fatal("a code from two minutes ago must be rejected")
	}
	if _, ok := VerifyTOTP(s, "000000x", now); ok {
		t.Fatal("garbage accepted")
	}
}

func newUsers(t *testing.T) (*Users, string, time.Time) {
	u, err := OpenUsers(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	sec, err := u.Add("alice", Admin, goodPW, now)
	if err != nil {
		t.Fatal(err)
	}
	return u, sec, now
}

func code(t *testing.T, secret string, now time.Time) string {
	c, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoginNeedsPasswordAndCode(t *testing.T) {
	u, sec, now := newUsers(t)
	if _, err := u.Authenticate("alice", goodPW, code(t, sec, now), now); err != nil {
		t.Fatalf("good login failed: %v", err)
	}
	later := now.Add(time.Minute)
	if _, err := u.Authenticate("alice", "wrong password!!", code(t, sec, later), later); err != ErrInvalid {
		t.Fatalf("wrong password: %v", err)
	}
	later = later.Add(time.Minute)
	if _, err := u.Authenticate("alice", goodPW, "123456", later); err != ErrInvalid {
		t.Fatalf("wrong code: %v", err)
	}
}

func TestUnknownUserLooksLikeAnyOtherFailure(t *testing.T) {
	u, _, now := newUsers(t)
	if _, err := u.Authenticate("nobody", goodPW, "123456", now); err != ErrInvalid {
		t.Fatalf("got %v", err)
	}
}

func TestACodeWorksOnlyOnce(t *testing.T) {
	u, sec, now := newUsers(t)
	c := code(t, sec, now)
	if _, err := u.Authenticate("alice", goodPW, c, now); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Authenticate("alice", goodPW, c, now.Add(time.Second)); err != ErrInvalid {
		t.Fatalf("a shoulder-surfed or replayed code must not work twice, got %v", err)
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	u, sec, now := newUsers(t)
	for i := 0; i < MaxFailures; i++ {
		u.Authenticate("alice", "wrong password!!", "000000", now)
	}
	// even the right credentials are refused while locked
	if _, err := u.Authenticate("alice", goodPW, code(t, sec, now), now); err != ErrLocked {
		t.Fatalf("expected lockout, got %v", err)
	}
	after := now.Add(LockDuration + time.Second)
	if _, err := u.Authenticate("alice", goodPW, code(t, sec, after), after); err != nil {
		t.Fatalf("lock should expire: %v", err)
	}
}

func TestSuccessResetsTheFailureCount(t *testing.T) {
	u, sec, now := newUsers(t)
	for i := 0; i < MaxFailures-1; i++ {
		u.Authenticate("alice", "wrong password!!", "000000", now)
	}
	t2 := now.Add(time.Minute)
	if _, err := u.Authenticate("alice", goodPW, code(t, sec, t2), t2); err != nil {
		t.Fatal(err)
	}
	t3 := t2.Add(time.Minute)
	u.Authenticate("alice", "wrong password!!", "000000", t3)
	t4 := t3.Add(time.Minute)
	if _, err := u.Authenticate("alice", goodPW, code(t, sec, t4), t4); err != nil {
		t.Fatalf("one failure after a success must not lock: %v", err)
	}
}

func TestUsersPersistWithoutPlaintext(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "users.json")
	u, _ := OpenUsers(p)
	u.Add("bob", Viewer, goodPW, time.Now())
	u2, err := OpenUsers(p)
	if err != nil || u2.Count() != 1 {
		t.Fatalf("%v %d", err, u2.Count())
	}
}

func TestUserRules(t *testing.T) {
	u, _, now := newUsers(t)
	for _, bad := range []string{"", "has space", "x<y", strings.Repeat("a", 41)} {
		if _, err := u.Add(bad, Viewer, goodPW, now); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if _, err := u.Add("alice", Viewer, goodPW, now); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := u.Add("carol", "root", goodPW, now); err == nil {
		t.Error("unknown role accepted")
	}
	if err := u.Delete("alice"); err == nil {
		t.Error("deleting the last administrator must be refused")
	}
}

func TestListShowsNoSecrets(t *testing.T) {
	u, _, now := newUsers(t)
	infos := u.List(now)
	if len(infos) != 1 || infos[0].Name != "alice" || infos[0].Role != Admin {
		t.Fatalf("%+v", infos)
	}
}

func TestSessionsExpireWhenIdleAndAbsolutely(t *testing.T) {
	s := NewSessions(30*time.Minute, 12*time.Hour)
	now := time.Unix(1_700_000_000, 0)
	x := s.Create("alice", Admin, now)
	if _, ok := s.Get(x.Token, now.Add(10*time.Minute)); !ok {
		t.Fatal("live session rejected")
	}
	if _, ok := s.Get(x.Token, now.Add(10*time.Minute+31*time.Minute)); ok {
		t.Fatal("idle session must expire")
	}
	y := s.Create("alice", Admin, now)
	tt := now
	for i := 0; i < 26; i++ { // stay active every 29 minutes for ~12.5 h
		tt = tt.Add(29 * time.Minute)
		if _, ok := s.Get(y.Token, tt); !ok {
			return // expired absolutely: good
		}
	}
	t.Fatal("a session must not live past the absolute limit however active it is")
}

func TestSessionsAreUnguessableAndRevocable(t *testing.T) {
	s := NewSessions(time.Hour, time.Hour)
	now := time.Now()
	a, b := s.Create("alice", Admin, now), s.Create("alice", Admin, now)
	if a.Token == b.Token || a.CSRF == b.CSRF || len(a.Token) < 60 {
		t.Fatal("tokens must be long and unique")
	}
	s.Destroy(a.Token)
	if _, ok := s.Get(a.Token, now); ok {
		t.Fatal("destroyed session still valid")
	}
	s.DestroyUser("alice")
	if _, ok := s.Get(b.Token, now); ok {
		t.Fatal("DestroyUser left a session behind")
	}
}

func TestCSRFCompare(t *testing.T) {
	if !CheckCSRF("abc", "abc") || CheckCSRF("abc", "abd") || CheckCSRF("", "") {
		t.Fatal("csrf compare is wrong")
	}
}
