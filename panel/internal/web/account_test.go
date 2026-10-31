package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"gamec/panel/internal/auth"
)

func TestChangingMyPasswordNeedsTheOldOneAndACodeAndLogsMeOut(t *testing.T) {
	e := newEnv(t, false)
	a := e.admin()
	const next = "a brand new long password"
	e.clock = e.clock.Add(31 * time.Second)
	good, _ := auth.TOTPCode(e.adminOTP, e.clock)
	if st, _, _ := a.post("/account/password", url.Values{"csrf": {a.csrf()}, "current": {"wrong wrong wrong"}, "code": {good}, "new": {next}, "again": {next}}, nil); st != http.StatusBadRequest {
		t.Fatalf("a wrong current password: %d", st)
	}
	e.clock = e.clock.Add(31 * time.Second)
	good, _ = auth.TOTPCode(e.adminOTP, e.clock)
	if st, _, _ := a.post("/account/password", url.Values{"csrf": {a.csrf()}, "current": {pass}, "code": {good}, "new": {next}, "again": {"different"}}, nil); st != http.StatusBadRequest {
		t.Fatalf("mismatched new passwords: %d", st)
	}
	st, _, h := a.post("/account/password", url.Values{"csrf": {a.csrf()}, "current": {pass}, "code": {good}, "new": {next}, "again": {next}}, nil)
	if st != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/login") {
		t.Fatalf("change: %d %s", st, h.Get("Location"))
	}
	if st, _, _ := a.get("/"); st != http.StatusSeeOther {
		t.Fatal("the session that changed the password should have ended")
	}
	e.clock = e.clock.Add(31 * time.Second)
	code, _ := auth.TOTPCode(e.adminOTP, e.clock)
	if st, _, _ := e.client().post("/login", url.Values{"user": {"alice"}, "password": {next}, "code": {code}}, nil); st != http.StatusSeeOther {
		t.Fatalf("login with the new password: %d", st)
	}
}

func TestAnAdminAddsAnAccountAndSeesItsCodeOnce(t *testing.T) {
	e := newEnv(t, false)
	a := e.admin()
	st, body, _ := a.post("/account/users", url.Values{"csrf": {a.csrf()}, "name": {"bob"}, "role": {"viewer"}, "password": {"bobs long password"}}, nil)
	if st != 200 || !strings.Contains(body, "data:image/png;base64,") {
		t.Fatalf("add: %d", st)
	}
	key := regexp.MustCompile(`id="totp-key">([A-Z2-7]+)<`).FindStringSubmatch(body)
	if key == nil {
		t.Fatal("the key is shown for typing in by hand")
	}
	e.clock = e.clock.Add(31 * time.Second)
	code, _ := auth.TOTPCode(key[1], e.clock)
	if st, _, _ := e.client().post("/login", url.Values{"user": {"bob"}, "password": {"bobs long password"}, "code": {code}}, nil); st != http.StatusSeeOther {
		t.Fatalf("the new account cannot log in: %d", st)
	}
	if _, page, _ := a.get("/account"); strings.Contains(page, key[1]) {
		t.Fatal("the code must not be shown again")
	}
	if st, _, _ := a.post("/account/users/delete", url.Values{"csrf": {a.csrf()}, "name": {"alice"}}, nil); st != http.StatusBadRequest {
		t.Fatal("deleting yourself must be refused")
	}
	if st, _, _ := a.post("/account/users/delete", url.Values{"csrf": {a.csrf()}, "name": {"bob"}}, nil); st != http.StatusSeeOther {
		t.Fatal("delete bob")
	}
	v := e.viewer()
	if st, _, _ := v.post("/account/users", url.Values{"csrf": {v.csrf()}, "name": {"eve"}, "role": {"admin"}, "password": {"eves long password"}}, nil); st != http.StatusForbidden {
		t.Fatalf("a viewer added an account: %d", st)
	}
	if st, body, _ := v.get("/account"); st != 200 || strings.Contains(body, "所有账号") {
		t.Fatal("a viewer sees only their own password form")
	}
}
