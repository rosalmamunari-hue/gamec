package web

import (
	"context"
	"errors"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"gamec/panel/internal/egress"
	"gamec/panel/internal/sshx"
)

type fakeJump struct {
	mu    sync.Mutex
	dials []string
	fail  bool
}

func (j *fakeJump) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.dials = append(j.dials, addr)
	if j.fail {
		return nil, errors.New("jump host unreachable")
	}
	c, _ := net.Pipe()
	return c, nil
}
func (j *fakeJump) Close() error { return nil }

func newEgressEnv(t *testing.T) (*sshEnv, *fakeJump) {
	e := newSSHEnv(t)
	j := &fakeJump{}
	e.s.Egress = &egress.Egress{Store: e.st,
		Signer:  func() (ssh.Signer, error) { pem, _, _ := e.vault.Get(SSHKeyName); return sshx.ParseSigner(pem) },
		NewJump: func(sshx.Target) egress.Jumper { return j }}
	e.s.FetchJumpKey = func(string, time.Duration) (string, string, error) { return fp2, "ssh-ed25519", nil }
	return e, j
}

func TestEgressPageIsForAdministratorsOnly(t *testing.T) {
	e, _ := newEgressEnv(t)
	if st, _, _ := e.viewer().get("/egress"); st != http.StatusForbidden {
		t.Fatalf("viewer got %d", st)
	}
	v := e.viewer()
	if st, _, _ := v.post("/egress/set", url.Values{"csrf": {v.csrf()}, "addr": {"1.2.3.4"}, "user": {"gamec-jump"}}, nil); st != http.StatusForbidden {
		t.Fatalf("viewer set %d", st)
	}
	if e.st.Snapshot().Egress != nil {
		t.Fatal("a viewer changed the egress host")
	}
}

func TestEgressSetThenHostKeyMustBeConfirmedAndNothingGoesDirect(t *testing.T) {
	e, j := newEgressEnv(t)
	a := e.admin()
	e.addNode(a, "n1", "10.1.1.1")
	a.post("/egress/set", url.Values{"csrf": {a.csrf()}, "addr": {"198.51.100.7"}, "user": {"gamec-jump"}}, nil)
	cfg := e.st.Snapshot().Egress
	if cfg == nil || cfg.Addr != "198.51.100.7:22" || cfg.HostKey != "" {
		t.Fatalf("%+v", cfg)
	}
	st, body, _ := a.post("/egress/test", url.Values{"csrf": {a.csrf()}}, nil)
	if st != 200 || !strings.Contains(body, "not been confirmed") || len(j.dials) != 0 {
		t.Fatalf("unconfirmed host was used: %d dials=%v", st, j.dials)
	}
	// fetching shows the key but trusts nothing
	_, body, _ = a.post("/egress/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"fetch"}}, nil)
	if !strings.Contains(body, fp2) || e.st.Snapshot().Egress.HostKey != "" {
		t.Fatal("fetch must not trust")
	}
	// a key that changed between showing and confirming is refused
	if st, _, _ := a.post("/egress/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"trust"}, "fingerprint": {fp1}}, nil); st != http.StatusConflict {
		t.Fatalf("mismatch %d", st)
	}
	a.post("/egress/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"trust"}, "fingerprint": {fp2}}, nil)
	if e.st.Snapshot().Egress.HostKey != fp2 {
		t.Fatal("not stored")
	}
	_, body, _ = a.post("/egress/test", url.Values{"csrf": {a.csrf()}}, nil)
	if !strings.Contains(body, "可连通") || len(j.dials) != 1 || j.dials[0] != "10.1.1.1:30800" {
		t.Fatalf("dials=%v", j.dials)
	}
}

func TestEgressTestReportsAFailureInsteadOfGoingDirect(t *testing.T) {
	e, j := newEgressEnv(t)
	a := e.admin()
	e.addNode(a, "n1", "10.1.1.1")
	a.post("/egress/set", url.Values{"csrf": {a.csrf()}, "addr": {"198.51.100.7:22"}, "user": {"gamec-jump"}}, nil)
	a.post("/egress/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"trust"}, "fingerprint": {fp2}}, nil)
	j.fail = true
	_, body, _ := a.post("/egress/test", url.Values{"csrf": {a.csrf()}}, nil)
	if !strings.Contains(body, "jump host unreachable") {
		t.Fatal("failure not shown")
	}
}

func TestChangingTheEgressAddressForgetsTheConfirmedKey(t *testing.T) {
	e, _ := newEgressEnv(t)
	a := e.admin()
	a.post("/egress/set", url.Values{"csrf": {a.csrf()}, "addr": {"198.51.100.7:22"}, "user": {"gamec-jump"}}, nil)
	a.post("/egress/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"trust"}, "fingerprint": {fp2}}, nil)
	a.post("/egress/set", url.Values{"csrf": {a.csrf()}, "addr": {"198.51.100.8:22"}, "user": {"gamec-jump"}}, nil)
	if e.st.Snapshot().Egress.HostKey != "" {
		t.Fatal("a key confirmed for another machine was kept")
	}
}

func TestEgressRejectsBadInputAndRemoveGoesBackToDirect(t *testing.T) {
	e, _ := newEgressEnv(t)
	a := e.admin()
	for _, u := range []string{"", "root;reboot", "a b"} {
		if st, _, _ := a.post("/egress/set", url.Values{"csrf": {a.csrf()}, "addr": {"198.51.100.7"}, "user": {u}}, nil); st != http.StatusBadRequest {
			t.Errorf("user %q accepted (%d)", u, st)
		}
	}
	a.post("/egress/set", url.Values{"csrf": {a.csrf()}, "addr": {"198.51.100.7"}, "user": {"gamec-jump"}}, nil)
	a.post("/egress/remove", url.Values{"csrf": {a.csrf()}}, nil)
	if e.st.Snapshot().Egress != nil {
		t.Fatal("not removed")
	}
}

func TestJumpScriptListsOnlyTheNodesAddresses(t *testing.T) {
	e, _ := newEgressEnv(t)
	a := e.admin()
	n := e.addNode(a, "n1", "10.1.1.1")
	e.setupSSH(a, n)
	a.post("/egress/set", url.Values{"csrf": {a.csrf()}, "addr": {"198.51.100.7"}, "user": {"gamec-jump"}}, nil)
	_, body, _ := a.post("/egress/script", url.Values{"csrf": {a.csrf()}, "from": {"203.0.113.9"}}, nil)
	u := html.UnescapeString(body)
	for _, want := range []string{`permitopen="10.1.1.1:30800"`, `permitopen="10.1.1.1:22"`, `from="203.0.113.9"`, e.pubLine} {
		if !strings.Contains(u, want) {
			t.Errorf("missing %s", want)
		}
	}
	if st, _, _ := a.post("/egress/script", url.Values{"csrf": {a.csrf()}, "from": {`1.2.3.4",command="/bin/sh`}}, nil); st != http.StatusBadRequest {
		t.Fatal("an injected key option was accepted")
	}
}
