package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"gamec/panel/internal/engine"
	"gamec/panel/internal/ops"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

const fp1 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const fp2 = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

// sshFake stands in for the servers: it answers the way nodectl does.
type sshFake struct {
	mu      sync.Mutex
	cmds    []string
	opens   int
	shas    map[string]string // by host; "oldsha" until an install
	staged  []byte
	logs    string
	healthy bool
	hostKey string
	hostErr error
}

func (f *sshFake) Open(_ context.Context, n store.Node) (ops.Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n.HostKey == "" { // what the real client does
		return nil, sshx.ErrHostKeyUnknown
	}
	f.opens++
	return hostRunner{f, n.Host}, nil
}

// hostRunner is one logged-in session to one fake server, so each server keeps its own program.
type hostRunner struct {
	f    *sshFake
	host string
}

func (r hostRunner) Close() error { return nil }
func (r hostRunner) Run(_ context.Context, cmd string, stdin io.Reader) (sshx.Result, error) {
	return r.f.run(r.host, cmd, stdin)
}

func (f *sshFake) sha(host string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.shas[host]; ok {
		return s
	}
	return "oldsha"
}

func (f *sshFake) run(host, cmd string, stdin io.Reader) (sshx.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.shas == nil {
		f.shas = map[string]string{}
	}
	cur := "oldsha"
	if s, ok := f.shas[host]; ok {
		cur = s
	}
	f.cmds = append(f.cmds, cmd)
	switch {
	case strings.HasPrefix(cmd, "cat >"):
		f.staged, _ = io.ReadAll(stdin)
		return sshx.Result{}, nil
	case strings.HasSuffix(cmd, " status"):
		b, _ := json.Marshal(ops.NodeStatus{Unit: "gamec-edge", Active: "active", Sub: "running", SHA256: cur, Version: "1"})
		return sshx.Result{Stdout: string(b)}, nil
	case strings.Contains(cmd, " install -sha256 "):
		h := sha256.Sum256(f.staged)
		f.shas[host] = hex.EncodeToString(h[:])
		return sshx.Result{Stdout: "{}"}, nil
	case strings.HasSuffix(cmd, " rollback"):
		return sshx.Result{Stdout: "{}"}, nil
	case strings.Contains(cmd, " logs -n "):
		return sshx.Result{Stdout: f.logs}, nil
	case strings.HasSuffix(cmd, " restart"), strings.HasSuffix(cmd, " start"), strings.HasSuffix(cmd, " stop"):
		return sshx.Result{Stdout: `{"unit":"gamec-edge","active":"active"}`}, nil
	case strings.Contains(cmd, " stop-for "):
		return sshx.Result{Stdout: "stopped\n"}, nil
	}
	return sshx.Result{Exit: 2, Stderr: "unknown\n"}, nil
}
func (f *sshFake) count(sub string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func program(marker string) ([]byte, string) {
	b := make([]byte, 1<<20+8)
	copy(b, "\x7fELF")
	copy(b[64:], marker)
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:])
}

type sshEnv struct {
	*env
	f       *sshFake
	rel     *httptest.Server
	hostKey *string
	pubLine string
	cl      *store.Cluster
}

func newSSHEnv(t *testing.T) *sshEnv {
	t.Helper()
	e := newEnv(t, false)
	f := &sshFake{healthy: true}
	edge, edgeSHA := program("edge-v2")
	nodectl, nodectlSHA := program("nodectl")
	rel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0.2.0/SHA256SUMS.txt":
			fmt.Fprintf(w, "%s  edge-linux-amd64\n%s  nodectl-linux-amd64\n%s  gencert-linux-amd64\n", edgeSHA, nodectlSHA, strings.Repeat("c", 64))
		case "/v0.2.0/edge-linux-amd64":
			w.Write(edge)
		case "/v0.2.0/nodectl-linux-amd64":
			w.Write(nodectl)
		case "/v0.3.0/SHA256SUMS.txt":
			fmt.Fprintf(w, "%s  edge-linux-amd64\n", strings.Repeat("0", 64)) // does not match what is served
		case "/v0.3.0/edge-linux-amd64":
			w.Write(edge)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(rel.Close)

	hk := fp1
	e.s.Ops = &ops.Ops{Open: f.Open, HealthyWithin: 50 * time.Millisecond, Poll: 5 * time.Millisecond,
		Probe: func(context.Context, store.Node) engine.ProbeResult {
			if f.healthy {
				return engine.ProbeResult{OK: true}
			}
			return engine.ProbeResult{Err: "token: no answer"}
		}}
	e.s.ReleaseBase = rel.URL
	e.s.Releases = &ops.Releases{Base: rel.URL, HTTP: rel.Client()}
	e.s.FetchHostKey = func(string, time.Duration) (string, string, error) { return hk, "ssh-ed25519", nil }

	pemKey, line, _ := sshx.GenerateKey("gamec-panel")
	e.vault.Set(SSHKeyName, pemKey)
	return &sshEnv{env: e, f: f, rel: rel, hostKey: &hk, pubLine: line, cl: e.seedCluster("official")}
}

func (e *sshEnv) addNode(c *client, name, host string) *store.Node {
	c.post("/cluster/"+e.cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {name}, "host": {host}, "port": {"30800"}, "pin": {pin}}, nil)
	for _, n := range e.st.Snapshot().Nodes {
		if n.Host == host {
			return n
		}
	}
	e.t.Fatal("node not added")
	return nil
}

func (e *sshEnv) setupSSH(c *client, n *store.Node) {
	base := "/cluster/" + e.cl.ID + "/node/" + n.ID
	c.post(base+"/ssh-settings", url.Values{"csrf": {c.csrf()}, "ssh_user": {"gamec-ops"}, "ssh_port": {"22"}}, nil)
	c.post(base+"/hostkey", url.Values{"csrf": {c.csrf()}, "action": {"trust"}, "fingerprint": {fp1}}, nil)
}

func (e *sshEnv) base(n *store.Node) string { return "/cluster/" + e.cl.ID + "/node/" + n.ID }

// ---------------------------------------------------------------- access

func TestSSHPagesAreForAdministratorsOnly(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	v := e.viewer()
	tok := v.csrf()
	for _, p := range []string{e.base(n), "/ssh"} {
		if st, _, _ := v.get(p); st != http.StatusForbidden {
			t.Errorf("a viewer got %d from GET %s", st, p)
		}
	}
	for _, p := range []string{e.base(n) + "/check", e.base(n) + "/ctl", e.base(n) + "/upgrade", e.base(n) + "/stop-for", e.base(n) + "/hostkey",
		e.base(n) + "/ssh-settings", "/cluster/" + e.cl.ID + "/upgrade-all", "/ssh"} {
		if st, _, _ := v.post(p, url.Values{"csrf": {tok}, "verb": {"stop"}, "tag": {"v0.2.0"}}, nil); st != http.StatusForbidden {
			t.Errorf("a viewer got %d from POST %s", st, p)
		}
	}
	if e.f.opens != 0 || len(e.f.cmds) != 0 {
		t.Fatal("a viewer reached a server")
	}
}

func TestSSHActionsNeedTheCSRFToken(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	e.setupSSH(a, n)
	if st, _, _ := a.post(e.base(n)+"/ctl", url.Values{"verb": {"stop"}}, nil); st != http.StatusForbidden {
		t.Fatalf("%d", st)
	}
	if len(e.f.cmds) != 0 {
		t.Fatal("a forged request reached the server")
	}
}

// ---------------------------------------------------------------- settings and host key

func TestSSHSettingsAreValidatedAndTheKeyIsForgottenWhenThePortChanges(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	base := e.base(n)
	for _, bad := range []url.Values{{"ssh_user": {"root user"}}, {"ssh_user": {"x;id"}}, {"ssh_user": {"u"}, "unit": {"sshd"}}, {"ssh_user": {"u"}, "ssh_port": {"99999"}}} {
		bad.Set("csrf", a.csrf())
		if st, _, _ := a.post(base+"/ssh-settings", bad, nil); st != http.StatusBadRequest {
			t.Errorf("accepted %v", bad)
		}
	}
	e.setupSSH(a, n)
	got := e.st.Snapshot().Node(n.ID)
	if got.SSHUser != "gamec-ops" || got.SSHPort != 22 || got.HostKey != fp1 {
		t.Fatalf("%+v", got)
	}
	a.post(base+"/ssh-settings", url.Values{"csrf": {a.csrf()}, "ssh_user": {"gamec-ops"}, "ssh_port": {"2222"}}, nil)
	if e.st.Snapshot().Node(n.ID).HostKey != "" {
		t.Fatal("another port may be another machine; the confirmed key must be dropped")
	}
}

func TestNothingIsSentUntilTheHostKeyIsConfirmed(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	a.post(e.base(n)+"/ssh-settings", url.Values{"csrf": {a.csrf()}, "ssh_user": {"gamec-ops"}}, nil)
	for _, p := range []string{"/check", "/ctl"} {
		st, body, _ := a.post(e.base(n)+p, url.Values{"csrf": {a.csrf()}, "verb": {"restart"}}, nil)
		if st != http.StatusBadGateway || !strings.Contains(body, "host key") {
			t.Errorf("%s: %d", p, st)
		}
	}
	if len(e.f.cmds) != 0 {
		t.Fatalf("commands went to a server whose key was never confirmed: %v", e.f.cmds)
	}
}

func TestHostKeyIsShownFirstAndOnlyStoredWhenConfirmed(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	base := e.base(n)
	a.post(base+"/ssh-settings", url.Values{"csrf": {a.csrf()}, "ssh_user": {"gamec-ops"}}, nil)

	st, body, _ := a.post(base+"/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"fetch"}}, nil)
	if st != 200 || !strings.Contains(body, fp1) || !strings.Contains(body, "信任它") {
		t.Fatalf("%d", st)
	}
	if e.st.Snapshot().Node(n.ID).HostKey != "" {
		t.Fatal("fetching must not trust anything")
	}
	a.post(base+"/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"trust"}, "fingerprint": {fp1}}, nil)
	if e.st.Snapshot().Node(n.ID).HostKey != fp1 {
		t.Fatal("not stored after confirming")
	}
}

func TestIfTheServersKeyChangesBetweenShowingAndConfirmingNothingIsSaved(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	a.post(e.base(n)+"/ssh-settings", url.Values{"csrf": {a.csrf()}, "ssh_user": {"gamec-ops"}}, nil)
	*e.hostKey = fp2 // an interceptor takes over after the administrator was shown fp1
	st, _, _ := a.post(e.base(n)+"/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"trust"}, "fingerprint": {fp1}}, nil)
	if st != http.StatusConflict || e.st.Snapshot().Node(n.ID).HostKey != "" {
		t.Fatalf("%d host key=%q", st, e.st.Snapshot().Node(n.ID).HostKey)
	}
}

func TestAChangedKeyIsFlaggedLoudly(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	e.setupSSH(a, n)
	*e.hostKey = fp2
	_, body, _ := a.post(e.base(n)+"/hostkey", url.Values{"csrf": {a.csrf()}, "action": {"fetch"}}, nil)
	if !strings.Contains(body, "和你之前确认的指纹不一样") {
		t.Fatal("a changed host key was shown like a new one")
	}
	if e.st.Snapshot().Node(n.ID).HostKey != fp1 {
		t.Fatal("showing a changed key must not replace the confirmed one")
	}
}

// ---------------------------------------------------------------- using it

func TestCheckShowsStatusAndEscapesLogs(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	e.setupSSH(a, n)
	e.f.logs = "<script>alert(1)</script> Oct 30 edge listening\n"
	st, body, _ := a.post(e.base(n)+"/check", url.Values{"csrf": {a.csrf()}}, nil)
	if st != 200 || !strings.Contains(body, "oldsha") || !strings.Contains(body, "running") {
		t.Fatalf("%d", st)
	}
	if strings.Contains(body, "<script>alert(1)") || !strings.Contains(html.UnescapeString(body), "<script>alert(1)</script>") {
		t.Fatal("log text must appear, escaped")
	}
}

func TestControlAndStopForReachTheServerAsFixedCommandsAndAreAudited(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	e.setupSSH(a, n)
	if st, _, _ := a.post(e.base(n)+"/ctl", url.Values{"csrf": {a.csrf()}, "verb": {"restart"}}, nil); st != 200 {
		t.Fatal(st)
	}
	if st, _, _ := a.post(e.base(n)+"/stop-for", url.Values{"csrf": {a.csrf()}, "minutes": {"2"}}, nil); st != 200 {
		t.Fatal(st)
	}
	if e.f.count("gamec-nodectl -unit gamec-edge restart") != 1 || e.f.count("stop-for -seconds 120") != 1 {
		t.Fatalf("%v", e.f.cmds)
	}
	for _, bad := range []url.Values{{"verb": {"restart; id"}}, {"verb": {"reboot"}}, {"verb": {""}}} {
		bad.Set("csrf", a.csrf())
		before := len(e.f.cmds)
		if st, _, _ := a.post(e.base(n)+"/ctl", bad, nil); st == 200 || len(e.f.cmds) != before {
			t.Errorf("verb %v reached the server (status %d)", bad["verb"], st)
		}
	}
	for _, m := range []string{"0", "61", "-1", "abc", "1; id"} {
		before := len(e.f.cmds)
		if st, _, _ := a.post(e.base(n)+"/stop-for", url.Values{"csrf": {a.csrf()}, "minutes": {m}}, nil); st != http.StatusBadRequest || len(e.f.cmds) != before {
			t.Errorf("minutes %q: %d", m, st)
		}
	}
	_, audit, _ := a.get("/audit")
	for _, want := range []string{"ssh-restart", "ssh-stop-for", "alice", "node=10.1.1.1:30800"} {
		if !strings.Contains(audit, want) {
			t.Errorf("the audit log lacks %q", want)
		}
	}
}

func TestSSHNeedsAnUnsealedVault(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	e.setupSSH(a, n)
	e.vault.Seal()
	st, body, _ := a.post(e.base(n)+"/check", url.Values{"csrf": {a.csrf()}}, nil)
	if st != http.StatusServiceUnavailable || !strings.Contains(body, "上锁") || len(e.f.cmds) != 0 {
		t.Fatalf("%d", st)
	}
}

// ---------------------------------------------------------------- upgrades

func TestUpgradeDownloadsChecksInstallsAndReports(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n1, n2 := e.addNode(a, "hk1", "10.1.1.1"), e.addNode(a, "hk2", "10.1.1.2")
	e.setupSSH(a, n1)
	e.s.Mon.Record(n2.ID, engine.ProbeResult{OK: true}) // another healthy node exists
	st, body, _ := a.post(e.base(n1)+"/upgrade", url.Values{"csrf": {a.csrf()}, "tag": {"v0.2.0"}}, nil)
	if st != 200 || !strings.Contains(html.UnescapeString(body), "oldsha -> ") {
		t.Fatalf("%d %s", st, body)
	}
	if e.f.sha(n1.Host) == "oldsha" || e.f.count(" install -sha256 ") != 1 {
		t.Fatalf("not installed: %v", e.f.cmds)
	}
}

func TestATamperedReleaseNeverReachesAServer(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n1, n2 := e.addNode(a, "hk1", "10.1.1.1"), e.addNode(a, "hk2", "10.1.1.2")
	e.setupSSH(a, n1)
	e.s.Mon.Record(n2.ID, engine.ProbeResult{OK: true})
	st, body, _ := a.post(e.base(n1)+"/upgrade", url.Values{"csrf": {a.csrf()}, "tag": {"v0.3.0"}}, nil)
	if st != http.StatusBadGateway || !strings.Contains(body, "does not match") {
		t.Fatalf("%d", st)
	}
	if e.f.opens != 0 {
		t.Fatal("the panel connected to a server with a program it could not verify")
	}
	for _, tag := range []string{"latest", "v1", "v0.2.0/../x", ""} {
		before := e.f.opens
		if st, _, _ := a.post(e.base(n1)+"/upgrade", url.Values{"csrf": {a.csrf()}, "tag": {tag}}, nil); st == 200 || e.f.opens != before {
			t.Errorf("tag %q: %d", tag, st)
		}
	}
}

func TestTheOnlyHealthyNodeIsNotUpgraded(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "only", "10.1.1.1")
	e.setupSSH(a, n)
	st, body, _ := a.post(e.base(n)+"/upgrade", url.Values{"csrf": {a.csrf()}, "tag": {"v0.2.0"}}, nil)
	if st != http.StatusBadGateway || !strings.Contains(body, "唯一健康的节点") || e.f.opens != 0 {
		t.Fatalf("%d opens=%d", st, e.f.opens)
	}
}

func TestUpgradeAllTouchesOnlyConfiguredNodesAndStopsAtAProblem(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n1, n2, n3 := e.addNode(a, "hk1", "10.1.1.1"), e.addNode(a, "hk2", "10.1.1.2"), e.addNode(a, "hk3", "10.1.1.3")
	e.setupSSH(a, n1)
	e.setupSSH(a, n2)
	_ = n3 // no SSH configured: must be skipped
	e.s.Mon.Record(n1.ID, engine.ProbeResult{OK: true})
	e.s.Mon.Record(n2.ID, engine.ProbeResult{OK: true})
	e.s.Mon.Record(n3.ID, engine.ProbeResult{OK: true})

	st, body, _ := a.post("/cluster/"+e.cl.ID+"/upgrade-all", url.Values{"csrf": {a.csrf()}, "tag": {"v0.2.0"}}, nil)
	if st != http.StatusSeeOther {
		t.Fatalf("%d %s", st, body)
	}
	if e.f.count(" install -sha256 ") != 2 {
		t.Fatalf("expected the two configured nodes, got %d installs", e.f.count(" install -sha256 "))
	}
	_, audit, _ := a.get("/audit")
	if !strings.Contains(audit, "upgrade-all") {
		t.Fatal("not audited")
	}

	// now the new version never becomes healthy: the first node fails and the second is not touched
	e.f.mu.Lock()
	e.f.healthy, e.f.shas, e.f.cmds = false, map[string]string{}, nil
	e.f.mu.Unlock()
	st, body, _ = a.post("/cluster/"+e.cl.ID+"/upgrade-all", url.Values{"csrf": {a.csrf()}, "tag": {"v0.2.0"}}, nil)
	if st != http.StatusBadGateway || !strings.Contains(body, "remaining nodes were not touched") {
		t.Fatalf("%d", st)
	}
	if e.f.count(" install -sha256 ") != 1 {
		t.Fatalf("a failing upgrade must stop after the first node: %d installs", e.f.count(" install -sha256 "))
	}
}

// ---------------------------------------------------------------- the prepare script

func TestPrepareScriptPageUsesThePanelKeyAndAVerifiedNodectl(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	_, page, _ := a.get("/ssh")
	if !strings.Contains(html.UnescapeString(page), e.pubLine) {
		t.Fatal("the page should show the panel's public key")
	}
	st, body, _ := a.post("/ssh", url.Values{"csrf": {a.csrf()}, "tag": {"v0.2.0"}, "from": {"203.0.113.9"}}, nil)
	u := html.UnescapeString(body)
	if st != 200 || !strings.Contains(u, "restrict,no-pty,from=\"203.0.113.9\" "+e.pubLine) || !strings.Contains(u, "sha256sum -c -") ||
		!strings.Contains(u, "nodectl-linux-amd64") {
		t.Fatalf("%d", st)
	}
	if st, _, _ := a.post("/ssh", url.Values{"csrf": {a.csrf()}, "tag": {"v0.2.0"}, "from": {`1.2.3.4",command="/bin/sh`}}, nil); st != http.StatusBadRequest {
		t.Fatal("an injected key option was accepted")
	}
	if st, _, _ := a.post("/ssh", url.Values{"csrf": {a.csrf()}, "tag": {"v9.9.9"}}, nil); st != http.StatusBadRequest {
		t.Fatal("a release that does not exist should be an error")
	}
}

func TestThePanelsPrivateKeyNeverAppearsAnywhere(t *testing.T) {
	e := newSSHEnv(t)
	a := e.admin()
	n := e.addNode(a, "hk", "10.1.1.1")
	e.setupSSH(a, n)
	priv, _, _ := e.vault.Get(SSHKeyName)
	for _, p := range []string{"/ssh", "/audit", "/", e.base(n)} {
		_, body, _ := a.get(p)
		u := html.UnescapeString(body)
		if strings.Contains(u, "BEGIN OPENSSH PRIVATE KEY") || strings.Contains(u, strings.TrimSpace(strings.Split(priv, "\n")[1])) {
			t.Errorf("%s shows the private key", p)
		}
	}
	_ = bytes.MinRead
}
