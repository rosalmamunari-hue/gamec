package web

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"gamec/panel/internal/engine"
	"gamec/panel/internal/sshx"
)

const secretHex = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"

func wizardEnv(t *testing.T) (*sshEnv, *client, *string) {
	e := newSSHEnv(t)
	e.vault.Set(engine.NodeSecretName(e.cl.ID), secretHex)
	nodePin := pin
	e.s.FetchPin = func(string, time.Duration) (string, error) {
		if nodePin == "" {
			return "", errors.New("connection refused")
		}
		return nodePin, nil
	}
	return e, e.admin(), &nodePin
}

func wizardForm1() url.Values {
	return url.Values{"name": {"hk-3"}, "host": {"203.0.113.21"}, "port": {"40123"}, "ssh_port": {"22"}, "tag": {"v0.2.0"},
		"origin": {"203.0.113.50:10443"}, "from": {"198.51.100.9"}}
}

func with(v url.Values, kv ...string) url.Values {
	out := url.Values{}
	for k, x := range v {
		out[k] = x
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out.Set(kv[i], kv[i+1])
	}
	return out
}

func TestTheWizardInstallsAndAddsANodeInThreeSteps(t *testing.T) {
	e, a, _ := wizardEnv(t)
	base := "/cluster/" + e.cl.ID + "/node/new"
	if st, body, _ := a.get(base); st != 200 || !strings.Contains(body, "填服务器地址") {
		t.Fatalf("step 1: %d", st)
	}
	st, body, _ := a.post(base+"/script", with(wizardForm1(), "csrf", a.csrf()), nil)
	u := html.UnescapeString(body)
	if st != 200 || !strings.Contains(u, "-listen :40123 -origin 203.0.113.50:10443") || !strings.Contains(u, secretHex) ||
		!strings.Contains(u, e.pubLine) || !strings.Contains(u, `from="198.51.100.9"`) {
		t.Fatalf("step 2: %d %s", st, firstMsg(body))
	}
	if c := e.st.Snapshot().Cluster(e.cl.ID); c.Origin != "203.0.113.50:10443" {
		t.Error("the origin should be remembered for the channel")
	}
	st, body, _ = a.post(base+"/check", with(wizardForm1(), "csrf", a.csrf()), nil)
	if st != 200 || !strings.Contains(body, pin) || !strings.Contains(body, fp1) {
		t.Fatalf("step 3: %d", st)
	}
	st, _, h := a.post(base+"/finish", with(wizardForm1(), "csrf", a.csrf(), "pin", pin, "host_key", fp1), nil)
	if st != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/cluster/"+e.cl.ID) {
		t.Fatalf("finish: %d", st)
	}
	ns := e.st.Snapshot().NodesOf(e.cl.ID)
	if len(ns) != 1 || ns[0].Addr() != "203.0.113.21:40123" || ns[0].Pin != pin || ns[0].HostKey != fp1 || ns[0].SSHUser != "gamec-ops" {
		t.Fatalf("stored: %+v", ns)
	}
	_, audit, _ := a.get("/audit")
	if !strings.Contains(audit, "node-install-script") || strings.Contains(audit, secretHex) {
		t.Error("the script is audited, without the secret")
	}
}

// What the person compared must be what is saved: if the server shows something else by the time they
// confirm, nothing is stored.
func TestTheWizardSavesNothingIfTheFingerprintsChangeBeforeConfirming(t *testing.T) {
	e, a, nodePin := wizardEnv(t)
	base := "/cluster/" + e.cl.ID + "/node/new"
	*nodePin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	st, body, _ := a.post(base+"/finish", with(wizardForm1(), "csrf", a.csrf(), "pin", pin, "host_key", fp1), nil)
	if st != http.StatusConflict || len(e.st.Snapshot().Nodes) != 0 || !strings.Contains(body, *nodePin) {
		t.Fatalf("a changed pin: %d, nodes %d", st, len(e.st.Snapshot().Nodes))
	}
	*nodePin = pin
	*e.hostKey = fp2
	if st, _, _ := a.post(base+"/finish", with(wizardForm1(), "csrf", a.csrf(), "pin", pin, "host_key", fp1), nil); st != http.StatusConflict || len(e.st.Snapshot().Nodes) != 0 {
		t.Fatalf("a changed SSH key: %d", st)
	}
}

func TestTheWizardExplainsANodeThatIsNotUpYet(t *testing.T) {
	e, a, nodePin := wizardEnv(t)
	*nodePin = ""
	st, body, _ := a.post("/cluster/"+e.cl.ID+"/node/new/check", with(wizardForm1(), "csrf", a.csrf()), nil)
	if st != 200 || !strings.Contains(body, "安全组") || !strings.Contains(body, "再试一次") {
		t.Fatalf("%d", st)
	}
}

func TestTheWizardChecksWhatGoesIntoTheScript(t *testing.T) {
	e, a, _ := wizardEnv(t)
	base := "/cluster/" + e.cl.ID + "/node/new/script"
	for _, bad := range []url.Values{
		with(wizardForm1(), "host", "203.0.113.21'; reboot; '"),
		with(wizardForm1(), "host", "node.example.com"), // a name could point anywhere later; the wizard wants the IP
		with(wizardForm1(), "origin", "1.2.3.4:80 -dev"),
		with(wizardForm1(), "port", "80"),
		with(wizardForm1(), "tag", "v0.2.0; reboot"),
		with(wizardForm1(), "from", `1.2.3.4",command="sh`),
	} {
		bad.Set("csrf", a.csrf())
		if st, body, _ := a.post(base, bad, nil); st == 200 || strings.Contains(body, secretHex) {
			t.Errorf("accepted %v: %d", bad, st)
		}
	}
	e.vault.Seal()
	if _, body, _ := a.get("/cluster/" + e.cl.ID + "/node/new"); !strings.Contains(body, "保险库上锁了") {
		t.Error("a sealed vault should be explained before the form is filled in")
	}
	v := e.viewer()
	if st, _, _ := v.get("/cluster/" + e.cl.ID + "/node/new"); st != http.StatusForbidden {
		t.Errorf("viewers cannot add nodes: %d", st)
	}
}

func firstMsg(body string) string {
	if i := strings.Index(body, "data-msg>"); i >= 0 {
		return body[i : i+min(200, len(body)-i)]
	}
	return ""
}

// ---------------------------------------------------------------- one-click install

type fakeRoot struct {
	password string // the right one
	seen     string // the SSH key the login presents
	printed  string // what the script reports as its SSH key
	exit     int
	gotPW    []string
	gotCmd   string
	gotIn    string
}

func (f *fakeRoot) run(_ context.Context, addr, user, password, cmd string, stdin io.Reader) (sshx.Result, string, error) {
	f.gotPW = append(f.gotPW, password)
	if user != "root" || password != f.password {
		return sshx.Result{}, "", errors.New("ssh: unable to authenticate")
	}
	b, _ := io.ReadAll(stdin)
	f.gotCmd, f.gotIn = cmd, string(b)
	out := "Installed.\n   node pin:  " + pin + "\n   SSH key:   " + f.printed + "\n"
	if f.exit != 0 {
		return sshx.Result{Stderr: "edge does not match its published checksum; stopping\n", Exit: f.exit}, f.seen, nil
	}
	return sshx.Result{Stdout: out}, f.seen, nil
}

func autoEnv(t *testing.T) (*sshEnv, *client, *fakeRoot, *string) {
	e, a, nodePin := wizardEnv(t)
	f := &fakeRoot{password: "root pass 123", seen: fp1, printed: fp1}
	e.s.RunWithPassword = f.run
	return e, a, f, nodePin
}

func TestOneClickInstallLogsInRunsTheScriptAndAddsTheNode(t *testing.T) {
	e, a, f, _ := autoEnv(t)
	st, body, h := a.post("/cluster/"+e.cl.ID+"/node/new/auto", with(wizardForm1(), "csrf", a.csrf(), "password", f.password), nil)
	if st != http.StatusSeeOther {
		t.Fatalf("%d %s", st, firstMsg(body))
	}
	if loc, _ := url.QueryUnescape(h.Get("Location")); !strings.Contains(loc, fp1) {
		t.Errorf("the SSH key accepted at the first login should be shown: %s", loc)
	}
	if f.gotCmd != installCmd || !strings.Contains(f.gotIn, secretHex) || !strings.Contains(f.gotIn, "-listen :40123 -origin 203.0.113.50:10443") {
		t.Fatalf("ran %q", f.gotCmd)
	}
	ns := e.st.Snapshot().NodesOf(e.cl.ID)
	if len(ns) != 1 || ns[0].Addr() != "203.0.113.21:40123" || ns[0].Pin != pin || ns[0].HostKey != fp1 || ns[0].SSHUser != "gamec-ops" {
		t.Fatalf("stored: %+v", ns)
	}
	_, audit, _ := a.get("/audit")
	if !strings.Contains(audit, "node-auto-install") || strings.Contains(audit, f.password) || strings.Contains(audit, secretHex) {
		t.Error("the install is audited, without the password or the secret")
	}
	if strings.Contains(fmt.Sprint(e.st.Snapshot()), f.password) {
		t.Error("the password was stored")
	}
}

func TestOneClickInstallSavesNothingWhenSomethingIsWrong(t *testing.T) {
	e, a, f, nodePin := autoEnv(t)
	post := func(pw string) (int, string) {
		st, body, _ := a.post("/cluster/"+e.cl.ID+"/node/new/auto", with(wizardForm1(), "csrf", a.csrf(), "password", pw), nil)
		return st, html.UnescapeString(body)
	}
	if st, body := post(""); st != http.StatusBadRequest || !strings.Contains(body, "root 密码") || len(f.gotPW) != 0 {
		t.Errorf("no password: %d", st)
	}
	if st, body := post("wrong"); st != http.StatusBadGateway || !strings.Contains(body, "PermitRootLogin") || strings.Contains(body, "wrong") {
		t.Errorf("a wrong password: %d", st)
	}
	f.exit = 1
	if st, body := post(f.password); st != http.StatusBadGateway || !strings.Contains(body, "checksum") {
		t.Errorf("a failed script: %d", st)
	}
	f.exit = 0
	f.printed = fp2 // the machine says it has another key than the one the login saw
	if st, _ := post(f.password); st != http.StatusConflict {
		t.Errorf("a login to someone else: %d", st)
	}
	f.printed = fp1
	*nodePin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // the network shows another node than the one installed
	if st, _ := post(f.password); st != http.StatusConflict {
		t.Errorf("a different pin over the network: %d", st)
	}
	if n := len(e.st.Snapshot().Nodes); n != 0 {
		t.Fatalf("%d nodes saved", n)
	}
	// installed, but the port is not open yet: carry on with the manual check, with the fingerprints to compare
	*nodePin = ""
	old := installTimeout
	installTimeout = 3 * time.Second
	defer func() { installTimeout = old }()
	if st, body := post(f.password); st != 200 || !strings.Contains(body, "再试一次") || !strings.Contains(body, pin) {
		t.Errorf("a node not reachable yet: %d", st)
	}
	if n := len(e.st.Snapshot().Nodes); n != 0 {
		t.Fatalf("%d nodes saved", n)
	}
}
