package web

import (
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"gamec/panel/internal/engine"
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
