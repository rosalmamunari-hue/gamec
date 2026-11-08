package ops

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gamec/panel/internal/store"
)

func relayParams() RelayParams {
	p := installParams()
	return RelayParams{Port: 31000, Target: "193.0.2.128:21443", Allow: []string{"203.0.113.11", "203.0.113.12"},
		Realip: Program{URL: "https://example.com/r/v1.0.0/realip-linux-amd64", SHA256: p.Edge.SHA256}, Nodectl: p.Nodectl, PubLine: p.PubLine, From: p.From}
}

func TestTheRelayScriptPassesConnectionsOnAndOnlyForItsNodes(t *testing.T) {
	s, err := RelayScript(relayParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/opt/gamec-relay/realip -pass -listen :31000 -backend 193.0.2.128:21443 -allow-file /opt/gamec-relay/allow",
		"/usr/local/sbin/gamec-nodectl relay-allow 203.0.113.11 203.0.113.12", "User=gamec-relay", "sha256sum -c -",
		`restrict,no-pty,from="198.51.100.9"`, "SSH key:", "ufw allow '31000/tcp'",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	if strings.Contains(s, "@PORT@") || strings.Contains(s, "@TARGET@") || strings.Contains(s, "@ALLOW@") {
		t.Error("a placeholder was left in the script")
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		f := filepath.Join(t.TempDir(), "relay.sh")
		os.WriteFile(f, []byte(s), 0o600)
		if out, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil {
			t.Fatalf("sh -n: %v\n%s", err, out)
		}
	}
	for i, f := range []func(*RelayParams){
		func(p *RelayParams) { p.Target = "1.2.3.4:80 -x" },
		func(p *RelayParams) { p.Target = "$(reboot):80" },
		func(p *RelayParams) { p.Allow = []string{"1.2.3.4; reboot"} },
		func(p *RelayParams) { p.Port = 80 },
		func(p *RelayParams) { p.Realip.URL = "http://x/realip" },
	} {
		p := relayParams()
		f(&p)
		if _, err := RelayScript(p); err == nil {
			t.Errorf("case %d was accepted", i)
		}
	}
}

func TestRelayAllowSendsTheNodesAddresses(t *testing.T) {
	f := &fakeNode{active: "active"}
	o := &Ops{Open: f.Open}
	r := store.Relay{ID: "aaaaaaaa", Name: "r1", Host: "198.51.100.20", Port: 31000, HostKey: "SHA256:" + strings.Repeat("A", 43)}
	if err := o.RelayAllow(context.Background(), r.AsNode(), []string{"203.0.113.11", "203.0.113.11", "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	if got := f.cmds[len(f.cmds)-1]; got != "sudo "+NodectlPath+" -unit gamec-edge relay-allow 203.0.113.11 2001:db8::1" {
		t.Fatal(got)
	}
	if err := o.RelayAllow(context.Background(), r.AsNode(), []string{"1.2.3.4 && reboot"}); err == nil {
		t.Fatal("accepted")
	}
}
