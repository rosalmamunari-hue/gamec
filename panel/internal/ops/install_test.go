package ops

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func installParams() InstallParams {
	sha := strings.Repeat("ab", 32)
	return InstallParams{
		Unit: "gamec-edge", Host: "203.0.113.11", Port: 48860, Origin: "203.0.113.50:10443", Secret: strings.Repeat("0f", 32),
		Edge:    Program{URL: "https://example.com/r/v1.0.0/edge-linux-amd64", SHA256: sha},
		Gencert: Program{URL: "https://example.com/r/v1.0.0/gencert-linux-amd64", SHA256: sha},
		Nodectl: Program{URL: "https://example.com/r/v1.0.0/nodectl-linux-amd64", SHA256: sha},
		PubLine: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpVb3n0dX3Jd9yQe2r7ZbTqXo5o0H2w0w8l3D0m5n1k gamec-panel",
		From:    "198.51.100.9",
	}
}

func TestTheInstallScriptSetsUpTheNodeAndItsManagement(t *testing.T) {
	s, err := InstallScript(installParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/opt/gamec-edge/edge -listen :48860 -origin 203.0.113.50:10443 -cert /opt/gamec-edge/tls/cert.pem",
		"-secret-file /opt/gamec-edge/secret", "User=gamec-edge", "-host '203.0.113.11'",
		"sha256sum -c -", `restrict,no-pty,from="198.51.100.9"`, "/usr/local/sbin/gamec-nodectl", "node pin:", "SSH key:",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	if strings.Contains(s, "-secret ") || strings.Count(s, strings.Repeat("0f", 32)) != 1 {
		t.Error("the secret must go into a file once, never onto a command line")
	}
	if strings.Contains(s, "@") && strings.Contains(s, "@DIR@") {
		t.Error("a placeholder was left in the script")
	}
	if sh, err := exec.LookPath("sh"); err == nil { // the script must at least parse
		f := filepath.Join(t.TempDir(), "install.sh")
		os.WriteFile(f, []byte(s), 0o600)
		if out, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil {
			t.Fatalf("sh -n: %v\n%s", err, out)
		}
	}
}

// Everything in the script runs as root, so nothing that could break out of its quotes may get in.
func TestTheInstallScriptRefusesValuesThatCouldInjectCommands(t *testing.T) {
	bad := []func(*InstallParams){
		func(p *InstallParams) { p.Host = "1.2.3.4'; rm -rf /; '" },
		func(p *InstallParams) { p.Host = "$(reboot)" },
		func(p *InstallParams) { p.Origin = "1.2.3.4:80 -dev" },
		func(p *InstallParams) { p.Origin = "a'b:80" },
		func(p *InstallParams) { p.Secret = "0f0f'; reboot; '" },
		func(p *InstallParams) { p.Unit = "gamec-edge;reboot" },
		func(p *InstallParams) { p.Port = 0 },
		func(p *InstallParams) { p.Edge.URL = "https://x/'$(reboot)'" },
		func(p *InstallParams) { p.Gencert.SHA256 = "nope" },
		func(p *InstallParams) { p.From = "1.2.3.4\" ,command=\"sh" },
	}
	for i, f := range bad {
		p := installParams()
		f(&p)
		if _, err := InstallScript(p); err == nil {
			t.Errorf("case %d was accepted", i)
		}
	}
}

func TestTheInstallScriptCanTellTheOriginThePlayer(t *testing.T) {
	p := installParams()
	p.ProxyV2 = true
	s, err := InstallScript(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "-origin 203.0.113.50:10443 -proxy-v2 -cert") {
		t.Fatal("the node is not started with -proxy-v2")
	}
}
