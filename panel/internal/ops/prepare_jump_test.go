package ops

import (
	"os/exec"
	"strings"
	"testing"
)

func TestJumpScriptAllowsOnlyTheListedDestinations(t *testing.T) {
	s, err := PrepareJumpScript(goodKey, []string{"203.0.113.10:30800", "203.0.113.10:22", "[2001:db8::1]:30800", "node.example.com:22", "203.0.113.10:22"}, "198.51.100.9")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`restrict,port-forwarding,command="/bin/false",from="198.51.100.9",permitopen="203.0.113.10:22",permitopen="203.0.113.10:30800"`,
		`permitopen="[2001:db8::1]:30800"`, `permitopen="node.example.com:22"`, goodKey, "--shell /usr/sbin/nologin", "set -eu",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	if strings.Count(s, `permitopen="203.0.113.10:22"`) != 1 {
		t.Error("a duplicate address was listed twice")
	}
	if strings.Contains(s, "sudo") || strings.Contains(s, "sudoers") {
		t.Error("the jump account must have no sudo rights at all")
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("the script is not valid shell: %v\n%s", err, out)
		}
	}
}

func TestJumpScriptRefusesAnythingThatCouldWidenOrInjectOptions(t *testing.T) {
	ok := []string{"203.0.113.10:22"}
	cases := map[string]struct {
		key     string
		targets []string
		from    string
	}{
		"no destinations":          {goodKey, nil, ""},
		"a wildcard":               {goodKey, []string{"*:22"}, ""},
		"a destination with quote": {goodKey, []string{`1.2.3.4:22",command="/bin/sh`}, ""},
		"no port":                  {goodKey, []string{"203.0.113.10"}, ""},
		"a space":                  {goodKey, []string{"203.0.113.10 :22"}, ""},
		"a newline in the key":     {goodKey + "\nssh-ed25519 AAAA evil", ok, ""},
		"command injected in from": {goodKey, ok, `1.2.3.4",command="/bin/sh`},
		"rsa key":                  {"ssh-rsa AAAAB3NzaC1yc2E x", ok, ""},
	}
	for what, c := range cases {
		if _, err := PrepareJumpScript(c.key, c.targets, c.from); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
}
