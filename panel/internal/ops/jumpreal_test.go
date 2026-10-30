package ops

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"gamec/panel/internal/engine"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
	"gamec/panel/internal/vault"
)

// TestRealJump sets up a jump account on a real server (as root, by password) and checks, with real
// connections, that a node behind it sees the jump host and not this machine. It only runs when
// GAMEC_REAL_JUMP_HOST is set; the same machine plays jump host and node.
func TestRealJump(t *testing.T) {
	host := os.Getenv("GAMEC_REAL_JUMP_HOST")
	if host == "" {
		t.Skip("GAMEC_REAL_JUMP_HOST not set")
	}
	rootPass, myIP := os.Getenv("GAMEC_REAL_ROOT_PASS"), strings.TrimSpace(os.Getenv("GAMEC_REAL_MYIP"))
	nodePort := os.Getenv("GAMEC_REAL_PORT")
	pin := os.Getenv("GAMEC_REAL_PIN")
	data := os.Getenv("GAMEC_REAL_DATA")

	v, err := vault.Open(data + "/vault.json")
	if err != nil {
		t.Fatal(err)
	}
	pp, _ := os.ReadFile(os.Getenv("PANEL_PASSPHRASE_FILE"))
	if err := v.Unseal(strings.TrimSpace(string(pp))); err != nil {
		t.Fatal(err)
	}
	pemKey, _, _ := v.Get("ssh/panel_key")
	signer, err := sshx.ParseSigner(pemKey)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := sshx.PublicLine(signer, "gamec-panel")

	root, err := ssh.Dial("tcp", host+":22", &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password(rootPass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	sh := func(cmd, stdin string) string {
		s, err := root.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		s.Stdin = strings.NewReader(stdin)
		out, err := s.CombinedOutput(cmd)
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
		return string(out)
	}

	script, err := PrepareJumpScript(pubLine, []string{host + ":22", host + ":" + nodePort}, myIP)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(sh("bash -s", script))

	fp := strings.TrimSpace(sh("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}'", ""))
	jump := sshx.NewJump(sshx.Target{Addr: host + ":22", User: "gamec-jump", HostKey: fp, Signer: signer, Timeout: 15 * time.Second})
	defer jump.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. the jump account runs nothing
	if c, err := sshx.Dial(sshx.Target{Addr: host + ":22", User: "gamec-jump", HostKey: fp, Signer: signer, Timeout: 10 * time.Second}); err == nil {
		if res, err := c.Run(ctx, "id", nil); err == nil && strings.Contains(res.Stdout, "uid=") {
			t.Fatalf("the jump account ran a command: %q", res.Stdout)
		}
		c.Close()
	}

	// 2. a real probe through the jump succeeds, and while a connection is held the node sees the jump host
	held, err := jump.DialContext(ctx, "tcp", net.JoinHostPort(host, nodePort))
	if err != nil {
		t.Fatalf("dial the node through the jump: %v", err)
	}
	peers := sh("ss -tn state established '( sport = :"+nodePort+" )'", "")
	held.Close()
	t.Logf("node-side connections:\n%s", peers)
	if myIP != "" && strings.Contains(peers, myIP) {
		t.Fatalf("the node saw this machine (%s)", myIP)
	}
	r := engine.RealProber{Dial: jump.DialContext, Timeout: 10 * time.Second}.Probe(ctx, nodeFor(host, nodePort, pin))
	if !r.OK {
		t.Fatalf("probe through the jump failed: %+v", r)
	}

	// 3. nothing outside the allow-list is reachable
	for _, bad := range []string{host + ":9101", "1.1.1.1:443", "127.0.0.1:22"} {
		if c, err := jump.DialContext(ctx, "tcp", bad); err == nil {
			c.Close()
			t.Errorf("the jump forwarded to %s, which is not allowed", bad)
		}
	}

	// 4. a wrong host key means nothing is sent, and there is no direct fallback
	bad := sshx.NewJump(sshx.Target{Addr: host + ":22", User: "gamec-jump", HostKey: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Signer: signer, Timeout: 10 * time.Second})
	defer bad.Close()
	if c, err := bad.DialContext(ctx, "tcp", net.JoinHostPort(host, nodePort)); err == nil {
		c.Close()
		t.Fatal("connected through a jump host whose key did not match")
	}
}

func nodeFor(host, port, pin string) store.Node {
	p, _ := strconv.Atoi(port)
	return store.Node{ID: "jt", Name: "jt", Host: host, Port: p, Pin: pin}
}
