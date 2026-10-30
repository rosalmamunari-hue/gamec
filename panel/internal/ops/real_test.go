package ops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"gamec/panel/internal/engine"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
	"gamec/panel/internal/vault"
)

// TestRealServer drives a real server over real SSH with a real systemd service. It only runs when
// GAMEC_REAL_HOST is set (see docs/PANEL.md); it needs a test instance of the edge service on that server
// (unit gamec-edge-sshtest) and the server prepared with the script from the panel.
func TestRealServer(t *testing.T) {
	host := os.Getenv("GAMEC_REAL_HOST")
	if host == "" {
		t.Skip("GAMEC_REAL_HOST not set")
	}
	port, _ := strconv.Atoi(os.Getenv("GAMEC_REAL_PORT"))
	hostKey := os.Getenv("GAMEC_REAL_HOSTKEY")
	read := func(env string) []byte {
		b, err := os.ReadFile(os.Getenv(env))
		if err != nil {
			t.Fatalf("%s: %v", env, err)
		}
		return b
	}
	sha := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	binA, binB, binBroken := read("GAMEC_REAL_BIN_A"), read("GAMEC_REAL_BIN_B"), read("GAMEC_REAL_BIN_BROKEN")

	v, err := vault.Open(os.Getenv("GAMEC_REAL_DATA") + "/vault.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unseal(strings.TrimSpace(string(read("PANEL_PASSPHRASE_FILE")))); err != nil {
		t.Fatal(err)
	}
	pemKey, ok, _ := v.Get("ssh/panel_key")
	if !ok {
		t.Fatal("no panel SSH key in the vault")
	}
	signer, err := sshx.ParseSigner(pemKey)
	if err != nil {
		t.Fatal(err)
	}

	node := store.Node{ID: "abcd1234", ClusterID: "c", Name: "sshtest", Host: host, Port: port, Pin: os.Getenv("GAMEC_REAL_PIN"),
		SSHUser: "gamec-ops", SSHPort: 22, Unit: "gamec-edge-sshtest", HostKey: hostKey}
	prober := engine.RealProber{Timeout: 6 * time.Second, Hold: 500 * time.Millisecond}
	o := &Ops{
		Open: func(ctx context.Context, n store.Node) (Runner, error) {
			c, err := sshx.Dial(sshx.Target{Addr: n.SSHAddr(), User: n.SSHUser, HostKey: n.HostKey, Signer: signer, Timeout: 10 * time.Second})
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		Probe:         func(ctx context.Context, n store.Node) engine.ProbeResult { return prober.Probe(ctx, n) },
		HealthyWithin: 40 * time.Second, Poll: 2 * time.Second,
	}
	ctx := context.Background()
	step := func(s string) { t.Log("== " + s) }
	healthy := func() engine.ProbeResult { return prober.Probe(ctx, node) }

	step("the host key the server shows is the one that was confirmed")
	fp, typ, err := sshx.FetchHostKey(node.SSHAddr(), 10*time.Second)
	if err != nil || fp != hostKey {
		t.Fatalf("fetched %s (%s), confirmed %s, err %v", fp, typ, hostKey, err)
	}

	step("status of the test instance")
	st, err := o.Status(ctx, node)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("status: %+v", st)
	if st.Active != "active" || st.SHA256 != sha(binA) || st.PID == 0 {
		t.Fatalf("expected the test instance running version A (%s)", sha(binA)[:12])
	}
	if r := healthy(); !r.OK {
		t.Fatalf("the test instance is not healthy from here: %+v", r)
	}

	step("logs")
	lg, err := o.Logs(ctx, node, 20)
	if err != nil || strings.TrimSpace(lg) == "" {
		t.Fatalf("logs: %q %v", lg, err)
	}
	t.Logf("last log line: %s", lastLine(lg))

	step("restart")
	if st, err := o.Control(ctx, node, "restart"); err != nil || st.Active != "active" {
		t.Fatalf("%+v %v", st, err)
	}

	step("stop for 10 seconds: it must be down, then come back by itself")
	t0 := time.Now()
	if err := o.StopFor(ctx, node, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if st, _ := o.Status(ctx, node); st.Active == "active" {
		t.Fatalf("still active right after stopping: %+v", st)
	}
	if r := healthy(); r.OK {
		t.Fatal("a stopped node passed its checks")
	}
	for {
		if st, err := o.Status(ctx, node); err == nil && st.Active == "active" {
			break
		}
		if time.Since(t0) > 40*time.Second {
			t.Fatal("the node did not start again by itself")
		}
		time.Sleep(time.Second)
	}
	t.Logf("it was down for about %s and came back without the panel doing anything", time.Since(t0).Round(time.Second))
	waitHealthy(t, healthy)

	step("upgrade A -> B (the v0.1.0 release)")
	res, err := o.Upgrade(ctx, node, Binary{Data: binB, SHA256: sha(binB), Label: "v0.1.0"})
	if err != nil || !res.Installed {
		t.Fatalf("%+v %v", res, err)
	}
	st, _ = o.Status(ctx, node)
	if st.SHA256 != sha(binB) || !st.HasBackup {
		t.Fatalf("after the upgrade: %+v", st)
	}
	waitHealthy(t, healthy)

	step("the same version again changes nothing")
	if res, err := o.Upgrade(ctx, node, Binary{Data: binB, SHA256: sha(binB)}); err != nil || !res.Already {
		t.Fatalf("%+v %v", res, err)
	}

	step("upgrade to a broken version: it must be rolled back and the node must still serve")
	res, err = o.Upgrade(ctx, node, Binary{Data: binBroken, SHA256: sha(binBroken), Label: "broken"})
	if err == nil || !res.RolledBack {
		t.Fatalf("a broken version was not rolled back: %+v %v", res, err)
	}
	t.Logf("result: %s", res)
	st, _ = o.Status(ctx, node)
	if st.SHA256 != sha(binB) || st.Active != "active" {
		t.Fatalf("after the rollback: %+v", st)
	}
	waitHealthy(t, healthy)

	step("security: what the panel's account cannot do")
	c, err := sshx.Dial(sshx.Target{Addr: node.SSHAddr(), User: node.SSHUser, HostKey: hostKey, Signer: signer, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, cmd := range []string{
		"sudo -n /bin/ls /root",
		"sudo -n /bin/sh -c id",
		"sudo -n /usr/bin/id",
		"sudo -n /usr/local/sbin/gamec-nodectl -unit sshd status",
		"sudo -n /usr/local/sbin/gamec-nodectl -unit 'gamec-edge;id' status",
		"sudo -n /usr/local/sbin/gamec-nodectl -unit gamec-edge-sshtest install -sha256 " + strings.Repeat("0", 64),
		"cat /etc/shadow",
		"cat /opt/gamec-edge-sshtest/key.pem",
	} {
		r, err := c.Run(ctx, cmd, nil)
		if err != nil || r.Exit == 0 {
			t.Errorf("this should have been refused but was not: %q -> exit %d err %v out %q", cmd, r.Exit, err, r.Stdout)
		}
	}
	if st, _ := o.Status(ctx, node); st.SHA256 != sha(binB) {
		t.Fatal("a refused command changed the installed program")
	}

	step("a wrong host key is refused before anything is sent")
	bad := node
	bad.HostKey = "SHA256:" + strings.Repeat("A", 43)
	if _, err := o.Status(ctx, bad); err == nil || !errors.Is(err, sshx.ErrHostKeyChanged) {
		t.Fatalf("got %v", err)
	}

	step("a stranger's key does not get in")
	other, _, _ := sshx.GenerateKey("stranger")
	strangerSigner, _ := sshx.ParseSigner(other)
	if _, err := sshx.Dial(sshx.Target{Addr: node.SSHAddr(), User: node.SSHUser, HostKey: hostKey, Signer: strangerSigner, Timeout: 10 * time.Second}); err == nil {
		t.Fatal("an unknown key logged in")
	}

	step("put version A back, as it was")
	if res, err := o.Upgrade(ctx, node, Binary{Data: binA, SHA256: sha(binA), Label: "A"}); err != nil || !res.Installed {
		t.Fatalf("%+v %v", res, err)
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func waitHealthy(t *testing.T, probe func() engine.ProbeResult) {
	t.Helper()
	var r engine.ProbeResult
	for i := 0; i < 15; i++ {
		if r = probe(); r.OK {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("the node did not become healthy: %+v", r)
}
