package ops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"gamec/panel/internal/engine"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

func bin(marker string) Binary {
	b := make([]byte, 1<<20+16)
	copy(b, "\x7fELF")
	copy(b[64:], marker)
	h := sha256.Sum256(b)
	return Binary{Data: b, SHA256: hex.EncodeToString(h[:]), Label: marker}
}

// fakeNode behaves like a server running nodectl.
type fakeNode struct {
	mu          sync.Mutex
	sha, backup string
	staged      []byte
	active      string
	cmds        []string
	installExit int  // 3 simulates "did not stay up, rolled back by nodectl"
	healthy     bool // what the panel's probe will see
	failOpen    error
	opens       int
	rolledBack  bool
}

func (f *fakeNode) Open(context.Context, store.Node) (Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	if f.failOpen != nil {
		return nil, f.failOpen
	}
	return f, nil
}
func (f *fakeNode) Close() error { return nil }

func (f *fakeNode) Run(_ context.Context, cmd string, stdin io.Reader) (sshx.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, cmd)
	switch {
	case strings.HasPrefix(cmd, "cat > "+StagingDir+"/"):
		f.staged, _ = io.ReadAll(stdin)
		return sshx.Result{}, nil
	case strings.Contains(cmd, " status"):
		st := NodeStatus{Unit: "gamec-edge", Active: f.active, SHA256: f.sha, HasBackup: f.backup != ""}
		b, _ := json.Marshal(st)
		return sshx.Result{Stdout: string(b)}, nil
	case strings.Contains(cmd, " install -sha256 "):
		want := cmd[strings.LastIndex(cmd, " ")+1:]
		h := sha256.Sum256(f.staged)
		if hex.EncodeToString(h[:]) != want {
			return sshx.Result{Exit: 1, Stderr: "checksum mismatch\n"}, nil
		}
		if f.installExit == 3 {
			return sshx.Result{Exit: 3, Stderr: "the new version did not stay running; the previous version was restored\n"}, nil
		}
		f.backup, f.sha = f.sha, want
		return sshx.Result{Stdout: "{}"}, nil
	case strings.HasSuffix(cmd, " rollback"):
		if f.backup == "" {
			return sshx.Result{Exit: 1, Stderr: "there is no previous version to go back to\n"}, nil
		}
		f.sha, f.backup = f.backup, f.sha
		f.rolledBack = true
		return sshx.Result{Stdout: "{}"}, nil
	case strings.Contains(cmd, " logs -n "):
		return sshx.Result{Stdout: "log line\n"}, nil
	case strings.HasSuffix(cmd, " start"), strings.HasSuffix(cmd, " stop"), strings.HasSuffix(cmd, " restart"):
		verb := cmd[strings.LastIndex(cmd, " ")+1:]
		f.active = map[string]string{"start": "active", "restart": "active", "stop": "inactive"}[verb]
		return sshx.Result{Stdout: `{"unit":"gamec-edge","active":"` + f.active + `"}`}, nil
	case strings.Contains(cmd, " stop-for "):
		f.active = "inactive"
		return sshx.Result{Stdout: "stopped\n"}, nil
	}
	return sshx.Result{Exit: 2, Stderr: "unknown command\n"}, nil
}

func (f *fakeNode) probe(context.Context, store.Node) engine.ProbeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.healthy {
		return engine.ProbeResult{OK: true}
	}
	return engine.ProbeResult{Err: "token: no answer"}
}

func (f *fakeNode) ops() *Ops {
	return &Ops{Open: f.Open, Probe: f.probe, HealthyWithin: 80 * time.Millisecond, Poll: 10 * time.Millisecond}
}

func newFake(sha string) *fakeNode { return &fakeNode{sha: sha, active: "active", healthy: true} }

func nodeWithSSH(host string) store.Node {
	return store.Node{ID: "abcd1234", ClusterID: "c", Name: "n", Host: host, Port: 30800, SSHUser: "gamec-ops"}
}

var allowed = regexp.MustCompile(`^(sudo /usr/local/sbin/gamec-nodectl -unit gamec-edge[a-z0-9-]* [A-Za-z0-9._: =-]+|cat > /var/lib/gamec-ops/incoming/gamec-edge[a-z0-9-]*\.edge\.new)$`)

func assertOnlyAllowedCommands(t *testing.T, f *fakeNode) {
	t.Helper()
	for _, c := range f.cmds {
		if !allowed.MatchString(c) {
			t.Errorf("a command outside the whitelist was sent: %q", c)
		}
	}
}

// ---------------------------------------------------------------- command safety

func TestCommandsAreBuiltFromAFixedTemplate(t *testing.T) {
	c, err := command("gamec-edge", "logs", "-n", "100")
	if err != nil || c != "sudo /usr/local/sbin/gamec-nodectl -unit gamec-edge logs -n 100" {
		t.Fatalf("%q %v", c, err)
	}
	for _, bad := range []string{"; rm -rf /", "a b", "$(id)", "`id`", "a|b", "a&b", "a>b", "a\nb", "'a'", `"a"`, "", "a*", "a\\b"} {
		if _, err := command("gamec-edge", bad); err == nil {
			t.Errorf("argument %q allowed", bad)
		}
	}
	for _, bad := range []string{"sshd", "gamec-edge;id", "gamec-edge ", "../gamec-edge", "", "GAMEC-EDGE"} {
		if _, err := command(bad, "status"); err == nil {
			t.Errorf("unit %q allowed", bad)
		}
	}
}

func TestNothingTypedByAUserReachesTheShell(t *testing.T) {
	f := newFake("aaa")
	n := nodeWithSSH("1.2.3.4")
	n.Unit = "gamec-edge; id"
	if _, err := f.ops().Status(context.Background(), n); err == nil {
		t.Fatal("a hostile service name was accepted")
	}
	if f.opens != 0 || len(f.cmds) != 0 {
		t.Fatal("something was sent for a hostile service name")
	}
	if _, err := f.ops().Control(context.Background(), nodeWithSSH("1.2.3.4"), "restart; id"); err == nil {
		t.Fatal("a hostile verb was accepted")
	}
	if _, err := f.ops().Logs(context.Background(), nodeWithSSH("1.2.3.4"), 100000); err == nil {
		t.Fatal("an absurd line count was accepted")
	}
	if len(f.cmds) != 0 {
		t.Fatalf("commands were sent: %v", f.cmds)
	}
}

func TestANodeWithoutAnSSHAccountIsNotContacted(t *testing.T) {
	f := newFake("aaa")
	n := nodeWithSSH("1.2.3.4")
	n.SSHUser = ""
	if _, err := f.ops().Status(context.Background(), n); err == nil || f.opens != 0 {
		t.Fatalf("%v opens=%d", err, f.opens)
	}
}

// ---------------------------------------------------------------- reading and controlling

func TestStatusLogsAndControl(t *testing.T) {
	f := newFake("abc123")
	o, n := f.ops(), nodeWithSSH("1.2.3.4")
	st, err := o.Status(context.Background(), n)
	if err != nil || st.SHA256 != "abc123" || st.Active != "active" {
		t.Fatalf("%+v %v", st, err)
	}
	if lg, err := o.Logs(context.Background(), n, 50); err != nil || lg != "log line\n" {
		t.Fatalf("%q %v", lg, err)
	}
	if st, err := o.Control(context.Background(), n, "stop"); err != nil || st.Active != "inactive" {
		t.Fatalf("%+v %v", st, err)
	}
	if st, err := o.Control(context.Background(), n, "start"); err != nil || st.Active != "active" {
		t.Fatalf("%+v %v", st, err)
	}
	assertOnlyAllowedCommands(t, f)
}

func TestStopForPassesWholeSecondsAndRefusesSillyDurations(t *testing.T) {
	f := newFake("a")
	o, n := f.ops(), nodeWithSSH("1.2.3.4")
	if err := o.StopFor(context.Background(), n, 90*time.Second); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(f.cmds[len(f.cmds)-1], "stop-for -seconds 90") {
		t.Fatalf("%v", f.cmds)
	}
	for _, d := range []time.Duration{0, 3 * time.Second, 2 * time.Hour, -time.Minute} {
		if err := o.StopFor(context.Background(), n, d); err == nil {
			t.Errorf("%v accepted", d)
		}
	}
}

func TestNonZeroExitBecomesAnErrorWithTheNodesMessage(t *testing.T) {
	f := newFake("a")
	n := nodeWithSSH("1.2.3.4")
	_, err := f.ops().Control(context.Background(), n, "restart")
	if err != nil {
		t.Fatal(err)
	}
	f.failOpen = errors.New("ssh: handshake failed: host key differs")
	if _, err := f.ops().Status(context.Background(), n); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("%v", err)
	}
}

// ---------------------------------------------------------------- upgrading

func TestUpgradeSendsVerifiesInstallsAndChecksHealth(t *testing.T) {
	f := newFake("oldsha")
	b := bin("v2")
	res, err := f.ops().Upgrade(context.Background(), nodeWithSSH("1.2.3.4"), b)
	if err != nil || !res.Installed || res.RolledBack || res.After != b.SHA256 || res.Before != "oldsha" {
		t.Fatalf("%+v %v", res, err)
	}
	if !bytes.Equal(f.staged, b.Data) {
		t.Fatal("the node did not receive the exact program")
	}
	assertOnlyAllowedCommands(t, f)
	// order: read state, send, install, read state again
	var seq []string
	for _, c := range f.cmds {
		switch {
		case strings.HasPrefix(c, "cat >"):
			seq = append(seq, "send")
		case strings.Contains(c, " install "):
			seq = append(seq, "install")
		case strings.HasSuffix(c, " status"):
			seq = append(seq, "status")
		}
	}
	if strings.Join(seq, ",") != "status,send,install,status" {
		t.Fatalf("order: %v", seq)
	}
}

func TestUpgradeToTheSameVersionDoesNothing(t *testing.T) {
	b := bin("v2")
	f := newFake(b.SHA256)
	res, err := f.ops().Upgrade(context.Background(), nodeWithSSH("1.2.3.4"), b)
	if err != nil || !res.Already || res.Installed {
		t.Fatalf("%+v %v", res, err)
	}
	for _, c := range f.cmds {
		if strings.HasPrefix(c, "cat >") || strings.Contains(c, " install ") {
			t.Fatalf("it re-sent a version that is already running: %q", c)
		}
	}
}

func TestACorruptedProgramIsNeverSent(t *testing.T) {
	f := newFake("a")
	b := bin("v2")
	b.Data[500] ^= 1
	if _, err := f.ops().Upgrade(context.Background(), nodeWithSSH("1.2.3.4"), b); err == nil {
		t.Fatal("a program that does not match its checksum was accepted")
	}
	if f.opens != 0 {
		t.Fatal("the panel connected to a node although it was holding a bad program")
	}
	small := Binary{Data: []byte("tiny"), SHA256: func() string { h := sha256.Sum256([]byte("tiny")); return hex.EncodeToString(h[:]) }()}
	if _, err := f.ops().Upgrade(context.Background(), nodeWithSSH("1.2.3.4"), small); err == nil {
		t.Fatal("a tiny file was accepted")
	}
}

func TestIfTheNodeCannotKeepTheNewVersionRunningItReportsTheRollback(t *testing.T) {
	f := newFake("oldsha")
	f.installExit = 3
	res, err := f.ops().Upgrade(context.Background(), nodeWithSSH("1.2.3.4"), bin("v2-broken"))
	if err == nil || !res.RolledBack || res.Installed {
		t.Fatalf("%+v %v", res, err)
	}
	if f.sha != "oldsha" {
		t.Fatal("the node did not keep its previous version")
	}
}

func TestAVersionThatRunsButFailsTheChecksIsRolledBackByThePanel(t *testing.T) {
	f := newFake("oldsha")
	f.healthy = false // the service is up, but players could not use it
	res, err := f.ops().Upgrade(context.Background(), nodeWithSSH("1.2.3.4"), bin("v2-subtly-broken"))
	if err == nil || !res.RolledBack || res.Installed {
		t.Fatalf("%+v %v", res, err)
	}
	if !f.rolledBack || f.sha != "oldsha" {
		t.Fatalf("the previous version was not restored: sha=%s", f.sha)
	}
	if !strings.Contains(res.Detail, "token: no answer") {
		t.Fatalf("the reason should be in the message: %q", res.Detail)
	}
}

func TestAnUpgradeWaitsForANodeThatIsSlowToComeUp(t *testing.T) {
	f := newFake("oldsha")
	f.healthy = false
	go func() { time.Sleep(30 * time.Millisecond); f.mu.Lock(); f.healthy = true; f.mu.Unlock() }()
	res, err := f.ops().Upgrade(context.Background(), nodeWithSSH("1.2.3.4"), bin("v2-slow-start"))
	if err != nil || !res.Installed || f.rolledBack {
		t.Fatalf("a node that was ready 30 ms late must not be rolled back: %+v %v", res, err)
	}
}

// ---------------------------------------------------------------- rolling upgrade

func TestRollingUpgradeGoesOneByOneAndStopsAtTheFirstFailure(t *testing.T) {
	a, b, c := newFake("old"), newFake("old"), newFake("old")
	b.healthy = false // the second node fails its checks after the upgrade
	nodes := map[string]*fakeNode{"10.0.0.1": a, "10.0.0.2": b, "10.0.0.3": c}
	o := &Ops{HealthyWithin: 60 * time.Millisecond, Poll: 10 * time.Millisecond,
		Open:  func(ctx context.Context, n store.Node) (Runner, error) { return nodes[n.Host].Open(ctx, n) },
		Probe: func(ctx context.Context, n store.Node) engine.ProbeResult { return nodes[n.Host].probe(ctx, n) }}
	var say []string
	results, err := o.RollingUpgrade(context.Background(),
		[]store.Node{nodeWithSSH("10.0.0.1"), nodeWithSSH("10.0.0.2"), nodeWithSSH("10.0.0.3")},
		bin("v2"), nil, func(s string) { say = append(say, s) })
	if err == nil || !strings.Contains(err.Error(), "remaining nodes were not touched") {
		t.Fatalf("%v", err)
	}
	if len(results) != 2 || !results[0].Installed || !results[1].RolledBack {
		t.Fatalf("%+v", results)
	}
	if c.opens != 0 || c.sha != "old" {
		t.Fatal("a bad version reached the third node")
	}
	if b.sha != "old" {
		t.Fatal("the failing node was left on the bad version")
	}
}

func TestRollingUpgradeGuardCanRefuseToTakeTheLastNodeDown(t *testing.T) {
	a := newFake("old")
	o := a.ops()
	_, err := o.RollingUpgrade(context.Background(), []store.Node{nodeWithSSH("10.0.0.1")}, bin("v2"),
		func(store.Node) error { return errors.New("it is the only healthy node of the cluster") }, nil)
	if err == nil || !strings.Contains(err.Error(), "only healthy node") || a.opens != 0 {
		t.Fatalf("%v opens=%d", err, a.opens)
	}
}

func TestRollingUpgradeOfEveryNodeSucceeds(t *testing.T) {
	a, b := newFake("old"), newFake("old")
	nodes := map[string]*fakeNode{"10.0.0.1": a, "10.0.0.2": b}
	o := &Ops{HealthyWithin: 60 * time.Millisecond, Poll: 10 * time.Millisecond,
		Open:  func(ctx context.Context, n store.Node) (Runner, error) { return nodes[n.Host].Open(ctx, n) },
		Probe: func(ctx context.Context, n store.Node) engine.ProbeResult { return nodes[n.Host].probe(ctx, n) }}
	v := bin("v3")
	res, err := o.RollingUpgrade(context.Background(), []store.Node{nodeWithSSH("10.0.0.1"), nodeWithSSH("10.0.0.2")}, v, nil, nil)
	if err != nil || len(res) != 2 || a.sha != v.SHA256 || b.sha != v.SHA256 {
		t.Fatalf("%v %+v", err, res)
	}
}

// ---------------------------------------------------------------- releases

func releaseServer(t *testing.T, asset []byte, sums string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0.1.0/SHA256SUMS.txt":
			io.WriteString(w, sums)
		case "/v0.1.0/edge-linux-amd64":
			w.Write(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestReleaseFetchVerifiesTheChecksumList(t *testing.T) {
	good := bin("release")
	sums := fmt.Sprintf("%s  edge-linux-amd64\n%s  other-thing\n", good.SHA256, strings.Repeat("0", 64))
	srv := releaseServer(t, good.Data, sums)
	r := &Releases{Base: srv.URL}
	got, err := r.Fetch(context.Background(), "v0.1.0", "edge-linux-amd64")
	if err != nil || got.SHA256 != good.SHA256 || !bytes.Equal(got.Data, good.Data) || got.Label != "v0.1.0" {
		t.Fatalf("%v", err)
	}
}

func TestReleaseFetchRefusesATamperedDownload(t *testing.T) {
	good := bin("release")
	evil := append([]byte(nil), good.Data...)
	evil[1000] ^= 1
	srv := releaseServer(t, evil, fmt.Sprintf("%s  edge-linux-amd64\n", good.SHA256))
	if _, err := (&Releases{Base: srv.URL}).Fetch(context.Background(), "v0.1.0", "edge-linux-amd64"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("%v", err)
	}
}

func TestReleaseFetchRefusesWhatTheListDoesNotCover(t *testing.T) {
	good := bin("release")
	srv := releaseServer(t, good.Data, fmt.Sprintf("%s  something-else\n", good.SHA256))
	if _, err := (&Releases{Base: srv.URL}).Fetch(context.Background(), "v0.1.0", "edge-linux-amd64"); err == nil || !strings.Contains(err.Error(), "no checksum") {
		t.Fatalf("%v", err)
	}
}

func TestReleaseFetchRejectsOddTagsAssetsAndPlainHTTP(t *testing.T) {
	srv := releaseServer(t, nil, "")
	r := &Releases{Base: srv.URL}
	for _, tag := range []string{"latest", "v1", "../v0.1.0", "v0.1.0/../../x", "v0.1.0 ", ""} {
		if _, err := r.Fetch(context.Background(), tag, "edge-linux-amd64"); err == nil {
			t.Errorf("tag %q accepted", tag)
		}
	}
	for _, asset := range []string{"../edge", "a b", "", "/etc/passwd"} {
		if _, err := r.Fetch(context.Background(), "v0.1.0", asset); err == nil {
			t.Errorf("asset %q accepted", asset)
		}
	}
	if _, err := (&Releases{Base: "http://example.com/x"}).Fetch(context.Background(), "v0.1.0", "edge-linux-amd64"); err == nil {
		t.Error("plain http to a remote host accepted")
	}
}

func TestReleaseFetchHasASizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "SHA256SUMS.txt") {
			io.WriteString(w, strings.Repeat("0", 64)+"  edge-linux-amd64\n")
			return
		}
		buf := make([]byte, 1<<20)
		for i := 0; i < 101; i++ {
			w.Write(buf)
		}
	}))
	defer srv.Close()
	if _, err := (&Releases{Base: srv.URL}).Fetch(context.Background(), "v0.1.0", "edge-linux-amd64"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("%v", err)
	}
}

// ---------------------------------------------------------------- the preparation script

const goodKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoFKLsSjvzvOeYYYmAZFVzNGaTZ gamec-panel"

func TestPrepareScriptContainsEverythingItShouldAndIsValidShell(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	s, err := PrepareScript(goodKey, "https://github.com/o/r/releases/download/v0.1.0/nodectl-linux-amd64", sha, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`restrict,no-pty,from="203.0.113.9" ssh-ed25519 AAAAC3`, "gamec-ops", "sha256sum -c -", sha,
		"NOPASSWD: /usr/local/sbin/gamec-nodectl", "visudo -c -f", "set -eu",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the script does not contain %q", want)
		}
	}
	if strings.Contains(s, "ALL=(ALL)") || strings.Contains(s, "NOPASSWD: ALL") {
		t.Error("the sudo rule is too broad")
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("the script is not valid shell: %v\n%s", err, out)
		}
	}
}

func TestPrepareScriptRefusesAnythingThatCouldInjectShell(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	url := "https://github.com/o/r/releases/download/v0.1.0/nodectl-linux-amd64"
	cases := map[string][4]string{
		"newline in key":    {goodKey + "\nssh-ed25519 AAAA evil", url, sha, ""},
		"quote in key":      {strings.Replace(goodKey, "gamec-panel", "x'y", 1), url, sha, ""},
		"rsa key":           {"ssh-rsa AAAAB3NzaC1yc2E gamec", url, sha, ""},
		"quote in url":      {goodKey, "https://x.com/a'; rm -rf /; '", sha, ""},
		"http url":          {goodKey, "http://github.com/x", sha, ""},
		"space in url":      {goodKey, "https://x.com/a b", sha, ""},
		"short sha":         {goodKey, url, "abc", ""},
		"command in from":   {goodKey, url, sha, `1.2.3.4",command="/bin/sh`},
		"semicolon in from": {goodKey, url, sha, "1.2.3.4;id"},
	}
	for what, c := range cases {
		if _, err := PrepareScript(c[0], c[1], c[2], c[3]); err == nil {
			t.Errorf("%s accepted", what)
		}
	}
}

func TestUpgradeResultSummaries(t *testing.T) {
	if s := (UpgradeResult{Node: "n", Already: true, After: "abcdef1234567890"}).String(); !strings.Contains(s, "already") {
		t.Error(s)
	}
	if s := (UpgradeResult{Node: "n", RolledBack: true, Detail: "boom"}).String(); !strings.Contains(s, "ROLLED BACK") {
		t.Error(s)
	}
}

func TestPrepareScriptAcceptsAPortInTheDownloadAddress(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	if _, err := PrepareScript(goodKey, "https://127.0.0.1:8443/v0.1.0/nodectl-linux-amd64", sha, ""); err != nil {
		t.Fatalf("a port is legitimate: %v", err)
	}
	if _, err := PrepareScript(goodKey, "https://x.com:80'/a", sha, ""); err == nil {
		t.Fatal("a quote must still be refused")
	}
}
