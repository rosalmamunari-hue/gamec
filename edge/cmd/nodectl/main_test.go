package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeSys struct {
	calls              []string
	active             bool            // what is-active reports
	failOn             map[string]bool // "systemctl restart gamec-edge" -> error
	activeAfterRestart func(restarts int) bool
	restarts           int
	show               string
	logs               string
}

func (f *fakeSys) run(name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.failOn[call] {
		return "boom\n", errors.New("exit status 1")
	}
	switch {
	case name == "systemctl" && args[0] == "is-active":
		if f.active {
			return "active\n", nil
		}
		return "failed\n", errors.New("exit status 3")
	case name == "systemctl" && (args[0] == "restart" || args[0] == "start"):
		f.restarts++
		if f.activeAfterRestart != nil {
			f.active = f.activeAfterRestart(f.restarts)
		} else {
			f.active = true
		}
	case name == "systemctl" && args[0] == "stop":
		f.active = false
	case name == "systemctl" && args[0] == "show":
		return f.show, nil
	case name == "journalctl":
		return f.logs, nil
	}
	return "", nil
}

func (f *fakeSys) called(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func newEnv(t *testing.T) (*env, *fakeSys, *bytes.Buffer) {
	root := t.TempDir()
	for _, d := range []string{"/opt/gamec-edge", "/var/lib/gamec-ops/incoming", "/proc"} {
		os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755)
	}
	sys := &fakeSys{active: true, failOn: map[string]bool{}}
	out := &bytes.Buffer{}
	e := &env{root: root, run: sys.run, now: time.Now, wait: 50 * time.Millisecond, out: out}
	return e, sys, out
}

// elf makes a plausible "binary": ELF magic, big enough, with a marker so versions differ.
func elf(marker string) []byte {
	b := make([]byte, minBinary+10)
	copy(b, "\x7fELF")
	copy(b[100:], marker)
	return b
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (e *env) write(t *testing.T, p string, b []byte) {
	t.Helper()
	full := e.path(p)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func (e *env) read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(e.path(p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------------------------------------------------------------- argument checks

func TestRefusesAnythingThatIsNotAnEdgeUnit(t *testing.T) {
	e, sys, _ := newEnv(t)
	for _, u := range []string{"sshd", "gamec-edge; rm -rf /", "../gamec-edge", "gamec-edge ", "GAMEC-EDGE", "gamec-edge" + strings.Repeat("x", 50), ""} {
		if code, err := e.dispatch([]string{"-unit", u, "restart"}); err == nil || code == 0 {
			t.Errorf("unit %q accepted", u)
		}
	}
	if len(sys.calls) != 0 {
		t.Fatalf("something was run: %v", sys.calls)
	}
	for _, u := range []string{"gamec-edge", "gamec-edge-channel-a", "gamec-edge2"} {
		if _, err := e.dispatch([]string{"-unit", u, "status"}); err != nil {
			t.Errorf("unit %q refused: %v", u, err)
		}
	}
}

func TestUnknownCommandsAndBadNumbersAreRefused(t *testing.T) {
	e, sys, _ := newEnv(t)
	cases := [][]string{
		{}, {"frobnicate"}, {"logs", "-n", "0"}, {"logs", "-n", "501"}, {"logs", "-n", "abc"},
		{"stop-for", "-seconds", "4"}, {"stop-for", "-seconds", "3601"}, {"stop-for"},
		{"install"}, {"install", "-sha256", "short"}, {"install", "-sha256", strings.Repeat("G", 64)},
		{"install", "-sha256", strings.ToUpper(sum(elf("x")))},
	}
	for _, c := range cases {
		if code, err := e.dispatch(c); err == nil || code == 0 {
			t.Errorf("%v accepted", c)
		}
	}
	if sys.called("systemctl stop")+sys.called("systemctl restart")+sys.called("systemd-run") != 0 {
		t.Fatalf("a refused command still acted: %v", sys.calls)
	}
}

// ---------------------------------------------------------------- status and logs

func TestStatusReadsServiceAndProcessFacts(t *testing.T) {
	e, sys, out := newEnv(t)
	sys.show = "ActiveState=active\nSubState=running\nMainPID=4242\nActiveEnterTimestamp=Fri 2026-10-30 14:22:43 CST\n"
	e.write(t, "/proc/4242/status", []byte("Name:\tedge\nVmRSS:\t   9792 kB\n"))
	os.MkdirAll(e.path("/proc/4242/fd"), 0o755)
	for _, n := range []string{"0", "1", "2", "3"} {
		os.WriteFile(e.path("/proc/4242/fd/"+n), nil, 0o600)
	}
	os.MkdirAll(e.path("/proc/4242/task/4242"), 0o755)
	os.MkdirAll(e.path("/proc/4242/task/4243"), 0o755)
	e.write(t, "/proc/loadavg", []byte("0.42 0.30 0.20 1/100 999\n"))
	e.write(t, "/proc/meminfo", []byte("MemTotal: 1652000 kB\nMemAvailable: 1048576 kB\n"))
	bin := elf("v1")
	e.write(t, "/opt/gamec-edge/edge", bin)
	e.write(t, "/opt/gamec-edge/edge.old", elf("v0"))

	if code, err := e.dispatch([]string{"status"}); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	var st Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if st.Active != "active" || st.PID != 4242 || st.RSSKB != 9792 || st.FDs != 4 || st.Threads != 2 ||
		st.Load1 != 0.42 || st.MemAvail != 1024 || st.SHA256 != sum(bin) || !st.HasBackup || st.Unit != "gamec-edge" {
		t.Fatalf("%+v", st)
	}
}

func TestStatusOfAStoppedServiceStillWorks(t *testing.T) {
	e, sys, out := newEnv(t)
	sys.show = "ActiveState=inactive\nSubState=dead\nMainPID=0\nActiveEnterTimestamp=\n"
	if code, err := e.dispatch([]string{"status"}); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	var st Status
	json.Unmarshal(out.Bytes(), &st)
	if st.Active != "inactive" || st.PID != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestLogsAskForExactlyTheRequestedLines(t *testing.T) {
	e, sys, out := newEnv(t)
	sys.logs = "line1\nline2\n"
	if _, err := e.dispatch([]string{"-unit", "gamec-edge-x", "logs", "-n", "20"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "line1\nline2\n" {
		t.Fatalf("%q", out.String())
	}
	if sys.calls[0] != "journalctl -u gamec-edge-x -n 20 --no-pager -o short-iso" {
		t.Fatalf("%v", sys.calls)
	}
}

// ---------------------------------------------------------------- stopping

func TestStopForSetsTheRestartTimerBeforeStopping(t *testing.T) {
	e, sys, _ := newEnv(t)
	if code, err := e.dispatch([]string{"stop-for", "-seconds", "30"}); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	if len(sys.calls) < 2 || !strings.HasPrefix(sys.calls[0], "systemd-run") || !strings.Contains(sys.calls[0], "--on-active=30s") ||
		!strings.HasSuffix(sys.calls[0], "/bin/systemctl start gamec-edge") {
		t.Fatalf("the timer must come first: %v", sys.calls)
	}
	if sys.calls[1] != "systemctl stop gamec-edge" {
		t.Fatalf("%v", sys.calls)
	}
}

func TestIfTheTimerCannotBeSetNothingIsStopped(t *testing.T) {
	e, sys, _ := newEnv(t)
	sys.failOn["systemd-run --quiet --unit=gamec-edge-restore-"+"X"] = true // never matches; use a generic failure below
	e.run = func(name string, args ...string) (string, error) {
		sys.calls = append(sys.calls, name+" "+strings.Join(args, " "))
		if name == "systemd-run" {
			return "no timers\n", errors.New("exit status 1")
		}
		return "", nil
	}
	if code, err := e.dispatch([]string{"stop-for", "-seconds", "30"}); err == nil || code == 0 {
		t.Fatal("should fail")
	}
	for _, c := range sys.calls {
		if strings.HasPrefix(c, "systemctl stop") {
			t.Fatal("stopped the node without a way to bring it back")
		}
	}
}

func TestRestartFailsIfTheServiceDoesNotComeUp(t *testing.T) {
	e, sys, _ := newEnv(t)
	sys.activeAfterRestart = func(int) bool { return false }
	if code, err := e.dispatch([]string{"restart"}); err == nil || code == 0 {
		t.Fatal("a restart that left the service down was reported as fine")
	}
}

// ---------------------------------------------------------------- install and rollback

func stage(t *testing.T, e *env, b []byte) {
	e.write(t, stagedFile("gamec-edge"), b)
}

func TestInstallReplacesTheBinaryKeepsTheOldOneAndRestarts(t *testing.T) {
	e, sys, out := newEnv(t)
	oldBin, newBin := elf("v1"), elf("v2")
	e.write(t, "/opt/gamec-edge/edge", oldBin)
	stage(t, e, newBin)
	sys.show = "ActiveState=active\nSubState=running\nMainPID=0\n"

	if code, err := e.dispatch([]string{"install", "-sha256", sum(newBin)}); err != nil || code != 0 {
		t.Fatalf("%d %v", code, err)
	}
	if sum(e.read(t, "/opt/gamec-edge/edge")) != sum(newBin) {
		t.Fatal("the new binary is not in place")
	}
	if sum(e.read(t, "/opt/gamec-edge/edge.old")) != sum(oldBin) {
		t.Fatal("the previous version was not kept")
	}
	if _, err := os.Stat(e.path(stagedFile("gamec-edge"))); err == nil {
		t.Fatal("the staged file was left behind")
	}
	if sys.called("systemctl restart gamec-edge") != 1 {
		t.Fatalf("%v", sys.calls)
	}
	var st Status
	if json.Unmarshal(out.Bytes(), &st) != nil || st.SHA256 != sum(newBin) {
		t.Fatalf("status after install: %s", out)
	}
}

func TestInstallWithTheWrongChecksumTouchesNothing(t *testing.T) {
	e, sys, _ := newEnv(t)
	oldBin := elf("v1")
	e.write(t, "/opt/gamec-edge/edge", oldBin)
	stage(t, e, elf("v2"))
	code, err := e.dispatch([]string{"install", "-sha256", sum(elf("something else"))})
	if err == nil || code == 0 || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("%d %v", code, err)
	}
	if sum(e.read(t, "/opt/gamec-edge/edge")) != sum(oldBin) {
		t.Fatal("the running binary was replaced by an unverified file")
	}
	if sys.called("systemctl restart") != 0 {
		t.Fatal("restarted although the file was not verified")
	}
}

func TestInstallRefusesFilesThatAreNotPrograms(t *testing.T) {
	e, _, _ := newEnv(t)
	e.write(t, "/opt/gamec-edge/edge", elf("v1"))
	script := append([]byte("#!/bin/sh\necho pwned\n"), make([]byte, minBinary)...)
	stage(t, e, script)
	if _, err := e.dispatch([]string{"install", "-sha256", sum(script)}); err == nil || !strings.Contains(err.Error(), "not an executable") {
		t.Fatalf("a script was accepted: %v", err)
	}
	stage(t, e, []byte("\x7fELFtiny"))
	if _, err := e.dispatch([]string{"install", "-sha256", sum([]byte("\x7fELFtiny"))}); err == nil || !strings.Contains(err.Error(), "plausible") {
		t.Fatalf("a tiny file was accepted: %v", err)
	}
	if _, err := e.dispatch([]string{"install", "-sha256", strings.Repeat("a", 64)}); err == nil || !strings.Contains(err.Error(), "nothing staged") {
		t.Fatalf("%v", err)
	}
}

func TestAVersionThatDoesNotStayUpIsRolledBackAutomatically(t *testing.T) {
	e, sys, _ := newEnv(t)
	oldBin, newBin := elf("v1"), elf("v2-broken")
	e.write(t, "/opt/gamec-edge/edge", oldBin)
	stage(t, e, newBin)
	// the broken version fails to start; once the old one is back, the service runs
	sys.activeAfterRestart = func(n int) bool { return n >= 2 }

	code, err := e.dispatch([]string{"install", "-sha256", sum(newBin)})
	if !errors.Is(err, errRolledBack) || code != 3 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if sum(e.read(t, "/opt/gamec-edge/edge")) != sum(oldBin) {
		t.Fatal("the previous version was not restored")
	}
	if sum(e.read(t, "/opt/gamec-edge/edge.failed")) != sum(newBin) {
		t.Fatal("the failed version should be kept for inspection")
	}
	if sys.called("systemctl restart gamec-edge") != 2 {
		t.Fatalf("expected a restart for the new version and one for the rollback: %v", sys.calls)
	}
}

func TestRollbackCommandSwapsBackToThePreviousVersion(t *testing.T) {
	e, _, _ := newEnv(t)
	v1, v2 := elf("v1"), elf("v2")
	e.write(t, "/opt/gamec-edge/edge", v2)
	e.write(t, "/opt/gamec-edge/edge.old", v1)
	if code, err := e.dispatch([]string{"rollback"}); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	if sum(e.read(t, "/opt/gamec-edge/edge")) != sum(v1) {
		t.Fatal("not rolled back")
	}
	os.Remove(e.path("/opt/gamec-edge/edge.old"))
	if _, err := e.dispatch([]string{"rollback"}); err == nil {
		t.Fatal("rolling back with no previous version must fail")
	}
}

func TestVersion(t *testing.T) {
	e, _, out := newEnv(t)
	if code, err := e.dispatch([]string{"version"}); err != nil || code != 0 || strings.TrimSpace(out.String()) != version {
		t.Fatal(code, err, out.String())
	}
}

// The staging directory belongs to the unprivileged account; a symlink there must not make root read (and
// install) some other file.
func TestAStagedSymlinkIsRefused(t *testing.T) {
	e, sys, _ := newEnv(t)
	e.write(t, "/opt/gamec-edge/edge", elf("v1"))
	other := elf("some other program")
	e.write(t, "/opt/gamec-edge/other", other)
	if err := os.Symlink(e.path("/opt/gamec-edge/other"), e.path(stagedFile("gamec-edge"))); err != nil {
		t.Skipf("cannot make a symlink here: %v", err)
	}
	if _, err := e.dispatch([]string{"install", "-sha256", sum(other)}); err == nil || !strings.Contains(err.Error(), "not a plain file") {
		t.Fatalf("a symlink was followed: %v", err)
	}
	if sys.called("systemctl restart gamec-edge") != 0 || sum(e.read(t, "/opt/gamec-edge/edge")) != sum(elf("v1")) {
		t.Fatal("something was installed")
	}
}

func TestStartingByHandCancelsTheStopForTimer(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		e, sys, _ := newEnv(t)
		if code, err := e.dispatch([]string{"-unit", "gamec-edge-x", verb}); err != nil || code != 0 {
			t.Fatalf("%s: %d %v", verb, code, err)
		}
		if sys.calls[0] != "systemctl stop gamec-edge-x-restore-*.timer" {
			t.Fatalf("%s: the stop-for timers must be dropped first: %v", verb, sys.calls)
		}
	}
}
