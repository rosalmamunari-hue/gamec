// nodectl is the only thing the control panel is allowed to run on a node (through sudo). It does a few fixed
// jobs on one edge service and checks every argument; it never runs anything it was handed.
//
//	gamec-nodectl [-unit gamec-edge] status
//	gamec-nodectl [-unit U] logs [-n 100]
//	gamec-nodectl [-unit U] start | stop | restart
//	gamec-nodectl [-unit U] stop-for -seconds 30      stop now, start again by itself after that long
//	gamec-nodectl [-unit U] install -sha256 HEX       install the staged binary, roll back if it does not run
//	gamec-nodectl [-unit U] rollback
//	gamec-nodectl version
//
// The staged binary is the file the panel uploaded to /var/lib/gamec-ops/incoming/<unit>.edge.new.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const version = "2"

var (
	unitRe = regexp.MustCompile(`^gamec-edge[a-z0-9-]{0,40}$`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	minBinary = 1 << 20   // a real edge node is several MB
	maxBinary = 100 << 20 // and never this big
	maxLogs   = 500
)

// runner runs a fixed program with fixed arguments. Tests replace it.
type runner func(name string, args ...string) (string, error)

func realRunner(name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

type env struct {
	root string // "/" in real use; a temp directory in tests
	run  runner
	now  func() time.Time
	wait time.Duration // how long a restart may take before it counts as failed
	out  io.Writer
}

func (e *env) path(p string) string { return filepath.Join(e.root, filepath.FromSlash(p)) }

func installDir(unit string) string { return "/opt/" + unit }
func stagedFile(unit string) string { return "/var/lib/gamec-ops/incoming/" + unit + ".edge.new" }

// ---------------------------------------------------------------- status

type Status struct {
	Unit      string    `json:"unit"`
	Active    string    `json:"active"`
	Sub       string    `json:"sub"`
	PID       int       `json:"pid"`
	Since     string    `json:"since"`
	RSSKB     int       `json:"rss_kb"`
	FDs       int       `json:"fds"`
	Threads   int       `json:"threads"`
	SHA256    string    `json:"binary_sha256"`
	HasBackup bool      `json:"has_backup"`
	Load1     float64   `json:"load1"`
	MemAvail  int       `json:"mem_available_mb"`
	At        time.Time `json:"at"`
	Version   string    `json:"nodectl_version"`
}

func parseShow(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func (e *env) status(unit string) (Status, error) {
	st := Status{Unit: unit, At: e.now().UTC(), Version: version}
	out, err := e.run("systemctl", "show", "-p", "ActiveState", "-p", "SubState", "-p", "MainPID", "-p", "ActiveEnterTimestamp", unit)
	if err != nil && out == "" {
		return st, fmt.Errorf("systemctl: %w", err)
	}
	m := parseShow(out)
	st.Active, st.Sub, st.Since = m["ActiveState"], m["SubState"], m["ActiveEnterTimestamp"]
	st.PID, _ = strconv.Atoi(m["MainPID"])
	if st.PID > 0 {
		if b, err := os.ReadFile(e.path(fmt.Sprintf("/proc/%d/status", st.PID))); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
					st.RSSKB, _ = strconv.Atoi(strings.Fields(v)[0])
				}
			}
		}
		if ents, err := os.ReadDir(e.path(fmt.Sprintf("/proc/%d/fd", st.PID))); err == nil {
			st.FDs = len(ents)
		}
		if ents, err := os.ReadDir(e.path(fmt.Sprintf("/proc/%d/task", st.PID))); err == nil {
			st.Threads = len(ents)
		}
	}
	if sum, err := fileSHA(e.path(installDir(unit) + "/edge")); err == nil {
		st.SHA256 = sum
	}
	_, err = os.Stat(e.path(installDir(unit) + "/edge.old"))
	st.HasBackup = err == nil
	if b, err := os.ReadFile(e.path("/proc/loadavg")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			st.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile(e.path("/proc/meminfo")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
				kb, _ := strconv.Atoi(strings.Fields(v)[0])
				st.MemAvail = kb / 1024
			}
		}
	}
	return st, nil
}

func fileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------------------------------------------------------------- start, stop, restart

func (e *env) isActive(unit string) bool {
	out, _ := e.run("systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

// waitActive reports whether the unit is active and stays active for a moment (a crash loop is "active" for
// an instant between restarts).
func (e *env) waitActive(unit string) bool {
	deadline := e.now().Add(e.wait)
	for {
		if e.isActive(unit) {
			time.Sleep(e.wait / 5)
			return e.isActive(unit)
		}
		if e.now().After(deadline) {
			return false
		}
		time.Sleep(e.wait / 20)
	}
}

func (e *env) control(unit, verb string) error {
	if out, err := e.run("systemctl", verb, unit); err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", verb, err, strings.TrimSpace(out))
	}
	if verb != "stop" && !e.waitActive(unit) {
		return fmt.Errorf("%s did not become active after %s", unit, verb)
	}
	return nil
}

// cancelRestore drops the timers that stop-for left behind, so a start, stop or restart by hand is the last
// word: without this a node stopped by hand would still be started again when such a timer fires.
func (e *env) cancelRestore(unit string) {
	e.run("systemctl", "stop", unit+"-restore-*.timer")
}

func (e *env) stopFor(unit string, seconds int) error {
	if seconds < 5 || seconds > 3600 {
		return errors.New("seconds must be between 5 and 3600")
	}
	// The timer is set first: if anything after this fails the node still comes back by itself.
	timer := fmt.Sprintf("%s-restore-%d", unit, e.now().Unix())
	if out, err := e.run("systemd-run", "--quiet", "--unit="+timer, fmt.Sprintf("--on-active=%ds", seconds), "/bin/systemctl", "start", unit); err != nil {
		return fmt.Errorf("could not set the restart timer, so nothing was stopped: %v: %s", err, strings.TrimSpace(out))
	}
	return e.control(unit, "stop")
}

// ---------------------------------------------------------------- install and rollback

var errRolledBack = errors.New("the new version did not stay running; the previous version was restored")

func (e *env) install(unit, wantSHA string) error {
	if !shaRe.MatchString(wantSHA) {
		return errors.New("-sha256 must be 64 lowercase hex characters")
	}
	staged := e.path(stagedFile(unit))
	// Read once and check, hash and install those same bytes: the staging directory belongs to the
	// unprivileged account, which could otherwise swap the file (or put a symlink there) in between.
	data, err := readStaged(staged)
	if err != nil {
		os.Remove(staged)
		return err
	}
	if len(data) < minBinary || len(data) > maxBinary {
		os.Remove(staged)
		return fmt.Errorf("the staged file is %d bytes, which is not a plausible edge node", len(data))
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		os.Remove(staged)
		return fmt.Errorf("checksum mismatch: staged file is %s, expected %s", got, wantSHA)
	}
	if string(data[:4]) != "\x7fELF" {
		os.Remove(staged)
		return errors.New("the staged file is not an executable program")
	}

	dir := e.path(installDir(unit))
	cur, old, tmp := filepath.Join(dir, "edge"), filepath.Join(dir, "edge.old"), filepath.Join(dir, "edge.new")
	if _, err := os.Stat(cur); err == nil {
		if err := copyFile(cur, old, 0o755); err != nil {
			return fmt.Errorf("could not keep the previous version: %w", err)
		}
	}
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, cur); err != nil {
		return err
	}
	os.Remove(staged)
	if err := e.control(unit, "restart"); err != nil {
		if rerr := e.restoreOld(unit); rerr != nil {
			return fmt.Errorf("%v; and restoring the previous version failed too: %v", err, rerr)
		}
		return errRolledBack
	}
	return nil
}

func (e *env) restoreOld(unit string) error {
	dir := e.path(installDir(unit))
	old, cur := filepath.Join(dir, "edge.old"), filepath.Join(dir, "edge")
	if _, err := os.Stat(old); err != nil {
		return errors.New("there is no previous version to go back to")
	}
	if err := copyFile(cur, filepath.Join(dir, "edge.failed"), 0o755); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := copyFile(old, filepath.Join(dir, "edge.restore"), 0o755); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(dir, "edge.restore"), cur); err != nil {
		return err
	}
	return e.control(unit, "restart")
}

// readStaged reads the staged program, refusing anything but a plain file that stayed the same file
// while it was opened (a symlink swapped in after the check would open something else).
func readStaged(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("nothing staged")
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("the staged file is not a plain file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, errors.New("the staged file changed while it was being read")
	}
	return io.ReadAll(io.LimitReader(f, maxBinary+1))
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ---------------------------------------------------------------- command line

func (e *env) dispatch(args []string) (int, error) {
	fs := flag.NewFlagSet("nodectl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	unit := fs.String("unit", "gamec-edge", "systemd unit of the edge service")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return 2, errors.New("a command is required")
	}
	cmd, cargs := rest[0], rest[1:]
	if cmd == "version" {
		fmt.Fprintln(e.out, version)
		return 0, nil
	}
	if !unitRe.MatchString(*unit) {
		return 2, fmt.Errorf("unit %q is not an edge unit name", *unit)
	}
	sub := flag.NewFlagSet(cmd, flag.ContinueOnError)
	sub.SetOutput(io.Discard)
	switch cmd {
	case "status":
		st, err := e.status(*unit)
		if err != nil {
			return 1, err
		}
		return 0, json.NewEncoder(e.out).Encode(st)
	case "logs":
		n := sub.Int("n", 100, "lines")
		if err := sub.Parse(cargs); err != nil {
			return 2, err
		}
		if *n < 1 || *n > maxLogs {
			return 2, fmt.Errorf("-n must be between 1 and %d", maxLogs)
		}
		out, err := e.run("journalctl", "-u", *unit, "-n", strconv.Itoa(*n), "--no-pager", "-o", "short-iso")
		fmt.Fprint(e.out, out)
		if err != nil && out == "" {
			return 1, err
		}
		return 0, nil
	case "start", "stop", "restart":
		e.cancelRestore(*unit)
		if err := e.control(*unit, cmd); err != nil {
			return 1, err
		}
		return 0, e.printStatus(*unit)
	case "stop-for":
		sec := sub.Int("seconds", 0, "seconds")
		if err := sub.Parse(cargs); err != nil {
			return 2, err
		}
		if err := e.stopFor(*unit, *sec); err != nil {
			return 1, err
		}
		fmt.Fprintf(e.out, "stopped; it starts again by itself in %d seconds\n", *sec)
		return 0, nil
	case "install":
		sha := sub.String("sha256", "", "expected sha256 of the staged file")
		if err := sub.Parse(cargs); err != nil {
			return 2, err
		}
		if err := e.install(*unit, *sha); err != nil {
			if errors.Is(err, errRolledBack) {
				return 3, err
			}
			return 1, err
		}
		return 0, e.printStatus(*unit)
	case "rollback":
		if err := e.restoreOld(*unit); err != nil {
			return 1, err
		}
		return 0, e.printStatus(*unit)
	}
	return 2, fmt.Errorf("unknown command %q", cmd)
}

func (e *env) printStatus(unit string) error {
	st, err := e.status(unit)
	if err != nil {
		return err
	}
	return json.NewEncoder(e.out).Encode(st)
}

func main() {
	e := &env{root: "/", run: realRunner, now: time.Now, wait: 10 * time.Second, out: os.Stdout}
	if r := os.Getenv("NODECTL_ROOT"); r != "" {
		e.root = r // only for tests of the real binary
	}
	code, err := e.dispatch(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(code)
}
