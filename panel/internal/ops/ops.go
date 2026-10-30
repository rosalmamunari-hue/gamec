// Package ops manages nodes over SSH. It can do only what the nodectl program on the node offers (status,
// logs, start/stop/restart, stop for a while, install a new version, roll back); every command line is built
// from a fixed template and its arguments are checked against a whitelist, so nothing a user types can
// become a shell command.
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
	"regexp"
	"strconv"
	"strings"
	"time"

	"gamec/panel/internal/engine"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

const (
	NodectlPath = "/usr/local/sbin/gamec-nodectl"
	StagingDir  = "/var/lib/gamec-ops/incoming"
)

var (
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9._:=-]+$`)
	unitRe  = regexp.MustCompile(`^gamec-edge[a-z0-9-]{0,40}$`)
	shaRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Runner is one logged-in session to a node.
type Runner interface {
	Run(ctx context.Context, cmd string, stdin io.Reader) (sshx.Result, error)
	Close() error
}

type Ops struct {
	// Open logs in to a node (the panel's key from the vault, the node's confirmed host key).
	Open func(ctx context.Context, n store.Node) (Runner, error)
	// Probe is the same check the monitor makes; it decides whether an upgraded node is really serving.
	Probe func(ctx context.Context, n store.Node) engine.ProbeResult
	// HealthyWithin is how long a node may take to pass its checks after an upgrade.
	HealthyWithin time.Duration
	Poll          time.Duration
}

func (o *Ops) healthyWithin() time.Duration {
	if o.HealthyWithin <= 0 {
		return 45 * time.Second
	}
	return o.HealthyWithin
}

func (o *Ops) poll() time.Duration {
	if o.Poll <= 0 {
		return 3 * time.Second
	}
	return o.Poll
}

// command builds "sudo <nodectl> -unit U arg...". Every piece must be plain characters; this is the
// guard that keeps user input out of the shell.
func command(unit string, args ...string) (string, error) {
	if !unitRe.MatchString(unit) {
		return "", fmt.Errorf("%q is not an edge service name", unit)
	}
	parts := []string{"sudo", NodectlPath, "-unit", unit}
	for _, a := range args {
		if !tokenRe.MatchString(a) {
			return "", fmt.Errorf("argument %q is not allowed", a)
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " "), nil
}

func stagingFile(unit string) string { return StagingDir + "/" + unit + ".edge.new" }

func (o *Ops) session(ctx context.Context, n store.Node) (Runner, error) {
	if !n.SSHConfigured() {
		return nil, errors.New("this node has no SSH account configured")
	}
	if !unitRe.MatchString(n.UnitName()) {
		return nil, fmt.Errorf("%q is not an edge service name", n.UnitName())
	}
	return o.Open(ctx, n)
}

// call runs one nodectl command and returns its output; a non-zero exit becomes an error carrying stderr.
func call(ctx context.Context, r Runner, unit string, args ...string) (sshx.Result, error) {
	c, err := command(unit, args...)
	if err != nil {
		return sshx.Result{}, err
	}
	res, err := r.Run(ctx, c, nil)
	if err != nil {
		return res, err
	}
	if res.Exit != 0 {
		return res, &ExitError{Code: res.Exit, Msg: strings.TrimSpace(res.Stderr)}
	}
	return res, nil
}

// ExitError is a command that ran and failed.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("the command failed (exit %d)", e.Code)
	}
	return e.Msg
}

// ---------------------------------------------------------------- reading

type NodeStatus struct {
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

func (o *Ops) Status(ctx context.Context, n store.Node) (NodeStatus, error) {
	r, err := o.session(ctx, n)
	if err != nil {
		return NodeStatus{}, err
	}
	defer r.Close()
	return status(ctx, r, n.UnitName())
}

func status(ctx context.Context, r Runner, unit string) (NodeStatus, error) {
	res, err := call(ctx, r, unit, "status")
	if err != nil {
		return NodeStatus{}, err
	}
	var st NodeStatus
	if err := json.Unmarshal([]byte(res.Stdout), &st); err != nil {
		return st, fmt.Errorf("unexpected reply from the node: %w", err)
	}
	return st, nil
}

func (o *Ops) Logs(ctx context.Context, n store.Node, lines int) (string, error) {
	if lines < 1 || lines > 500 {
		return "", errors.New("lines must be between 1 and 500")
	}
	r, err := o.session(ctx, n)
	if err != nil {
		return "", err
	}
	defer r.Close()
	res, err := call(ctx, r, n.UnitName(), "logs", "-n", strconv.Itoa(lines))
	return res.Stdout, err
}

// ---------------------------------------------------------------- start, stop, restart

func (o *Ops) Control(ctx context.Context, n store.Node, verb string) (NodeStatus, error) {
	if verb != "start" && verb != "stop" && verb != "restart" {
		return NodeStatus{}, fmt.Errorf("%q is not start, stop or restart", verb)
	}
	r, err := o.session(ctx, n)
	if err != nil {
		return NodeStatus{}, err
	}
	defer r.Close()
	if _, err := call(ctx, r, n.UnitName(), verb); err != nil {
		return NodeStatus{}, err
	}
	return status(ctx, r, n.UnitName())
}

// StopFor stops the node's service and has the node start it again by itself after d. The timer lives on
// the node, so it still fires if the panel loses contact.
func (o *Ops) StopFor(ctx context.Context, n store.Node, d time.Duration) error {
	secs := int(d.Seconds())
	if secs < 5 || secs > 3600 {
		return errors.New("the time must be between 5 seconds and 1 hour")
	}
	r, err := o.session(ctx, n)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = call(ctx, r, n.UnitName(), "stop-for", "-seconds", strconv.Itoa(secs))
	return err
}

// ---------------------------------------------------------------- upgrading

// Binary is a program to install, with the checksum it must have.
type Binary struct {
	Data   []byte
	SHA256 string
	Label  string // for messages, e.g. the release tag
}

func (b Binary) check() error {
	if !shaRe.MatchString(b.SHA256) {
		return errors.New("the checksum is not 64 lowercase hex characters")
	}
	h := sha256.Sum256(b.Data)
	if hex.EncodeToString(h[:]) != b.SHA256 {
		return errors.New("the program does not match its checksum; refusing to send it")
	}
	if len(b.Data) < 1<<20 {
		return errors.New("the program is too small to be an edge node")
	}
	return nil
}

type UpgradeResult struct {
	Node       string
	Label      string
	Already    bool   // it was already running this exact version
	Installed  bool   // the new version is in place and healthy
	RolledBack bool   // it failed and the previous version is back
	Before     string // sha256 before
	After      string // sha256 after
	Detail     string
}

func (o *Ops) waitHealthy(ctx context.Context, n store.Node) (engine.ProbeResult, bool) {
	deadline := time.Now().Add(o.healthyWithin())
	var last engine.ProbeResult
	for {
		last = o.Probe(ctx, n)
		if last.OK {
			return last, true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return last, false
		}
		select {
		case <-ctx.Done():
			return last, false
		case <-time.After(o.poll()):
		}
	}
}

// Upgrade installs b on one node: send it, let nodectl verify and swap it in, then require the node to pass
// the same checks a player's phone would. If anything fails the previous version is put back.
func (o *Ops) Upgrade(ctx context.Context, n store.Node, b Binary) (UpgradeResult, error) {
	res := UpgradeResult{Node: n.Addr(), Label: b.Label}
	if err := b.check(); err != nil {
		return res, err
	}
	r, err := o.session(ctx, n)
	if err != nil {
		return res, err
	}
	defer r.Close()
	unit := n.UnitName()

	before, err := status(ctx, r, unit)
	if err != nil {
		return res, fmt.Errorf("reading the current state: %w", err)
	}
	res.Before = before.SHA256
	if before.SHA256 == b.SHA256 {
		res.Already, res.After = true, before.SHA256
		res.Detail = "already running this version"
		return res, nil
	}

	up, err := r.Run(ctx, "cat > "+stagingFile(unit), bytes.NewReader(b.Data))
	if err != nil {
		return res, fmt.Errorf("sending the program: %w", err)
	}
	if up.Exit != 0 {
		return res, fmt.Errorf("sending the program: %s", strings.TrimSpace(up.Stderr))
	}

	if _, err := call(ctx, r, unit, "install", "-sha256", b.SHA256); err != nil {
		var ee *ExitError
		if errors.As(err, &ee) && ee.Code == 3 {
			res.RolledBack = true
			res.Detail = "the new version did not stay running on the node; the previous version was restored"
			return res, errors.New(res.Detail)
		}
		return res, err
	}

	probe, ok := o.waitHealthy(ctx, n)
	if !ok {
		// The checks also stop when the caller gives up; going back must happen anyway.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if _, rerr := call(rctx, r, unit, "rollback"); rerr != nil {
			res.Detail = fmt.Sprintf("the new version never passed the checks (%s) and going back failed: %v", probe.Err, rerr)
			return res, errors.New(res.Detail)
		}
		res.RolledBack = true
		res.Detail = fmt.Sprintf("the new version started but never passed the checks (%s); the previous version was restored", probe.Err)
		return res, errors.New(res.Detail)
	}
	after, err := status(ctx, r, unit)
	if err == nil {
		res.After = after.SHA256
	}
	res.Installed = true
	res.Detail = "installed and passing its checks"
	return res, nil
}

// RollingUpgrade upgrades nodes one at a time and stops at the first problem, so a bad version can take down
// at most one node. guard runs before each node (the panel uses it to refuse taking down the last healthy
// node of a cluster).
func (o *Ops) RollingUpgrade(ctx context.Context, nodes []store.Node, b Binary, guard func(store.Node) error, progress func(string)) ([]UpgradeResult, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	say := func(s string) {
		if progress != nil {
			progress(s)
		}
	}
	var results []UpgradeResult
	for _, n := range nodes {
		if guard != nil {
			if err := guard(n); err != nil {
				return results, fmt.Errorf("not touching %s: %w", n.Addr(), err)
			}
		}
		say("upgrading " + n.Addr())
		r, err := o.Upgrade(ctx, n, b)
		results = append(results, r)
		if err != nil {
			return results, fmt.Errorf("%s: %w; the remaining nodes were not touched", n.Addr(), err)
		}
		say(n.Addr() + ": " + r.Detail)
	}
	return results, nil
}
