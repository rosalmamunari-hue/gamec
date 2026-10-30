// Package sshx is the SSH client the panel uses to manage nodes. It logs in with a key only (no passwords),
// refuses any server whose host key is not the one an administrator confirmed, caps what it reads back, and
// honours cancellation.
package sshx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	// ErrHostKeyUnknown: no host key has been confirmed for this node yet, so nothing is sent.
	ErrHostKeyUnknown = errors.New("the host key of this server has not been confirmed yet")
	// ErrHostKeyChanged: the server presented a different key from the confirmed one: either it was
	// reinstalled or somebody is intercepting the connection.
	ErrHostKeyChanged = errors.New("the server's host key differs from the confirmed one: it was reinstalled, or the connection is being intercepted")
)

// hostKeyAlgos is the only host key type the panel accepts. A server usually has several host keys (ed25519,
// ecdsa, rsa) and the client's own preference decides which one it presents; leaving that open makes the
// fingerprint an administrator compares depend on the library's ordering. Fixing the type makes it the
// ed25519 key, which is the one the prepare script prints, and stops anyone steering the connection to a
// weaker key type.
var hostKeyAlgos = []string{ssh.KeyAlgoED25519}

// MaxOutput bounds what Run keeps of a command's output (each of stdout and stderr).
const MaxOutput = 1 << 20

// DialFunc opens a TCP connection. Pass one to send everything through a jump host or proxy.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type Target struct {
	Addr    string // host:port
	User    string
	HostKey string // SHA256 fingerprint as printed by ssh-keygen -l, e.g. "SHA256:abc..."
	Signer  ssh.Signer
	Timeout time.Duration
	// Dial, if set, makes the TCP connection to Addr. Nothing here ever connects any other way, so with a
	// jump host's Dial the server sees the jump host's address and never this machine's.
	Dial DialFunc
}

func (t Target) connect(ctx context.Context) (net.Conn, error) {
	if t.Dial != nil {
		return t.Dial(ctx, "tcp", t.Addr)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", t.Addr)
}

// GenerateKey makes an ed25519 key pair: the private key in OpenSSH PEM form (kept in the vault) and the
// public key as one authorized_keys line.
func GenerateKey(comment string) (privatePEM, publicLine string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", "", err
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	line := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(sp))) + " " + comment
	return string(pem.EncodeToMemory(block)), line, nil
}

func ParseSigner(privatePEM string) (ssh.Signer, error) {
	return ssh.ParsePrivateKey([]byte(privatePEM))
}

// PublicLine returns the authorized_keys line for a signer.
func PublicLine(s ssh.Signer, comment string) string {
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " " + comment
}

func timeout(t time.Duration) time.Duration {
	if t <= 0 {
		return 10 * time.Second
	}
	return t
}

// FetchHostKey connects without trusting anything and reports the server's host key fingerprint, so an
// administrator can compare it with the one on the server (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)
// before confirming it. Nothing is sent to the server.
func FetchHostKey(addr string, to time.Duration) (fingerprint, keyType string, err error) {
	return FetchHostKeyVia(nil, addr, to)
}

// FetchHostKeyVia is FetchHostKey with the TCP connection made by dial (nil = from this machine).
func FetchHostKeyVia(dial DialFunc, addr string, to time.Duration) (fingerprint, keyType string, err error) {
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "gamec-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errors.New("host key captured") // stop right after the key exchange
		},
		HostKeyAlgorithms: hostKeyAlgos,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout(to))
	defer cancel()
	nc, derr := Target{Addr: addr, Dial: dial}.connect(ctx)
	if derr != nil {
		return "", "", derr
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(timeout(to)))
	cc, _, _, err := ssh.NewClientConn(nc, addr, cfg)
	if cc != nil {
		cc.Close()
	}
	if got == nil {
		if err == nil {
			err = errors.New("no host key was presented")
		}
		return "", "", err
	}
	return ssh.FingerprintSHA256(got), got.Type(), nil
}

type Conn struct {
	c *ssh.Client
}

// Dial logs in with the key. The host key must already be confirmed and must match.
func Dial(t Target) (*Conn, error) {
	if t.HostKey == "" {
		return nil, ErrHostKeyUnknown
	}
	cfg := &ssh.ClientConfig{
		User:              t.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(t.Signer)},
		Timeout:           timeout(t.Timeout),
		HostKeyAlgorithms: hostKeyAlgos,
		ClientVersion:     "SSH-2.0-gamec-panel",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != t.HostKey {
				return fmt.Errorf("%w (confirmed %s, server presented %s)", ErrHostKeyChanged, t.HostKey, ssh.FingerprintSHA256(key))
			}
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout(t.Timeout))
	defer cancel()
	nc, err := t.connect(ctx)
	if err != nil {
		return nil, err
	}
	nc.SetDeadline(time.Now().Add(timeout(t.Timeout))) // for the handshake and login
	cc, chans, reqs, err := ssh.NewClientConn(nc, t.Addr, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	nc.SetDeadline(time.Time{})
	return &Conn{c: ssh.NewClient(cc, chans, reqs)}, nil
}

func (c *Conn) Close() error { return c.c.Close() }

// DialContext opens a TCP connection from the far side of this SSH connection (a "direct-tcpip" channel),
// so the destination sees this server's address. The server decides what it allows (see permitopen).
func (c *Conn) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		conn, err := c.c.Dial(network, addr)
		ch <- res{conn, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		go func() { // a connection that arrives after we gave up must not leak
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// Alive reports whether the SSH connection is still usable.
func (c *Conn) Alive() bool {
	_, _, err := c.c.SendRequest("keepalive@openssh.com", true, nil)
	return err == nil
}

// Jump keeps one logged-in connection to a jump host and dials through it, logging in again if the
// connection has gone away. It never falls back to connecting directly: if the jump host cannot be reached
// the dial fails, because a quiet fallback would show this machine's address to the destination.
type Jump struct {
	t  Target
	mu sync.Mutex
	c  *Conn
}

func NewJump(t Target) *Jump { return &Jump{t: t} }

func (j *Jump) conn() (*Conn, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.c != nil {
		return j.c, nil
	}
	c, err := Dial(j.t)
	if err != nil {
		return nil, fmt.Errorf("the egress host %s: %w", j.t.Addr, err)
	}
	j.c = c
	return c, nil
}

func (j *Jump) reset(old *Conn) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.c == old && old != nil {
		old.Close()
		j.c = nil
	}
}

// DialContext satisfies DialFunc.
func (j *Jump) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		c, err := j.conn()
		if err != nil {
			return nil, err
		}
		conn, err := c.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		var oe *ssh.OpenChannelError
		if errors.As(err, &oe) {
			// The jump host answered and said no (the destination is not allowed, or it refused the
			// connection). Logging in again would not change that.
			return nil, fmt.Errorf("via the egress host %s: %w", j.t.Addr, err)
		}
		last = err
		j.reset(c) // the connection itself is broken: log in again and retry once
	}
	return nil, fmt.Errorf("via the egress host %s: %w", j.t.Addr, last)
}

func (j *Jump) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.c != nil {
		err := j.c.Close()
		j.c = nil
		return err
	}
	return nil
}

type Result struct {
	Stdout    string
	Stderr    string
	Exit      int
	Truncated bool
}

// capped keeps the first MaxOutput bytes and counts the rest as lost.
type capped struct {
	buf  bytes.Buffer
	lost bool
}

func (w *capped) Write(p []byte) (int, error) {
	room := MaxOutput - w.buf.Len()
	if room > 0 {
		if len(p) <= room {
			w.buf.Write(p)
		} else {
			w.buf.Write(p[:room])
			w.lost = true
		}
	} else if len(p) > 0 {
		w.lost = true
	}
	return len(p), nil // never block the remote side
}

// Run executes one command. A non-zero exit status is a normal result (Exit), not an error.
func (c *Conn) Run(ctx context.Context, cmd string, stdin io.Reader) (Result, error) {
	s, err := c.c.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer s.Close()
	var out, errb capped
	s.Stdout, s.Stderr = &out, &errb
	if stdin != nil {
		s.Stdin = stdin
	}
	if err := s.Start(cmd); err != nil {
		return Result{}, err
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case <-ctx.Done():
		s.Close()
		return Result{}, ctx.Err()
	case err := <-done:
		r := Result{Stdout: out.buf.String(), Stderr: errb.buf.String(), Truncated: out.lost || errb.lost}
		var ee *ssh.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee):
			r.Exit = ee.ExitStatus()
		default:
			return r, err
		}
		return r, nil
	}
}
