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

// MaxOutput bounds what Run keeps of a command's output (each of stdout and stderr).
const MaxOutput = 1 << 20

type Target struct {
	Addr    string // host:port
	User    string
	HostKey string // SHA256 fingerprint as printed by ssh-keygen -l, e.g. "SHA256:abc..."
	Signer  ssh.Signer
	Timeout time.Duration
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
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "gamec-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errors.New("host key captured") // stop right after the key exchange
		},
		Timeout: timeout(to),
	}
	_, err = ssh.Dial("tcp", addr, cfg)
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
		User:          t.User,
		Auth:          []ssh.AuthMethod{ssh.PublicKeys(t.Signer)},
		Timeout:       timeout(t.Timeout),
		ClientVersion: "SSH-2.0-gamec-panel",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != t.HostKey {
				return fmt.Errorf("%w (confirmed %s, server presented %s)", ErrHostKeyChanged, t.HostKey, ssh.FingerprintSHA256(key))
			}
			return nil
		},
	}
	c, err := ssh.Dial("tcp", t.Addr, cfg)
	if err != nil {
		return nil, err
	}
	return &Conn{c: c}, nil
}

func (c *Conn) Close() error { return c.c.Close() }

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
