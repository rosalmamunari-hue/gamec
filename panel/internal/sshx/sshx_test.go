package sshx

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------- an SSH server in the test process

type handler func(cmd string, stdin []byte) (stdout, stderr string, exit int)

type server struct {
	addr       string
	hostKey    ssh.Signer
	authorized ssh.PublicKey
	handle     handler
	execs      atomic.Int32
	rejected   atomic.Int32
	lastRemote atomic.Value // where the latest connection came from
	ln         net.Listener
}

func newSigner(t *testing.T) ssh.Signer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startServer(t *testing.T, authorized ssh.PublicKey, h handler) *server {
	t.Helper()
	srv := &server{hostKey: newSigner(t), authorized: authorized, handle: h}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), srv.authorized.Marshal()) {
				return nil, nil
			}
			srv.rejected.Add(1)
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(srv.hostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.ln, srv.addr = ln, ln.Addr().String()
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(nc, cfg)
		}
	}()
	return srv
}

func (s *server) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	s.lastRemote.Store(nc.RemoteAddr().String())
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		nc.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, reqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for r := range reqs {
				if r.Type != "exec" {
					r.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(r.Payload)
				cmd := string(r.Payload[4 : 4+n])
				r.Reply(true, nil)
				s.execs.Add(1)
				in, _ := io.ReadAll(ch) // the client closes its side when it has sent everything
				stdout, stderr, exit := s.handle(cmd, in)
				io.WriteString(ch, stdout)
				io.WriteString(ch.Stderr(), stderr)
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(exit)}))
				return
			}
		}()
	}
}

func clientKey(t *testing.T) ssh.Signer { return newSigner(t) }

func echo(cmd string, _ []byte) (string, string, int) { return "ran: " + cmd + "\n", "", 0 }

// ---------------------------------------------------------------- tests

func TestRunsACommandAndReturnsItsOutput(t *testing.T) {
	k := clientKey(t)
	srv := startServer(t, k.PublicKey(), func(cmd string, _ []byte) (string, string, int) { return "hello\n", "warning\n", 0 })
	c, err := Dial(Target{Addr: srv.addr, User: "gamec-ops", HostKey: ssh.FingerprintSHA256(srv.hostKey.PublicKey()), Signer: k})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := c.Run(context.Background(), "uptime", nil)
	if err != nil || r.Stdout != "hello\n" || r.Stderr != "warning\n" || r.Exit != 0 || r.Truncated {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestANonZeroExitIsAResultNotAnError(t *testing.T) {
	k := clientKey(t)
	srv := startServer(t, k.PublicKey(), func(string, []byte) (string, string, int) { return "", "no such unit\n", 3 })
	c, _ := Dial(Target{Addr: srv.addr, User: "u", HostKey: ssh.FingerprintSHA256(srv.hostKey.PublicKey()), Signer: k})
	defer c.Close()
	r, err := c.Run(context.Background(), "x", nil)
	if err != nil || r.Exit != 3 || !strings.Contains(r.Stderr, "no such unit") {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestOnlyTheRightKeyGetsIn(t *testing.T) {
	good, bad := clientKey(t), clientKey(t)
	srv := startServer(t, good.PublicKey(), echo)
	fp := ssh.FingerprintSHA256(srv.hostKey.PublicKey())
	if _, err := Dial(Target{Addr: srv.addr, User: "u", HostKey: fp, Signer: bad}); err == nil {
		t.Fatal("a stranger's key was accepted")
	}
	c, err := Dial(Target{Addr: srv.addr, User: "u", HostKey: fp, Signer: good})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestNothingIsSentToAServerWhoseHostKeyIsUnconfirmed(t *testing.T) {
	k := clientKey(t)
	srv := startServer(t, k.PublicKey(), echo)
	if _, err := Dial(Target{Addr: srv.addr, User: "u", HostKey: "", Signer: k}); !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("got %v", err)
	}
	if srv.rejected.Load() != 0 || srv.execs.Load() != 0 {
		t.Fatal("the client authenticated to a server it had no reason to trust")
	}
}

func TestAChangedHostKeyIsRefusedBeforeAnyLogin(t *testing.T) {
	k := clientKey(t)
	srv := startServer(t, k.PublicKey(), echo)
	other := ssh.FingerprintSHA256(newSigner(t).PublicKey())
	_, err := Dial(Target{Addr: srv.addr, User: "u", HostKey: other, Signer: k})
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), ssh.FingerprintSHA256(srv.hostKey.PublicKey())) {
		t.Fatalf("the message should show both fingerprints: %v", err)
	}
	if srv.execs.Load() != 0 {
		t.Fatal("a command reached the impostor")
	}
}

func TestFetchHostKeyReportsTheFingerprintAndSendsNothing(t *testing.T) {
	k := clientKey(t)
	srv := startServer(t, k.PublicKey(), echo)
	fp, typ, err := FetchHostKey(srv.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if fp != ssh.FingerprintSHA256(srv.hostKey.PublicKey()) || typ != "ssh-ed25519" || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("%s %s", fp, typ)
	}
	if srv.execs.Load() != 0 {
		t.Fatal("fetching a host key must not run anything")
	}
	if _, _, err := FetchHostKey("127.0.0.1:1", time.Second); err == nil {
		t.Fatal("an unreachable server should be an error")
	}
}

func TestUploadsGoThroughStdinIntact(t *testing.T) {
	k := clientKey(t)
	srv := startServer(t, k.PublicKey(), func(_ string, in []byte) (string, string, int) {
		h := sha256.Sum256(in)
		return hex.EncodeToString(h[:]), "", 0
	})
	c, _ := Dial(Target{Addr: srv.addr, User: "u", HostKey: ssh.FingerprintSHA256(srv.hostKey.PublicKey()), Signer: k})
	defer c.Close()
	data := make([]byte, 3<<20)
	rand.Read(data)
	r, err := c.Run(context.Background(), "cat > file", bytes.NewReader(data))
	want := sha256.Sum256(data)
	if err != nil || r.Stdout != hex.EncodeToString(want[:]) {
		t.Fatalf("the server received different bytes: %v %q", err, r.Stdout)
	}
}

func TestCancellationReturnsPromptly(t *testing.T) {
	k := clientKey(t)
	block := make(chan struct{})
	srv := startServer(t, k.PublicKey(), func(string, []byte) (string, string, int) { <-block; return "", "", 0 })
	defer close(block)
	c, _ := Dial(Target{Addr: srv.addr, User: "u", HostKey: ssh.FingerprintSHA256(srv.hostKey.PublicKey()), Signer: k})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	_, err := c.Run(ctx, "sleep 1000", nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(t0) > 3*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(t0))
	}
}

func TestHugeOutputIsCappedNotBuffered(t *testing.T) {
	k := clientKey(t)
	srv := startServer(t, k.PublicKey(), func(string, []byte) (string, string, int) {
		return strings.Repeat("A", 3*MaxOutput), "", 0
	})
	c, _ := Dial(Target{Addr: srv.addr, User: "u", HostKey: ssh.FingerprintSHA256(srv.hostKey.PublicKey()), Signer: k})
	defer c.Close()
	r, err := c.Run(context.Background(), "yes", nil)
	if err != nil || len(r.Stdout) != MaxOutput || !r.Truncated {
		t.Fatalf("len=%d truncated=%v err=%v", len(r.Stdout), r.Truncated, err)
	}
}

func TestGeneratedKeysRoundTripAndLookRight(t *testing.T) {
	pemText, line, err := GenerateKey("gamec-panel")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pemText, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("%.40s", pemText)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") || !strings.HasSuffix(line, " gamec-panel") || strings.Contains(line, "\n") {
		t.Fatalf("%q", line)
	}
	s, err := ParseSigner(pemText)
	if err != nil {
		t.Fatal(err)
	}
	if PublicLine(s, "gamec-panel") != line {
		t.Fatal("the public line does not belong to the private key")
	}
	if _, err := ParseSigner("not a key"); err == nil {
		t.Fatal("garbage accepted")
	}
	_, line2, _ := GenerateKey("gamec-panel")
	if line == line2 {
		t.Fatal("two generated keys are identical")
	}
}

// ---------------------------------------------------------------- a server with several host keys

// startMultiKeyServer presents an ECDSA key as well as an ed25519 one, the way a stock OpenSSH server does.
func startMultiKeyServer(t *testing.T, authorized ssh.PublicKey, withEd25519 bool) (addr string, ed ssh.Signer, ec ssh.Signer) {
	t.Helper()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec, _ = ssh.NewSignerFromKey(ecKey)
	ed = newSigner(t)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), authorized.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("unknown key")
	}}
	cfg.AddHostKey(ec) // listed first on purpose: this is the key a naive client would meet first
	if withEd25519 {
		cfg.AddHostKey(ed)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					nc.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					for range chans {
					}
				}()
				_ = conn
			}()
		}
	}()
	return ln.Addr().String(), ed, ec
}

func TestTheEd25519HostKeyIsAlwaysTheOneThatIsFetchedAndPinned(t *testing.T) {
	k := clientKey(t)
	addr, ed, ec := startMultiKeyServer(t, k.PublicKey(), true)
	want, other := ssh.FingerprintSHA256(ed.PublicKey()), ssh.FingerprintSHA256(ec.PublicKey())
	for i := 0; i < 5; i++ { // not a matter of luck
		fp, typ, err := FetchHostKey(addr, 3*time.Second)
		if err != nil || fp != want || typ != "ssh-ed25519" {
			t.Fatalf("fetched %s (%s) err %v; want the ed25519 key %s, not the ecdsa key %s", fp, typ, err, want, other)
		}
	}
	c, err := Dial(Target{Addr: addr, User: "u", HostKey: want, Signer: k})
	if err != nil {
		t.Fatalf("pinning the ed25519 fingerprint must work on a server that also has an ecdsa key: %v", err)
	}
	c.Close()
	if _, err := Dial(Target{Addr: addr, User: "u", HostKey: other, Signer: k}); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("pinning the ecdsa fingerprint must not be satisfiable: %v", err)
	}
}

func TestAServerWithOnlyAWeakerHostKeyIsRefusedClearly(t *testing.T) {
	k := clientKey(t)
	addr, _, ec := startMultiKeyServer(t, k.PublicKey(), false)
	if fp, _, err := FetchHostKey(addr, 3*time.Second); err == nil {
		t.Fatalf("a server offering only an ecdsa key was accepted (%s)", fp)
	}
	if _, err := Dial(Target{Addr: addr, User: "u", HostKey: ssh.FingerprintSHA256(ec.PublicKey()), Signer: k}); err == nil {
		t.Fatal("the panel must not fall back to another host key type")
	}
}
