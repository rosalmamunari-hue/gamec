package sshx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// jumpServer is an SSH server that forwards ("direct-tcpip") only to the destinations it is told to allow,
// like sshd with permitopen, and connects onward FROM 127.0.0.2. A destination therefore sees 127.0.0.2
// when the connection came through the jump host, and 127.0.0.1 when it came straight from the test.
type jumpServer struct {
	addr     string
	hostKey  ssh.Signer
	allowed  map[string]bool
	logins   atomic.Int32
	forwards atomic.Int32
	ln       net.Listener
	mu       sync.Mutex
	conns    []*ssh.ServerConn
}

func startJump(t *testing.T, authorized ssh.PublicKey, allowed ...string) *jumpServer {
	t.Helper()
	j := &jumpServer{hostKey: newSigner(t), allowed: map[string]bool{}}
	for _, a := range allowed {
		j.allowed[a] = true
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), authorized.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("unknown key")
	}}
	cfg.AddHostKey(j.hostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	j.ln, j.addr = ln, ln.Addr().String()
	t.Cleanup(func() { ln.Close(); j.dropAll() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go j.serve(nc, cfg)
		}
	}()
	return j
}

func (j *jumpServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		nc.Close()
		return
	}
	j.logins.Add(1)
	j.mu.Lock()
	j.conns = append(j.conns, conn)
	j.mu.Unlock()
	go func() {
		for r := range reqs {
			if r.WantReply {
				r.Reply(r.Type == "keepalive@openssh.com", nil)
			}
		}
	}()
	for nch := range chans {
		if nch.ChannelType() != "direct-tcpip" {
			nch.Reject(ssh.UnknownChannelType, "only forwarding")
			continue
		}
		var p struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		ssh.Unmarshal(nch.ExtraData(), &p)
		dest := net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
		if !j.allowed[dest] {
			nch.Reject(ssh.Prohibited, "administratively prohibited")
			continue
		}
		out, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).Dial("tcp", dest)
		if err != nil {
			nch.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			out.Close()
			continue
		}
		go ssh.DiscardRequests(creqs)
		j.forwards.Add(1)
		go func() { io.Copy(ch, out); ch.Close() }()
		go func() { io.Copy(out, ch); out.Close() }()
	}
}

func (j *jumpServer) dropAll() {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range j.conns {
		c.Close()
	}
	j.conns = nil
}

// target is a plain TCP server that records who connected to it.
type target struct {
	addr  string
	seen  chan string
	count atomic.Int32
}

func startTarget(t *testing.T) *target {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg := &target{addr: ln.Addr().String(), seen: make(chan string, 16)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tg.count.Add(1)
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			tg.seen <- host
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return tg
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "hi" {
		t.Fatalf("%q %v", b, err)
	}
}

func jumpTarget(j *jumpServer, k ssh.Signer) Target {
	return Target{Addr: j.addr, User: "gamec-jump", HostKey: ssh.FingerprintSHA256(j.hostKey.PublicKey()), Signer: k, Timeout: 3 * time.Second}
}

// ---------------------------------------------------------------- tests

func TestTheDestinationSeesTheJumpHostNotTheCaller(t *testing.T) {
	k := clientKey(t)
	tg := startTarget(t)
	j := startJump(t, k.PublicKey(), tg.addr)
	jump := NewJump(jumpTarget(j, k))
	defer jump.Close()

	// straight from here: the destination sees this machine
	c, err := (&net.Dialer{}).Dial("tcp", tg.addr)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c)
	c.Close()
	if got := <-tg.seen; got != "127.0.0.1" {
		t.Fatalf("direct connection seen from %s", got)
	}

	// through the jump host: the destination sees the jump host
	c, err = jump.DialContext(context.Background(), "tcp", tg.addr)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c)
	c.Close()
	if got := <-tg.seen; got != "127.0.0.2" {
		t.Fatalf("through the jump host the destination saw %s; it must see the jump host's address (127.0.0.2), never the caller's", got)
	}
}

func TestOnlyPermittedDestinationsCanBeReachedThroughTheJump(t *testing.T) {
	k := clientKey(t)
	allowed, forbidden := startTarget(t), startTarget(t)
	j := startJump(t, k.PublicKey(), allowed.addr)
	jump := NewJump(jumpTarget(j, k))
	defer jump.Close()
	if c, err := jump.DialContext(context.Background(), "tcp", forbidden.addr); err == nil {
		c.Close()
		t.Fatal("the jump host forwarded to a destination it does not permit")
	} else if !strings.Contains(err.Error(), "egress host") {
		t.Fatalf("the error should say it came from the egress host: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if forbidden.count.Load() != 0 {
		t.Fatal("the forbidden destination received a connection")
	}
	if j.logins.Load() != 1 {
		t.Fatalf("a refusal by the jump host must not trigger endless re-logins (%d logins)", j.logins.Load())
	}
}

func TestThereIsNoFallbackToADirectConnection(t *testing.T) {
	k := clientKey(t)
	tg := startTarget(t)
	j := startJump(t, k.PublicKey(), tg.addr)
	jump := NewJump(jumpTarget(j, k))
	j.ln.Close() // the jump host is down
	j.dropAll()
	jump.Close()
	if c, err := jump.DialContext(context.Background(), "tcp", tg.addr); err == nil {
		c.Close()
		t.Fatal("it connected although the jump host is down")
	}
	time.Sleep(100 * time.Millisecond)
	if tg.count.Load() != 0 {
		t.Fatal("the destination was reached directly while the jump host was down: that would have shown this machine's address")
	}
}

func TestTheJumpLogsInAgainWhenItsConnectionDies(t *testing.T) {
	k := clientKey(t)
	tg := startTarget(t)
	j := startJump(t, k.PublicKey(), tg.addr)
	jump := NewJump(jumpTarget(j, k))
	defer jump.Close()
	c, err := jump.DialContext(context.Background(), "tcp", tg.addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	j.dropAll() // the connection to the jump host is cut
	c, err = jump.DialContext(context.Background(), "tcp", tg.addr)
	if err != nil {
		t.Fatalf("it should have logged in again: %v", err)
	}
	roundTrip(t, c)
	c.Close()
	if j.logins.Load() != 2 {
		t.Fatalf("logins: %d", j.logins.Load())
	}
}

func TestAJumpHostWithTheWrongKeyIsRefusedAndNothingIsForwarded(t *testing.T) {
	k := clientKey(t)
	tg := startTarget(t)
	j := startJump(t, k.PublicKey(), tg.addr)
	bad := jumpTarget(j, k)
	bad.HostKey = ssh.FingerprintSHA256(newSigner(t).PublicKey())
	jump := NewJump(bad)
	defer jump.Close()
	if c, err := jump.DialContext(context.Background(), "tcp", tg.addr); !errors.Is(err, ErrHostKeyChanged) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("got %v", err)
	}
	if j.forwards.Load() != 0 || j.logins.Load() != 0 {
		t.Fatal("a jump host with an unexpected host key was logged in to")
	}
}

func TestAnSSHSessionToANodeThroughTheJumpShowsTheJumpAddress(t *testing.T) {
	k, nodeKey := clientKey(t), clientKey(t)
	node := startServer(t, nodeKey.PublicKey(), func(string, []byte) (string, string, int) { return "ok\n", "", 0 })
	j := startJump(t, k.PublicKey(), node.addr)
	jump := NewJump(jumpTarget(j, k))
	defer jump.Close()

	c, err := Dial(Target{Addr: node.addr, User: "gamec-ops", HostKey: ssh.FingerprintSHA256(node.hostKey.PublicKey()),
		Signer: nodeKey, Timeout: 3 * time.Second, Dial: jump.DialContext})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := c.Run(context.Background(), "uptime", nil)
	if err != nil || r.Stdout != "ok\n" {
		t.Fatalf("%+v %v", r, err)
	}
	host, _, _ := net.SplitHostPort(node.lastRemote.Load().(string))
	if host != "127.0.0.2" {
		t.Fatalf("the node's sshd saw the connection from %s, not from the jump host", host)
	}

	fp, _, err := FetchHostKeyVia(jump.DialContext, node.addr, 3*time.Second)
	if err != nil || fp != ssh.FingerprintSHA256(node.hostKey.PublicKey()) {
		t.Fatalf("reading a node's host key must also go through the jump: %s %v", fp, err)
	}
	host, _, _ = net.SplitHostPort(node.lastRemote.Load().(string))
	if host != "127.0.0.2" {
		t.Fatalf("the host key fetch revealed this machine: %s", host)
	}
}

func TestDialContextGivesUpWhenAskedTo(t *testing.T) {
	k := clientKey(t)
	block := startTarget(t)
	j := startJump(t, k.PublicKey(), block.addr)
	jump := NewJump(jumpTarget(j, k))
	defer jump.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, err := jump.DialContext(ctx, "tcp", block.addr); err == nil {
		c.Close()
		t.Fatal("a cancelled dial went ahead")
	}
}
