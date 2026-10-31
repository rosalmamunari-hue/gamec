package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func startEcho(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func startEdge(t *testing.T) string {
	*origin = startEcho(t)
	*secret = "test-secret"
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned()},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	lim := &limiter{n: map[string]int{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c, lim)
		}
	}()
	return ln.Addr().String()
}

func dial(t *testing.T, addr, token string) *tls.Conn {
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(token)))
	c.Write(append(h[:], token...))
	return c
}

func echoWorks(c net.Conn) bool {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("ping"))
	b := make([]byte, 4)
	_, err := io.ReadFull(c, b)
	return err == nil && string(b) == "ping"
}

func TestValidToken(t *testing.T) {
	addr := startEdge(t)
	c := dial(t, addr, MakeToken("test-secret", "u1", time.Now()))
	defer c.Close()
	if !echoWorks(c) {
		t.Fatal("valid token should relay to origin")
	}
}

func TestBadToken(t *testing.T) {
	addr := startEdge(t)
	for name, tok := range map[string]string{
		"wrong secret": MakeToken("other", "u1", time.Now()),
		"expired":      MakeToken("test-secret", "u1", time.Now().Add(-time.Hour)),
		"garbage":      "nope",
	} {
		c := dial(t, addr, tok)
		if echoWorks(c) {
			t.Errorf("%s: should have been rejected", name)
		}
		c.Close()
	}
}

func TestPerIPLimit(t *testing.T) {
	addr := startEdge(t)
	*maxPerIP = 3
	defer func() { *maxPerIP = 20 }()
	var ok []*tls.Conn
	for i := 0; i < 3; i++ {
		c := dial(t, addr, MakeToken("test-secret", "u", time.Now()))
		if !echoWorks(c) {
			t.Fatalf("conn %d should work", i)
		}
		ok = append(ok, c)
	}
	if c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}); err == nil {
		var h [2]byte
		tok := MakeToken("test-secret", "u", time.Now())
		binary.BigEndian.PutUint16(h[:], uint16(len(tok)))
		c.Write(append(h[:], tok...))
		if echoWorks(c) {
			t.Error("4th connection should be refused")
		}
		c.Close()
	}
	for _, c := range ok {
		c.Close()
	}
}

func TestNoTokenTimeout(t *testing.T) {
	addr := startEdge(t)
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected server to close idle connection")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server did not close within 5s")
	}
}

func TestIPv6LimitsCountTheWholeSlash64(t *testing.T) {
	if limitKey("2001:db8:1:2::1") != limitKey("2001:db8:1:2:ffff::9") {
		t.Fatal("two addresses in one /64 must share a limit")
	}
	if limitKey("2001:db8:1:2::1") == limitKey("2001:db8:1:3::1") {
		t.Fatal("different /64s must not share a limit")
	}
	if limitKey("203.0.113.7") != "203.0.113.7" {
		t.Fatal("IPv4 is counted per address")
	}
}

func TestWeakSecretsAreRefused(t *testing.T) {
	defer func(s, f string) { *secret, *secretFile = s, f }(*secret, *secretFile)
	*secretFile = ""
	for _, s := range []string{"", "change-me", "short"} {
		*secret = s
		if _, err := loadSecret(); err == nil {
			t.Fatalf("secret %q was accepted", s)
		}
	}
	f := t.TempDir() + "/secret"
	os.WriteFile(f, []byte("a-long-enough-secret-from-a-file\n"), 0o600)
	*secret, *secretFile = "", f
	if s, err := loadSecret(); err != nil || s != "a-long-enough-secret-from-a-file" {
		t.Fatalf("%q %v", s, err)
	}
}

// pair returns the two ends of a relay through relay(): what the client holds and what the origin holds.
func pair(t *testing.T, idle time.Duration) (client, origin net.Conn) {
	c1, c2 := tcpPair(t)
	o1, o2 := tcpPair(t)
	go relay(c2, o1, idle)
	return c1, o2
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); got <- c }()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-got
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestASilentRelayIsClosed(t *testing.T) {
	client, _ := pair(t, 200*time.Millisecond)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("a relay with no traffic should be closed, got %v", err)
	}
}

func TestARelayBusyInOneDirectionStaysOpen(t *testing.T) {
	client, origin := pair(t, 300*time.Millisecond)
	go func() { // the origin pushes, the client never sends
		for i := 0; i < 10; i++ {
			if _, err := origin.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := io.ReadFull(client, make([]byte, 10)); err != nil {
		t.Fatalf("got %d bytes, then %v: the quiet direction must not close a busy relay", n, err)
	}
}

func TestAReplyAfterTheClientFinishesSendingGetsThrough(t *testing.T) {
	client, origin := pair(t, 0)
	client.Write([]byte("last request"))
	client.(*net.TCPConn).CloseWrite()
	go func() {
		io.ReadAll(origin) // the request, then EOF passed on by the relay
		time.Sleep(50 * time.Millisecond)
		origin.Write([]byte("reply"))
		origin.Close()
	}()
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if b, err := io.ReadAll(client); err != nil || string(b) != "reply" {
		t.Fatalf("%q %v", b, err)
	}
}

// A server that never closes its side after the client is done must not hold the relay (and its origin
// connection) until the idle timeout, or forever with -idle-timeout 0.
func TestAHalfClosedRelayIsClosedAfterTheGrace(t *testing.T) {
	defer halfCloseGrace.Store(halfCloseGrace.Load())
	halfCloseGrace.Store(int64(200 * time.Millisecond))
	client, origin := pair(t, 0)
	client.(*net.TCPConn).CloseWrite()
	origin.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(origin); err != nil { // the EOF passed on by the relay
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the relay should have closed after the grace, got %v", err)
	}
}
