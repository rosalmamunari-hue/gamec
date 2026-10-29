package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
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
