package main

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// startEcho records the first bytes it gets and echoes everything.
func startEcho(t *testing.T) (string, chan []byte) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan []byte, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 200)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := io.ReadAtLeast(c, b, 1)
				ch <- b[:n]
				c.Write(b[:n])
			}()
		}
	}()
	return ln.Addr().String(), ch
}

func startPass(t *testing.T, p *passConfig) string {
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
			go p.serve(c)
		}
	}()
	return ln.Addr().String()
}

func passSend(t *testing.T, addr string, msg []byte) []byte {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(msg)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(c)
	return b
}

func TestTheRelayPassesTheNodesHeaderOnUnchanged(t *testing.T) {
	next, got := startEcho(t)
	file := filepath.Join(t.TempDir(), "allow")
	os.WriteFile(file, []byte("# the nodes\n127.0.0.1\n"), 0o644)
	p := &passConfig{backend: next, allow: &allowList{path: file, every: 0, logf: t.Logf}, logf: t.Logf}
	addr := startPass(t, p)

	msg := []byte("PROXY TCP4 198.51.100.7 10.0.0.5 51000 48860\r\nhello")
	if b := passSend(t, addr, msg); !bytes.Equal(b, msg) {
		t.Fatalf("echoed %q", b)
	}
	if b := <-got; !bytes.Equal(b, msg) {
		t.Fatalf("the next hop got %q, want it unchanged", b)
	}

	// the node is taken off: it may no longer connect, and nothing reaches the next hop
	os.WriteFile(file, []byte("203.0.113.9, 10.1.0.0/16\n"), 0o644)
	os.Chtimes(file, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	if b := passSend(t, addr, msg); len(b) != 0 {
		t.Fatalf("a removed address still got %q", b)
	}
	select {
	case b := <-got:
		t.Fatalf("the next hop got %q", b)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTheAllowFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "allow")
	a := &allowList{path: file, every: time.Hour, logf: t.Logf}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.9")
	if a.allows(ip, now) {
		t.Fatal("no file, yet allowed")
	}
	os.WriteFile(file, []byte("203.0.113.9\n"), 0o644)
	if a.allows(ip, now.Add(time.Second)) {
		t.Fatal("read again before -every passed")
	}
	if !a.allows(ip, now.Add(2*time.Hour)) {
		t.Fatal("not picked up")
	}
	// a broken file keeps the last good list
	os.WriteFile(file, []byte("203.0.113.9\nnot-an-ip\n"), 0o644)
	os.Chtimes(file, now.Add(time.Minute), now.Add(time.Minute))
	if !a.allows(ip, now.Add(4*time.Hour)) {
		t.Fatal("a broken file emptied the list")
	}
	// a removed file closes the relay
	os.Remove(file)
	if a.allows(ip, now.Add(6*time.Hour)) {
		t.Fatal("still allowed after the file is gone")
	}
	if l, err := parseAllow([]byte("1.2.3.4, 10.0.0.0/8 2001:db8::1 # x\n\n")); err != nil || len(l) != 3 {
		t.Fatal(l, err)
	}
}
