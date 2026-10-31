package main

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gamec/edge/shieldclient"
)

type seen struct {
	h   shieldclient.ProxyHeader
	err error
}

// startGame is a game server that expects one PROXY v2 header, reports it, then echoes.
func startGame(t *testing.T) (string, chan seen) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan seen, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				h, err := shieldclient.ReadProxyV2(r)
				ch <- seen{h, err}
				if err == nil {
					r.WriteTo(c)
				}
			}()
		}
	}()
	return ln.Addr().String(), ch
}

func startRealip(t *testing.T, cfg *config) string {
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
			go cfg.serve(c)
		}
	}()
	return ln.Addr().String()
}

var (
	node   = netip.MustParseAddrPort("203.0.113.11:40000")
	front  = netip.MustParseAddrPort("193.0.2.1:10443")
	player = netip.MustParseAddrPort("198.51.100.77:51234")
	edgeIn = netip.MustParseAddrPort("203.0.113.11:30800")
)

func setup(t *testing.T, mod func(*config)) (string, chan seen) {
	game, ch := startGame(t)
	trust, _ := parseTrust("203.0.113.11, 203.0.113.64/26")
	cfg := &config{trust: trust, outer: true, send: true, backend: game, logf: t.Logf}
	if mod != nil {
		mod(cfg)
	}
	return startRealip(t, cfg), ch
}

// talk sends head then a first message and says whether it came back.
func talk(t *testing.T, addr string, head []byte) bool {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(append(head, "ping, the first bytes of a game"...))
	b := make([]byte, 31)
	_, err = io.ReadFull(c, b)
	return err == nil && string(b) == "ping, the first bytes of a game"
}

func got(t *testing.T, ch chan seen) shieldclient.ProxyHeader {
	select {
	case s := <-ch:
		if s.err != nil {
			t.Fatal("game server got no header:", s.err)
		}
		return s.h
	case <-time.After(2 * time.Second):
		t.Fatal("nothing reached the game server")
	}
	return shieldclient.ProxyHeader{}
}

func none(t *testing.T, ch chan seen) {
	select {
	case <-ch:
		t.Fatal("the connection should not have reached the game server")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestThePlayerBehindTheNodeAndTheFront(t *testing.T) {
	addr, ch := setup(t, nil)
	head := shieldclient.AppendProxyV2(nil, node, front)    // the front: "from the node"
	head = shieldclient.AppendProxyV2(head, player, edgeIn) // the node: "from the player"
	if !talk(t, addr, head) {
		t.Fatal("no echo")
	}
	if h := got(t, ch); h.Src != player || h.Dst != edgeIn {
		t.Fatalf("game server was told %+v, want the player", h)
	}
}

func TestANodeWithoutTheHeaderStillWorks(t *testing.T) {
	addr, ch := setup(t, nil)
	if !talk(t, addr, shieldclient.AppendProxyV2(nil, netip.MustParseAddrPort("203.0.113.70:1"), front)) {
		t.Fatal("no echo")
	}
	if h := got(t, ch); h.Src.Addr().String() != "203.0.113.70" {
		t.Fatalf("%+v: an old node should be passed on with its own address", h)
	}
}

func TestNobodyElseCanNameAPlayer(t *testing.T) {
	addr, ch := setup(t, nil)
	stranger := netip.MustParseAddrPort("192.0.2.66:999")
	head := shieldclient.AppendProxyV2(nil, stranger, front)
	if talk(t, addr, shieldclient.AppendProxyV2(head, player, edgeIn)) {
		t.Fatal("a forged player address got through")
	}
	none(t, ch)

	// without a forged header a stranger is passed on as itself, unless only nodes are let in
	if !talk(t, addr, head) {
		t.Fatal("no echo")
	}
	if h := got(t, ch); h.Src != stranger {
		t.Fatalf("%+v", h)
	}
	addr2, ch2 := setup(t, func(c *config) { c.onlyNodes = true })
	if talk(t, addr2, head) {
		t.Fatal("-only-nodes let a stranger in")
	}
	none(t, ch2)
}

func TestNoFrontAndHealthChecks(t *testing.T) {
	// nodes connecting straight to realip: the address of the connection is the node's
	addr, ch := setup(t, func(c *config) { c.outer = false; c.trust, _ = parseTrust("127.0.0.1") })
	if !talk(t, addr, shieldclient.AppendProxyV2(nil, player, edgeIn)) {
		t.Fatal("no echo")
	}
	if h := got(t, ch); h.Src != player {
		t.Fatalf("%+v", h)
	}
	// the front's own health check (LOCAL) is passed on as LOCAL
	addr, ch = setup(t, nil)
	if !talk(t, addr, shieldclient.AppendProxyV2Local(nil)) {
		t.Fatal("no echo")
	}
	if h := got(t, ch); !h.Local {
		t.Fatalf("%+v", h)
	}
	// without the front's header nothing goes through
	addr, ch = setup(t, nil)
	if talk(t, addr, []byte("hello there, game")) {
		t.Fatal("a connection without the front's header got through")
	}
	none(t, ch)
}

func TestSlowFirstBytesAreNotLost(t *testing.T) {
	old := peekWait
	peekWait = 200 * time.Millisecond
	defer func() { peekWait = old }()
	addr, ch := setup(t, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(append(shieldclient.AppendProxyV2(nil, node, front), "pi"...)) // fewer bytes than a signature
	time.Sleep(400 * time.Millisecond)
	c.Write([]byte("ng"))
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatalf("%q %v", b, err)
	}
	if h := got(t, ch); h.Src != node {
		t.Fatalf("%+v", h)
	}
}
