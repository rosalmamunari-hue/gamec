package main

import (
	"bufio"
	"net"
	"net/netip"
	"testing"

	"gamec/edge/shieldclient"
)

// startGameV1 is a game server that expects one PROXY v1 header (like gnetway with PPV1: true), reports it,
// then echoes.
func startGameV1(t *testing.T) (string, chan seen) {
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
				h, err := shieldclient.ReadProxyV1(r)
				ch <- seen{h, err}
				if err == nil {
					r.WriteTo(c)
				}
			}()
		}
	}()
	return ln.Addr().String(), ch
}

// The live set-up: Gcore adds a v1 header naming the node, the node (edge -proxy-v1) adds one naming the
// player, and gnetway reads exactly one v1 header.
func TestV1FrontV1NodeV1Game(t *testing.T) {
	game, ch := startGameV1(t)
	trust, _ := parseTrust("203.0.113.11")
	addr := startRealip(t, &config{trust: trust, outer: true, send: "v1", backend: game, logf: t.Logf})

	head := shieldclient.AppendProxyV1(nil, node, front)
	head = shieldclient.AppendProxyV1(head, player, edgeIn)
	if !talk(t, addr, head) {
		t.Fatal("no echo")
	}
	if h := got(t, ch); h.Src != player {
		t.Fatalf("the game server was told %+v, want the player", h)
	}

	// a node without its own header: passed on with the node's address, as today
	if !talk(t, addr, shieldclient.AppendProxyV1(nil, node, front)) {
		t.Fatal("no echo")
	}
	if h := got(t, ch); h.Src != node {
		t.Fatalf("%+v", h)
	}

	// someone else naming a player is refused
	stranger := netip.MustParseAddrPort("192.0.2.66:999")
	if talk(t, addr, shieldclient.AppendProxyV1(shieldclient.AppendProxyV1(nil, stranger, front), player, edgeIn)) {
		t.Fatal("a forged player address got through")
	}
	none(t, ch)

	// the front's own check (PROXY UNKNOWN) goes on as PROXY UNKNOWN
	if !talk(t, addr, shieldclient.AppendProxyV1Local(nil)) {
		t.Fatal("no echo")
	}
	if h := got(t, ch); !h.Local {
		t.Fatalf("%+v", h)
	}
}
