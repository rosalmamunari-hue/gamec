package main

import (
	"bufio"
	"net"
	"testing"
	"time"

	"gamec/edge/shieldclient"
)

// startHeaderOrigin is an origin that reads one PROXY v2 header, reports it, and then echoes.
func startHeaderOrigin(t *testing.T) (string, chan shieldclient.ProxyHeader) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan shieldclient.ProxyHeader, 4)
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
				if err != nil {
					return
				}
				got <- h
				r.WriteTo(c)
			}()
		}
	}()
	return ln.Addr().String(), got
}

func TestProxyV2NamesThePlayerToTheOrigin(t *testing.T) {
	addr := startEdge(t)
	o, got := startHeaderOrigin(t)
	*origin = o
	*proxyV2 = true
	defer func() { *proxyV2 = false }()

	c := dial(t, addr, MakeToken("test-secret", "dev", time.Now()))
	defer c.Close()
	if !echoWorks(c) {
		t.Fatal("the relay should work after the header")
	}
	h := <-got
	if h.Src.String() != c.LocalAddr().String() {
		t.Fatalf("origin was told %s, the player is %s", h.Src, c.LocalAddr())
	}
	if h.Dst.String() != addr {
		t.Fatalf("dst %s, want the node's %s", h.Dst, addr)
	}
}
