// Command realip runs on the origin server, in front of the game server, so the game server sees each
// player's own address instead of the node's.
//
// The nodes (edge -proxy-v2) start every connection with a PROXY v2 header naming the player. When the origin
// sits behind an anti-DDoS front that adds its own PROXY v2 header (naming the node), the game server would get
// two headers; realip reads the outer one, and when it comes from one of the nodes (-trust) and is followed by
// the node's header, sends the game server a single PROXY v2 header naming the player. A connection that does
// not come from a node is passed on as it is (with its own address), unless -only-nodes refuses it; one that
// claims a player's address without coming from a node is refused, so nobody can forge an address.
//
//	internet -> anti-DDoS front -> realip :10443 -> game server 127.0.0.1:10444 (expects PROXY v2)
//
// It can be started before the nodes send their header: from a node without one the connection is passed on
// with the node's address, as before.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"gamec/edge/shieldclient"
)

var (
	listen    = flag.String("listen", ":10443", "where the anti-DDoS front (or the nodes) connect")
	backend   = flag.String("backend", "127.0.0.1:10444", "the game server")
	trustList = flag.String("trust", "", "the nodes' outgoing addresses, comma separated IPs or CIDRs (required)")
	outer     = flag.Bool("outer", true, "connections arrive with a PROXY v2 header of the anti-DDoS front; false: the nodes connect directly")
	send      = flag.Bool("send", true, "send the game server a PROXY v2 header; false: it gets the bare stream")
	onlyNodes = flag.Bool("only-nodes", false, "refuse every connection that does not come from a node")
	quiet     = flag.Bool("quiet", false, "do not log refused connections")
)

type config struct {
	trust     []netip.Prefix
	outer     bool
	send      bool
	onlyNodes bool
	backend   string
	logf      func(string, ...any)
}

func parseTrust(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func (c *config) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range c.trust {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peekWait is how long a connection may take to show whether it starts with a header (the nodes write theirs
// at once; a player's own first bytes follow straight after).
var peekWait = 3 * time.Second

// serve handles one incoming connection.
func (cfg *config) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 8192)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))

	src, dst := shieldclient.AddrPortOf(c.RemoteAddr()), shieldclient.AddrPortOf(c.LocalAddr())
	local := false
	if cfg.outer {
		h, err := shieldclient.ReadProxyV2(br)
		if err != nil {
			cfg.logf("refused %s: no PROXY header from the front: %v", c.RemoteAddr(), err)
			return
		}
		local, src, dst = h.Local, h.Src, h.Dst
	}

	if !local {
		fromNode := cfg.trusted(src.Addr())
		if !fromNode && cfg.onlyNodes {
			cfg.logf("refused %s: not one of the nodes", src)
			return
		}
		c.SetReadDeadline(time.Now().Add(peekWait))
		inner, err := shieldclient.HasProxyV2(br)
		if err != nil && !isTimeout(err) {
			return // gone before saying anything
		}
		switch {
		case inner && !fromNode:
			cfg.logf("refused %s: names a player but is not one of the nodes (add its address to -trust if it is a node)", src)
			return
		case inner:
			h, err := shieldclient.ReadProxyV2(br)
			if err != nil {
				cfg.logf("refused %s: bad PROXY header from the node: %v", src, err)
				return
			}
			if !h.Local {
				src, dst = h.Src, h.Dst
			}
		}
	}
	c.SetReadDeadline(time.Time{})

	up, err := net.DialTimeout("tcp", cfg.backend, 3*time.Second)
	if err != nil {
		cfg.logf("game server: %v", err)
		return
	}
	defer up.Close()
	var head []byte
	if cfg.send {
		if local || !src.IsValid() {
			head = shieldclient.AppendProxyV2Local(head)
		} else {
			head = shieldclient.AppendProxyV2(head, src, dst)
		}
	}
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		head = append(head, b...)
		br.Discard(n)
	}
	if len(head) > 0 {
		if _, err := up.Write(head); err != nil {
			return
		}
	}
	relay(c, up)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// relay copies both ways; a side that finishes is half-closed towards the other.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			cw.CloseWrite()
			return
		}
		a.Close()
		b.Close()
	}
	wg.Add(2)
	go pipe(b, a)
	go pipe(a, b)
	wg.Wait()
}

func main() {
	flag.Parse()
	trust, err := parseTrust(*trustList)
	if err != nil {
		log.Fatal(err)
	}
	if len(trust) == 0 {
		fmt.Fprintln(os.Stderr, "-trust is required: the nodes' addresses, e.g. -trust 203.0.113.11,203.0.113.12")
		os.Exit(2)
	}
	cfg := &config{trust: trust, outer: *outer, send: *send, onlyNodes: *onlyNodes, backend: *backend, logf: log.Printf}
	if *quiet {
		cfg.logf = func(string, ...any) {}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("realip listening on %s -> %s, %d trusted node address(es)", *listen, *backend, len(trust))
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go cfg.serve(c)
	}
}
