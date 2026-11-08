package main

// Relay mode (-pass): realip on a relay server that sits between the nodes and the anti-DDoS front,
//
//	player -> node (edge -proxy-v1) -> relay (realip -pass) -> anti-DDoS front -> origin (realip) -> game server
//
// passes every connection on byte for byte, the node's PROXY header included, so the origin still learns the
// player's address. It reads and adds nothing. Only the addresses in -allow-file (the nodes that use this
// relay) may connect; the panel rewrites that file when a node is added or removed, and it is re-read when it
// changes.

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"gamec/edge/shieldclient"
)

// allowList is the set of addresses that may use the relay, kept in step with a file.
type allowList struct {
	path  string
	every time.Duration // how often the file is looked at

	mu      sync.Mutex
	list    []netip.Prefix
	mod     time.Time
	size    int64
	checked time.Time
	logf    func(string, ...any)
}

// parseAllow reads IPs or CIDRs separated by commas, spaces or new lines; # starts a comment.
func parseAllow(b []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' }) {
			p, err := parseTrust(f)
			if err != nil {
				return nil, err
			}
			out = append(out, p...)
		}
	}
	return out, nil
}

// refresh re-reads the file when it changed. A file that cannot be read or parsed keeps the last good list,
// except that a file that is gone empties it (the relay is closed until it comes back).
func (a *allowList) refresh(now time.Time) {
	if now.Sub(a.checked) < a.every && !a.checked.IsZero() {
		return
	}
	a.checked = now
	fi, err := os.Stat(a.path)
	if errors.Is(err, os.ErrNotExist) {
		if a.list != nil || a.mod.IsZero() {
			a.logf("%s does not exist: nobody may connect", a.path)
		}
		a.list, a.mod, a.size = nil, time.Unix(1, 0), 0
		return
	}
	if err != nil || (fi.ModTime().Equal(a.mod) && fi.Size() == a.size) {
		return
	}
	b, err := os.ReadFile(a.path)
	if err != nil {
		a.logf("%s: %v (keeping the previous list)", a.path, err)
		return
	}
	list, err := parseAllow(b)
	if err != nil {
		a.logf("%s: %v (keeping the previous list)", a.path, err)
		return
	}
	a.list, a.mod, a.size = list, fi.ModTime(), fi.Size()
	a.logf("%d address(es) may connect", len(list))
}

func (a *allowList) allows(ip netip.Addr, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refresh(now)
	ip = ip.Unmap()
	for _, p := range a.list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type passConfig struct {
	backend string
	allow   *allowList // nil: anyone may connect
	logf    func(string, ...any)
}

func (p *passConfig) serve(c net.Conn) {
	defer c.Close()
	if p.allow != nil {
		src := shieldclient.AddrPortOf(c.RemoteAddr())
		if !p.allow.allows(src.Addr(), time.Now()) {
			p.logf("refused %s: not in the allow file", src.Addr())
			return
		}
	}
	up, err := net.DialTimeout("tcp", p.backend, 5*time.Second)
	if err != nil {
		p.logf("next hop: %v", err)
		return
	}
	defer up.Close()
	relay(c, up)
}

// runPass is main for -pass.
func runPass() {
	cfg := &passConfig{backend: *backend, logf: log.Printf}
	if *quiet {
		cfg.logf = func(string, ...any) {}
	}
	who := "anyone may connect"
	if *allowFile != "" {
		cfg.allow = &allowList{path: *allowFile, every: 5 * time.Second, logf: log.Printf}
		cfg.allow.allows(netip.Addr{}, time.Now()) // read it now, so a bad file shows in the log at start
		who = "addresses from " + *allowFile
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("realip relay listening on %s -> %s, passing connections unchanged; %s", *listen, *backend, who)
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
