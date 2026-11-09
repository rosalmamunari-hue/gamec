package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// -origin may list several addresses, best first (the anti-DDoS front, then a backup line). A connection goes
// to the first one that is up. One that fails to answer is set aside for a while (doubling up to a minute while
// it keeps failing) and connections go to the next; once its time is up, one connection tries it again (and
// falls back at once if it still fails), so the nodes return to the first line by themselves when it recovers.
// With every address set aside they are all tried anyway, in order: never refuse a player without trying.
var (
	originTimeout = flag.Duration("origin-timeout", 3*time.Second, "how long to wait for an -origin address to answer before trying the next")
	originRest    = flag.Duration("origin-rest", 10*time.Second, "how long an -origin address that failed is skipped at first (doubles while it keeps failing, up to -origin-rest-max)")
	originRestMax = flag.Duration("origin-rest-max", time.Minute, "the longest an -origin address that keeps failing is skipped between tries")
)

type upstream struct {
	addr     string
	fails    int       // in a row
	until    time.Time // skipped until then
	trying   bool      // one connection is finding out whether it is back
	wasDown  bool
	lastWarn time.Time
}

type origins struct {
	mu   sync.Mutex
	list []*upstream
	dial func(addr string, timeout time.Duration) (net.Conn, error)
	now  func() time.Time
	logf func(string, ...any)
}

func parseOrigins(s string) (*origins, error) {
	o := &origins{dial: func(a string, t time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", a, t) },
		now: time.Now, logf: log.Printf}
	seen := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if h, p, err := net.SplitHostPort(f); err != nil || h == "" || p == "" {
			return nil, fmt.Errorf("-origin %q is not host:port", f)
		}
		if seen[f] {
			return nil, fmt.Errorf("-origin lists %s twice", f)
		}
		seen[f] = true
		o.list = append(o.list, &upstream{addr: f})
	}
	if len(o.list) == 0 {
		return nil, errors.New("-origin is required")
	}
	if len(o.list) > 8 {
		return nil, errors.New("-origin takes at most 8 addresses")
	}
	return o, nil
}

func (o *origins) String() string {
	a := make([]string, len(o.list))
	for i, u := range o.list {
		a[i] = u.addr
	}
	return strings.Join(a, ", ")
}

// order returns the addresses to try for one connection: those up (or due for a retry, which this connection
// then takes on), best first; then, if none is, all of them.
func (o *origins) order() []*upstream {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	var out []*upstream
	for _, u := range o.list {
		switch {
		case u.fails == 0:
			out = append(out, u)
		case !now.Before(u.until) && !u.trying:
			u.trying = true
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		out = append(out, o.list...)
	}
	return out
}

func (o *origins) ok(u *upstream) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if u.wasDown {
		o.logf("origin %s is answering again (after %d failed tries)", u.addr, u.fails)
	}
	u.fails, u.trying, u.wasDown = 0, false, false
}

func (o *origins) failed(u *upstream, err error, next bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	u.fails++
	u.trying = false
	rest := *originRest
	for i := 1; i < u.fails && rest < *originRestMax; i++ {
		rest *= 2
	}
	u.until = now.Add(min(rest, *originRestMax))
	// One line per address per few seconds is enough to see an outage, its start and its end in the log.
	if !u.wasDown || now.Sub(u.lastWarn) >= 5*time.Second {
		u.lastWarn = now
		then := "no other address to try"
		if next {
			then = "trying the next"
		}
		o.logf("origin dial: %v (%s; %s)", err, u.addr, then)
	}
	u.wasDown = true
}

// Dial connects to the best origin that answers.
func (o *origins) Dial() (net.Conn, string, error) {
	try := o.order()
	var last error
	for i, u := range try {
		c, err := o.dial(u.addr, *originTimeout)
		if err == nil {
			o.ok(u)
			return c, u.addr, nil
		}
		o.failed(u, err, i < len(try)-1)
		last = err
	}
	return nil, "", last
}
