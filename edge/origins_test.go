package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLines stands in for the network: an address answers unless it is marked down.
type fakeLines struct {
	mu    sync.Mutex
	down  map[string]bool
	tried []string
	now   time.Time
	logs  []string
}

func newFake(t *testing.T, s string) (*origins, *fakeLines) {
	t.Helper()
	o, err := parseOrigins(s)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeLines{down: map[string]bool{}, now: time.Unix(1_000_000, 0)}
	o.dial = func(a string, _ time.Duration) (net.Conn, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tried = append(f.tried, a)
		if f.down[a] {
			return nil, errors.New("dial tcp " + a + ": i/o timeout")
		}
		c1, c2 := net.Pipe()
		c2.Close()
		return c1, nil
	}
	o.now = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	o.logf = func(format string, a ...any) {
		f.mu.Lock()
		f.logs = append(f.logs, fmt.Sprintf(format, a...))
		f.mu.Unlock()
	}
	return o, f
}

func (f *fakeLines) set(addr string, down bool) { f.mu.Lock(); f.down[addr] = down; f.mu.Unlock() }
func (f *fakeLines) wait(d time.Duration)       { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }
func (f *fakeLines) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.tried
	f.tried = nil
	return t
}

func dialFrom(t *testing.T, o *origins) string {
	t.Helper()
	c, a, err := o.Dial()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	return a
}

func TestOriginsAreParsed(t *testing.T) {
	o, err := parseOrigins(" 203.0.113.5:21443 , 198.51.100.7:21444,")
	if err != nil || o.String() != "203.0.113.5:21443, 198.51.100.7:21444" {
		t.Fatal(o, err)
	}
	for _, bad := range []string{"", ",", "203.0.113.5", "a:1,a:1", ":80", "1:1,2:1,3:1,4:1,5:1,6:1,7:1,8:1,9:1"} {
		if _, err := parseOrigins(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The first line goes down: connections move to the second at once, the first is retried by one connection
// once its rest is over, and everything returns to it when it answers again.
func TestTheNodeMovesToTheBackupAndBack(t *testing.T) {
	o, f := newFake(t, "gcore:1,aws:2")
	if a := dialFrom(t, o); a != "gcore:1" {
		t.Fatal("with both up the first is used, not", a)
	}
	f.take()

	f.set("gcore:1", true)
	if a := dialFrom(t, o); a != "aws:2" {
		t.Fatal("the player is not moved to the backup:", a)
	}
	if got := f.take(); strings.Join(got, " ") != "gcore:1 aws:2" {
		t.Fatal(got)
	}
	for i := 0; i < 5; i++ { // while it rests, the first is not tried (no 3 s wait for every player)
		if a := dialFrom(t, o); a != "aws:2" {
			t.Fatal(a)
		}
	}
	if got := f.take(); strings.Join(got, " ") != "aws:2 aws:2 aws:2 aws:2 aws:2" {
		t.Fatal("the resting address was tried:", got)
	}

	f.wait(*originRest) // rest over, still down: one try, then the backup; the next rest is longer
	dialFrom(t, o)
	if got := f.take(); strings.Join(got, " ") != "gcore:1 aws:2" {
		t.Fatal(got)
	}
	f.wait(*originRest)
	dialFrom(t, o)
	if got := f.take(); strings.Join(got, " ") != "aws:2" {
		t.Fatal("the rest did not grow:", got)
	}

	f.set("gcore:1", false)
	f.wait(*originRestMax)
	if a := dialFrom(t, o); a != "gcore:1" {
		t.Fatal("the node did not return to the first line:", a)
	}
	if a := dialFrom(t, o); a != "gcore:1" {
		t.Fatal(a)
	}
	f.mu.Lock()
	logs := strings.Join(f.logs, "\n")
	f.mu.Unlock()
	if !strings.Contains(logs, "gcore:1; trying the next") || !strings.Contains(logs, "origin gcore:1 is answering again") {
		t.Fatal("the log does not show the outage and its end:\n" + logs)
	}
}

func TestTheRestNeverExceedsTheMaximum(t *testing.T) {
	o, f := newFake(t, "a:1,b:2")
	f.set("a:1", true)
	for i := 0; i < 20; i++ {
		dialFrom(t, o)
		f.wait(*originRestMax)
	}
	if u := o.list[0]; u.until.Sub(f.now) > *originRestMax {
		t.Fatal("rest", u.until.Sub(f.now))
	}
}

func TestWithEveryLineDownAllAreStillTried(t *testing.T) {
	o, f := newFake(t, "a:1,b:2")
	f.set("a:1", true)
	f.set("b:2", true)
	if _, _, err := o.Dial(); err == nil {
		t.Fatal("no error")
	}
	f.take()
	f.set("b:2", false) // both resting, b is back: the player still gets through
	if a := dialFrom(t, o); a != "b:2" {
		t.Fatal(a)
	}
	if got := f.take(); strings.Join(got, " ") != "a:1 b:2" {
		t.Fatal(got)
	}
}

// Only one connection at a time finds out whether a resting address is back; the others go straight to the
// backup instead of all waiting on it.
func TestOnlyOneConnectionRetriesAResting(t *testing.T) {
	o, f := newFake(t, "a:1,b:2")
	f.set("a:1", true)
	dialFrom(t, o)
	f.wait(*originRest)
	first := o.order()
	second := o.order()
	if len(first) != 2 || first[0].addr != "a:1" || len(second) != 1 || second[0].addr != "b:2" {
		t.Fatal(len(first), len(second))
	}
}

// One address works as before.
func TestASingleOriginIsJustUsed(t *testing.T) {
	o, f := newFake(t, "only:1")
	f.set("only:1", true)
	if _, _, err := o.Dial(); err == nil {
		t.Fatal("no error")
	}
	f.set("only:1", false)
	if a := dialFrom(t, o); a != "only:1" { // resting, but it is all there is
		t.Fatal(a)
	}
}

// Through the real network and a whole relay: the first origin refuses, the player still reaches the second.
func TestARelayReachesTheBackupOrigin(t *testing.T) {
	addr := startEdge(t)
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := dead.Addr().String()
	dead.Close()
	if upstreams, err = parseOrigins(gone + "," + *origin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upstreams, _ = parseOrigins(*origin) })
	c := dial(t, addr, MakeToken(*secret, "dev1", time.Now()))
	defer c.Close()
	if !echoWorks(c) {
		t.Fatal("the backup origin did not answer")
	}
}
