package engine

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"gamec/panel/internal/store"
)

func TestProbeIDLooksLikeADeviceAndIsNeverRepeated(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		id := ProbeID()
		if !re.MatchString(id) {
			t.Fatalf("odd id %q", id)
		}
		if strings.Contains(strings.ToLower(id), "panel") || seen[id] {
			t.Fatalf("recognisable or repeated id %q", id)
		}
		seen[id] = true
	}
}

func TestJitteredStaysWithinBounds(t *testing.T) {
	d := 10 * time.Second
	if got := jittered(d, 0, 0.9); got != d {
		t.Fatalf("no jitter must not change the interval, got %v", got)
	}
	lo, hi := jittered(d, 0.2, 0), jittered(d, 0.2, 0.999999)
	if lo != 8*time.Second || hi < 11900*time.Millisecond || hi > 12*time.Second {
		t.Fatalf("bounds %v %v", lo, hi)
	}
	if mid := jittered(d, 0.2, 0.5); mid != d {
		t.Fatalf("mid %v", mid)
	}
}

type stampProber struct {
	mu sync.Mutex
	at map[string]time.Time
}

func (p *stampProber) Probe(_ context.Context, n store.Node) ProbeResult {
	p.mu.Lock()
	p.at[n.ID] = time.Now()
	p.mu.Unlock()
	return ProbeResult{At: time.Now(), OK: true}
}

func TestProbesAreSpreadNotFiredTogether(t *testing.T) {
	sp := &stampProber{at: map[string]time.Time{}}
	m := NewMonitor(sp)
	i := 0
	m.rnd = func() float64 { i++; return float64(i%4) / 4 } // 0, .25, .5, .75
	var nodes []*store.Node
	for _, id := range []string{"a", "b", "c", "d"} {
		nodes = append(nodes, &store.Node{ID: id})
	}
	start := time.Now()
	m.probeSpread(context.Background(), nodes, 400*time.Millisecond)
	if len(sp.at) != 4 {
		t.Fatalf("probed %d", len(sp.at))
	}
	var first, last time.Time
	for _, ts := range sp.at {
		if first.IsZero() || ts.Before(first) {
			first = ts
		}
		if ts.After(last) {
			last = ts
		}
	}
	if last.Sub(first) < 200*time.Millisecond {
		t.Fatalf("probes bunched within %v", last.Sub(first))
	}
	if last.Sub(start) > 2*time.Second {
		t.Fatal("spread is too slow")
	}
}

func TestRealProberOpensEveryConnectionThroughTheGivenDialer(t *testing.T) {
	var mu sync.Mutex
	var addrs []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		addrs = append(addrs, addr)
		mu.Unlock()
		return nil, errors.New("jump down")
	}
	n := store.Node{ID: "x", Host: "203.0.113.5", Port: 443, Pin: "AAAA"}
	r := RealProber{Dial: dial, Timeout: time.Second}.Probe(context.Background(), n)
	if r.OK || !strings.Contains(r.Err, "jump down") {
		t.Fatalf("a dead jump host must fail the probe, not fall back to direct: %+v", r)
	}
	if len(addrs) != 1 || addrs[0] != n.Addr() {
		t.Fatalf("dialed %v", addrs)
	}
}
