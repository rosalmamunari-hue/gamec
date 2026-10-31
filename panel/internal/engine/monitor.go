// Package engine is what the panel does on its own: probe the nodes, decide which belong in each cluster's
// list, sign and publish the list, verify it from the outside, and renew it before it expires.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"sync"
	"time"

	"gamec/edge/shieldclient"
	"gamec/panel/internal/store"
)

type ProbeResult struct {
	At        time.Time     `json:"at"`
	OK        bool          `json:"ok"`
	Handshake time.Duration `json:"handshake"`
	TokenOK   bool          `json:"token_ok"`
	RelayOK   bool          `json:"relay_ok"`
	Err       string        `json:"err,omitempty"`
}

type Prober interface {
	Probe(ctx context.Context, n store.Node) ProbeResult
}

// ProbeID is the device id a probe presents: 32 random hex characters, the same shape as the ids the apps
// generate, new every time. A probe therefore does not look like one fixed, recognisable client.
func ProbeID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("no secure random source: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// RealProber checks a node the way a player's phone would: pinned TLS, ask for a token, open a relay and
// see that the node keeps it open (it closes at once if it cannot reach the origin).
//
// Dial opens every TCP connection. Set it to send probes through the egress jump host; if it is nil the
// connections are made from this machine.
type RealProber struct {
	Timeout time.Duration
	Hold    time.Duration
	Dial    shieldclient.DialFunc
}

func (p RealProber) Probe(ctx context.Context, n store.Node) ProbeResult {
	r := ProbeResult{At: time.Now()}
	timeout, hold := p.Timeout, p.Hold
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	if hold == 0 {
		hold = time.Second
	}
	addr := n.Addr()
	dial := p.Dial
	if dial == nil {
		dial = shieldclient.DirectDial
	}
	c, hs, err := shieldclient.DialVia(dial, addr, n.Pin, timeout)
	if err != nil {
		r.Err = "connect: " + err.Error()
		return r
	}
	c.Close()
	r.Handshake = hs
	if ctx.Err() != nil {
		r.Err = "cancelled"
		return r
	}
	tok, _, err := shieldclient.RequestTokenVia(dial, addr, n.Pin, ProbeID(), timeout)
	if err != nil {
		r.Err = "token: " + err.Error()
		return r
	}
	r.TokenOK = true
	ok, err := shieldclient.OriginReachableVia(dial, addr, n.Pin, tok, hold, timeout)
	if err != nil || !ok {
		if err != nil {
			r.Err = "origin: " + err.Error()
		}
		return r
	}
	r.RelayOK = true
	r.OK = true
	return r
}

// Health is what the monitor knows about one node.
type Health struct {
	Last       ProbeResult   `json:"last"`
	Recent     []ProbeResult `json:"recent"`
	ConsecFail int           `json:"consec_fail"`
	ConsecOK   int           `json:"consec_ok"`
	Ejected    bool          `json:"ejected"`
	Seen       bool          `json:"seen"`
}

const recentKept = 60

type Monitor struct {
	// FailToEject consecutive failures take a node out of the list; OKToAdmit consecutive successes put a
	// node (back) in. The gap between them stops a flapping node from being added and removed over and over.
	FailToEject int
	OKToAdmit   int

	// Jitter is the fraction by which each probing round's interval varies at random (0.2 = plus or minus
	// 20 %), and the nodes of one round are probed at random moments within the first half of the interval.
	// A probe that fires on the second, at every node at once, is easy to recognise as a monitor.
	Jitter float64

	mu     sync.Mutex
	health map[string]*Health
	prober Prober
	rnd    func() float64
}

func NewMonitor(p Prober) *Monitor {
	return &Monitor{FailToEject: 5, OKToAdmit: 5, Jitter: 0.2, health: map[string]*Health{}, prober: p, rnd: mrand.Float64}
}

func (m *Monitor) Record(id string, r ProbeResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.health[id]
	if h == nil {
		h = &Health{}
		m.health[id] = h
	}
	h.Seen = true
	h.Last = r
	h.Recent = append(h.Recent, r)
	if len(h.Recent) > recentKept {
		h.Recent = h.Recent[len(h.Recent)-recentKept:]
	}
	if r.OK {
		h.ConsecOK++
		h.ConsecFail = 0
		if h.Ejected && h.ConsecOK >= m.OKToAdmit {
			h.Ejected = false
		}
	} else {
		h.ConsecFail++
		h.ConsecOK = 0
		if h.ConsecFail >= m.FailToEject {
			h.Ejected = true
		}
	}
}

func (m *Monitor) Health(id string) Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h := m.health[id]; h != nil {
		cp := *h
		cp.Recent = append([]ProbeResult(nil), h.Recent...)
		return cp
	}
	return Health{}
}

// Forget drops what is known about a node (it was deleted or its address changed).
func (m *Monitor) Forget(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.health, id)
}

// ProbeAll probes the given nodes in parallel, at once (used for "probe now").
func (m *Monitor) ProbeAll(ctx context.Context, nodes []*store.Node) {
	m.probeSpread(ctx, nodes, 0)
}

// jittered varies d by up to +-frac; r is a number in [0,1).
func jittered(d time.Duration, frac, r float64) time.Duration {
	if frac <= 0 {
		return d
	}
	return time.Duration(float64(d) * (1 + frac*(2*r-1)))
}

// probeSpread probes every node once, each after its own random delay of up to maxDelay.
func (m *Monitor) probeSpread(ctx context.Context, nodes []*store.Node, maxDelay time.Duration) {
	var wg sync.WaitGroup
	for _, n := range nodes {
		wait := time.Duration(m.rnd() * float64(maxDelay))
		wg.Add(1)
		go func(n store.Node, wait time.Duration) {
			defer wg.Done()
			if wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
			m.Record(n.ID, m.prober.Probe(ctx, n))
		}(*n, wait)
	}
	wg.Wait()
}

// Run probes in rounds until ctx ends. nodesFn is asked each round, so changes are picked up.
func (m *Monitor) Run(ctx context.Context, nodesFn func() []*store.Node, interval time.Duration) {
	for {
		start := time.Now()
		next := start.Add(jittered(interval, m.Jitter, m.rnd()))
		spread := time.Duration(0)
		if m.Jitter > 0 {
			spread = interval / 2
		}
		m.probeSpread(ctx, nodesFn(), spread)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
	}
}

type Decision struct {
	Nodes []*store.Node
	Note  string
}

// Decide chooses which of a cluster's switched-on nodes belong in its list.
//
//   - a node that has been failing for FailToEject probes in a row stays out until it has passed OKToAdmit
//     probes in a row;
//   - a node that is not in the published list yet must first pass OKToAdmit probes, so a node that was just
//     added, or just came back, is not announced before it has proved itself;
//   - the list is never emptied by monitoring: if no node qualifies, the nodes already published are kept,
//     because every node failing at once is far more likely to be a problem on the panel's side than a
//     simultaneous outage of all of them.
func (m *Monitor) Decide(active []*store.Node, published map[string]bool) Decision {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keep []*store.Node
	for _, n := range active {
		h := m.health[n.ID]
		if h != nil && h.Ejected {
			continue
		}
		if published[n.Key()] {
			keep = append(keep, n)
			continue
		}
		if h != nil && h.ConsecOK >= m.OKToAdmit {
			keep = append(keep, n)
		}
	}
	if len(keep) > 0 {
		return Decision{Nodes: keep}
	}
	var fallback []*store.Node
	for _, n := range active {
		if published[n.Key()] {
			fallback = append(fallback, n)
		}
	}
	if len(fallback) > 0 {
		return Decision{Nodes: fallback, Note: "现在没有节点通过检查，先保留已经发布的名单（所有节点同时失败时，更可能是面板自己的网络出了问题）"}
	}
	return Decision{Note: "还没有节点通过检查，暂时不能发布名单"}
}
