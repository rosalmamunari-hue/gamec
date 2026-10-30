// Package engine is what the panel does on its own: probe the nodes, decide which belong in each cluster's
// list, sign and publish the list, verify it from the outside, and renew it before it expires.
package engine

import (
	"context"
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

// RealProber checks a node the way a player's phone would: pinned TLS, ask for a token, open a relay and
// see that the node keeps it open (it closes at once if it cannot reach the origin).
type RealProber struct {
	Timeout time.Duration
	Hold    time.Duration
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
	c, hs, err := shieldclient.Dial(addr, n.Pin, timeout)
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
	tok, _, err := shieldclient.RequestToken(addr, n.Pin, "panel-"+n.ID+"-probe-check", timeout)
	if err != nil {
		r.Err = "token: " + err.Error()
		return r
	}
	r.TokenOK = true
	ok, err := shieldclient.OriginReachable(addr, n.Pin, tok, hold, timeout)
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

	mu     sync.Mutex
	health map[string]*Health
	prober Prober
}

func NewMonitor(p Prober) *Monitor {
	return &Monitor{FailToEject: 5, OKToAdmit: 5, health: map[string]*Health{}, prober: p}
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

// ProbeAll probes the given nodes in parallel once.
func (m *Monitor) ProbeAll(ctx context.Context, nodes []*store.Node) {
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n store.Node) {
			defer wg.Done()
			m.Record(n.ID, m.prober.Probe(ctx, n))
		}(*n)
	}
	wg.Wait()
}

// Run probes every interval until ctx ends. nodesFn is asked each round, so changes are picked up.
func (m *Monitor) Run(ctx context.Context, nodesFn func() []*store.Node, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		m.ProbeAll(ctx, nodesFn())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
		return Decision{Nodes: fallback, Note: "no node qualifies right now; keeping the list that is already published (if every node fails together the panel's own network is the likelier cause)"}
	}
	return Decision{Note: "no node is ready to be published"}
}
