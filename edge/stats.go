package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gamec/edge/shieldclient"
)

// counters is what the node reports to the panel (GET-STATS, see shieldclient/stats.go). It keeps numbers
// only: which devices and addresses hold relays right now, and totals since start. Nothing is written down.
type counters struct {
	started   time.Time
	relays    atomic.Uint64
	tokens    atomic.Uint64
	bytesUp   atomic.Uint64
	bytesDown atomic.Uint64

	mu      sync.Mutex
	refused map[string]uint64
	open    map[string]map[string]int // client address -> device -> relays open
}

func newCounters() *counters {
	return &counters{started: time.Now(), refused: map[string]uint64{}, open: map[string]map[string]int{}}
}

var stats = newCounters()

func (c *counters) refuse(reason string) {
	c.mu.Lock()
	c.refused[reason]++
	c.mu.Unlock()
}

// relayOpened records a relay for device from ip and returns the function that records its end.
func (c *counters) relayOpened(ip, device string) func() {
	c.relays.Add(1)
	c.mu.Lock()
	if c.open[ip] == nil {
		c.open[ip] = map[string]int{}
	}
	c.open[ip][device]++
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.open[ip][device]--; c.open[ip][device] <= 0 {
			delete(c.open[ip], device)
		}
		if len(c.open[ip]) == 0 {
			delete(c.open, ip)
		}
	}
}

func (c *counters) snapshot(now time.Time) shieldclient.NodeStats {
	st := shieldclient.NodeStats{
		At: now.Unix(), Started: c.started.Unix(), Version: buildVersion(),
		MaxConns: *maxConns, MaxPerIP: *maxPerIP,
		Relays: c.relays.Load(), Tokens: c.tokens.Load(),
		BytesUp: c.bytesUp.Load(), BytesDown: c.bytesDown.Load(),
		Refused: map[string]uint64{},
	}
	c.mu.Lock()
	for k, v := range c.refused {
		st.Refused[k] = v
	}
	devices := map[string]bool{}
	for ip, devs := range c.open {
		load := shieldclient.IPLoad{IP: ip, Devices: len(devs)}
		for d, n := range devs {
			load.Relays += n
			devices[d] = true
		}
		st.Active += load.Relays
		st.Top = append(st.Top, load)
	}
	c.mu.Unlock()
	st.Devices, st.IPs = len(devices), len(st.Top)
	sort.Slice(st.Top, func(i, j int) bool {
		if st.Top[i].Relays != st.Top[j].Relays {
			return st.Top[i].Relays > st.Top[j].Relays
		}
		return st.Top[i].IP < st.Top[j].IP
	})
	if len(st.Top) > shieldclient.StatsTopIPs {
		st.Top = st.Top[:shieldclient.StatsTopIPs]
	}
	return st
}

// buildVersion is the module version or VCS revision the binary was built from, if Go recorded one.
func buildVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			return s.Value[:7]
		}
	}
	return ""
}

// handleStatsRequest answers a GET-STATS frame made with this node's secret; anything else is just closed.
func handleStatsRequest(c net.Conn, first []byte) {
	now := time.Now()
	if !shieldclient.CheckStatsRequest(string(first), *secret, now, *tokenTTL) {
		stats.refuse("bad_token")
		return
	}
	body, _ := json.Marshal(stats.snapshot(now))
	c.SetWriteDeadline(now.Add(5 * time.Second))
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(body)))
	c.Write(append(h[:], body...))
}

// countingConn adds every byte read from it to n.
type countingConn struct {
	net.Conn
	n *atomic.Uint64
}

func (c countingConn) Read(b []byte) (int, error) {
	k, err := c.Conn.Read(b)
	c.n.Add(uint64(k))
	return k, err
}

// CloseWrite passes through, so relay can still half-close (tls.Conn and *net.TCPConn both have it).
func (c countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}
