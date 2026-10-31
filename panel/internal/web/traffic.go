package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"gamec/edge/shieldclient"
	"gamec/panel/internal/auth"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/store"
)

// Traffic: once a minute the panel asks every node for its connection numbers (GET-STATS, signed with the
// cluster's token secret, so nobody else can ask) and keeps the last hour in memory. Nothing is stored on
// disk; after a restart the history starts again.

const trafficKept = 60

type trafficSample struct {
	At      time.Time
	Started int64
	Active  int
	Devices int
	Up      uint64
	Down    uint64
}

type nodeTraffic struct {
	Last    *shieldclient.NodeStats
	LastAt  time.Time // when Last was read
	Err     string    // the last attempt failed with this
	Old     bool      // the node answered nothing: older program, or a different secret
	Tried   time.Time
	Samples []trafficSample // oldest first
}

type trafficBook struct {
	mu    sync.Mutex
	nodes map[string]*nodeTraffic
}

func (b *trafficBook) record(id string, st *shieldclient.NodeStats, err error, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nodes == nil {
		b.nodes = map[string]*nodeTraffic{}
	}
	t := b.nodes[id]
	if t == nil {
		t = &nodeTraffic{}
		b.nodes[id] = t
	}
	t.Tried = now
	if err != nil {
		t.Err, t.Old = err.Error(), errors.Is(err, shieldclient.ErrNoStats)
		return
	}
	t.Err, t.Old, t.Last, t.LastAt = "", false, st, now
	t.Samples = append(t.Samples, trafficSample{At: now, Started: st.Started, Active: st.Active, Devices: st.Devices, Up: st.BytesUp, Down: st.BytesDown})
	if len(t.Samples) > trafficKept {
		t.Samples = t.Samples[len(t.Samples)-trafficKept:]
	}
}

func (b *trafficBook) get(id string) nodeTraffic {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t := b.nodes[id]; t != nil {
		c := *t
		c.Samples = append([]trafficSample(nil), t.Samples...)
		return c
	}
	return nodeTraffic{}
}

func (b *trafficBook) forget(id string) {
	b.mu.Lock()
	delete(b.nodes, id)
	b.mu.Unlock()
}

// ---------------------------------------------------------------- reading the nodes

func (s *Server) statsDial() shieldclient.DialFunc {
	if s.Egress != nil {
		return s.Egress.DialContext
	}
	return shieldclient.DirectDial
}

// fetchStats is how one node is asked; tests replace it.
func (s *Server) fetchStats(n *store.Node, secret string) (*shieldclient.NodeStats, error) {
	if s.FetchStats != nil {
		return s.FetchStats(n, secret)
	}
	return shieldclient.FetchStatsVia(s.statsDial(), n.Addr(), n.Pin, secret, 8*time.Second)
}

// PollTraffic asks every node of every cluster for its numbers, all at once. With the vault locked the token
// secrets cannot be read, so nothing is asked.
func (s *Server) PollTraffic(ctx context.Context) {
	if s.Vault.Sealed() {
		return
	}
	st := s.Store.Snapshot()
	var wg sync.WaitGroup
	for _, c := range st.Clusters {
		secret, ok, err := s.Vault.Get(engine.NodeSecretName(c.ID))
		if err != nil || !ok {
			continue
		}
		for _, n := range st.NodesOf(c.ID) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.pollNode(n, secret)
			}()
		}
	}
	wg.Wait()
}

func (s *Server) pollNode(n *store.Node, secret string) {
	st, err := s.fetchStats(n, secret)
	s.traffic.record(n.ID, st, err, s.now())
}

// ---------------------------------------------------------------- what the pages show

type refusedRow struct {
	Word string
	N    uint64
}

type trafficView struct {
	Has    bool // there are numbers to show
	Old    bool // the node program is too old to report them
	Err    string
	Sealed bool
	At     time.Time
	Stale  bool // the last reading is more than a few minutes old

	Active, Devices, IPs int
	MaxConns, MaxPerIP   int
	Load                 int    // Active as a percentage of MaxConns
	UpRate, DownRate     string // over the last minute
	Up, Down             string // since the node program started
	Relays, Tokens       uint64
	Uptime, Version      string
	Refused              []refusedRow
	RefusedAll           uint64
	Top                  []shieldclient.IPLoad

	Spark     string // polyline points of Active over the last hour, in a 300 x 48 box
	SparkMax  int
	SparkFrom time.Time
}

var refusedWords = map[string]string{
	"bad_token":     "令牌不对（伪造、过期或别的渠道的）",
	"per_ip":        "同一个 IP 连接太多",
	"full":          "节点连接数满了",
	"token_refused": "拒发令牌（请求太频繁或设备被封）",
	"no_frame":      "连上就断、什么都没发（多半是扫描器）",
	"origin":        "源站连不上",
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	f, i := float64(n), 0
	for f >= unit && i < 4 {
		f /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", f, []string{"B", "KB", "MB", "GB", "TB"}[i])
}

func humanRate(bytes uint64, d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	return humanBytes(uint64(float64(bytes)/d.Seconds())) + "/s"
}

func humanSpan(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "不到 1 分钟"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d 小时 %d 分钟", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d 天", int(d.Hours()/24))
}

func (s *Server) trafficView(n *store.Node) trafficView {
	t := s.traffic.get(n.ID)
	now := s.now()
	v := trafficView{Old: t.Old, Err: t.Err, Sealed: s.Vault.Sealed()}
	if t.Last == nil {
		return v
	}
	st := t.Last
	v.Has, v.At, v.Stale = true, t.LastAt, now.Sub(t.LastAt) > 3*time.Minute
	v.Active, v.Devices, v.IPs, v.MaxConns, v.MaxPerIP = st.Active, st.Devices, st.IPs, st.MaxConns, st.MaxPerIP
	if st.MaxConns > 0 {
		v.Load = st.Active * 100 / st.MaxConns
	}
	v.Up, v.Down, v.Relays, v.Tokens, v.Version = humanBytes(st.BytesUp), humanBytes(st.BytesDown), st.Relays, st.Tokens, st.Version
	v.Uptime = humanSpan(time.Unix(st.At, 0).Sub(time.Unix(st.Started, 0)))
	v.UpRate, v.DownRate = "—", "—"
	if k := len(t.Samples); k >= 2 {
		a, b := t.Samples[k-2], t.Samples[k-1]
		if a.Started == b.Started && b.Up >= a.Up && b.Down >= a.Down { // not across a restart
			v.UpRate, v.DownRate = humanRate(b.Up-a.Up, b.At.Sub(a.At)), humanRate(b.Down-a.Down, b.At.Sub(a.At))
		}
	}
	for k, n := range st.Refused {
		if n == 0 {
			continue
		}
		w := refusedWords[k]
		if w == "" {
			w = k
		}
		v.Refused = append(v.Refused, refusedRow{w, n})
		v.RefusedAll += n
	}
	sort.Slice(v.Refused, func(i, j int) bool { return v.Refused[i].N > v.Refused[j].N })
	v.Top = st.Top
	v.Spark, v.SparkMax = spark(t.Samples)
	if len(t.Samples) > 0 {
		v.SparkFrom = t.Samples[0].At
	}
	return v
}

// spark draws Active over the samples as polyline points in a 300 x 48 box (y grows downwards).
func spark(samples []trafficSample) (string, int) {
	if len(samples) < 2 {
		return "", 0
	}
	top := 1
	for _, x := range samples {
		top = max(top, x.Active)
	}
	from, to := samples[0].At, samples[len(samples)-1].At
	span := to.Sub(from).Seconds()
	var b strings.Builder
	for i, x := range samples {
		px := 300.0
		if span > 0 {
			px = 300 * x.At.Sub(from).Seconds() / span
		}
		py := 46 - 44*float64(x.Active)/float64(top)
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", px, py)
	}
	return b.String(), top
}

// clusterTraffic adds up the nodes of one cluster.
type clusterTraffic struct {
	Reporting, Nodes int
	Active, Devices  int
	UpRate, DownRate string
	Old              int // nodes too old to report
}

func (s *Server) clusterTraffic(views []nodeView) clusterTraffic {
	var ct clusterTraffic
	var up, down float64
	rates := false
	for _, nv := range views {
		ct.Nodes++
		t := s.traffic.get(nv.N.ID)
		if t.Old {
			ct.Old++
		}
		if t.Last == nil || s.now().Sub(t.LastAt) > 3*time.Minute {
			continue
		}
		ct.Reporting++
		ct.Active += t.Last.Active
		ct.Devices += t.Last.Devices
		if k := len(t.Samples); k >= 2 {
			a, b := t.Samples[k-2], t.Samples[k-1]
			if d := b.At.Sub(a.At).Seconds(); d > 0 && a.Started == b.Started && b.Up >= a.Up && b.Down >= a.Down {
				up += float64(b.Up-a.Up) / d
				down += float64(b.Down-a.Down) / d
				rates = true
			}
		}
	}
	ct.UpRate, ct.DownRate = "—", "—"
	if rates {
		ct.UpRate, ct.DownRate = humanBytes(uint64(up))+"/s", humanBytes(uint64(down))+"/s"
	}
	return ct
}

// ---------------------------------------------------------------- refresh by hand

func (s *Server) trafficNow(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, n, ok := s.lookup(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if s.Vault.Sealed() {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "保险库锁着，读不到令牌密钥，没法向节点要连接数据。先解锁。", http.StatusConflict)
		return
	}
	secret, ok, err := s.Vault.Get(engine.NodeSecretName(c.ID))
	if err != nil || !ok {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "保险库里没有这个渠道的令牌密钥。", http.StatusConflict)
		return
	}
	s.pollNode(n, secret)
	s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "已刷新。", "", http.StatusOK)
}
