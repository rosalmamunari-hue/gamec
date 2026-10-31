package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"gamec/edge/shieldclient"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/store"
)

func TestAPausedNodeCanBeResumedAtOnce(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"hk"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}, nil)
	n := e.st.Snapshot().Nodes[0]
	base := "/cluster/" + cl.ID + "/node/" + n.ID
	c.post(base+"/pause", url.Values{"csrf": {c.csrf()}, "minutes": {"30"}}, nil)

	for _, page := range []string{"/cluster/" + cl.ID, base} {
		if _, body, _ := c.get(page); !strings.Contains(body, `action="`+base+`/resume"`) {
			t.Fatalf("%s offers no way to end the pause", page)
		}
	}
	if st, _, _ := e.viewer().post(base+"/resume", url.Values{}, nil); st == http.StatusSeeOther {
		t.Fatal("a viewer resumed a node")
	}
	if st, _, _ := c.post(base+"/resume", url.Values{"csrf": {c.csrf()}}, nil); st != http.StatusSeeOther {
		t.Fatal(st)
	}
	if len(e.st.Snapshot().Active(cl.ID, e.clock)) != 1 {
		t.Fatal("the node is still paused")
	}
	if _, body, _ := c.get("/cluster/" + cl.ID); strings.Contains(body, base+"/resume") || !strings.Contains(body, base+"/pause") {
		t.Fatal("after resuming, the menu should offer pausing again")
	}
}

type fakeStats struct {
	mu      sync.Mutex
	secrets []string
	answer  map[string]*shieldclient.NodeStats // by node host
}

func (f *fakeStats) fetch(n *store.Node, secret string) (*shieldclient.NodeStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets = append(f.secrets, secret)
	if st := f.answer[n.Host]; st != nil {
		c := *st
		return &c, nil
	}
	return nil, shieldclient.ErrNoStats
}

func TestConnectionNumbersAreShownForEachNodeAndTheCluster(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	e.vault.Set(engine.NodeSecretName(cl.ID), "the-node-secret-0123456789")
	for i, h := range []string{"1.2.3.4", "5.6.7.8"} {
		c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"n" + string(rune('1'+i))}, "host": {h}, "port": {"30800"}, "pin": {pin}}, nil)
	}
	started := e.clock.Add(-2 * time.Hour).Unix()
	f := &fakeStats{answer: map[string]*shieldclient.NodeStats{
		"1.2.3.4": {Started: started, At: e.clock.Unix(), MaxConns: 10000, MaxPerIP: 20, Active: 7, Devices: 3, IPs: 2,
			Relays: 120, Tokens: 40, BytesUp: 1 << 20, BytesDown: 8 << 20,
			Refused: map[string]uint64{"no_frame": 15, "bad_token": 2},
			Top:     []shieldclient.IPLoad{{IP: "203.0.113.9", Relays: 20, Devices: 1}, {IP: "198.51.100.4", Relays: 2, Devices: 2}}},
	}}
	e.s.FetchStats = f.fetch

	e.s.PollTraffic(context.Background())
	e.clock = e.clock.Add(time.Minute)
	f.answer["1.2.3.4"].BytesDown += 6 << 20 // 6 MB in a minute: 102.4 KB/s
	f.answer["1.2.3.4"].Active = 9
	e.s.PollTraffic(context.Background())

	for _, s := range f.secrets {
		if s != "the-node-secret-0123456789" {
			t.Fatalf("asked with secret %q", s)
		}
	}
	nodes := e.st.Snapshot().NodesOf(cl.ID)
	_, body, _ := c.get("/cluster/" + cl.ID + "/node/" + nodes[0].ID)
	for _, want := range []string{"连接详情", ">9<", ">3<", "102.4 KB/s", "203.0.113.9", "到上限了", "连上就断、什么都没发", "2 小时", "<polyline"} {
		if !strings.Contains(body, want) {
			t.Errorf("node page lacks %q", want)
		}
	}
	_, body, _ = c.get("/cluster/" + cl.ID + "/node/" + nodes[1].ID)
	if !strings.Contains(body, "v0.5.1 起才会报连接数据") {
		t.Error("a node that does not answer should be explained as needing an upgrade")
	}
	_, body, _ = c.get("/cluster/" + cl.ID)
	for _, want := range []string{"<b>9</b> 个连接", "<b>3</b> 台设备", "1/2 个节点报了数据，1 个要升级", "9 连接"} {
		if !strings.Contains(body, want) {
			t.Errorf("cluster page lacks %q", want)
		}
	}
	if _, body, _ = c.get("/"); !strings.Contains(body, "<b>9</b> 连接") {
		t.Error("the overview lacks the channel's connections")
	}

	// a viewer can refresh by hand too; with the vault locked nothing is asked
	v := e.viewer()
	n := len(f.secrets)
	if st, _, _ := v.post("/cluster/"+cl.ID+"/node/"+nodes[0].ID+"/traffic", url.Values{"csrf": {v.csrf()}}, nil); st != http.StatusOK || len(f.secrets) != n+1 {
		t.Fatalf("refresh: %d, %d asks", st, len(f.secrets)-n)
	}
	e.vault.Seal()
	e.s.PollTraffic(context.Background())
	if len(f.secrets) != n+1 {
		t.Fatal("nodes were asked with the vault locked")
	}
}

func TestSparkAndRates(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	pts, top := spark([]trafficSample{{At: t0, Active: 0}, {At: t0.Add(time.Minute), Active: 4}, {At: t0.Add(2 * time.Minute), Active: 2}})
	if top != 4 || pts != "0.0,46.0 150.0,2.0 300.0,24.0" {
		t.Fatalf("%q %d", pts, top)
	}
	if humanBytes(1536) != "1.5 KB" || humanRate(6<<20, time.Minute) != "102.4 KB/s" {
		t.Fatal(humanBytes(1536), humanRate(6<<20, time.Minute))
	}
}
