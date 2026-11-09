package web

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"gamec/edge/shieldclient"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/store"
)

// Two nodes forward along Gcore, then a backup. When Gcore stops answering on both, the panel raises an alert
// that says players are not affected (the backup still works); when the backup goes too, one that says they
// are; once both answer again, the alerts close.
func TestALineGoingDownIsAlertedOn(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	e.vault.Set(engine.NodeSecretName(cl.ID), "the-node-secret-0123456789")
	for i, h := range []string{"1.2.3.4", "5.6.7.8"} {
		c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"n" + string(rune('1'+i))}, "host": {h}, "port": {"30800"}, "pin": {pin}}, nil)
	}
	e.st.Mutate(func(st *store.State) error {
		st.Cluster(cl.ID).Last = store.Published{At: e.clock, Exp: e.clock.Add(30 * 24 * time.Hour).Unix(), Verified: true}
		return nil
	})
	report := func(gcoreUp, backupUp bool) {
		f := &fakeStats{answer: map[string]*shieldclient.NodeStats{}}
		for _, h := range []string{"1.2.3.4", "5.6.7.8"} {
			g := shieldclient.OriginState{Addr: "193.0.2.1:21443", Up: gcoreUp, Used: 10}
			if !gcoreUp {
				g.Fails, g.LastFail, g.DownFrom, g.LastErr = 4, e.clock.Unix(), e.clock.Add(-time.Minute).Unix(), "dial tcp 193.0.2.1:21443: i/o timeout"
			}
			b := shieldclient.OriginState{Addr: "198.51.100.7:21444", Up: backupUp}
			if !backupUp {
				b.Fails, b.DownFrom = 1, e.clock.Unix()
			}
			f.answer[h] = &shieldclient.NodeStats{At: e.clock.Unix(), Started: e.clock.Add(-time.Hour).Unix(), Origins: []shieldclient.OriginState{g, b}}
		}
		e.s.FetchStats = f.fetch
		e.s.PollTraffic(context.Background())
	}
	lineAlerts := func() []string {
		var out []string
		for _, cond := range e.s.alertConditions() {
			if strings.Contains(cond.Key, ":line:") {
				out = append(out, cond.Text)
			}
		}
		return out
	}

	report(true, true)
	if a := lineAlerts(); len(a) != 0 {
		t.Fatal("alerts with every line up:", a)
	}
	report(false, true)
	a := lineAlerts()
	if len(a) != 1 || !strings.Contains(a[0], "193.0.2.1:21443（2/2 个节点）") || !strings.Contains(a[0], "玩家不受影响") || !strings.Contains(a[0], "连接超时") {
		t.Fatal(a)
	}
	report(false, false)
	if a := lineAlerts(); len(a) != 2 || !strings.Contains(a[0], "玩家现在连不上") {
		t.Fatal(a)
	}
	if _, body, _ := c.get("/cluster/" + cl.ID); !strings.Contains(body, "源站线路") || !strings.Contains(body, "2/2 个节点连不上") || !strings.Contains(body, "连接超时") {
		t.Fatal("the channel page does not show the lines")
	}
	report(true, true)
	if a := lineAlerts(); len(a) != 0 {
		t.Fatal("the alerts did not close:", a)
	}

	// A report older than a few minutes no longer counts: a node that stopped answering is alerted on as such.
	report(false, true)
	e.clock = e.clock.Add(10 * time.Minute)
	if a := lineAlerts(); len(a) != 0 {
		t.Fatal("stale reports still count:", a)
	}
}
