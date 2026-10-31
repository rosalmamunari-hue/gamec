package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"gamec/panel/internal/engine"
	"gamec/panel/internal/notify"
	"gamec/panel/internal/store"
)

type robot struct {
	mu     sync.Mutex
	got    []string
	refuse bool
	srv    *httptest.Server
}

func newRobot(t *testing.T) *robot {
	r := &robot{}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.refuse {
			io.WriteString(w, `{"code":19024,"msg":"Key Words Not Found"}`)
			return
		}
		r.got = append(r.got, string(b))
		io.WriteString(w, `{"code":0}`)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *robot) messages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

func TestARobotIsTestedBeforeItIsSaved(t *testing.T) {
	e := newEnv(t, false)
	rb := newRobot(t)
	e.s.Notifier = &notify.Sender{HTTP: rb.srv.Client()}
	a := e.admin()
	rb.refuse = true
	if st, body, _ := a.post("/alerts/add", url.Values{"csrf": {a.csrf()}, "kind": {"feishu"}, "url": {rb.srv.URL + "/hook/abc"}}, nil); st != http.StatusBadGateway || !strings.Contains(body, "Key Words") {
		t.Fatalf("a refusing robot: %d", st)
	}
	if e.st.Snapshot().Alerts != nil && len(e.st.Snapshot().Alerts.To) != 0 {
		t.Fatal("a robot that refused the test was saved")
	}
	rb.refuse = false
	if st, _, _ := a.post("/alerts/add", url.Values{"csrf": {a.csrf()}, "kind": {"feishu"}, "url": {rb.srv.URL + "/hook/abc"}}, nil); st != http.StatusSeeOther {
		t.Fatalf("add: %d", st)
	}
	if len(e.st.Snapshot().Alerts.To) != 1 || len(rb.messages()) != 1 {
		t.Fatal("saved, with one test message")
	}
	if st, _, _ := a.post("/alerts/add", url.Values{"csrf": {a.csrf()}, "kind": {"feishu"}, "url": {"http://plain.example/x"}}, nil); st != http.StatusBadRequest {
		t.Fatal("a plain http address must be refused")
	}
	if st, _, _ := e.viewer().get("/alerts"); st != http.StatusForbidden {
		t.Fatal("viewers do not manage alerts")
	}
}

func TestALockedVaultAndADeadNodeAreAnnouncedAndTheirEnd(t *testing.T) {
	e := newEnv(t, false)
	rb := newRobot(t)
	e.s.Notifier = &notify.Sender{HTTP: rb.srv.Client()}
	e.st.Mutate(func(st *store.State) error {
		st.Alerts = &store.Alerts{To: []notify.Destination{{Kind: "wecom", URL: rb.srv.URL + "/w"}}, RemindHours: 6}
		return nil
	})
	a := e.admin()
	cl := e.seedCluster("official")
	a.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {a.csrf()}, "name": {"hk"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}, nil)
	n := e.st.Snapshot().NodesOf(cl.ID)[0]
	e.st.Mutate(func(st *store.State) error { // in use: it has a list
		c := st.Cluster(cl.ID)
		c.Last = store.Published{At: e.clock, Exp: e.clock.Add(30 * 24 * time.Hour).Unix(), Verified: true}
		return nil
	})
	ctx := context.Background()

	e.vault.Seal()
	for i := 0; i < 6; i++ {
		e.s.Mon.Record(n.ID, engine.ProbeResult{At: e.clock, Err: "connect: dial tcp: i/o timeout"})
	}
	e.s.checkAlerts(ctx)
	if m := rb.messages(); len(m) != 0 {
		t.Fatalf("nothing is said in the first minutes: %v", m)
	}
	e.clock = e.clock.Add(6 * time.Minute)
	e.s.checkAlerts(ctx)
	m := strings.Join(rb.messages(), "\n")
	if !strings.Contains(m, "保险库上锁了") || !strings.Contains(m, "hk") || !strings.Contains(m, "连接超时") {
		t.Fatalf("announce: %s", m)
	}
	if !strings.Contains(m, "没有任何节点") {
		t.Fatalf("the only node is down, so the channel is: %s", m)
	}

	e.vault.Unseal(e.passph)
	e.s.Mon.Record(n.ID, engine.ProbeResult{At: e.clock, OK: true, TokenOK: true, RelayOK: true})
	for i := 0; i < 5; i++ {
		e.s.Mon.Record(n.ID, engine.ProbeResult{At: e.clock, OK: true, TokenOK: true, RelayOK: true})
	}
	before := len(rb.messages())
	e.clock = e.clock.Add(time.Minute)
	e.s.checkAlerts(ctx)
	after := rb.messages()[before:]
	if len(after) != 3 || !strings.Contains(strings.Join(after, ""), "已恢复") {
		t.Fatalf("recoveries: %v", after)
	}
	_, audit, _ := a.get("/audit?kind=alert")
	if !strings.Contains(audit, "已恢复") {
		t.Error("alerts are in the audit log")
	}
}
