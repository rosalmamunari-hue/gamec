package web

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"gamec/edge/shieldclient"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/notify"
	"gamec/panel/internal/store"
)

// TestDemoServer serves the panel with made-up channels so its pages can be looked at in a browser:
//
//	GAMEC_DEMO=127.0.0.1:8099 go test ./internal/web -run TestDemoServer -timeout 0
//
// It writes the admin session cookie to $GAMEC_DEMO_COOKIE (if set) and runs until $GAMEC_DEMO_STOP exists.
func TestDemoServer(t *testing.T) {
	addr := os.Getenv("GAMEC_DEMO")
	if addr == "" {
		t.Skip("set GAMEC_DEMO=host:port to run the demo server")
	}
	e := newEnv(t, false)
	e.clock = time.Now()
	e.s.Now = time.Now
	e.s.ReleaseBase = ""

	a := e.admin()
	official := e.seedCluster("官服")
	e.st.Mutate(func(st *store.State) error {
		c := st.Cluster(official.ID)
		c.Origin = "203.0.113.50:10443"
		c.Targets = append(c.Targets, store.DNSTarget{Provider: "cloudflare", Zone: "example.net", Name: "update.example.net", CredRef: "main"})
		return nil
	})
	for i, n := range []struct{ name, host string }{{"hk-1", "203.0.113.11"}, {"hk-2", "203.0.113.12"}, {"sg-1", "203.0.113.13"}} {
		a.post("/cluster/"+official.ID+"/node", url.Values{"csrf": {a.csrf()}, "name": {n.name}, "host": {n.host}, "port": {[]string{"48860", "30522", "23198"}[i]}, "pin": {pin}}, nil)
	}
	e.s.Vault.Set("dns/main/api_token", "demo")
	time.Sleep(200 * time.Millisecond) // the probes started by adding the nodes
	nodes := e.st.Snapshot().NodesOf(official.ID)
	for round := 0; round < 40; round++ {
		at := time.Now().Add(time.Duration(round-40) * time.Minute)
		for _, n := range nodes {
			r := engine.ProbeResult{At: at, OK: true, TokenOK: true, RelayOK: true, Handshake: time.Duration(30+round%7*3) * time.Millisecond}
			if n.Name == "sg-1" && round > 33 {
				r = engine.ProbeResult{At: at, Err: "connect: dial tcp 203.0.113.13:23198: i/o timeout"}
			}
			e.s.Mon.Record(n.ID, r)
		}
	}
	a.post("/cluster/"+official.ID+"/publish", url.Values{"csrf": {a.csrf()}}, nil)
	e.st.Mutate(func(st *store.State) error { st.Cluster(official.ID).Last.Verified = true; return nil })
	e.s.origins.res = map[string]originResult{official.ID: {At: time.Now(), Err: "连接超时（被防火墙挡住了）"}}

	// an hour of connection numbers for hk-1 and hk-2; sg-1 runs an older node program that reports none
	started := time.Now().Add(-26 * time.Hour).Unix()
	for _, n := range nodes {
		if n.Name == "sg-1" {
			e.s.traffic.record(n.ID, nil, shieldclient.ErrNoStats, time.Now())
			continue
		}
		var up, down uint64 = 3 << 30, 41 << 30
		for m := 0; m < 60; m++ {
			at := time.Now().Add(time.Duration(m-59) * time.Minute)
			active := 180 + 60*((m/7)%3) + m*2
			if n.Name == "hk-2" {
				active = active * 2 / 3
			}
			up += uint64(active) * 900
			down += uint64(active) * 14000
			st := &shieldclient.NodeStats{At: at.Unix(), Started: started, MaxConns: 10000, MaxPerIP: 20,
				Active: active, Devices: active * 2 / 5, IPs: active / 3, Relays: 48211 + uint64(m)*97, Tokens: 19302 + uint64(m)*31,
				BytesUp: up, BytesDown: down, Version: "v0.5.1",
				Refused: map[string]uint64{"no_frame": 3120, "bad_token": 41, "per_ip": 12, "token_refused": 6},
				Top: []shieldclient.IPLoad{{IP: "223.104.3.17", Relays: 20, Devices: 9}, {IP: "117.136.12.88", Relays: 14, Devices: 6},
					{IP: "2409:8a55:1a2b:3c4d::/64", Relays: 9, Devices: 3}, {IP: "112.97.54.201", Relays: 4, Devices: 2}}}
			e.s.traffic.record(n.ID, st, nil, at)
		}
	}
	e.st.Mutate(func(st *store.State) error {
		for _, n := range st.NodesOf(official.ID) {
			if n.Name == "hk-2" {
				n.DisabledUntil = time.Now().Add(24 * time.Minute)
			}
		}
		return nil
	})

	e.seedCluster("测试渠道")
	e.st.Mutate(func(st *store.State) error {
		st.Alerts = &store.Alerts{RemindHours: 6, To: []notify.Destination{{Kind: "feishu", URL: "https://open.feishu.cn/open-apis/bot/v2/hook/demo"}}}
		return nil
	})
	e.s.alerter().Update(time.Now().Add(-10*time.Minute), e.s.alertConditions())
	e.s.alerter().Record(notify.Sent{At: time.Now().Add(-4 * time.Minute), Text: "🟡 渠道「官服」的节点 sg-1（203.0.113.13:23198）连续 6 次检查失败，已从名单拿掉：连接超时"})

	if p := os.Getenv("GAMEC_DEMO_COOKIE"); p != "" {
		u, _ := url.Parse(e.ts.URL)
		for _, c := range a.c.Jar.Cookies(u) {
			if c.Name == cookieName {
				os.WriteFile(p, []byte(c.Value), 0o600)
			}
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var session string
	if u, _ := url.Parse(e.ts.URL); u != nil {
		for _, c := range a.c.Jar.Cookies(u) {
			if c.Name == cookieName {
				session = c.Value
			}
		}
	}
	h := e.s.Handler()
	// Demo only: every request is the admin's, so a headless browser can take screenshots without logging in.
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(cookieName); err != nil && r.URL.Path != "/login" {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: session})
		}
		h.ServeHTTP(w, r)
	})}
	go srv.Serve(ln)
	t.Logf("demo panel on http://%s", addr)
	stop := os.Getenv("GAMEC_DEMO_STOP")
	for {
		if _, err := os.Stat(stop); stop != "" && err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	srv.Shutdown(context.Background())
}
