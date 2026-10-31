package web

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"gamec/panel/internal/engine"
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

	e.seedCluster("测试渠道")

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
