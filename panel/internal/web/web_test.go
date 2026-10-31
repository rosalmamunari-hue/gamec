package web

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"gamec/edge/shieldlist"
	"gamec/panel/internal/audit"
	"gamec/panel/internal/auth"
	"gamec/panel/internal/dns"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/store"
	"gamec/panel/internal/vault"
)

const (
	pass = "a long enough password"
	pin  = "c65StCewbul2pPTQFu2ZuxI3TLhWb6lxMQacqAJDYoE="
)

type okProber struct{}

func (okProber) Probe(_ context.Context, n store.Node) engine.ProbeResult {
	return engine.ProbeResult{At: time.Now(), OK: true, TokenOK: true, RelayOK: true, Handshake: 40 * time.Millisecond}
}

type recProv struct {
	mu    sync.Mutex
	calls int
}

func (r *recProv) Name() string { return "rec" }
func (r *recProv) ReplaceTXT(_ context.Context, _, fqdn string, _ []string) error {
	if strings.HasPrefix(fqdn, "dw2.") { // the next names, written after each list
		return nil
	}
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return nil
}

type env struct {
	t        *testing.T
	s        *Server
	ts       *httptest.Server
	vault    *vault.Vault
	st       *store.Store
	auditP   string
	clock    time.Time
	adminOTP string
	viewOTP  string
	prov     *recProv
	passph   string
}

func newEnv(t *testing.T, secure bool) *env {
	t.Helper()
	dir := t.TempDir()
	const passph = "vault passphrase 123"
	v, err := vault.Create(filepath.Join(dir, "vault.json"), passph)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open(filepath.Join(dir, "state.json"))
	ap := filepath.Join(dir, "audit.log")
	al, _ := audit.Open(ap)
	users, _ := auth.OpenUsers(filepath.Join(dir, "users.json"))
	e := &env{t: t, vault: v, st: st, auditP: ap, clock: time.Unix(1_800_000_000, 0), prov: &recProv{}, passph: passph}
	e.adminOTP, _ = users.Add("alice", auth.Admin, pass, e.clock)
	e.viewOTP, _ = users.Add("victor", auth.Viewer, pass, e.clock)

	mon := engine.NewMonitor(okProber{})
	pub := &engine.Publisher{Vault: v, Store: st, Audit: al, Now: func() time.Time { return e.clock },
		Provider: func(store.DNSTarget) (dns.Provider, error) { return e.prov, nil }}
	e.s = &Server{Users: users, Sessions: auth.NewSessions(30*time.Minute, 12*time.Hour), Vault: v, Store: st, Audit: al,
		AuditPath: ap, Mon: mon, Pub: pub, Sched: engine.NewScheduler(pub, mon, st), Now: func() time.Time { return e.clock }, Secure: secure}
	e.ts = httptest.NewServer(e.s.Handler())
	t.Cleanup(e.ts.Close)
	return e
}

type client struct {
	e *env
	c *http.Client
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) get(path string) (int, string, http.Header) {
	c.e.t.Helper()
	resp, err := c.c.Get(c.e.ts.URL + path)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (c *client) post(path string, form url.Values, hdr map[string]string) (int, string, http.Header) {
	c.e.t.Helper()
	req, _ := http.NewRequest("POST", c.e.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (c *client) login(user, otp string) int {
	c.e.t.Helper()
	c.e.clock = c.e.clock.Add(31 * time.Second) // a TOTP code can be used once
	code, _ := auth.TOTPCode(otp, c.e.clock)
	st, _, _ := c.post("/login", url.Values{"user": {user}, "password": {pass}, "code": {code}}, nil)
	return st
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (c *client) csrf() string {
	c.e.t.Helper()
	_, body, _ := c.get("/")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		c.e.t.Fatalf("no csrf token on the page:\n%s", body)
	}
	return m[1]
}

func (e *env) admin() *client {
	c := e.client()
	if st := c.login("alice", e.adminOTP); st != http.StatusSeeOther {
		e.t.Fatalf("admin login: %d", st)
	}
	return c
}

func (e *env) viewer() *client {
	c := e.client()
	if st := c.login("victor", e.viewOTP); st != http.StatusSeeOther {
		e.t.Fatalf("viewer login: %d", st)
	}
	return c
}

// seedCluster makes a cluster with a key in the vault, bypassing the form.
func (e *env) seedCluster(name string) *store.Cluster {
	e.t.Helper()
	c := &store.Cluster{ID: store.NewID(), Name: name, ValidDays: 30, RenewBeforeDays: 10,
		Targets: []store.DNSTarget{{Provider: "cloudflare", Zone: "example.com", Name: "_gs.example.com", CredRef: "main"}}}
	if err := e.st.Mutate(func(s *store.State) error { s.Clusters = append(s.Clusters, c); return nil }); err != nil {
		e.t.Fatal(err)
	}
	k, _ := shieldlist.GenerateKey()
	enc, _ := shieldlist.PrivateKeyB64(k)
	e.vault.Set(engine.SigningKeyName(c.ID), enc)
	return c
}

// ---------------------------------------------------------------- authentication

func TestEverythingNeedsALogin(t *testing.T) {
	e := newEnv(t, false)
	c := e.client()
	for _, p := range []string{"/", "/audit", "/secrets", "/unseal", "/cluster/new", "/cluster/deadbeef"} {
		st, _, h := c.get(p)
		if st != http.StatusSeeOther || h.Get("Location") != "/login" {
			t.Errorf("GET %s without a session: %d -> %q", p, st, h.Get("Location"))
		}
	}
	for _, p := range []string{"/logout", "/cluster/new", "/secrets", "/unseal", "/cluster/deadbeef/publish", "/cluster/deadbeef/node"} {
		if st, _, _ := c.post(p, url.Values{}, nil); st != http.StatusUnauthorized {
			t.Errorf("POST %s without a session: %d", p, st)
		}
	}
	if st, body, _ := c.get("/login"); st != 200 || !strings.Contains(body, `name="code"`) {
		t.Error("the login page must ask for the second factor")
	}
}

func TestLoginNeedsAllThreeFactorsAndGivesOneMessage(t *testing.T) {
	e := newEnv(t, false)
	c := e.client()
	e.clock = e.clock.Add(31 * time.Second)
	good, _ := auth.TOTPCode(e.adminOTP, e.clock)
	cases := map[string]url.Values{
		"wrong password": {"user": {"alice"}, "password": {"nope nope nope nope"}, "code": {good}},
		"wrong code":     {"user": {"alice"}, "password": {pass}, "code": {"000000"}},
		"unknown user":   {"user": {"mallory"}, "password": {pass}, "code": {good}},
	}
	var msgs []string
	for what, form := range cases {
		st, body, h := c.post("/login", form, nil)
		if st != http.StatusUnauthorized || h.Get("Set-Cookie") != "" {
			t.Errorf("%s: status %d, cookie %q", what, st, h.Get("Set-Cookie"))
		}
		msgs = append(msgs, regexp.MustCompile(`data-msg>([^<]*)`).FindStringSubmatch(body)[1])
	}
	if msgs[0] != msgs[1] || msgs[1] != msgs[2] {
		t.Errorf("the message reveals which part was wrong: %v", msgs)
	}
}

func TestSessionCookieIsLockedDown(t *testing.T) {
	for _, secure := range []bool{false, true} {
		e := newEnv(t, secure)
		c := e.client()
		e.clock = e.clock.Add(31 * time.Second)
		code, _ := auth.TOTPCode(e.adminOTP, e.clock)
		_, _, h := c.post("/login", url.Values{"user": {"alice"}, "password": {pass}, "code": {code}}, nil)
		ck := h.Get("Set-Cookie")
		for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/"} {
			if !strings.Contains(ck, want) {
				t.Errorf("secure=%v cookie lacks %s: %s", secure, want, ck)
			}
		}
		if secure != strings.Contains(ck, "Secure") {
			t.Errorf("secure=%v but cookie is %s", secure, ck)
		}
	}
}

func TestLoginsAreThrottledPerAddress(t *testing.T) {
	e := newEnv(t, false)
	c := e.client()
	var last int
	for i := 0; i < 12; i++ {
		last, _, _ = c.post("/login", url.Values{"user": {"alice"}, "password": {"wrong wrong wrong"}, "code": {"000000"}}, nil)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("12 quick attempts ended with %d, want 429", last)
	}
	// even a correct login from that address is refused while throttled
	if st := c.login("alice", e.adminOTP); st != http.StatusTooManyRequests {
		t.Fatalf("a correct login while throttled: %d", st)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	tok := c.csrf()
	if st, _, _ := c.post("/logout", url.Values{"csrf": {tok}}, nil); st != http.StatusSeeOther {
		t.Fatal(st)
	}
	if st, _, h := c.get("/"); st != http.StatusSeeOther || h.Get("Location") != "/login" {
		t.Fatalf("still signed in after logout: %d", st)
	}
}

func TestSessionExpiresWhenIdle(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	e.clock = e.clock.Add(31 * time.Minute)
	if st, _, _ := c.get("/"); st != http.StatusSeeOther {
		t.Fatalf("idle session still valid: %d", st)
	}
}

// ---------------------------------------------------------------- headers, CSRF, roles

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t, true)
	c := e.client()
	for _, p := range []string{"/login", "/", "/static/app.css", "/nope"} {
		_, _, h := c.get(p)
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s: CSP %q", p, csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Referrer-Policy") != "same-origin" || h.Get("Cache-Control") != "no-store" ||
			!strings.Contains(h.Get("Strict-Transport-Security"), "max-age") {
			t.Errorf("%s: missing a header: %v", p, h)
		}
	}
}

func TestPagesUseNoInlineScriptOrStyle(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"hk"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}, nil)
	nid := e.st.Snapshot().NodesOf(cl.ID)[0].ID
	scriptTag := regexp.MustCompile(`<script[^>]*>`)
	for _, p := range []string{"/login", "/", "/cluster/new", "/cluster/" + cl.ID, "/cluster/" + cl.ID + "/node/" + nid, "/cluster/" + cl.ID + "/node/new", "/secrets", "/unseal", "/audit", "/alerts", "/account", "/ssh", "/egress"} {
		_, body, _ := c.get(p)
		low := strings.ToLower(body)
		for _, bad := range []string{"style=", "onclick=", "onload=", "onsubmit=", "javascript:"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s contains %q, which the content security policy would block", p, bad)
			}
		}
		// scripts come only from our own files, never written into the page
		for _, tag := range scriptTag.FindAllString(low, -1) {
			if !regexp.MustCompile(`^<script src="/static/[a-z0-9./-]+\.js">$`).MatchString(tag) {
				t.Errorf("%s has an inline or foreign script: %s", p, tag)
			}
		}
		if n := strings.Count(low, "<script"); n != len(scriptTag.FindAllString(low, -1)) || n != strings.Count(low, `<script src="/static/`) {
			t.Errorf("%s: scripts that are not plain /static/ files", p)
		}
	}
}

func TestChangesNeedTheCSRFToken(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	form := url.Values{"name": {"x"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}
	if st, _, _ := c.post("/cluster/"+cl.ID+"/node", form, nil); st != http.StatusForbidden {
		t.Fatalf("no token: %d", st)
	}
	form.Set("csrf", "not-the-token")
	if st, _, _ := c.post("/cluster/"+cl.ID+"/node", form, nil); st != http.StatusForbidden {
		t.Fatalf("wrong token: %d", st)
	}
	form.Set("csrf", c.csrf())
	if st, _, _ := c.post("/cluster/"+cl.ID+"/node", form, nil); st != http.StatusSeeOther {
		t.Fatalf("right token: %d", st)
	}
	if len(e.st.Snapshot().Nodes) != 1 {
		t.Fatal("the node was not added")
	}
}

func TestACrossSiteRequestIsRefusedEvenWithTheToken(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	form := url.Values{"csrf": {c.csrf()}, "name": {"x"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}
	st, _, _ := c.post("/cluster/"+cl.ID+"/node", form, map[string]string{"Origin": "https://evil.example"})
	if st != http.StatusForbidden || len(e.st.Snapshot().Nodes) != 0 {
		t.Fatalf("a request from another origin got through: %d", st)
	}
}

// Browsers send "Origin: null" for same-site forms under some referrer policies; Sec-Fetch-Site tells the truth.
func TestOriginNullIsJudgedBySecFetchSite(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	try := func(h map[string]string, host string) int {
		form := url.Values{"csrf": {c.csrf()}, "name": {"n" + host}, "host": {host}, "port": {"30800"}, "pin": {pin}}
		st, _, _ := c.post("/cluster/"+cl.ID+"/node", form, h)
		return st
	}
	if st := try(map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}, "1.2.3.4"); st == http.StatusForbidden {
		t.Fatal("a same-origin form with Origin: null was refused")
	}
	if st := try(map[string]string{"Origin": "null", "Sec-Fetch-Site": "cross-site"}, "1.2.3.5"); st != http.StatusForbidden {
		t.Fatal("a cross-site request got through")
	}
	if st := try(map[string]string{"Sec-Fetch-Site": "same-site"}, "1.2.3.6"); st != http.StatusForbidden {
		t.Fatal("a request from a sibling site got through")
	}
	if st := try(map[string]string{"Origin": "null"}, "1.2.3.7"); st != http.StatusForbidden {
		t.Fatal("Origin: null with no Sec-Fetch-Site says nothing and must be refused")
	}
	if n := len(e.st.Snapshot().Nodes); n != 1 {
		t.Fatalf("expected exactly the one same-origin node, got %d", n)
	}
}

func TestAViewerCanLookButNotTouch(t *testing.T) {
	e := newEnv(t, false)
	cl := e.seedCluster("official")
	v := e.viewer()
	if st, body, _ := v.get("/"); st != 200 || strings.Contains(body, "New cluster") {
		t.Fatalf("dashboard: %d, offers admin actions: %v", st, strings.Contains(body, "New cluster"))
	}
	if st, body, _ := v.get("/cluster/" + cl.ID); st != 200 || strings.Contains(body, "Sign and publish now") || strings.Contains(body, "Add a node") {
		t.Fatalf("cluster page shows admin controls to a viewer")
	}
	tok := v.csrf()
	for _, p := range []string{"/cluster/new", "/cluster/" + cl.ID + "/publish", "/cluster/" + cl.ID + "/node", "/cluster/" + cl.ID + "/auto", "/secrets", "/unseal"} {
		if st, _, _ := v.post(p, url.Values{"csrf": {tok}, "name": {"x"}}, nil); st != http.StatusForbidden {
			t.Errorf("a viewer got %d from POST %s", st, p)
		}
	}
	for _, p := range []string{"/cluster/new", "/secrets", "/unseal"} {
		if st, _, _ := v.get(p); st != http.StatusForbidden {
			t.Errorf("a viewer got %d from GET %s", st, p)
		}
	}
	if e.prov.calls != 0 {
		t.Fatal("a viewer triggered a publish")
	}
	if st, _, _ := v.get("/audit"); st != 200 {
		t.Fatal("viewers may read the audit log")
	}
}

// ---------------------------------------------------------------- injection

func TestUserSuppliedTextIsEscaped(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	evil := `<script>alert(1)</script>`
	c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {evil}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}, nil)
	for _, p := range []string{"/", "/cluster/" + cl.ID, "/audit"} {
		_, body, _ := c.get(p)
		if strings.Contains(body, evil) {
			t.Errorf("%s shows the script tag unescaped", p)
		}
	}
	_, body, _ := c.get("/cluster/" + cl.ID)
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the name should appear, escaped")
	}
	_, body, _ = c.get("/?ok=" + url.QueryEscape(evil))
	if strings.Contains(body, evil) {
		t.Error("the flash message from the URL is reflected unescaped")
	}
}

func TestClusterNamesWithMarkupAreRefused(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	form := newClusterForm("<b>x</b>")
	form.Set("csrf", c.csrf())
	if st, _, _ := c.post("/cluster/new", form, nil); st != http.StatusBadRequest {
		t.Fatalf("%d", st)
	}
	if len(e.st.Snapshot().Clusters) != 0 {
		t.Fatal("created")
	}
}

// ---------------------------------------------------------------- clusters, nodes, publishing

func newClusterForm(name string) url.Values {
	return url.Values{"name": {name}, "origin": {"203.0.113.5:10443"}, "valid_days": {"30"}, "renew_days": {"10"},
		"provider": {"manual"}, "zone": {"example.com"}, "dns_name": {"_gs.example.com"}}
}

func TestCreatingAClusterStoresItsKeysAndShowsTheSecretOnce(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	form := newClusterForm("channel-a")
	form.Set("csrf", c.csrf())
	st, body, _ := c.post("/cluster/new", form, nil)
	if st != 200 {
		t.Fatalf("%d %s", st, body)
	}
	cl := e.st.Snapshot().Clusters[0]
	secret, ok, _ := e.vault.Get(engine.NodeSecretName(cl.ID))
	if !ok || len(secret) != 64 {
		t.Fatalf("token secret: %q", secret)
	}
	if !strings.Contains(body, secret) {
		t.Fatal("the secret must be shown once on the creation page")
	}
	key, ok, _ := e.vault.Get(engine.SigningKeyName(cl.ID))
	if !ok {
		t.Fatal("no signing key stored")
	}
	k, err := shieldlist.ParsePrivateKeyB64(key)
	if err != nil || shieldlist.PublicKeyB64(&k.PublicKey) != cl.PublicKey || !strings.Contains(html.UnescapeString(body), cl.PublicKey) {
		t.Fatal("the shown public key does not match the stored private key")
	}
	for _, p := range []string{"/", "/cluster/" + cl.ID, "/audit", "/secrets"} {
		_, b, _ := c.get(p)
		if u := html.UnescapeString(b); strings.Contains(u, secret) || strings.Contains(u, key) {
			t.Errorf("%s shows a secret again", p)
		}
	}
}

func TestEachNewClusterGetsDifferentKeys(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	for _, n := range []string{"official", "channel-a"} {
		f := newClusterForm(n)
		f.Set("csrf", c.csrf())
		f.Set("dns_name", "_gs-"+n+".example.com")
		if st, _, _ := c.post("/cluster/new", f, nil); st != 200 {
			t.Fatalf("%s: %d", n, st)
		}
	}
	cs := e.st.Snapshot().Clusters
	k0, _, _ := e.vault.Get(engine.SigningKeyName(cs[0].ID))
	k1, _, _ := e.vault.Get(engine.SigningKeyName(cs[1].ID))
	s0, _, _ := e.vault.Get(engine.NodeSecretName(cs[0].ID))
	s1, _, _ := e.vault.Get(engine.NodeSecretName(cs[1].ID))
	if k0 == k1 || s0 == s1 || cs[0].PublicKey == cs[1].PublicKey {
		t.Fatal("two channels share a key or a token secret")
	}
}

func TestNewSecretIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s := newSecret()
		if len(s) != 64 || seen[s] || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s) {
			t.Fatalf("bad secret %q", s)
		}
		seen[s] = true
	}
}

func TestCreatingAClusterWhileSealedIsRefusedAndLeavesNothing(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	e.vault.Seal()
	f := newClusterForm("official")
	f.Set("csrf", c.csrf())
	if st, _, _ := c.post("/cluster/new", f, nil); st != http.StatusBadRequest {
		t.Fatalf("%d", st)
	}
	if len(e.st.Snapshot().Clusters) != 0 {
		t.Fatal("a cluster without keys was left behind")
	}
}

func TestNodeValidationErrorsAreShown(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	st, body, _ := c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"x"}, "host": {"1.2.3.4"}, "port": {"99999"}, "pin": {pin}}, nil)
	if st != http.StatusBadRequest || !strings.Contains(body, "port") {
		t.Fatalf("%d", st)
	}
}

func TestPausingAndSwitchingOffAndDeletingANode(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"hk"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}, nil)
	n := e.st.Snapshot().Nodes[0]
	base := "/cluster/" + cl.ID + "/node/" + n.ID

	if st, _, _ := c.post(base+"/pause", url.Values{"csrf": {c.csrf()}, "minutes": {"30"}}, nil); st != http.StatusSeeOther {
		t.Fatal(st)
	}
	got := e.st.Snapshot().Node(n.ID)
	if d := got.DisabledUntil.Sub(e.clock); d < 29*time.Minute || d > 31*time.Minute {
		t.Fatalf("paused for %v", d)
	}
	if len(e.st.Snapshot().Active(cl.ID, e.clock)) != 0 {
		t.Fatal("a paused node is still active")
	}
	if len(e.st.Snapshot().Active(cl.ID, e.clock.Add(31*time.Minute))) != 1 {
		t.Fatal("the pause did not end by itself")
	}
	if st, _, _ := c.post(base+"/pause", url.Values{"csrf": {c.csrf()}, "minutes": {"0"}}, nil); st != http.StatusBadRequest {
		t.Fatal("0 minutes accepted")
	}

	c.post(base+"/enable", url.Values{"csrf": {c.csrf()}, "enabled": {"0"}}, nil)
	if e.st.Snapshot().Node(n.ID).Enabled {
		t.Fatal("not switched off")
	}
	c.post(base+"/delete", url.Values{"csrf": {c.csrf()}}, nil)
	if len(e.st.Snapshot().Nodes) != 0 {
		t.Fatal("not deleted")
	}
	if st, _, _ := c.post("/cluster/"+cl.ID+"/node/deadbeef/delete", url.Values{"csrf": {c.csrf()}}, nil); st != http.StatusBadRequest {
		t.Fatal("deleting a node that does not exist should say so")
	}
}

func TestANodeOfAnotherClusterCannotBeTouchedThroughThisOne(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	a, b := e.seedCluster("official"), e.seedCluster("channel-a")
	c.post("/cluster/"+b.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"b1"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}, nil)
	nb := e.st.Snapshot().Nodes[0]
	st, _, _ := c.post("/cluster/"+a.ID+"/node/"+nb.ID+"/delete", url.Values{"csrf": {c.csrf()}}, nil)
	if st != http.StatusBadRequest || len(e.st.Snapshot().Nodes) != 1 {
		t.Fatalf("cluster A deleted cluster B's node: %d", st)
	}
}

func TestPublishingByHandSignsSendsAndTurnsAutoOn(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"hk"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}, nil)

	if st, _, _ := c.post("/cluster/"+cl.ID+"/auto", url.Values{"csrf": {c.csrf()}, "auto": {"1"}}, nil); st != http.StatusBadRequest {
		t.Fatal("automatic publishing must not be switched on before a first manual publish")
	}
	if st, _, _ := c.post("/cluster/"+cl.ID+"/publish", url.Values{"csrf": {c.csrf()}}, nil); st != http.StatusSeeOther {
		t.Fatalf("publish: %d", st)
	}
	if e.prov.calls != 1 {
		t.Fatalf("provider calls: %d", e.prov.calls)
	}
	got := e.st.Snapshot().Cluster(cl.ID)
	if got.Last.At.IsZero() || !got.AutoPublish {
		t.Fatalf("%+v", got.Last)
	}
	_, body, _ := c.get("/cluster/" + cl.ID)
	if u := html.UnescapeString(body); !strings.Contains(u, got.PublicKey) || !strings.Contains(u, "1.2.3.4:30800") {
		t.Fatal("the cluster page should show the key for the app and the published nodes")
	}
}

func TestPublishingAnEmptyClusterFailsClearly(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	st, body, _ := c.post("/cluster/"+cl.ID+"/publish", url.Values{"csrf": {c.csrf()}}, nil)
	if st != http.StatusBadGateway || !strings.Contains(body, "empty") || e.prov.calls != 0 {
		t.Fatalf("%d calls=%d", st, e.prov.calls)
	}
}

// ---------------------------------------------------------------- vault and secrets

func TestSealedVaultIsAnnouncedAndUnsealingWorks(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	e.vault.Seal()
	_, body, _ := c.get("/")
	if !strings.Contains(body, "上锁") {
		t.Fatal("the dashboard does not say the vault is sealed")
	}
	if st, _, _ := c.post("/unseal", url.Values{"csrf": {c.csrf()}, "passphrase": {"wrong wrong wrong"}}, nil); st != http.StatusUnauthorized || !e.vault.Sealed() {
		t.Fatal("a wrong passphrase unsealed the vault")
	}
	if st, _, _ := c.post("/unseal", url.Values{"csrf": {c.csrf()}, "passphrase": {e.passph}}, nil); st != http.StatusSeeOther || e.vault.Sealed() {
		t.Fatal("the right passphrase did not unseal")
	}
}

func TestSecretsAreWriteOnly(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	const val = "cf-token-VALUE-that-must-not-reappear"
	e.s.CFZones = func(_ context.Context, tok string) ([]string, error) { return []string{"example.com"}, nil }
	st, saved, _ := c.post("/secrets", url.Values{"csrf": {c.csrf()}, "ref": {"main"}, "field": {"api_token"}, "value": {val}}, nil)
	if st != http.StatusOK || !strings.Contains(saved, "令牌可以用") || strings.Contains(saved, val) {
		t.Fatalf("saving a token should test it at once and never echo it: %d", st)
	}
	got, ok, _ := e.vault.Get("dns/main/api_token")
	if !ok || got != val {
		t.Fatal("not stored")
	}
	_, body, _ := c.get("/secrets")
	if !strings.Contains(body, "<b>main</b>") || !strings.Contains(body, "api_token") || strings.Contains(body, val) {
		t.Fatal("the page must list names but never values")
	}
	raw, _ := os.ReadFile(e.auditP)
	if strings.Contains(string(raw), val) {
		t.Fatal("the secret value reached the audit log")
	}
	for _, bad := range []url.Values{
		{"ref": {"Bad Name!"}, "field": {"api_token"}, "value": {"x"}},
		{"ref": {"main"}, "field": {"../../etc"}, "value": {"x"}},
		{"ref": {"main"}, "field": {"api_token"}, "value": {""}},
	} {
		bad.Set("csrf", c.csrf())
		if st, _, _ := c.post("/secrets", bad, nil); st != http.StatusBadRequest {
			t.Errorf("accepted %v", bad)
		}
	}
}

// ---------------------------------------------------------------- audit

func TestEveryChangeIsAuditedWithWhoAndFromWhere(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {c.csrf()}, "name": {"hk"}, "host": {"1.2.3.4"}, "port": {"30800"}, "pin": {pin}}, nil)
	c.post("/cluster/"+cl.ID+"/node", url.Values{"csrf": {"bad"}, "name": {"x"}}, nil)
	v := e.viewer()
	v.post("/cluster/"+cl.ID+"/publish", url.Values{"csrf": {v.csrf()}}, nil)

	_, body, _ := c.get("/audit")
	for _, want := range []string{"login", "node-add", "csrf-rejected", "forbidden", "alice", "victor", "没有被改动"} {
		if !strings.Contains(body, want) {
			t.Errorf("the audit page does not mention %q", want)
		}
	}
	if n, err := audit.Verify(e.auditP); err != nil || n < 5 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestSealingTheListMakesAKeyShowsItAndCanBeSwitchedOff(t *testing.T) {
	e := newEnv(t, false)
	c := e.admin()
	cl := e.seedCluster("official")
	if st, _, _ := c.post("/cluster/"+cl.ID+"/seal", url.Values{"csrf": {c.csrf()}, "seal": {"1"}}, nil); st != http.StatusSeeOther {
		t.Fatalf("seal on: %d", st)
	}
	if !e.st.Snapshot().Cluster(cl.ID).Sealed {
		t.Fatal("not marked sealed")
	}
	key, ok, _ := e.vault.Get(engine.SealKeyName(cl.ID))
	if !ok || key == "" {
		t.Fatal("no key in the vault")
	}
	if _, body, _ := c.get("/cluster/" + cl.ID); !strings.Contains(html.UnescapeString(body), key) {
		t.Fatal("the cluster page does not show the key the app needs")
	}
	if _, body, _ := e.viewer().get("/cluster/" + cl.ID); strings.Contains(html.UnescapeString(body), key) {
		t.Fatal("a read-only account was shown the list key")
	}
	if st, _, _ := c.post("/cluster/"+cl.ID+"/seal", url.Values{"csrf": {c.csrf()}, "seal": {"0"}}, nil); st != http.StatusSeeOther || e.st.Snapshot().Cluster(cl.ID).Sealed {
		t.Fatal("seal off did not work")
	}
	again, _, _ := e.vault.Get(engine.SealKeyName(cl.ID))
	if again != key {
		t.Fatal("the key must be kept when sealing is switched off, so switching it on again does not break apps")
	}
}
