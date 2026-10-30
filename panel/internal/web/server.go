// Package web is the panel's browser interface. Every page needs a login; every change needs a CSRF token
// and the administrator role; secrets are write-only (the interface never shows a stored secret again).
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gamec/edge/shieldlist"
	"gamec/panel/internal/audit"
	"gamec/panel/internal/auth"
	"gamec/panel/internal/egress"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/ops"
	"gamec/panel/internal/store"
	"gamec/panel/internal/vault"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	Users     *auth.Users
	Sessions  *auth.Sessions
	Vault     *vault.Vault
	Store     *store.Store
	Audit     *audit.Log
	AuditPath string
	Mon       *engine.Monitor
	Pub       *engine.Publisher
	Sched     *engine.Scheduler
	Now       func() time.Time

	// SSH management of nodes (optional).
	Ops          *ops.Ops
	Releases     *ops.Releases
	ReleaseBase  string // like https://github.com/OWNER/REPO/releases/download
	FetchHostKey func(addr string, timeout time.Duration) (fingerprint, keyType string, err error)
	// FetchJumpKey reads the egress host's key (always directly); nil means sshx.FetchHostKey.
	FetchJumpKey func(addr string, timeout time.Duration) (fingerprint, keyType string, err error)
	// Egress sends connections to nodes through a jump host; nil means they are made directly.
	Egress *egress.Egress

	// Secure marks cookies Secure and sends HSTS: set it whenever the panel is served over HTTPS.
	Secure bool
	// TrustProxy reads the client address from X-Forwarded-For (the last entry, added by the proxy in
	// front). Only turn it on when the panel is reachable only through that proxy.
	TrustProxy bool

	tpl  *template.Template
	lim  *limiter
	once sync.Once
}

const cookieName = "gc_session"

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) init() {
	s.once.Do(func() {
		funcs := template.FuncMap{
			"ago":      func(t time.Time) string { return humanAgo(s.now(), t) },
			"until":    func(unix int64) string { return humanUntil(s.now(), unix) },
			"ms":       func(d time.Duration) string { return fmt.Sprintf("%d ms", d.Milliseconds()) },
			"ts":       func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") },
			"unixTime": func(u int64) time.Time { return time.Unix(u, 0) },
			"list":     func(v ...string) []string { return v },
		}
		s.tpl = template.Must(template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html"))
		s.lim = newLimiter(10, 10*time.Minute)
	})
}

func humanAgo(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d 分鐘前", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d 小時前", int(d.Hours()))
	}
	return fmt.Sprintf("%d 天前", int(d.Hours()/24))
}

func humanUntil(now time.Time, unix int64) string {
	if unix == 0 {
		return "尚未發布"
	}
	d := time.Unix(unix, 0).Sub(now)
	switch {
	case d <= 0:
		return "EXPIRED"
	case d < 48*time.Hour:
		return fmt.Sprintf("剩 %d 小時", int(d.Hours()))
	}
	return fmt.Sprintf("剩 %d 天", int(d.Hours()/24))
}

// ---------------------------------------------------------------- login throttling

type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

// allow records an attempt and says whether it is within the limit.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// ---------------------------------------------------------------- request helpers

func (s *Server) clientIP(r *http.Request) string {
	if s.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

type ctxKey struct{}

type page struct {
	Title  string
	User   string
	Admin  bool
	CSRF   string
	Sealed bool
	Flash  string
	Error  string
	Data   any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page, status int) {
	sess, _ := r.Context().Value(ctxKey{}).(*auth.Session)
	if sess != nil {
		p.User, p.Admin, p.CSRF = sess.User, sess.Role == auth.Admin, sess.CSRF
	}
	p.Sealed = s.Vault.Sealed()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tpl.ExecuteTemplate(w, name, p); err != nil {
		fmt.Fprintf(w, "template error")
	}
}

func (s *Server) log(r *http.Request, action, detail string, ok bool) {
	user := "-"
	if sess, _ := r.Context().Value(ctxKey{}).(*auth.Session); sess != nil {
		user = sess.User
	}
	if s.Audit != nil {
		s.Audit.Append(audit.Entry{User: user, IP: s.clientIP(r), Action: action, Detail: detail, OK: ok})
	}
}

// ---------------------------------------------------------------- middleware

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if s.Secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin refuses a state-changing request whose Origin (or Referer) points somewhere else.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		o = r.Header.Get("Referer")
	}
	if o == "" {
		return true // old clients; the CSRF token still protects
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

// need wraps a handler: it requires a live session, the admin role if admin is true, and for POST a valid
// CSRF token and same-origin request.
func (s *Server) need(admin bool, h func(http.ResponseWriter, *http.Request, *auth.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var sess *auth.Session
		if err == nil {
			sess, _ = s.Sessions.Get(c.Value, s.now())
		}
		if sess == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				http.Error(w, "請重新登入", http.StatusUnauthorized)
			}
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess))
		if r.Method == http.MethodPost {
			if !sameOrigin(r) || !auth.CheckCSRF(sess.CSRF, r.FormValue("csrf")) {
				s.log(r, "csrf-rejected", r.URL.Path, false)
				http.Error(w, "表單已過期或來自其他網站；請重新整理頁面再試一次", http.StatusForbidden)
				return
			}
		}
		if admin && sess.Role != auth.Admin {
			s.log(r, "forbidden", r.Method+" "+r.URL.Path, false)
			http.Error(w, "這個操作需要管理員權限", http.StatusForbidden)
			return
		}
		h(w, r, sess)
	}
}

// ---------------------------------------------------------------- routes

func (s *Server) Handler() http.Handler {
	s.init()
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(assets))
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.need(false, s.logout))

	mux.HandleFunc("GET /{$}", s.need(false, s.dashboard))
	mux.HandleFunc("GET /cluster/new", s.need(true, s.clusterNewForm))
	mux.HandleFunc("POST /cluster/new", s.need(true, s.clusterCreate))
	mux.HandleFunc("GET /cluster/{id}", s.need(false, s.clusterPage))
	mux.HandleFunc("POST /cluster/{id}/node", s.need(true, s.nodeAdd))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/enable", s.need(true, s.nodeEnable))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/pause", s.need(true, s.nodePause))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/delete", s.need(true, s.nodeDelete))
	mux.HandleFunc("POST /cluster/{id}/probe", s.need(true, s.probeNow))
	mux.HandleFunc("POST /cluster/{id}/publish", s.need(true, s.publishNow))
	mux.HandleFunc("POST /cluster/{id}/auto", s.need(true, s.autoToggle))
	mux.HandleFunc("POST /cluster/{id}/target", s.need(true, s.targetAdd))
	mux.HandleFunc("POST /cluster/{id}/target/{idx}/delete", s.need(true, s.targetDelete))

	mux.HandleFunc("GET /secrets", s.need(true, s.secretsPage))
	mux.HandleFunc("POST /secrets", s.need(true, s.secretSet))
	mux.HandleFunc("GET /unseal", s.need(true, s.unsealForm))
	mux.HandleFunc("POST /unseal", s.need(true, s.unsealSubmit))
	mux.HandleFunc("GET /audit", s.need(false, s.auditPage))
	s.routesSSH(mux)
	s.routesEgress(mux)
	return s.headers(mux)
}

// ---------------------------------------------------------------- login / logout

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login.html", page{Title: "登入"}, http.StatusOK)
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.lim.allow("login:"+ip, s.now()) {
		s.log(r, "login-throttled", "ip="+ip, false)
		s.render(w, r, "login.html", page{Title: "登入", Error: "這個位址嘗試次數過多，請等幾分鐘再試。"}, http.StatusTooManyRequests)
		return
	}
	name := strings.TrimSpace(r.FormValue("user"))
	u, err := s.Users.Authenticate(name, r.FormValue("password"), r.FormValue("code"), s.now())
	if err != nil {
		s.log(r, "login-failed", "user="+safe(name), false)
		// the same message for every failure, locked accounts included
		s.render(w, r, "login.html", page{Title: "登入", Error: "登入失敗。請檢查使用者名稱、密碼和驗證碼。"}, http.StatusUnauthorized)
		return
	}
	sess := s.Sessions.Create(u.Name, u.Role, s.now())
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sess.Token, Path: "/", HttpOnly: true,
		Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	s.log(r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)), "login", "", true)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	s.log(r, "logout", "", true)
	s.Sessions.Destroy(sess.Token)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.Secure})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// safe strips control characters from user-supplied text before it goes into the audit log.
func safe(s string) string {
	if len(s) > 60 {
		s = s[:60]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '?'
		}
		return r
	}, s)
}

// ---------------------------------------------------------------- dashboard and cluster pages

type nodeView struct {
	N       *store.Node
	Status  string // ok | fail | ejected | paused | off | unknown
	Detail  string
	Latency string
}

func (s *Server) nodeViews(st store.State, c *store.Cluster) []nodeView {
	now := s.now()
	var out []nodeView
	for _, n := range st.NodesOf(c.ID) {
		v := nodeView{N: n}
		h := s.Mon.Health(n.ID)
		switch {
		case !n.Enabled:
			v.Status, v.Detail = "off", "已關閉"
		case now.Before(n.DisabledUntil):
			v.Status, v.Detail = "paused", "暫停至 "+n.DisabledUntil.UTC().Format("15:04 UTC")
		case !h.Seen:
			v.Status, v.Detail = "unknown", "尚未探測"
		case h.Ejected:
			v.Status, v.Detail = "ejected", fmt.Sprintf("已移出名單：連續 %d 次探測失敗（%s）", h.ConsecFail, h.Last.Err)
		case h.Last.OK:
			v.Status, v.Detail, v.Latency = "ok", "全部檢查通過", fmt.Sprintf("%d ms", h.Last.Handshake.Milliseconds())
		default:
			v.Status, v.Detail = "fail", fmt.Sprintf("失敗中（連續 %d 次）：%s", h.ConsecFail, h.Last.Err)
		}
		out = append(out, v)
	}
	return out
}

type clusterRow struct {
	C       *store.Cluster
	Nodes   []nodeView
	OK, All int
	Expiry  string
	Alerts  []string
	Note    string
}

func (s *Server) clusterRow(st store.State, c *store.Cluster) clusterRow {
	row := clusterRow{C: c, Nodes: s.nodeViews(st, c), Note: s.Sched.Note(c.ID)}
	for _, n := range row.Nodes {
		row.All++
		if n.Status == "ok" {
			row.OK++
		}
	}
	row.Expiry = humanUntil(s.now(), c.Last.Exp)
	now := s.now()
	switch {
	case c.Last.At.IsZero():
		row.Alerts = append(row.Alerts, "never published")
	case time.Unix(c.Last.Exp, 0).Before(now):
		row.Alerts = append(row.Alerts, "the published list has EXPIRED: players cannot find nodes")
	case time.Unix(c.Last.Exp, 0).Sub(now) < time.Duration(c.RenewBeforeDays)*24*time.Hour:
		row.Alerts = append(row.Alerts, "名單已進入續期期間")
	}
	if c.Last.Manual {
		row.Alerts = append(row.Alerts, "records are waiting to be pasted at a manual DNS target")
	}
	if !c.Last.At.IsZero() && !c.Last.Manual && !c.Last.Verified {
		row.Alerts = append(row.Alerts, "最近一次發布無法從外部讀回驗證")
	}
	if row.All > 0 && row.OK == 0 {
		row.Alerts = append(row.Alerts, "沒有任何節點通過檢查")
	}
	return row
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	st := s.Store.Snapshot()
	var rows []clusterRow
	for _, c := range st.Clusters {
		rows = append(rows, s.clusterRow(st, c))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].C.Name < rows[j].C.Name })
	s.render(w, r, "dashboard.html", page{Title: "集群", Flash: r.URL.Query().Get("ok"), Data: rows}, http.StatusOK)
}

type clusterPageData struct {
	Row    clusterRow
	Others []string
}

func (s *Server) clusterPage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.renderCluster(w, r, r.PathValue("id"), "", "", http.StatusOK)
}

func (s *Server) renderCluster(w http.ResponseWriter, r *http.Request, id, flash, errMsg string, status int) {
	st := s.Store.Snapshot()
	c := st.Cluster(id)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	if flash == "" {
		flash = r.URL.Query().Get("ok")
	}
	s.render(w, r, "cluster.html", page{Title: c.Name, Flash: flash, Error: errMsg,
		Data: clusterPageData{Row: s.clusterRow(st, c)}}, status)
}

// ---------------------------------------------------------------- creating a cluster

type createdData struct {
	Cluster    *store.Cluster
	NodeSecret string
	PublicKey  string
}

func (s *Server) clusterNewForm(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.render(w, r, "cluster_new.html", page{Title: "新增集群"}, http.StatusOK)
}

var clusterNameRe = regexp.MustCompile(`^[^<>"'&\x00-\x1f]{1,60}$`)

func (s *Server) clusterCreate(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	fail := func(msg string) {
		s.render(w, r, "cluster_new.html", page{Title: "新增集群", Error: msg}, http.StatusBadRequest)
	}
	if s.Vault.Sealed() {
		fail("保險庫是封存狀態；請先解封，新集群需要把金鑰存進去。")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !clusterNameRe.MatchString(name) {
		fail("名稱必須是 1-60 個字元，且不能包含 < > \" ' &。")
		return
	}
	valid, err1 := strconv.Atoi(r.FormValue("valid_days"))
	renew, err2 := strconv.Atoi(r.FormValue("renew_days"))
	if err1 != nil || err2 != nil {
		fail("有效期與續期天數必須是數字。")
		return
	}
	c := &store.Cluster{
		ID: store.NewID(), Name: name, Origin: strings.TrimSpace(r.FormValue("origin")),
		ValidDays: valid, RenewBeforeDays: renew, Created: s.now(),
		Targets: []store.DNSTarget{{
			Provider: r.FormValue("provider"), Zone: strings.ToLower(strings.TrimSpace(r.FormValue("zone"))),
			Name: strings.ToLower(strings.TrimSpace(r.FormValue("dns_name"))), CredRef: strings.TrimSpace(r.FormValue("cred_ref")),
		}},
	}
	key, err := shieldlist.GenerateKey()
	if err != nil {
		fail(err.Error())
		return
	}
	enc, _ := shieldlist.PrivateKeyB64(key)
	c.PublicKey = shieldlist.PublicKeyB64(&key.PublicKey)
	secret := newSecret()

	if err := s.Store.Mutate(func(st *store.State) error { st.Clusters = append(st.Clusters, c); return nil }); err != nil {
		fail(err.Error())
		return
	}
	if err := s.Vault.Set(engine.SigningKeyName(c.ID), enc); err == nil {
		err = s.Vault.Set(engine.NodeSecretName(c.ID), secret)
	}
	if _, ok, _ := s.Vault.Get(engine.NodeSecretName(c.ID)); !ok {
		s.Store.Mutate(func(st *store.State) error { // do not leave a cluster without keys behind
			for i, x := range st.Clusters {
				if x.ID == c.ID {
					st.Clusters = append(st.Clusters[:i], st.Clusters[i+1:]...)
				}
			}
			return nil
		})
		fail("金鑰無法儲存，所以沒有建立任何東西。")
		return
	}
	s.log(r, "cluster-create", "cluster="+c.Name, true)
	// The only time the node secret is shown. Afterwards it can only be read on the server itself.
	s.render(w, r, "cluster_created.html", page{Title: "集群已建立", Data: createdData{Cluster: c, NodeSecret: secret, PublicKey: c.PublicKey}}, http.StatusOK)
}

// newSecret returns 32 bytes from the system's secure random source, as hex. It is the shared secret that
// lets the nodes of a cluster check the tokens they issue.
func newSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("no secure random source: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------- nodes

func (s *Server) back(w http.ResponseWriter, r *http.Request, id, msg string) {
	http.Redirect(w, r, "/cluster/"+id+"?ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *Server) nodeAdd(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	port, _ := strconv.Atoi(r.FormValue("port"))
	n := &store.Node{ID: store.NewID(), ClusterID: id, Name: strings.TrimSpace(r.FormValue("name")),
		Host: strings.TrimSpace(r.FormValue("host")), Port: port, Pin: strings.TrimSpace(r.FormValue("pin")),
		Enabled: true, Created: s.now()}
	err := s.Store.Mutate(func(st *store.State) error {
		if st.Cluster(id) == nil {
			return fmt.Errorf("沒有這個集群")
		}
		st.Nodes = append(st.Nodes, n)
		return nil
	})
	if err != nil {
		s.log(r, "node-add", "error="+err.Error(), false)
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "node-add", fmt.Sprintf("cluster=%s node=%s %s", id, safe(n.Name), n.Addr()), true)
	go s.Mon.ProbeAll(context.Background(), []*store.Node{n})
	s.back(w, r, id, "節點已新增。通過檢查後會加入發布的名單。")
}

func (s *Server) mutateNode(w http.ResponseWriter, r *http.Request, action string, fn func(*store.Node) error) {
	id, nid := r.PathValue("id"), r.PathValue("nid")
	var label string
	err := s.Store.Mutate(func(st *store.State) error {
		n := st.Node(nid)
		if n == nil || n.ClusterID != id {
			return fmt.Errorf("這個集群裡沒有這個節點")
		}
		label = n.Addr()
		return fn(n)
	})
	if err != nil {
		s.log(r, action, "error="+err.Error(), false)
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, action, fmt.Sprintf("cluster=%s node=%s", id, label), true)
	s.back(w, r, id, "完成。")
}

func (s *Server) nodeEnable(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	on := r.FormValue("enabled") == "1"
	s.mutateNode(w, r, "node-enable", func(n *store.Node) error { n.Enabled = on; n.DisabledUntil = time.Time{}; return nil })
}

// nodePause takes a node out of the list for a while; it comes back by itself. For testing failover.
func (s *Server) nodePause(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	mins, err := strconv.Atoi(r.FormValue("minutes"))
	if err != nil || mins < 1 || mins > 24*60 {
		s.renderCluster(w, r, r.PathValue("id"), "", "分鐘數必須在 1 到 1440 之間。", http.StatusBadRequest)
		return
	}
	until := s.now().Add(time.Duration(mins) * time.Minute)
	s.mutateNode(w, r, "node-pause", func(n *store.Node) error { n.DisabledUntil = until; return nil })
}

func (s *Server) nodeDelete(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id, nid := r.PathValue("id"), r.PathValue("nid")
	var label string
	err := s.Store.Mutate(func(st *store.State) error {
		for i, n := range st.Nodes {
			if n.ID == nid && n.ClusterID == id {
				label = n.Addr()
				st.Nodes = append(st.Nodes[:i], st.Nodes[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("這個集群裡沒有這個節點")
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.Mon.Forget(nid)
	s.log(r, "node-delete", fmt.Sprintf("cluster=%s node=%s", id, label), true)
	s.back(w, r, id, "節點已移除。請發布一次，把它從名單中拿掉。")
}

func (s *Server) probeNow(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	st := s.Store.Snapshot()
	if st.Cluster(id) == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	s.Mon.ProbeAll(ctx, st.NodesOf(id))
	s.back(w, r, id, "已探測。")
}

// ---------------------------------------------------------------- publishing

func (s *Server) publishNow(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	id := r.PathValue("id")
	st := s.Store.Snapshot()
	c := st.Cluster(id)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	nodes := st.Active(id, s.now())
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
	defer cancel()
	res, err := s.Pub.Publish(ctx, id, nodes, sess.User, s.clientIP(r), "published by hand")
	if err != nil {
		s.renderCluster(w, r, id, "", "發布失敗："+err.Error(), http.StatusBadGateway)
		return
	}
	if !c.AutoPublish {
		s.Store.Mutate(func(st *store.State) error { st.Cluster(id).AutoPublish = true; return nil })
	}
	msg := fmt.Sprintf("已發布 %d 個節點。", len(res.Nodes))
	if res.Manual {
		msg += " Some targets are manual: paste the records shown below."
	}
	s.back(w, r, id, msg+" 自動發布現在已開啟。")
}

func (s *Server) autoToggle(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	on := r.FormValue("auto") == "1"
	err := s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil {
			return fmt.Errorf("沒有這個集群")
		}
		if on && c.Last.At.IsZero() {
			return fmt.Errorf("請先手動發布一次，確認送出去的內容")
		}
		c.AutoPublish = on
		return nil
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "auto-publish", fmt.Sprintf("cluster=%s on=%v", id, on), true)
	s.back(w, r, id, "已儲存。")
}

func (s *Server) targetAdd(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	t := store.DNSTarget{Provider: r.FormValue("provider"), Zone: strings.ToLower(strings.TrimSpace(r.FormValue("zone"))),
		Name: strings.ToLower(strings.TrimSpace(r.FormValue("dns_name"))), CredRef: strings.TrimSpace(r.FormValue("cred_ref"))}
	err := s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil {
			return fmt.Errorf("沒有這個集群")
		}
		c.Targets = append(c.Targets, t)
		return nil
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "target-add", fmt.Sprintf("cluster=%s %s %s", id, t.Provider, t.Name), true)
	s.back(w, r, id, "DNS 目標已新增。請發布一次，把名單送過去。")
}

func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	idx, _ := strconv.Atoi(r.PathValue("idx"))
	err := s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil || idx < 0 || idx >= len(c.Targets) {
			return fmt.Errorf("沒有這個 DNS 目標")
		}
		c.Targets = append(c.Targets[:idx], c.Targets[idx+1:]...)
		return nil
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "target-delete", fmt.Sprintf("cluster=%s index=%d", id, idx), true)
	s.back(w, r, id, "DNS 目標已移除。")
}

// ---------------------------------------------------------------- secrets, unseal, audit

var (
	credRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	credField = map[string]bool{"api_key": true, "api_secret": true, "api_token": true, "access_key_id": true, "access_key_secret": true}
)

func (s *Server) secretsPage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	var names []string
	if !s.Vault.Sealed() {
		all, _ := s.Vault.Names()
		for _, n := range all {
			if strings.HasPrefix(n, "dns/") {
				names = append(names, n)
			}
		}
	}
	s.render(w, r, "secrets.html", page{Title: "DNS 憑證", Flash: r.URL.Query().Get("ok"), Data: names}, http.StatusOK)
}

func (s *Server) secretSet(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	ref, field, value := strings.TrimSpace(r.FormValue("ref")), r.FormValue("field"), r.FormValue("value")
	fail := func(msg string) {
		s.render(w, r, "secrets.html", page{Title: "DNS 憑證", Error: msg}, http.StatusBadRequest)
	}
	if s.Vault.Sealed() {
		fail("保險庫是封存狀態。")
		return
	}
	if !credRefRe.MatchString(ref) || !credField[field] || value == "" || len(value) > 4096 {
		fail("請填一個簡短的名稱（a-z、0-9、- _），選擇欄位，並填入值。")
		return
	}
	if err := s.Vault.Set("dns/"+ref+"/"+field, value); err != nil {
		fail(err.Error())
		return
	}
	s.log(r, "secret-set", "dns/"+ref+"/"+field, true) // the value is never logged
	http.Redirect(w, r, "/secrets?ok="+url.QueryEscape("已儲存。這個值之後不會再顯示。"), http.StatusSeeOther)
}

func (s *Server) unsealForm(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.render(w, r, "unseal.html", page{Title: "解封"}, http.StatusOK)
}

func (s *Server) unsealSubmit(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	if !s.lim.allow("unseal:"+s.clientIP(r), s.now()) {
		s.render(w, r, "unseal.html", page{Title: "解封", Error: "嘗試次數過多。"}, http.StatusTooManyRequests)
		return
	}
	if err := s.Vault.Unseal(r.FormValue("passphrase")); err != nil {
		s.log(r, "unseal", "failed", false)
		s.render(w, r, "unseal.html", page{Title: "解封", Error: "這個口令打不開保險庫。"}, http.StatusUnauthorized)
		return
	}
	s.log(r, "unseal", "ok", true)
	http.Redirect(w, r, "/?ok="+url.QueryEscape("保險庫已解封。"), http.StatusSeeOther)
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	es, _ := audit.Tail(s.AuditPath, 200)
	intact := "intact"
	if _, err := audit.Verify(s.AuditPath); err != nil {
		intact = "BROKEN: " + err.Error()
	}
	s.render(w, r, "audit.html", page{Title: "稽核日誌", Data: struct {
		Entries []audit.Entry
		Chain   string
	}{es, intact}}, http.StatusOK)
}
