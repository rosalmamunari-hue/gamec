// Package web is the panel's browser interface. Every page needs a login; every change needs a CSRF token
// and the administrator role; secrets are write-only (the interface never shows a stored secret again).
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
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
	"gamec/panel/internal/notify"
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
	// CFZones lists the domains a Cloudflare token can manage; nil means ask Cloudflare.
	CFZones      func(ctx context.Context, token string) ([]string, error)
	FetchJumpKey func(addr string, timeout time.Duration) (fingerprint, keyType string, err error)
	// Egress sends connections to nodes through a jump host; nil means they are made directly.
	Egress *egress.Egress

	// Secure marks cookies Secure and sends HSTS: set it whenever the panel is served over HTTPS.
	Secure bool
	// TrustProxy reads the client address from X-Forwarded-For (the last entry, added by the proxy in
	// front). Only turn it on when the panel is reachable only through that proxy.
	TrustProxy bool

	// FetchPin reads the TLS pin a node presents (for the add-a-node wizard); nil means connect to it.
	FetchPin func(addr string, timeout time.Duration) (string, error)
	// Notifier sends alerts and Alerter decides when; nil means the defaults.
	Notifier *notify.Sender
	Alerter  *notify.Alerter
	// DialOrigin connects to an origin to see whether it is open to the internet; nil means directly.
	DialOrigin dialOriginFunc

	tpl       *template.Template
	lim       *limiter
	once      sync.Once
	origins   originChecks
	latest    latestCache
	alertOnce sync.Once
}

const cookieName = "gc_session"

// deviceCookie marks a browser the user has logged in from, so a lockout someone else caused does not keep
// them out (see auth.AuthenticateDevice). Sent to /login only.
const deviceCookie = "gc_device"

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) init() {
	s.once.Do(func() {
		funcs := template.FuncMap{
			"ago":          func(t time.Time) string { return humanAgo(s.now(), t) },
			"until":        func(unix int64) string { return humanUntil(s.now(), unix) },
			"ms":           func(d time.Duration) string { return fmt.Sprintf("%d ms", d.Milliseconds()) },
			"ts":           showTime,
			"clock":        showClock,
			"zone":         func() string { return zoneLabel },
			"unixTime":     func(u int64) time.Time { return time.Unix(u, 0) },
			"list":         func(v ...string) []string { return v },
			"icon":         icon,
			"hasPrefix":    strings.HasPrefix,
			"statusColor":  statusColor,
			"statusWord":   statusWord,
			"actionWord":   actionWord,
			"add":          func(a, b int) int { return a + b },
			"levelColor":   levelColor,
			"providerName": providerName,
			"daysLeft":     func(exp int64) int { return daysLeft(s.now(), exp) },
			"dict":         dict,
		}
		s.tpl = template.Must(template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html"))
		s.lim = newLimiter(10, 10*time.Minute)
	})
}

func humanAgo(now, t time.Time) string {
	if t.IsZero() {
		return "从来没有"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	}
	return fmt.Sprintf("%d 天前", int(d.Hours()/24))
}

func humanUntil(now time.Time, unix int64) string {
	if unix == 0 {
		return "还没更新过"
	}
	d := time.Unix(unix, 0).Sub(now)
	switch {
	case d <= 0:
		return "已经过期"
	case d < 48*time.Hour:
		return fmt.Sprintf("剩 %d 小时", int(d.Hours()))
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
	if len(l.hits) > 10000 { // many addresses (IPv6 makes that cheap): drop the ones whose attempts are all old
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= l.window {
				delete(l.hits, k)
			}
		}
	}
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
	Lead   string    // one line under the title
	Back   *backLink // "back to ..." above the title
	User   string
	Admin  bool
	CSRF   string
	Sealed bool
	Flash  string
	Error  string
	Data   any

	Path     string       // for highlighting the menu
	Channels []navChannel // the channels in the menu, with a dot for how each is doing
}

type backLink struct{ Href, Label string }

type navChannel struct {
	ID, Name, Color string
	Active          bool
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page, status int) {
	sess, _ := r.Context().Value(ctxKey{}).(*auth.Session)
	if sess != nil {
		p.User, p.Admin, p.CSRF = sess.User, sess.Role == auth.Admin, sess.CSRF
	}
	p.Sealed = s.Vault.Sealed()
	p.Path = r.URL.Path
	if sess != nil {
		st := s.Store.Snapshot()
		for _, c := range st.Clusters {
			row := s.clusterRow(st, c)
			p.Channels = append(p.Channels, navChannel{ID: c.ID, Name: c.Name, Color: levelColor(row.Level),
				Active: strings.HasPrefix(p.Path, "/cluster/"+c.ID)})
		}
		sort.Slice(p.Channels, func(i, j int) bool { return p.Channels[i].Name < p.Channels[j].Name })
	}
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
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin") // not "no-referrer": that makes Firefox send Origin: null on our own forms
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if s.Secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin refuses a state-changing request that comes from another site. Browsers say where a request
// comes from in Sec-Fetch-Site, which cannot be forged by a web page; older ones are judged by Origin or
// Referer. (An Origin of "null" tells nothing, so without Sec-Fetch-Site it is refused.)
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
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
				http.Error(w, "请重新登录", http.StatusUnauthorized)
			}
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess))
		if r.Method == http.MethodPost {
			origin, tokenOK := sameOrigin(r), auth.CheckCSRF(sess.CSRF, r.FormValue("csrf"))
			if !origin || !tokenOK {
				s.log(r, "csrf-rejected", fmt.Sprintf("%s same-origin=%v token=%v host=%s origin=%s", r.URL.Path, origin, tokenOK,
					safe(r.Host), safe(r.Header.Get("Origin"))), false)
				http.Error(w, "表单已过期或来自其他网站；请刷新页面再试一次", http.StatusForbidden)
				return
			}
		}
		if admin && sess.Role != auth.Admin {
			s.log(r, "forbidden", r.Method+" "+r.URL.Path, false)
			http.Error(w, "这个操作需要管理员权限", http.StatusForbidden)
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
	mux.HandleFunc("POST /cluster/{id}/seal", s.need(true, s.sealToggle))
	mux.HandleFunc("POST /cluster/{id}/target", s.need(true, s.targetAdd))
	mux.HandleFunc("POST /cluster/{id}/target/{idx}/delete", s.need(true, s.targetDelete))
	mux.HandleFunc("POST /cluster/{id}/origin-check", s.need(true, s.originCheckNow))

	mux.HandleFunc("GET /secrets", s.need(true, s.secretsPage))
	mux.HandleFunc("POST /secrets", s.need(true, s.secretSet))
	mux.HandleFunc("POST /secrets/test", s.need(true, s.secretTest))
	mux.HandleFunc("GET /unseal", s.need(true, s.unsealForm))
	mux.HandleFunc("POST /unseal", s.need(true, s.unsealSubmit))
	mux.HandleFunc("GET /audit", s.need(false, s.auditPage))
	s.routesSSH(mux)
	s.routesEdit(mux)
	s.routesWizard(mux)
	s.routesAlerts(mux)
	s.routesAccount(mux)
	s.routesEgress(mux)
	return s.headers(mux)
}

// ---------------------------------------------------------------- login / logout

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login.html", page{Title: "登录", Flash: r.URL.Query().Get("ok")}, http.StatusOK)
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.lim.allow("login:"+ip, s.now()) {
		s.log(r, "login-throttled", "ip="+ip, false)
		s.render(w, r, "login.html", page{Title: "登录", Error: "这个地址尝试次数过多，请等几分钟再试。"}, http.StatusTooManyRequests)
		return
	}
	name := strings.TrimSpace(r.FormValue("user"))
	var device string
	if c, err := r.Cookie(deviceCookie); err == nil {
		device = c.Value
	}
	u, fresh, err := s.Users.AuthenticateDevice(name, r.FormValue("password"), r.FormValue("code"), device, s.now())
	if err != nil {
		s.log(r, "login-failed", "user="+safe(name), false)
		// the same message for every failure, locked accounts included
		s.render(w, r, "login.html", page{Title: "登录", Error: "登录失败。请检查用户名、密码和验证码。"}, http.StatusUnauthorized)
		return
	}
	sess := s.Sessions.Create(u.Name, u.Role, s.now())
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sess.Token, Path: "/", HttpOnly: true,
		Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	http.SetCookie(w, &http.Cookie{Name: deviceCookie, Value: fresh, Path: "/login", HttpOnly: true,
		Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 180 * 24 * 3600})
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
	Checked time.Time     // when it was last probed
	Recent  []recentProbe // oldest first, for the row of coloured blocks
}

type recentProbe struct {
	OK   bool
	Text string
}

func (s *Server) nodeViews(st store.State, c *store.Cluster) []nodeView {
	now := s.now()
	var out []nodeView
	for _, n := range st.NodesOf(c.ID) {
		v := nodeView{N: n}
		h := s.Mon.Health(n.ID)
		switch {
		case !n.Enabled:
			v.Status, v.Detail = "off", "已停用，不会出现在名单里"
		case now.Before(n.DisabledUntil):
			v.Status, v.Detail = "paused", "暂停到 "+showClock(n.DisabledUntil)+"，到时自动恢复"
		case !h.Seen:
			v.Status, v.Detail = "unknown", "还没检查过，一分钟内会检查"
		case h.Ejected:
			v.Status, v.Detail = "ejected", fmt.Sprintf("连续 %d 次检查失败，已从名单拿掉：%s", h.ConsecFail, probeProblem(h.Last))
		case h.Last.OK:
			v.Status, v.Detail = "ok", "正常"
		default:
			v.Status, v.Detail = "fail", fmt.Sprintf("检查失败（连续 %d 次）：%s", h.ConsecFail, probeProblem(h.Last))
		}
		if h.Seen {
			v.Checked = h.Last.At
			if h.Last.OK {
				v.Latency = fmt.Sprintf("%d ms", h.Last.Handshake.Milliseconds())
			}
		}
		for _, r := range h.Recent {
			t := showClock(r.At) + " 正常"
			if !r.OK {
				t = showClock(r.At) + " 失败：" + probeProblem(r)
			}
			v.Recent = append(v.Recent, recentProbe{OK: r.OK, Text: t})
		}
		out = append(out, v)
	}
	return out
}

// problem is something wrong with a channel, said so that a person knows what to do about it.
type problem struct {
	Text string
	Bad  bool   // players are (or soon will be) affected, rather than something to keep an eye on
	Href string // where to fix it, if anywhere
	Link string
}

type clusterRow struct {
	C        *store.Cluster
	Nodes    []nodeView
	OK, All  int
	Expiry   string
	Problems []problem
	Note     string
	Steps    []step
	Next     *step
	Left     int

	// Level is the one-word state of the channel: ok, warn (something to look at), bad (players are
	// affected or soon will be) or setup (not finished yet). Headline says it in a sentence.
	Level    string
	Headline string
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
	page := "/cluster/" + c.ID
	add := func(bad bool, text, href, link string) {
		row.Problems = append(row.Problems, problem{Text: text, Bad: bad, Href: href, Link: link})
	}
	if s.Vault.Sealed() {
		add(true, "保险库上锁了：面板不能更新名单，也不会自动续期。", "/unseal", "去解锁")
	}
	switch {
	case c.Last.At.IsZero():
		// covered by the setup steps
	case time.Unix(c.Last.Exp, 0).Before(now):
		add(true, "名单已经过期，玩家找不到任何节点！请马上更新名单。", page+"#publish", "去更新")
	case time.Unix(c.Last.Exp, 0).Sub(now) < time.Duration(c.RenewBeforeDays)*24*time.Hour:
		if c.AutoPublish && !s.Vault.Sealed() {
			add(false, "名单快到期了（"+row.Expiry+"），面板会自动续期。", "", "")
		} else {
			add(true, "名单快到期了（"+row.Expiry+"），而自动维护没在运行。请手动更新一次。", page+"#publish", "去更新")
		}
	}
	if c.Last.Manual {
		add(true, "有一个「手动」域名在等你把记录贴进 DNS。", page+"#publish", "查看记录")
	}
	if !c.Last.At.IsZero() && !c.Last.Manual && !c.Last.Verified {
		add(false, "名单写进去了，但从外面还读不到（可能 DNS 还没生效）。几分钟后再更新一次看看。", page+"#publish", "去看看")
	}
	if row.All > 0 && row.OK == 0 {
		add(true, "没有任何节点通过检查，玩家可能连不上。", page+"#nodes", "看节点")
	} else if row.OK < row.All {
		bad := 0
		for _, n := range row.Nodes {
			if n.Status == "fail" || n.Status == "ejected" {
				bad++
			}
		}
		if bad > 0 {
			add(false, fmt.Sprintf("%d 个节点检查失败，玩家会自动用其他节点。", bad), page+"#nodes", "看节点")
		}
	}
	if o := s.originState(c.ID); o.Open {
		add(false, "源站 "+c.Origin+" 对公网开放：别人知道地址就能绕过节点直接打源站。请把源站防火墙改成只放行节点的 IP。", page+"#settings", "详情")
	}
	if c.AutoPublish && row.Note != "" && strings.HasPrefix(row.Note, "自动更新名单失败") {
		add(true, row.Note, page+"#publish", "去看看")
	}
	row.Steps = s.steps(st, c, row)
	row.Next = nextStep(row.Steps)
	for _, st := range row.Steps {
		if !st.Done {
			row.Left++
		}
	}
	bad, warn := false, len(row.Problems) > 0
	for _, p := range row.Problems {
		bad = bad || p.Bad
	}
	switch {
	case c.Last.At.IsZero():
		row.Level, row.Headline = "setup", fmt.Sprintf("还没设置好：还差 %d 步，玩家才能用这个渠道", row.Left)
	case bad:
		row.Level, row.Headline = "bad", "有问题，需要你处理"
	case warn:
		row.Level, row.Headline = "warn", "玩家可以连接，但有地方要留意"
	default:
		row.Level, row.Headline = "ok", "一切正常，玩家可以连接"
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
	s.render(w, r, "dashboard.html", page{Title: "总览", Lead: "每个渠道是一组独立的节点和域名（比如一个渠道服），这里一眼看出每个渠道好不好。", Flash: r.URL.Query().Get("ok"), Data: rows}, http.StatusOK)
}

type clusterPageData struct {
	Row     clusterRow
	SealKey string // shown only while the cluster encrypts its list and the vault is unlocked
	Origin  originResult
	Latest  string // the newest release, to suggest for upgrades
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
	data := clusterPageData{Row: s.clusterRow(st, c), Origin: s.originState(id), Latest: s.latestRelease()}
	// the key is a secret like the others: read-only accounts see that the list is sealed, not the key
	if sess, _ := r.Context().Value(ctxKey{}).(*auth.Session); c.Sealed && !s.Vault.Sealed() && sess != nil && sess.Role == auth.Admin {
		data.SealKey, _, _ = s.Vault.Get(engine.SealKeyName(id))
	}
	s.render(w, r, "cluster.html", page{Title: c.Name, Lead: clusterLead(c), Flash: flash, Error: errMsg, Data: data}, status)
}

// ---------------------------------------------------------------- creating a cluster

type createdData struct {
	Cluster    *store.Cluster
	NodeSecret string
	PublicKey  string
}

func (s *Server) clusterNewForm(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.render(w, r, "cluster_new.html", page{Title: "添加渠道", Back: &backLink{"/", "返回总览"}}, http.StatusOK)
}

var clusterNameRe = regexp.MustCompile(`^[^<>"'&\x00-\x1f]{1,60}$`)

func (s *Server) clusterCreate(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	fail := func(msg string) {
		s.render(w, r, "cluster_new.html", page{Title: "添加渠道", Back: &backLink{"/", "返回总览"}, Error: msg}, http.StatusBadRequest)
	}
	if s.Vault.Sealed() {
		fail("保险库是上锁状态；请先解锁，新渠道需要把密钥存进去。")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !clusterNameRe.MatchString(name) {
		fail("名称必须是 1-60 个字符，且不能包含 < > \" ' &。")
		return
	}
	valid, err1 := strconv.Atoi(r.FormValue("valid_days"))
	renew, err2 := strconv.Atoi(r.FormValue("renew_days"))
	if err1 != nil || err2 != nil {
		fail("有效期与续期天数必须是数字。")
		return
	}
	origin := strings.TrimSpace(r.FormValue("origin"))
	if err := validOrigin(origin); err != nil {
		fail(err.Error())
		return
	}
	target, err := s.targetFromForm(r)
	if err != nil {
		fail(err.Error())
		return
	}
	c := &store.Cluster{
		ID: store.NewID(), Name: name, Origin: origin,
		ValidDays: valid, RenewBeforeDays: renew, Created: s.now(),
		Targets: []store.DNSTarget{target},
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
		fail(friendlyStoreError(err))
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
		fail("密钥无法保存，所以没有创建任何东西。")
		return
	}
	s.log(r, "cluster-create", "cluster="+c.Name, true)
	// The only time the node secret is shown. Afterwards it can only be read on the server itself.
	s.render(w, r, "cluster_created.html", page{Title: "渠道已创建", Data: createdData{Cluster: c, NodeSecret: secret, PublicKey: c.PublicKey}}, http.StatusOK)
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
			return fmt.Errorf("没有这个渠道")
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
	s.back(w, r, id, "节点已加入。连续通过几次检查后，会自动进入名单。")
}

func (s *Server) mutateNode(w http.ResponseWriter, r *http.Request, action string, fn func(*store.Node) error) {
	id, nid := r.PathValue("id"), r.PathValue("nid")
	var label string
	err := s.Store.Mutate(func(st *store.State) error {
		n := st.Node(nid)
		if n == nil || n.ClusterID != id {
			return fmt.Errorf("这个渠道里没有这个节点")
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
		s.renderCluster(w, r, r.PathValue("id"), "", "分钟数必须在 1 到 1440 之间。", http.StatusBadRequest)
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
		return fmt.Errorf("这个渠道里没有这个节点")
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.Mon.Forget(nid)
	s.log(r, "node-delete", fmt.Sprintf("cluster=%s node=%s", id, label), true)
	s.back(w, r, id, "节点已删除。请再「立即更新名单」一次，把它从名单里拿掉。")
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
	s.back(w, r, id, "已检查完。")
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
		s.renderCluster(w, r, id, "", "更新名单失败："+err.Error(), http.StatusBadGateway)
		return
	}
	if !c.AutoPublish {
		s.Store.Mutate(func(st *store.State) error { st.Cluster(id).AutoPublish = true; return nil })
	}
	msg := fmt.Sprintf("名单已更新，现在有 %d 个节点。", len(res.Nodes))
	if res.Manual {
		msg += " Some targets are manual: paste the records shown below."
	}
	s.back(w, r, id, msg+" 自动更新已打开，之后面板会自己维护。")
}

func (s *Server) autoToggle(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	on := r.FormValue("auto") == "1"
	err := s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil {
			return fmt.Errorf("没有这个渠道")
		}
		if on && c.Last.At.IsZero() {
			return fmt.Errorf("请先手动「立即更新名单」一次，确认写进去的内容没问题，再开自动更新")
		}
		c.AutoPublish = on
		return nil
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "auto-publish", fmt.Sprintf("cluster=%s on=%v", id, on), true)
	s.back(w, r, id, "已保存。")
}

// sealToggle turns on or off the encryption of the published list. The key is made the first time and kept.
func (s *Server) sealToggle(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	on := r.FormValue("seal") == "1"
	if on {
		if s.Vault.Sealed() {
			s.renderCluster(w, r, id, "", "请先解锁保险库。", http.StatusBadRequest)
			return
		}
		if _, ok, _ := s.Vault.Get(engine.SealKeyName(id)); !ok {
			k, err := shieldlist.NewSealKey()
			if err == nil {
				err = s.Vault.Set(engine.SealKeyName(id), base64.StdEncoding.EncodeToString(k))
			}
			if err != nil {
				s.renderCluster(w, r, id, "", "无法产生加密密钥："+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	err := s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil {
			return fmt.Errorf("没有这个渠道")
		}
		c.Sealed = on
		return nil
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "seal-list", fmt.Sprintf("cluster=%s on=%v", id, on), true)
	s.back(w, r, id, "已保存。下一次「更新名单」开始生效。")
}

func (s *Server) targetAdd(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	t, err := s.targetFromForm(r)
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	err = s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil {
			return fmt.Errorf("没有这个渠道")
		}
		c.Targets = append(c.Targets, t)
		return nil
	})
	if err != nil {
		s.renderCluster(w, r, id, "", friendlyStoreError(err), http.StatusBadRequest)
		return
	}
	s.log(r, "target-add", fmt.Sprintf("cluster=%s %s %s", id, t.Provider, t.Name), true)
	s.back(w, r, id, "域名已加入。请「立即更新名单」一次，把名单写过去。")
}

func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	idx, _ := strconv.Atoi(r.PathValue("idx"))
	name := strings.TrimSpace(r.FormValue("name"))
	err := s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil || idx < 0 || idx >= len(c.Targets) {
			return fmt.Errorf("没有这个域名")
		}
		if name != "" && c.Targets[idx].Name != name { // the list changed since the page was shown
			return fmt.Errorf("域名列表刚刚被改过，没有移除任何东西。请刷新页面再试")
		}
		if len(c.Targets) == 1 {
			return fmt.Errorf("这是最后一个域名，不能移除：App 至少要有一个地方读名单。可以先加一个新的再移除它")
		}
		c.Targets = append(c.Targets[:idx], c.Targets[idx+1:]...)
		return nil
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "target-delete", fmt.Sprintf("cluster=%s index=%d name=%s", id, idx, safe(name)), true)
	s.back(w, r, id, "域名已移除。")
}

// ---------------------------------------------------------------- secrets, unseal, audit

var (
	credRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	credField = map[string]bool{"api_key": true, "api_secret": true, "api_token": true, "access_key_id": true, "access_key_secret": true}
)

func (s *Server) unsealForm(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.render(w, r, "unseal.html", page{Title: "解锁保险库"}, http.StatusOK)
}

func (s *Server) unsealSubmit(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	if !s.lim.allow("unseal:"+s.clientIP(r), s.now()) {
		s.render(w, r, "unseal.html", page{Title: "解锁保险库", Error: "尝试次数过多。"}, http.StatusTooManyRequests)
		return
	}
	if err := s.Vault.Unseal(r.FormValue("passphrase")); err != nil {
		s.log(r, "unseal", "failed", false)
		s.render(w, r, "unseal.html", page{Title: "解锁保险库", Error: "这个口令打不开保险库。"}, http.StatusUnauthorized)
		return
	}
	s.log(r, "unseal", "ok", true)
	http.Redirect(w, r, "/?ok="+url.QueryEscape("保险库已解锁。"), http.StatusSeeOther)
}

type auditKind struct{ Key, Label string }

var auditKinds = []auditKind{{"login", "登录"}, {"node", "节点"}, {"publish", "名单"}, {"dns", "域名和授权"},
	{"settings", "设置和账号"}, {"security", "被拒绝的请求"}, {"alert", "告警"}}

// auditKindOf groups an action code for the filter on the audit page.
func auditKindOf(action string) string {
	switch {
	case action == "csrf-rejected" || action == "forbidden" || action == "login-throttled":
		return "security"
	case strings.HasPrefix(action, "login") || action == "logout" || action == "unseal" || action == "start":
		return "login"
	case strings.HasPrefix(action, "node-") || strings.HasPrefix(action, "ssh-") || action == "upgrade-all" || action == "hostkey-trust":
		return "node"
	case action == "publish" || action == "auto-publish" || action == "seal-list":
		return "publish"
	case strings.HasPrefix(action, "target-") || strings.HasPrefix(action, "secret-") || action == "set-secret" || action == "get-secret":
		return "dns"
	case action == "alert":
		return "alert"
	}
	return "settings"
}

const auditPerPage = 100

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	all, _ := audit.Tail(s.AuditPath, 1<<20) // newest first
	chain := "intact"
	if _, err := audit.Verify(s.AuditPath); err != nil {
		chain = "BROKEN: " + err.Error()
	}
	q, kind, failed := strings.TrimSpace(r.URL.Query().Get("q")), r.URL.Query().Get("kind"), r.URL.Query().Get("failed") == "1"
	var hits []audit.Entry
	for _, e := range all {
		if kind != "" && auditKindOf(e.Action) != kind || failed && e.OK {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.User+" "+e.IP+" "+e.Action+" "+actionWord(e.Action)+" "+e.Detail), strings.ToLower(q)) {
			continue
		}
		hits = append(hits, e)
	}
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pg < 1 {
		pg = 1
	}
	from := (pg - 1) * auditPerPage
	if from > len(hits) {
		from = len(hits)
	}
	to := min(from+auditPerPage, len(hits))
	link := func(p int) string {
		v := url.Values{"page": {strconv.Itoa(p)}}
		if q != "" {
			v.Set("q", q)
		}
		if kind != "" {
			v.Set("kind", kind)
		}
		if failed {
			v.Set("failed", "1")
		}
		return "/audit?" + v.Encode()
	}
	d := struct {
		Entries                  []audit.Entry
		Chain                    string
		Q, Kind                  string
		Failed                   bool
		Kinds                    []auditKind
		Total, Matched, From, To int
		Prev, Next               string
	}{Entries: hits[from:to], Chain: chain, Q: q, Kind: kind, Failed: failed, Kinds: auditKinds,
		Total: len(all), Matched: len(hits), From: from + 1, To: to}
	if pg > 1 {
		d.Prev = link(pg - 1)
	}
	if to < len(hits) {
		d.Next = link(pg + 1)
	}
	s.render(w, r, "audit.html", page{Title: "操作记录", Lead: "谁在什么时候做了什么，包括被拒绝的尝试。", Data: d}, http.StatusOK)
}

func clusterLead(c *store.Cluster) string {
	if c.Origin == "" {
		return "玩家 → 节点 → 源站（还没填源站地址）"
	}
	return "玩家 → 节点 → 源站 " + c.Origin
}
