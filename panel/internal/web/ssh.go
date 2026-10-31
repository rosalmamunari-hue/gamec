package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gamec/panel/internal/auth"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/ops"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

// SSHKeyName is the vault entry holding the panel's SSH private key.
const SSHKeyName = "ssh/panel_key"

func (s *Server) routesSSH(mux *http.ServeMux) {
	mux.HandleFunc("GET /cluster/{id}/node/{nid}", s.need(true, s.nodePage))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/ssh-settings", s.need(true, s.sshSettings))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/hostkey", s.need(true, s.hostKey))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/check", s.need(true, s.sshCheck))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/ctl", s.need(true, s.sshControl))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/stop-for", s.need(true, s.sshStopFor))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/upgrade", s.need(true, s.sshUpgrade))
	mux.HandleFunc("POST /cluster/{id}/upgrade-all", s.need(true, s.upgradeAll))
	mux.HandleFunc("GET /ssh", s.need(true, s.sshPage))
	mux.HandleFunc("POST /ssh", s.need(true, s.sshScript))
}

type nodePageData struct {
	Cluster     *store.Cluster
	Node        *store.Node
	View        nodeView
	Status      *ops.NodeStatus
	Logs        string
	Result      string
	Fingerprint string // freshly fetched, waiting for the administrator to confirm
	KeyType     string
	KeyChanged  bool
	Latest      string // newest release, suggested for upgrades
}

func (s *Server) lookup(r *http.Request) (*store.Cluster, *store.Node, bool) {
	st := s.Store.Snapshot()
	c, n := st.Cluster(r.PathValue("id")), st.Node(r.PathValue("nid"))
	if c == nil || n == nil || n.ClusterID != c.ID {
		return nil, nil, false
	}
	return c, n, true
}

func (s *Server) renderNode(w http.ResponseWriter, r *http.Request, d nodePageData, flash, errMsg string, status int) {
	st := s.Store.Snapshot()
	if n := st.Node(d.Node.ID); n != nil { // always show what is stored now
		d.Node = n
	}
	for _, v := range s.nodeViews(st, d.Cluster) {
		if v.N.ID == d.Node.ID {
			d.View = v
		}
	}
	d.Latest = s.latestRelease()
	s.render(w, r, "node.html", page{Title: d.Node.Name, Back: &backLink{"/cluster/" + d.Cluster.ID, "返回 " + d.Cluster.Name}, Flash: flash, Error: errMsg, Data: d}, status)
}

func (s *Server) nodePage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, n, ok := s.lookup(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, r.URL.Query().Get("ok"), "", http.StatusOK)
}

func (s *Server) sshSettings(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, n, ok := s.lookup(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	port, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("ssh_port")))
	user, unit := strings.TrimSpace(r.FormValue("ssh_user")), strings.TrimSpace(r.FormValue("unit"))
	err := s.Store.Mutate(func(st *store.State) error {
		x := st.Node(n.ID)
		if x == nil {
			return errors.New("this node was just removed")
		}
		hostChanged := x.SSHPort != port
		x.SSHUser, x.SSHPort, x.Unit = user, port, unit
		if hostChanged {
			x.HostKey = "" // another port may be another machine: confirm the key again
		}
		return nil
	})
	if err != nil {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "ssh-settings", fmt.Sprintf("node=%s user=%s port=%d unit=%s", n.Addr(), safe(user), port, safe(unit)), true)
	http.Redirect(w, r, "/cluster/"+c.ID+"/node/"+n.ID+"?ok="+url.QueryEscape("SSH 设置已保存。"), http.StatusSeeOther)
}

// hostKey is the two-step confirmation: "fetch" shows the fingerprint, "trust" stores it, and only if the
// server still presents exactly the fingerprint the administrator was shown.
func (s *Server) hostKey(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, n, ok := s.lookup(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	fetch := s.FetchHostKey
	if fetch == nil { // a node's key is read through the egress host too, or the node would see the panel
		fetch = func(addr string, to time.Duration) (string, string, error) {
			return sshx.FetchHostKeyVia(s.nodeDial(), addr, to)
		}
	}
	fp, typ, err := fetch(n.SSHAddr(), 10*time.Second)
	if err != nil {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "无法读取服务器的主机密钥："+err.Error(), http.StatusBadGateway)
		return
	}
	if r.FormValue("action") != "trust" {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n, Fingerprint: fp, KeyType: typ, KeyChanged: n.HostKey != "" && n.HostKey != fp},
			"", "", http.StatusOK)
		return
	}
	if r.FormValue("fingerprint") != fp {
		s.log(r, "hostkey-trust", fmt.Sprintf("node=%s the key changed between showing and confirming", n.Addr()), false)
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "服务器出示的密钥和你刚才看到的不一样。没有保存任何东西。", http.StatusConflict)
		return
	}
	if err := s.Store.Mutate(func(st *store.State) error {
		x := st.Node(n.ID)
		if x == nil {
			return errors.New("this node was just removed")
		}
		x.HostKey = fp
		return nil
	}); err != nil {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "hostkey-trust", fmt.Sprintf("node=%s fingerprint=%s", n.Addr(), fp), true)
	http.Redirect(w, r, "/cluster/"+c.ID+"/node/"+n.ID+"?ok="+url.QueryEscape("主机密钥已确认。"), http.StatusSeeOther)
}

// sshOp runs one SSH action with a deadline and the same error handling for all of them.
func (s *Server) sshOp(w http.ResponseWriter, r *http.Request, action string, timeout time.Duration,
	fn func(ctx context.Context, c *store.Cluster, n store.Node) (nodePageData, string, error)) {
	c, n, ok := s.lookup(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if s.Ops == nil {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "这个面板还没有设置 SSH 管理。", http.StatusServiceUnavailable)
		return
	}
	if s.Vault.Sealed() {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "保险库是上锁状态；面板的 SSH 密钥目前无法使用。", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	d, msg, err := fn(ctx, c, *n)
	d.Cluster, d.Node = c, n
	if err != nil {
		s.log(r, action, fmt.Sprintf("node=%s error=%v", n.Addr(), err), false)
		s.renderNode(w, r, d, "", err.Error(), http.StatusBadGateway)
		return
	}
	s.log(r, action, fmt.Sprintf("node=%s %s", n.Addr(), msg), true)
	s.renderNode(w, r, d, msg, "", http.StatusOK)
}

func (s *Server) sshCheck(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.sshOp(w, r, "ssh-check", 40*time.Second, func(ctx context.Context, c *store.Cluster, n store.Node) (nodePageData, string, error) {
		st, err := s.Ops.Status(ctx, n)
		if err != nil {
			return nodePageData{}, "", err
		}
		logs, err := s.Ops.Logs(ctx, n, 60)
		if err != nil {
			return nodePageData{Status: &st}, "", err
		}
		return nodePageData{Status: &st, Logs: logs}, "已通过 SSH 读取。", nil
	})
}

func (s *Server) sshControl(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	verb := r.FormValue("verb")
	s.sshOp(w, r, "ssh-"+safe(verb), 40*time.Second, func(ctx context.Context, c *store.Cluster, n store.Node) (nodePageData, string, error) {
		st, err := s.Ops.Control(ctx, n, verb)
		if err != nil {
			return nodePageData{}, "", err
		}
		return nodePageData{Status: &st}, fmt.Sprintf("%s 已运行；服务目前状态：%s。", verb, st.Active), nil
	})
}

func (s *Server) sshStopFor(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	mins, err := strconv.Atoi(strings.TrimSpace(r.FormValue("minutes")))
	if err != nil || mins < 1 || mins > 60 {
		c, n, ok := s.lookup(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "分钟数必须在 1 到 60 之间。", http.StatusBadRequest)
		return
	}
	s.sshOp(w, r, "ssh-stop-for", 40*time.Second, func(ctx context.Context, c *store.Cluster, n store.Node) (nodePageData, string, error) {
		if err := s.Ops.StopFor(ctx, n, time.Duration(mins)*time.Minute); err != nil {
			return nodePageData{}, "", err
		}
		return nodePageData{}, fmt.Sprintf("服务已停止，%d 分钟后会自己再启动。期间玩家会切换到其他节点。", mins), nil
	})
}

func (s *Server) releases() *ops.Releases {
	if s.Releases != nil {
		return s.Releases
	}
	return &ops.Releases{Base: s.ReleaseBase}
}

func (s *Server) sshUpgrade(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	tag := strings.TrimSpace(r.FormValue("tag"))
	s.sshOp(w, r, "ssh-upgrade", 8*time.Minute, func(ctx context.Context, c *store.Cluster, n store.Node) (nodePageData, string, error) {
		if err := s.guardLastHealthy(n); err != nil {
			return nodePageData{}, "", err
		}
		b, err := s.releases().Fetch(ctx, tag, "edge-linux-amd64")
		if err != nil {
			return nodePageData{}, "", err
		}
		res, err := s.Ops.Upgrade(ctx, n, b)
		if err != nil {
			return nodePageData{Result: res.String()}, "", fmt.Errorf("%w (%s)", err, res)
		}
		return nodePageData{Result: res.String()}, res.String(), nil
	})
}

// guardLastHealthy refuses to take down the only node that is serving players.
func (s *Server) guardLastHealthy(n store.Node) error {
	st := s.Store.Snapshot()
	healthy := 0
	for _, x := range st.NodesOf(n.ClusterID) {
		if x.ID == n.ID || !x.Enabled {
			continue
		}
		if h := s.Mon.Health(x.ID); h.Seen && h.Last.OK {
			healthy++
		}
	}
	if healthy == 0 {
		return fmt.Errorf("%s 是它所在渠道里唯一健康的节点；升级它会让玩家无处可连", n.Addr())
	}
	return nil
}

func (s *Server) upgradeAll(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	id := r.PathValue("id")
	st := s.Store.Snapshot()
	c := st.Cluster(id)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	tag := strings.TrimSpace(r.FormValue("tag"))
	var targets []store.Node
	for _, n := range st.NodesOf(id) {
		if n.SSHConfigured() && n.HostKey != "" {
			targets = append(targets, *n)
		}
	}
	if s.Ops == nil || len(targets) == 0 {
		s.renderCluster(w, r, id, "", "这个渠道还没有任何节点设置好 SSH 管理。", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	// the server's write timeout (10 minutes) would otherwise drop the answer to a long rolling upgrade
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(21 * time.Minute))
	defer cancel()
	b, err := s.releases().Fetch(ctx, tag, "edge-linux-amd64")
	if err != nil {
		s.log(r, "upgrade-all", "cluster="+c.Name+" error="+err.Error(), false)
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadGateway)
		return
	}
	results, err := s.Ops.RollingUpgrade(ctx, targets, b, s.guardLastHealthy, nil)
	var lines []string
	for _, x := range results {
		lines = append(lines, x.String())
	}
	if err != nil {
		s.log(r, "upgrade-all", fmt.Sprintf("cluster=%s tag=%s stopped: %v | %s", c.Name, safe(tag), err, strings.Join(lines, " | ")), false)
		s.renderCluster(w, r, id, "", "已停止："+err.Error()+" 目前已完成："+strings.Join(lines, "; "), http.StatusBadGateway)
		return
	}
	s.log(r, "upgrade-all", fmt.Sprintf("cluster=%s tag=%s %s", c.Name, safe(tag), strings.Join(lines, " | ")), true)
	s.back(w, r, id, "所有节点已升级到 "+tag+"："+strings.Join(lines, "; "))
}

// ---------------------------------------------------------------- the panel's SSH key and the prepare script

type sshPageData struct {
	HasKey     bool
	PublicLine string
	Script     string
	Latest     string
}

func (s *Server) panelKey() (pub string, has bool, err error) {
	if s.Vault.Sealed() {
		return "", false, fmt.Errorf("保险库是上锁状态")
	}
	pem, ok, err := s.Vault.Get(SSHKeyName)
	if err != nil || !ok {
		return "", false, err
	}
	signer, err := sshx.ParseSigner(pem)
	if err != nil {
		return "", true, err
	}
	return sshx.PublicLine(signer, "gamec-panel"), true, nil
}

func (s *Server) sshPage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	pub, has, err := s.panelKey()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	s.render(w, r, "ssh.html", page{Title: "服务器管理", Lead: "让面板远程管理节点：看状态和日志、启停、升级、出问题自动退回。", Error: msg, Data: sshPageData{HasKey: has, PublicLine: pub, Latest: s.latestRelease()}}, http.StatusOK)
}

func (s *Server) sshScript(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	pub, has, err := s.panelKey()
	data := sshPageData{HasKey: has, PublicLine: pub, Latest: s.latestRelease()}
	fail := func(msg string) {
		s.render(w, r, "ssh.html", page{Title: "服务器管理", Lead: "让面板远程管理节点：看状态和日志、启停、升级、出问题自动退回。", Error: msg, Data: data}, http.StatusBadRequest)
	}
	if err != nil || !has {
		fail("面板还没有 SSH 密钥。请在服务器上用 `panel ssh-keygen` 创建。")
		return
	}
	tag := strings.TrimSpace(r.FormValue("tag"))
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	b, err := s.releases().Fetch(ctx, tag, "nodectl-linux-amd64")
	if err != nil {
		fail("无法取得该版本的 nodectl：" + err.Error())
		return
	}
	base := strings.TrimRight(s.releases().Base, "/")
	script, err := ops.PrepareScript(pub, base+"/"+tag+"/nodectl-linux-amd64", b.SHA256, strings.TrimSpace(r.FormValue("from")))
	if err != nil {
		fail(err.Error())
		return
	}
	data.Script = script
	s.log(r, "ssh-script", "release="+safe(tag), true)
	s.render(w, r, "ssh.html", page{Title: "服务器管理", Lead: "让面板远程管理节点：看状态和日志、启停、升级、出问题自动退回。", Data: data}, http.StatusOK)
}

var _ = engine.ProbeResult{}

// latestRelease is the newest published version, to fill in as a suggestion. It never waits for the
// network: the answer is refreshed in the background at most once an hour, and is empty until then.
func (s *Server) latestRelease() string {
	s.latest.mu.Lock()
	defer s.latest.mu.Unlock()
	if s.ReleaseBase != "" && !s.latest.busy && time.Since(s.latest.at) > time.Hour {
		s.latest.busy = true
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			tag, err := s.releases().Latest(ctx)
			s.latest.mu.Lock()
			defer s.latest.mu.Unlock()
			s.latest.busy, s.latest.at = false, time.Now()
			if err == nil {
				s.latest.tag = tag
			}
		}()
	}
	return s.latest.tag
}

type latestCache struct {
	mu   sync.Mutex
	tag  string
	at   time.Time
	busy bool
}
