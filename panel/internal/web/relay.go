package web

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gamec/panel/internal/auth"
	"gamec/panel/internal/ops"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

// Relays: plain forwarders between some nodes and the origin (player -> node -> relay -> origin). A relay is
// installed in one click with its root password, like a node; nodes are then added "through" it, and the
// panel keeps the relay's list of allowed nodes in step (nodectl relay-allow) whenever one is added or
// removed.

func (s *Server) routesRelay(mux *http.ServeMux) {
	mux.HandleFunc("GET /cluster/{id}/relay/new", s.need(true, s.relayNewForm))
	mux.HandleFunc("POST /cluster/{id}/relay/new", s.need(true, s.relayInstall))
	mux.HandleFunc("POST /cluster/{id}/relay/{rid}/sync", s.need(true, s.relaySyncNow))
	mux.HandleFunc("POST /cluster/{id}/relay/{rid}/delete", s.need(true, s.relayDelete))
}

type relayForm struct {
	Name    string
	Host    string
	Port    int
	SSHPort int
	Target  string
	Tag     string
	From    string
}

func (f relayForm) addr() string    { return net.JoinHostPort(f.Host, strconv.Itoa(f.Port)) }
func (f relayForm) sshAddr() string { return net.JoinHostPort(f.Host, strconv.Itoa(f.SSHPort)) }

type relayNewData struct {
	Cluster *store.Cluster
	Form    relayForm
	Ready   bool
	Missing string
}

func (s *Server) renderRelayNew(w http.ResponseWriter, r *http.Request, c *store.Cluster, f relayForm, errMsg string, status int) {
	d := relayNewData{Cluster: c, Form: f, Ready: true}
	switch {
	case s.Ops == nil:
		d.Ready, d.Missing = false, "面板没有开远程管理（SSH），装不了中转。"
	case s.Vault.Sealed():
		d.Ready, d.Missing = false, "保险库上锁了：要用到保险库里面板的 SSH 密钥。先解锁。"
	default:
		if _, has, err := s.panelKey(); err != nil || !has {
			d.Ready, d.Missing = false, "面板还没有自己的 SSH 密钥：先停掉面板，在面板服务器上运行一次 panel ssh-keygen，再启动面板。"
		}
	}
	s.render(w, r, "relay_new.html", page{Title: "加一个中转", Back: &backLink{"/cluster/" + c.ID + "#relays", "返回 " + c.Name}, Error: errMsg, Data: d}, status)
}

func (s *Server) relayNewForm(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, ok := s.wizardCluster(w, r)
	if !ok {
		return
	}
	st := s.Store.Snapshot()
	f := relayForm{Name: fmt.Sprintf("relay%d", len(st.RelaysOf(c.ID))+1), Port: 20000 + rand.IntN(40000), SSHPort: 22,
		Target: c.Origin, Tag: s.latestRelease()}
	if e := st.Egress; e != nil {
		if h, _, err := net.SplitHostPort(e.Addr); err == nil {
			f.From = h
		}
	}
	s.renderRelayNew(w, r, c, f, "", http.StatusOK)
}

func readRelayForm(r *http.Request) (relayForm, error) {
	f := relayForm{Name: strings.TrimSpace(r.FormValue("name")), Host: strings.TrimSpace(r.FormValue("host")),
		Target: strings.TrimSpace(r.FormValue("target")), Tag: strings.TrimSpace(r.FormValue("tag")), From: strings.TrimSpace(r.FormValue("from"))}
	var err1, err2 error
	f.Port, err1 = strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	f.SSHPort, err2 = strconv.Atoi(strings.TrimSpace(r.FormValue("ssh_port")))
	switch {
	case f.Name == "" || len(f.Name) > 60:
		return f, errors.New("名称要 1-60 个字符。")
	case net.ParseIP(f.Host) == nil:
		return f, errors.New("服务器 IP 不对：请填中转机的公网 IP，比如 203.0.113.30。")
	case err1 != nil || f.Port < 1024 || f.Port > 65535:
		return f, errors.New("节点连中转的端口要在 1024 到 65535 之间。")
	case err2 != nil || f.SSHPort < 1 || f.SSHPort > 65535:
		return f, errors.New("SSH 端口不对，一般是 22。")
	case f.Target == "":
		return f, errors.New("要填转发目标：中转把节点的连接转到哪里（一般就是渠道的源站地址）。")
	}
	if err := validOrigin(f.Target); err != nil {
		return f, errors.New("转发目标要写成 IP:端口，比如 203.0.113.5:21443")
	}
	return f, nil
}

// relayInstall logs in to the new relay with its root password, runs the relay install script there and
// saves the relay once the SSH key the script printed matches the one the login saw and the one the network
// shows. The password is used for this one login only; it is not stored or logged.
func (s *Server) relayInstall(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, ok := s.wizardCluster(w, r)
	if !ok {
		return
	}
	f, err := readRelayForm(r)
	fail := func(msg string, status int) { s.renderRelayNew(w, r, c, f, msg, status) }
	if err != nil {
		fail(err.Error(), http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		fail("要填中转机的 root 密码：面板用它登录一次来安装。", http.StatusBadRequest)
		return
	}
	if s.Ops == nil {
		fail("面板没有开远程管理（SSH），装不了中转。", http.StatusBadRequest)
		return
	}
	st := s.Store.Snapshot()
	for _, n := range st.Nodes {
		if n.Host == f.Host {
			fail(f.Host+" 已经是节点「"+n.Name+"」了：中转要用另一台服务器。", http.StatusBadRequest)
			return
		}
	}
	for _, x := range st.Relays {
		if x.Host == f.Host {
			fail(f.Host+" 已经是中转「"+x.Name+"」了。", http.StatusBadRequest)
			return
		}
	}
	pub, has, err := s.panelKey()
	if err != nil || !has {
		fail("面板还没有 SSH 密钥，或保险库上锁了。", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), installTimeout)
	defer cancel()
	sums, err := s.releases().Checksums(ctx, f.Tag)
	if err != nil {
		fail("读不到版本 "+f.Tag+" 的校验码："+err.Error(), http.StatusBadGateway)
		return
	}
	base := strings.TrimRight(s.releases().Base, "/") + "/" + f.Tag + "/"
	prog := func(name string) ops.Program { return ops.Program{URL: base + name, SHA256: sums[name]} }
	script, err := ops.RelayScript(ops.RelayParams{Port: f.Port, Target: f.Target, Realip: prog("realip-linux-amd64"),
		Nodectl: prog("nodectl-linux-amd64"), PubLine: pub, From: f.From})
	if err != nil {
		fail("生成安装脚本失败："+err.Error()+"（版本 "+f.Tag+" 里有没有 realip 和 nodectl？）", http.StatusBadRequest)
		return
	}
	what := fmt.Sprintf("cluster=%s relay %s -> %s release=%s", c.Name, f.addr(), safe(f.Target), safe(f.Tag))
	res, seen, err := s.runWithPassword(ctx, f.sshAddr(), "root", password, installCmd, strings.NewReader(script))
	if err != nil {
		s.log(r, "relay-install", what+": "+err.Error(), false)
		fail(fmt.Sprintf("没能登录 %s 并运行安装（%v）。请检查 IP、SSH 端口和 root 密码；有的服务器默认不允许 root 用密码登录（sshd 的 PermitRootLogin）。", f.sshAddr(), err), http.StatusBadGateway)
		return
	}
	if res.Exit != 0 {
		s.log(r, "relay-install", fmt.Sprintf("%s: the script exited with %d", what, res.Exit), false)
		fail(fmt.Sprintf("安装脚本在中转机上出错了（退出码 %d）：%s", res.Exit, lastLines(res.Stderr, res.Stdout)), http.StatusBadGateway)
		return
	}
	_, printed := ops.InstallReport(res.Stdout)
	if printed == "" || printed != seen {
		s.log(r, "relay-install", fmt.Sprintf("%s: logged in to %s but the server reports %q", what, seen, printed), false)
		fail("登录时服务器出示的 SSH 指纹和它自己报的不一样（或没报），可能有人在中间拦截。没有保存任何东西。", http.StatusConflict)
		return
	}
	fetch := s.FetchHostKey
	if fetch == nil {
		fetch = func(addr string, to time.Duration) (string, string, error) {
			return sshx.FetchHostKeyVia(s.nodeDial(), addr, to)
		}
	}
	if again, _, err := fetch(f.sshAddr(), 10*time.Second); err != nil || again != printed {
		s.log(r, "relay-install", what+": the SSH key read again over the network differs", false)
		fail("中转装好了，但再次从网络上读到的 SSH 指纹对不上（或读不到），没有保存。请检查后重试。", http.StatusConflict)
		return
	}
	s.log(r, "relay-install", what+" ssh="+seen, true)

	rl := &store.Relay{ID: store.NewID(), ClusterID: c.ID, Name: f.Name, Host: f.Host, Port: f.Port, Target: f.Target, HostKey: printed, Created: s.now()}
	if f.SSHPort != 22 {
		rl.SSHPort = f.SSHPort
	}
	if err := s.Store.Mutate(func(st *store.State) error {
		if st.Cluster(c.ID) == nil {
			return errors.New("没有这个渠道")
		}
		st.Relays = append(st.Relays, rl)
		return nil
	}); err != nil {
		fail(friendlyStoreError(err), http.StatusBadRequest)
		return
	}
	s.log(r, "relay-add", fmt.Sprintf("cluster=%s relay=%s %s -> %s ssh=%s", c.ID, safe(rl.Name), rl.Addr(), safe(rl.Target), printed), true)
	msg := "中转「" + rl.Name + "」装好了（" + rl.Addr() + " → " + rl.Target + "）。现在加节点时，在「源站」那里选它就行。"
	// the panel's management account must work, or nodes could never be allowed in
	if _, err := s.syncRelay(ctx, rl.ID); err != nil {
		msg += " 注意：面板用远程管理连它没成功（" + err.Error() + "），加节点前请在中转列表里点「同步白名单」试一次。"
	}
	msg += " 首次登录时记下的 SSH 指纹是 " + printed + "。现在可以改掉 root 密码了。"
	http.Redirect(w, r, "/cluster/"+c.ID+"?ok="+url.QueryEscape(msg)+"#relays", http.StatusSeeOther)
}

// syncRelay tells a relay which nodes may use it: the nodes saved as forwarding through it, plus extra (a
// node being installed). It returns how many addresses were sent.
func (s *Server) syncRelay(ctx context.Context, relayID string, extra ...string) (int, error) {
	if s.Ops == nil {
		return 0, errors.New("面板没有开远程管理")
	}
	st := s.Store.Snapshot()
	rl := st.Relay(relayID)
	if rl == nil {
		return 0, errors.New("没有这个中转")
	}
	var ips []string
	for _, n := range st.NodesVia(relayID) {
		if net.ParseIP(n.Host) != nil {
			ips = append(ips, n.Host)
		}
	}
	ips = append(ips, extra...)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.Ops.RelayAllow(ctx, rl.AsNode(), ips); err != nil {
		return 0, err
	}
	return len(ips), nil
}

func (s *Server) relaySyncNow(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id, rid := r.PathValue("id"), r.PathValue("rid")
	rl := s.Store.Snapshot().Relay(rid)
	if rl == nil || rl.ClusterID != id {
		http.NotFound(w, r)
		return
	}
	n, err := s.syncRelay(r.Context(), rid)
	s.log(r, "relay-sync", fmt.Sprintf("relay=%s %s: %d node(s)", safe(rl.Name), rl.Addr(), n), err == nil)
	if err != nil {
		s.renderCluster(w, r, id, "", "没能更新中转「"+rl.Name+"」的白名单："+err.Error(), http.StatusBadGateway)
		return
	}
	s.back(w, r, id, fmt.Sprintf("中转「%s」的白名单已更新：放行 %d 个节点。", rl.Name, n))
}

func (s *Server) relayDelete(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id, rid := r.PathValue("id"), r.PathValue("rid")
	var label string
	err := s.Store.Mutate(func(st *store.State) error {
		if users := st.NodesVia(rid); len(users) > 0 {
			return fmt.Errorf("还有 %d 个节点经过这个中转（比如「%s」）：先删掉或重装这些节点", len(users), users[0].Name)
		}
		for i, x := range st.Relays {
			if x.ID == rid && x.ClusterID == id {
				label = x.Addr()
				st.Relays = append(st.Relays[:i], st.Relays[i+1:]...)
				return nil
			}
		}
		return errors.New("这个渠道里没有这个中转")
	})
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "relay-delete", fmt.Sprintf("cluster=%s relay=%s", id, label), true)
	s.back(w, r, id, "中转已从面板删除。服务器上的程序还在运行，不用了的话可以直接退掉那台服务器。")
}

// relayView is one relay on the channel page.
type relayView struct {
	R     *store.Relay
	Nodes []*store.Node
}

func relayViews(st store.State, clusterID string) []relayView {
	var out []relayView
	for _, rl := range st.RelaysOf(clusterID) {
		out = append(out, relayView{R: rl, Nodes: st.NodesVia(rl.ID)})
	}
	return out
}
