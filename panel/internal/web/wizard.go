package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gamec/edge/shieldclient"
	"gamec/panel/internal/auth"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/ops"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

// The "add a node" wizard. Instead of making a certificate somewhere, copying files, writing a service,
// preparing SSH and typing a pin and a fingerprint into three pages, the administrator:
//
//  1. types the server's address,
//  2. runs one script on it as root (it installs everything and prints two fingerprints),
//  3. compares the two fingerprints the panel reads from the new server with what the script printed.
//
// The panel never trusts what it reads in step 3 by itself: the person confirms it, and it is read again at
// the moment of saving and must not have changed.

func (s *Server) routesWizard(mux *http.ServeMux) {
	mux.HandleFunc("GET /cluster/{id}/node/new", s.need(true, s.wizardStart))
	mux.HandleFunc("POST /cluster/{id}/node/new/script", s.need(true, s.wizardScript))
	mux.HandleFunc("POST /cluster/{id}/node/new/check", s.need(true, s.wizardCheck))
	mux.HandleFunc("POST /cluster/{id}/node/new/finish", s.need(true, s.wizardFinish))
	mux.HandleFunc("POST /cluster/{id}/node/new/auto", s.need(true, s.wizardAuto))
}

// wizardForm is what the administrator typed in step 1; it is carried through the later steps.
type wizardForm struct {
	Name    string
	Host    string
	Port    int
	SSHPort int
	Tag     string
	Origin  string
	From    string
	Relay   string // the relay the node forwards through; empty: straight to Origin
}

func (f wizardForm) addr() string    { return net.JoinHostPort(f.Host, strconv.Itoa(f.Port)) }
func (f wizardForm) sshAddr() string { return net.JoinHostPort(f.Host, strconv.Itoa(f.SSHPort)) }

type wizardData struct {
	Cluster *store.Cluster
	Step    int
	Form    wizardForm
	Script  string
	Pin     string // what the new node presents (step 3)
	HostKey string // its SSH key
	Problem string // why step 3 could not read the fingerprints yet
	Relays  []*store.Relay
	Ready   bool // what is needed for step 2 is there (unsealed vault, a panel key)
	Missing string
}

func (s *Server) renderWizard(w http.ResponseWriter, r *http.Request, d wizardData, errMsg string, status int) {
	if d.Step == 0 {
		d.Step = 1
	}
	d.Relays = s.Store.Snapshot().RelaysOf(d.Cluster.ID)
	d.Ready, d.Missing = true, ""
	switch {
	case s.Vault.Sealed():
		d.Ready, d.Missing = false, "保险库上锁了：安装脚本要用到存在保险库里的渠道密钥。先解锁。"
	default:
		if _, has, err := s.panelKey(); err != nil || !has {
			d.Ready, d.Missing = false, "面板还没有自己的 SSH 密钥：先停掉面板，在面板服务器上运行一次 panel ssh-keygen，再启动面板。"
		}
	}
	s.render(w, r, "node_new.html", page{Title: "加一个节点", Back: &backLink{"/cluster/" + d.Cluster.ID, "返回 " + d.Cluster.Name},
		Error: errMsg, Data: d}, status)
}

func (s *Server) wizardCluster(w http.ResponseWriter, r *http.Request) (*store.Cluster, bool) {
	c := s.Store.Snapshot().Cluster(r.PathValue("id"))
	if c == nil {
		http.NotFound(w, r)
		return nil, false
	}
	return c, true
}

func (s *Server) wizardStart(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, ok := s.wizardCluster(w, r)
	if !ok {
		return
	}
	f := wizardForm{Port: 20000 + rand.IntN(40000), SSHPort: 22, Tag: s.latestRelease(), Origin: c.Origin,
		Name: fmt.Sprintf("node%d", len(s.Store.Snapshot().NodesOf(c.ID))+1)}
	if e := s.Store.Snapshot().Egress; e != nil { // the nodes see the jump host, so that is where SSH comes from
		if h, _, err := net.SplitHostPort(e.Addr); err == nil {
			f.From = h
		}
	}
	s.renderWizard(w, r, wizardData{Cluster: c, Form: f}, "", http.StatusOK)
}

func readWizardForm(r *http.Request) (wizardForm, error) {
	f := wizardForm{Name: strings.TrimSpace(r.FormValue("name")), Host: strings.TrimSpace(r.FormValue("host")),
		Tag: strings.TrimSpace(r.FormValue("tag")), Origin: strings.TrimSpace(r.FormValue("origin")), From: strings.TrimSpace(r.FormValue("from")),
		Relay: strings.TrimSpace(r.FormValue("relay"))}
	var err1, err2 error
	f.Port, err1 = strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	f.SSHPort, err2 = strconv.Atoi(strings.TrimSpace(r.FormValue("ssh_port")))
	switch {
	case f.Name == "" || len(f.Name) > 60:
		return f, errors.New("名称要 1-60 个字符。")
	case net.ParseIP(f.Host) == nil:
		return f, errors.New("服务器 IP 不对：请填新服务器的公网 IP，比如 203.0.113.11。")
	case err1 != nil || f.Port < 1024 || f.Port > 65535:
		return f, errors.New("玩家连接的端口要在 1024 到 65535 之间。")
	case err2 != nil || f.SSHPort < 1 || f.SSHPort > 65535:
		return f, errors.New("SSH 端口不对，一般是 22。")
	case f.Origin == "" && f.Relay == "":
		return f, errors.New("要填源站地址：节点要知道把玩家的流量转到哪里。")
	}
	if f.Relay != "" {
		return f, nil // the origin is the relay's address (see readWizard)
	}
	if err := validOrigin(f.Origin); err != nil {
		return f, err
	}
	return f, nil
}

// readWizard reads the form and, for a node that forwards through a relay, points it at the relay.
func (s *Server) readWizard(r *http.Request, c *store.Cluster) (wizardForm, error) {
	f, err := readWizardForm(r)
	if err != nil || f.Relay == "" {
		return f, err
	}
	rl := s.Store.Snapshot().Relay(f.Relay)
	if rl == nil || rl.ClusterID != c.ID {
		f.Relay = ""
		return f, errors.New("选的中转不在这个渠道里了，请重新选。")
	}
	f.Origin = rl.Addr()
	return f, nil
}

func (s *Server) wizardScript(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, ok := s.wizardCluster(w, r)
	if !ok {
		return
	}
	f, err := s.readWizard(r, c)
	d := wizardData{Cluster: c, Form: f}
	if err != nil {
		s.renderWizard(w, r, d, err.Error(), http.StatusBadRequest)
		return
	}
	script, msg, status := s.buildInstall(r, c, f)
	if msg != "" {
		s.renderWizard(w, r, d, msg, status)
		return
	}
	s.log(r, "node-install-script", fmt.Sprintf("cluster=%s host=%s port=%d release=%s", c.Name, f.Host, f.Port, safe(f.Tag)), true)
	d.Step, d.Script = 2, script
	s.renderWizard(w, r, d, "", http.StatusOK)
}

// buildInstall makes the install script for the new server. On failure it returns what to tell the
// administrator and the HTTP status.
func (s *Server) buildInstall(r *http.Request, c *store.Cluster, f wizardForm) (script, msg string, status int) {
	for _, n := range s.Store.Snapshot().Nodes {
		if n.Addr() == f.addr() {
			return "", f.addr() + " 已经是节点「" + n.Name + "」了。", http.StatusBadRequest
		}
	}
	pub, has, err := s.panelKey()
	if err != nil || !has {
		return "", "面板还没有 SSH 密钥，或保险库上锁了。", http.StatusBadRequest
	}
	secret, ok, err := s.Vault.Get(engine.NodeSecretName(c.ID))
	if err != nil || !ok {
		return "", "保险库里找不到这个渠道的节点密钥。", http.StatusBadRequest
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sums, err := s.releases().Checksums(ctx, f.Tag)
	if err != nil {
		return "", "读不到版本 " + f.Tag + " 的校验码：" + err.Error(), http.StatusBadGateway
	}
	base := strings.TrimRight(s.releases().Base, "/") + "/" + f.Tag + "/"
	prog := func(name string) ops.Program { return ops.Program{URL: base + name, SHA256: sums[name]} }
	script, err = ops.InstallScript(ops.InstallParams{Unit: "gamec-edge", Host: f.Host, Port: f.Port, Origin: f.Origin, Proxy: c.ProxyHeader(), Secret: secret,
		Edge: prog("edge-linux-amd64"), Gencert: prog("gencert-linux-amd64"), Nodectl: prog("nodectl-linux-amd64"), PubLine: pub, From: f.From})
	if err != nil {
		return "", "生成脚本失败：" + err.Error(), http.StatusBadRequest
	}
	if f.Relay != "" { // the relay must let the new node in before it can reach the origin
		if _, err := s.syncRelay(r.Context(), f.Relay, f.Host); err != nil {
			return "", "没能让中转放行这台新节点（" + err.Error() + "）。请先确认中转正常（渠道页的中转列表里点「同步白名单」试试）。", http.StatusBadGateway
		}
	}
	if c.Origin == "" && f.Relay == "" { // remember the origin for the next node
		s.Store.Mutate(func(st *store.State) error {
			if x := st.Cluster(c.ID); x != nil && x.Origin == "" {
				x.Origin = f.Origin
			}
			return nil
		})
	}
	return script, "", 0
}

// readFingerprints reads, through the egress host when one is set, the TLS pin and the SSH key the new
// server presents.
func (s *Server) readFingerprints(f wizardForm) (pin, hostKey string, err error) {
	if s.FetchPin != nil {
		pin, err = s.FetchPin(f.addr(), 10*time.Second)
	} else {
		dial := shieldclient.DialFunc(shieldclient.DirectDial)
		if d := s.nodeDial(); d != nil {
			dial = shieldclient.DialFunc(d)
		}
		pin, err = shieldclient.FetchPinVia(dial, f.addr(), 10*time.Second)
	}
	if err != nil {
		return "", "", fmt.Errorf("连不上节点程序 %s（%v）。脚本跑完了吗？有没有报错？云服务商的安全组有没有放行这个端口？", f.addr(), err)
	}
	fetch := s.FetchHostKey
	if fetch == nil {
		fetch = func(addr string, to time.Duration) (string, string, error) {
			return sshx.FetchHostKeyVia(s.nodeDial(), addr, to)
		}
	}
	hostKey, _, err = fetch(f.sshAddr(), 10*time.Second)
	if err != nil {
		return pin, "", fmt.Errorf("读不到服务器的 SSH 指纹（%v）。SSH 端口对吗？", err)
	}
	return pin, hostKey, nil
}

func (s *Server) wizardCheck(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, ok := s.wizardCluster(w, r)
	if !ok {
		return
	}
	f, err := s.readWizard(r, c)
	d := wizardData{Cluster: c, Form: f, Step: 3}
	if err != nil {
		d.Step = 1
		s.renderWizard(w, r, d, err.Error(), http.StatusBadRequest)
		return
	}
	d.Pin, d.HostKey, err = s.readFingerprints(f)
	if err != nil {
		d.Problem = err.Error()
	}
	s.renderWizard(w, r, d, "", http.StatusOK)
}

func (s *Server) wizardFinish(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, ok := s.wizardCluster(w, r)
	if !ok {
		return
	}
	f, err := s.readWizard(r, c)
	d := wizardData{Cluster: c, Form: f, Step: 3}
	if err != nil {
		d.Step = 1
		s.renderWizard(w, r, d, err.Error(), http.StatusBadRequest)
		return
	}
	pin, hostKey, err := s.readFingerprints(f)
	if err != nil {
		d.Problem = err.Error()
		s.renderWizard(w, r, d, "", http.StatusBadGateway)
		return
	}
	if pin != r.FormValue("pin") || hostKey != r.FormValue("host_key") {
		s.log(r, "node-add", fmt.Sprintf("cluster=%s %s: the fingerprints changed between showing and confirming", c.Name, f.addr()), false)
		d.Pin, d.HostKey = pin, hostKey
		s.renderWizard(w, r, d, "服务器出示的指纹和你刚才看到的不一样，没有保存任何东西。请重新核对下面的指纹。", http.StatusConflict)
		return
	}
	msg, err := s.saveWizardNode(r, c, f, pin, hostKey, "wizard")
	if err != nil {
		s.renderWizard(w, r, d, friendlyStoreError(err), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/cluster/"+c.ID+"?ok="+url.QueryEscape(msg)+"#nodes", http.StatusSeeOther)
}

// saveWizardNode adds the new server as a node, with the fingerprints that were checked, and returns the
// message for the channel page.
func (s *Server) saveWizardNode(r *http.Request, c *store.Cluster, f wizardForm, pin, hostKey, how string) (string, error) {
	n := &store.Node{ID: store.NewID(), ClusterID: c.ID, Name: f.Name, Host: f.Host, Port: f.Port, Pin: pin, Enabled: true,
		SSHUser: "gamec-ops", HostKey: hostKey, RelayID: f.Relay, Created: s.now()}
	if f.SSHPort != 22 {
		n.SSHPort = f.SSHPort
	}
	err := s.Store.Mutate(func(st *store.State) error {
		if st.Cluster(c.ID) == nil {
			return errors.New("没有这个渠道")
		}
		st.Nodes = append(st.Nodes, n)
		return nil
	})
	if err != nil {
		return "", err
	}
	s.log(r, "node-add", fmt.Sprintf("cluster=%s node=%s %s pin=%s ssh=%s (%s)", c.ID, safe(n.Name), n.Addr(), pin, hostKey, how), true)
	go s.Mon.ProbeAll(context.Background(), []*store.Node{n})
	if n.RelayID != "" { // it was let in before the install; this also tidies up after installs that were abandoned
		s.syncRelay(r.Context(), n.RelayID)
	}
	msg := "节点「" + n.Name + "」已加入，远程管理也开好了。它要连续通过 5 次检查（约 5 分钟）才会进名单"
	if c.AutoPublish {
		msg += "，之后自动维护会把它写进名单。"
	} else {
		msg += "，然后请点「立即更新名单」。"
	}
	return msg, nil
}

// ---------------------------------------------------------------- one-click install with the root password

// installCmd runs the script that arrives on stdin from a private temporary file, so nothing the script
// starts can read the rest of it as its own input.
const installCmd = `f=$(mktemp) && cat > "$f" && sh "$f" </dev/null; rc=$?; rm -f "$f"; exit $rc`

// installTimeout bounds the whole one-click install (two downloads and starting the service).
var installTimeout = 5 * time.Minute

// runWithPassword logs in to addr with a password, runs cmd with stdin and returns its result and the SSH key
// the server presented.
func (s *Server) runWithPassword(ctx context.Context, addr, user, password, cmd string, stdin io.Reader) (sshx.Result, string, error) {
	if s.RunWithPassword != nil {
		return s.RunWithPassword(ctx, addr, user, password, cmd, stdin)
	}
	c, seen, err := sshx.DialPassword(sshx.Target{Addr: addr, User: user, Timeout: 20 * time.Second, Dial: s.nodeDial()}, password)
	if err != nil {
		return sshx.Result{}, seen, err
	}
	defer c.Close()
	res, err := c.Run(ctx, cmd, stdin)
	return res, seen, err
}

// wizardAuto does steps 2 and 3 itself: it logs in to the new server with the root password typed in step 1,
// runs the install script there, and adds the node once what the script printed matches what the server
// presents over the network. The password is used for this one login only; it is not stored or logged.
//
// What this cannot check is the very first login: the panel has never seen the server's SSH key, so it
// accepts the one presented. It is shown in the result so it can be compared with the cloud console.
func (s *Server) wizardAuto(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, ok := s.wizardCluster(w, r)
	if !ok {
		return
	}
	f, err := s.readWizard(r, c)
	d := wizardData{Cluster: c, Form: f}
	if err != nil {
		s.renderWizard(w, r, d, err.Error(), http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		s.renderWizard(w, r, d, "一键安装要填服务器的 root 密码。不想把密码交给面板，就点「生成脚本，我自己运行」。", http.StatusBadRequest)
		return
	}
	script, msg, status := s.buildInstall(r, c, f)
	if msg != "" {
		s.renderWizard(w, r, d, msg, status)
		return
	}
	what := fmt.Sprintf("cluster=%s host=%s port=%d release=%s", c.Name, f.Host, f.Port, safe(f.Tag))
	ctx, cancel := context.WithTimeout(r.Context(), installTimeout)
	defer cancel()
	res, seen, err := s.runWithPassword(ctx, f.sshAddr(), "root", password, installCmd, strings.NewReader(script))
	if err != nil {
		s.log(r, "node-auto-install", what+": "+err.Error(), false)
		s.renderWizard(w, r, d, fmt.Sprintf("没能登录 %s 并运行安装（%v）。请检查 IP、SSH 端口和 root 密码；有的服务器默认不允许 root 用密码登录（sshd 的 PermitRootLogin）。", f.sshAddr(), err), http.StatusBadGateway)
		return
	}
	if res.Exit != 0 {
		s.log(r, "node-auto-install", fmt.Sprintf("%s: the script exited with %d", what, res.Exit), false)
		s.renderWizard(w, r, d, fmt.Sprintf("安装脚本在服务器上出错了（退出码 %d）：%s", res.Exit, lastLines(res.Stderr, res.Stdout)), http.StatusBadGateway)
		return
	}
	printedPin, printedKey := ops.InstallReport(res.Stdout)
	if printedPin == "" || printedKey == "" {
		s.log(r, "node-auto-install", what+": the script did not print both fingerprints", false)
		s.renderWizard(w, r, d, "脚本跑完了，但没有印出节点指纹和 SSH 指纹："+lastLines(res.Stderr, res.Stdout), http.StatusBadGateway)
		return
	}
	if printedKey != seen {
		s.log(r, "node-auto-install", fmt.Sprintf("%s: logged in to %s but the server reports %s", what, seen, printedKey), false)
		s.renderWizard(w, r, d, "登录时服务器出示的 SSH 指纹和它自己报的不一样，可能有人在中间拦截。没有保存任何东西，请改用「生成脚本，我自己运行」。", http.StatusConflict)
		return
	}
	s.log(r, "node-auto-install", what+" ssh="+seen, true)

	// The same check a person does in step 3, against what the script printed.
	var pin, hostKey string
	for try := 0; ; try++ {
		pin, hostKey, err = s.readFingerprints(f)
		if err == nil || try == 2 || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	if err != nil {
		d.Step, d.Problem = 3, err.Error()+fmt.Sprintf(" 节点已经装好了。放行端口后点「再试一次」，对照的指纹是：node pin %s，SSH key %s。", printedPin, printedKey)
		s.renderWizard(w, r, d, "", http.StatusOK)
		return
	}
	if pin != printedPin || hostKey != printedKey {
		s.log(r, "node-add", fmt.Sprintf("cluster=%s %s: the fingerprints over the network differ from what the script printed", c.Name, f.addr()), false)
		s.renderWizard(w, r, d, fmt.Sprintf("从网络上读到的指纹和服务器上脚本印出的不一样（读到 %s / %s，脚本印出 %s / %s），可能 IP 不对或有人拦截。没有保存任何东西。", pin, hostKey, printedPin, printedKey), http.StatusConflict)
		return
	}
	msg, err = s.saveWizardNode(r, c, f, pin, hostKey, "one-click install")
	if err != nil {
		s.renderWizard(w, r, d, friendlyStoreError(err), http.StatusBadRequest)
		return
	}
	msg += " 首次登录时记下的 SSH 指纹是 " + hostKey + "，想核对可以在云服务商控制台里看。现在可以改掉 root 密码了。"
	http.Redirect(w, r, "/cluster/"+c.ID+"?ok="+url.QueryEscape(msg)+"#nodes", http.StatusSeeOther)
}

// lastLines is the end of what a failed script said, for the error message.
func lastLines(outs ...string) string {
	for _, o := range outs {
		var keep []string
		for _, l := range strings.Split(strings.TrimSpace(o), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				keep = append(keep, l)
			}
		}
		if len(keep) > 0 {
			keep = keep[max(0, len(keep)-5):]
			out := strings.Join(keep, " | ")
			if r := []rune(out); len(r) > 600 {
				out = "…" + string(r[len(r)-600:])
			}
			return out
		}
	}
	return "（没有输出）"
}
