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
	Ready   bool   // what is needed for step 2 is there (unsealed vault, a panel key)
	Missing string
}

func (s *Server) renderWizard(w http.ResponseWriter, r *http.Request, d wizardData, errMsg string, status int) {
	if d.Step == 0 {
		d.Step = 1
	}
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
		Tag: strings.TrimSpace(r.FormValue("tag")), Origin: strings.TrimSpace(r.FormValue("origin")), From: strings.TrimSpace(r.FormValue("from"))}
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
	case f.Origin == "":
		return f, errors.New("要填源站地址：节点要知道把玩家的流量转到哪里。")
	}
	if err := validOrigin(f.Origin); err != nil {
		return f, err
	}
	return f, nil
}

func (s *Server) wizardScript(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, ok := s.wizardCluster(w, r)
	if !ok {
		return
	}
	f, err := readWizardForm(r)
	d := wizardData{Cluster: c, Form: f}
	if err != nil {
		s.renderWizard(w, r, d, err.Error(), http.StatusBadRequest)
		return
	}
	for _, n := range s.Store.Snapshot().Nodes {
		if n.Addr() == f.addr() {
			s.renderWizard(w, r, d, f.addr()+" 已经是节点「"+n.Name+"」了。", http.StatusBadRequest)
			return
		}
	}
	pub, has, err := s.panelKey()
	if err != nil || !has {
		s.renderWizard(w, r, d, "面板还没有 SSH 密钥，或保险库上锁了。", http.StatusBadRequest)
		return
	}
	secret, ok, err := s.Vault.Get(engine.NodeSecretName(c.ID))
	if err != nil || !ok {
		s.renderWizard(w, r, d, "保险库里找不到这个渠道的节点密钥。", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sums, err := s.releases().Checksums(ctx, f.Tag)
	if err != nil {
		s.renderWizard(w, r, d, "读不到版本 "+f.Tag+" 的校验码："+err.Error(), http.StatusBadGateway)
		return
	}
	base := strings.TrimRight(s.releases().Base, "/") + "/" + f.Tag + "/"
	prog := func(name string) ops.Program { return ops.Program{URL: base + name, SHA256: sums[name]} }
	script, err := ops.InstallScript(ops.InstallParams{Unit: "gamec-edge", Host: f.Host, Port: f.Port, Origin: f.Origin, Secret: secret,
		Edge: prog("edge-linux-amd64"), Gencert: prog("gencert-linux-amd64"), Nodectl: prog("nodectl-linux-amd64"), PubLine: pub, From: f.From})
	if err != nil {
		s.renderWizard(w, r, d, "生成脚本失败："+err.Error(), http.StatusBadRequest)
		return
	}
	if c.Origin == "" { // remember the origin for the next node
		s.Store.Mutate(func(st *store.State) error {
			if x := st.Cluster(c.ID); x != nil && x.Origin == "" {
				x.Origin = f.Origin
			}
			return nil
		})
	}
	s.log(r, "node-install-script", fmt.Sprintf("cluster=%s host=%s port=%d release=%s", c.Name, f.Host, f.Port, safe(f.Tag)), true)
	d.Step, d.Script = 2, script
	s.renderWizard(w, r, d, "", http.StatusOK)
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
	f, err := readWizardForm(r)
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
	f, err := readWizardForm(r)
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
	n := &store.Node{ID: store.NewID(), ClusterID: c.ID, Name: f.Name, Host: f.Host, Port: f.Port, Pin: pin, Enabled: true,
		SSHUser: "gamec-ops", HostKey: hostKey, Created: s.now()}
	if f.SSHPort != 22 {
		n.SSHPort = f.SSHPort
	}
	err = s.Store.Mutate(func(st *store.State) error {
		if st.Cluster(c.ID) == nil {
			return errors.New("没有这个渠道")
		}
		st.Nodes = append(st.Nodes, n)
		return nil
	})
	if err != nil {
		s.renderWizard(w, r, d, friendlyStoreError(err), http.StatusBadRequest)
		return
	}
	s.log(r, "node-add", fmt.Sprintf("cluster=%s node=%s %s pin=%s ssh=%s (wizard)", c.ID, safe(n.Name), n.Addr(), pin, hostKey), true)
	go s.Mon.ProbeAll(context.Background(), []*store.Node{n})
	msg := "节点「" + n.Name + "」已加入，远程管理也开好了。它要连续通过 5 次检查（约 5 分钟）才会进名单"
	if c.AutoPublish {
		msg += "，之后自动维护会把它写进名单。"
	} else {
		msg += "，然后请点「立即更新名单」。"
	}
	http.Redirect(w, r, "/cluster/"+c.ID+"?ok="+url.QueryEscape(msg)+"#nodes", http.StatusSeeOther)
}
