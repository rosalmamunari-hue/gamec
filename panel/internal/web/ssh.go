package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	s.render(w, r, "node.html", page{Title: d.Node.Name, Flash: flash, Error: errMsg, Data: d}, status)
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
	http.Redirect(w, r, "/cluster/"+c.ID+"/node/"+n.ID+"?ok="+url.QueryEscape("SSH settings saved."), http.StatusSeeOther)
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
	if fetch == nil {
		fetch = sshx.FetchHostKey
	}
	fp, typ, err := fetch(n.SSHAddr(), 10*time.Second)
	if err != nil {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "Could not read the server's host key: "+err.Error(), http.StatusBadGateway)
		return
	}
	if r.FormValue("action") != "trust" {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n, Fingerprint: fp, KeyType: typ, KeyChanged: n.HostKey != "" && n.HostKey != fp},
			"", "", http.StatusOK)
		return
	}
	if r.FormValue("fingerprint") != fp {
		s.log(r, "hostkey-trust", fmt.Sprintf("node=%s the key changed between showing and confirming", n.Addr()), false)
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "The server presented a different key than the one you were shown. Nothing was saved.", http.StatusConflict)
		return
	}
	if err := s.Store.Mutate(func(st *store.State) error { st.Node(n.ID).HostKey = fp; return nil }); err != nil {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "hostkey-trust", fmt.Sprintf("node=%s fingerprint=%s", n.Addr(), fp), true)
	http.Redirect(w, r, "/cluster/"+c.ID+"/node/"+n.ID+"?ok="+url.QueryEscape("Host key confirmed."), http.StatusSeeOther)
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
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "SSH management is not set up on this panel.", http.StatusServiceUnavailable)
		return
	}
	if s.Vault.Sealed() {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "The vault is sealed; the panel's SSH key is not available.", http.StatusServiceUnavailable)
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
		return nodePageData{Status: &st, Logs: logs}, "Read over SSH.", nil
	})
}

func (s *Server) sshControl(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	verb := r.FormValue("verb")
	s.sshOp(w, r, "ssh-"+safe(verb), 40*time.Second, func(ctx context.Context, c *store.Cluster, n store.Node) (nodePageData, string, error) {
		st, err := s.Ops.Control(ctx, n, verb)
		if err != nil {
			return nodePageData{}, "", err
		}
		return nodePageData{Status: &st}, fmt.Sprintf("%s done; the service is %s.", verb, st.Active), nil
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
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "Minutes must be between 1 and 60.", http.StatusBadRequest)
		return
	}
	s.sshOp(w, r, "ssh-stop-for", 40*time.Second, func(ctx context.Context, c *store.Cluster, n store.Node) (nodePageData, string, error) {
		if err := s.Ops.StopFor(ctx, n, time.Duration(mins)*time.Minute); err != nil {
			return nodePageData{}, "", err
		}
		return nodePageData{}, fmt.Sprintf("The service is stopped and starts again by itself in %d minute(s). Players switch to the other nodes meanwhile.", mins), nil
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
		return fmt.Errorf("%s is the only healthy node of its cluster; upgrading it would leave players with nothing", n.Addr())
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
		s.renderCluster(w, r, id, "", "No node of this cluster is set up for SSH management yet.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
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
		s.renderCluster(w, r, id, "", "Stopped: "+err.Error()+" Done so far: "+strings.Join(lines, "; "), http.StatusBadGateway)
		return
	}
	s.log(r, "upgrade-all", fmt.Sprintf("cluster=%s tag=%s %s", c.Name, safe(tag), strings.Join(lines, " | ")), true)
	s.back(w, r, id, "All nodes upgraded to "+tag+": "+strings.Join(lines, "; "))
}

// ---------------------------------------------------------------- the panel's SSH key and the prepare script

type sshPageData struct {
	HasKey     bool
	PublicLine string
	Script     string
}

func (s *Server) panelKey() (pub string, has bool, err error) {
	if s.Vault.Sealed() {
		return "", false, fmt.Errorf("the vault is sealed")
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
	s.render(w, r, "ssh.html", page{Title: "SSH management", Error: msg, Data: sshPageData{HasKey: has, PublicLine: pub}}, http.StatusOK)
}

func (s *Server) sshScript(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	pub, has, err := s.panelKey()
	data := sshPageData{HasKey: has, PublicLine: pub}
	fail := func(msg string) {
		s.render(w, r, "ssh.html", page{Title: "SSH management", Error: msg, Data: data}, http.StatusBadRequest)
	}
	if err != nil || !has {
		fail("The panel has no SSH key yet. Create one with `panel ssh-keygen` on the server.")
		return
	}
	tag := strings.TrimSpace(r.FormValue("tag"))
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	b, err := s.releases().Fetch(ctx, tag, "nodectl-linux-amd64")
	if err != nil {
		fail("Could not get nodectl for that release: " + err.Error())
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
	s.render(w, r, "ssh.html", page{Title: "SSH management", Data: data}, http.StatusOK)
}

var _ = engine.ProbeResult{}
