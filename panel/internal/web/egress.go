package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gamec/panel/internal/auth"
	"gamec/panel/internal/egress"
	"gamec/panel/internal/ops"
	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

func (s *Server) routesEgress(mux *http.ServeMux) {
	mux.HandleFunc("GET /egress", s.need(true, s.egressPage))
	mux.HandleFunc("POST /egress/set", s.need(true, s.egressSet))
	mux.HandleFunc("POST /egress/hostkey", s.need(true, s.egressHostKey))
	mux.HandleFunc("POST /egress/remove", s.need(true, s.egressRemove))
	mux.HandleFunc("POST /egress/script", s.need(true, s.egressScript))
	mux.HandleFunc("POST /egress/test", s.need(true, s.egressTest))
}

type testRow struct {
	Node string
	Addr string
	OK   bool
	Took string
	Err  string
}

type egressPageData struct {
	Cfg         *store.Egress
	Fingerprint string
	KeyType     string
	KeyChanged  bool
	HasKey      bool
	Script      string
	Tests       []testRow
}

// nodeDial is how connections to nodes are opened: through the egress host when one is configured.
func (s *Server) nodeDial() sshx.DialFunc {
	if s.Egress == nil {
		return nil
	}
	return s.Egress.DialContext
}

func (s *Server) renderEgress(w http.ResponseWriter, r *http.Request, d egressPageData, flash, errMsg string, status int) {
	d.Cfg = s.Store.Snapshot().Egress
	_, d.HasKey, _ = s.panelKey()
	s.render(w, r, "egress.html", page{Title: "出口中转", Lead: "让面板发往节点的所有连接先经过一台中转机，节点就看不到面板的 IP。", Flash: flash, Error: errMsg, Data: d}, status)
}

func (s *Server) egressPage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.renderEgress(w, r, egressPageData{}, r.URL.Query().Get("ok"), "", http.StatusOK)
}

func (s *Server) egressSet(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	addr, user := strings.TrimSpace(r.FormValue("addr")), strings.TrimSpace(r.FormValue("user"))
	if _, _, err := net.SplitHostPort(addr); err != nil { // a bare host means the SSH port
		addr = net.JoinHostPort(addr, "22")
	}
	err := s.Store.Mutate(func(st *store.State) error {
		keep := ""
		if st.Egress != nil && st.Egress.Addr == addr {
			keep = st.Egress.HostKey // the same machine: the confirmed key stays valid
		}
		st.Egress = &store.Egress{Addr: addr, User: user, HostKey: keep}
		return nil
	})
	if err != nil {
		s.renderEgress(w, r, egressPageData{}, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "egress-set", fmt.Sprintf("addr=%s user=%s", safe(addr), safe(user)), true)
	http.Redirect(w, r, "/egress?ok="+url.QueryEscape("已保存。请先在下面确认主机密钥，之后才会有东西经过它。"), http.StatusSeeOther)
}

// egressHostKey reads the jump host's key directly (that connection is the one thing that is not tunnelled).
func (s *Server) egressHostKey(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	cfg := s.Store.Snapshot().Egress
	if cfg == nil {
		s.renderEgress(w, r, egressPageData{}, "", "请先设置出口跳板机。", http.StatusBadRequest)
		return
	}
	fetch := s.FetchJumpKey
	if fetch == nil {
		fetch = sshx.FetchHostKey
	}
	fp, typ, err := fetch(cfg.Addr, 10*time.Second)
	if err != nil {
		s.renderEgress(w, r, egressPageData{}, "", "无法读取主机密钥："+err.Error(), http.StatusBadGateway)
		return
	}
	if r.FormValue("action") != "trust" {
		s.renderEgress(w, r, egressPageData{Fingerprint: fp, KeyType: typ, KeyChanged: cfg.HostKey != "" && cfg.HostKey != fp}, "", "", http.StatusOK)
		return
	}
	if r.FormValue("fingerprint") != fp {
		s.log(r, "egress-hostkey", "the key changed between showing and confirming", false)
		s.renderEgress(w, r, egressPageData{}, "", "主机出示的密钥和你刚才看到的不一样。没有保存任何东西。", http.StatusConflict)
		return
	}
	if err := s.Store.Mutate(func(st *store.State) error {
		if st.Egress == nil || st.Egress.Addr != cfg.Addr {
			return fmt.Errorf("出口跳板机在这段时间被改过了，请重新开始")
		}
		st.Egress.HostKey = fp
		return nil
	}); err != nil {
		s.renderEgress(w, r, egressPageData{}, "", err.Error(), http.StatusConflict)
		return
	}
	s.log(r, "egress-hostkey", "fingerprint="+fp, true)
	http.Redirect(w, r, "/egress?ok="+url.QueryEscape("主机密钥已确认。从现在起，连到节点的所有连接都会经过这台主机。"), http.StatusSeeOther)
}

func (s *Server) egressRemove(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.Store.Mutate(func(st *store.State) error { st.Egress = nil; return nil })
	if s.Egress != nil {
		s.Egress.Close()
	}
	s.log(r, "egress-remove", "", true)
	http.Redirect(w, r, "/egress?ok="+url.QueryEscape("已移除。连到节点的连接改回直连，节点会看到面板自己的地址。"), http.StatusSeeOther)
}

// allowedDestinations are the addresses the jump host must be willing to forward to.
func allowedDestinations(st store.State) []string {
	var out []string
	for _, n := range st.Nodes {
		out = append(out, n.Addr())
		if n.SSHConfigured() {
			out = append(out, n.SSHAddr())
		}
	}
	return out
}

func (s *Server) egressScript(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	pub, has, err := s.panelKey()
	if err != nil || !has {
		s.renderEgress(w, r, egressPageData{}, "", "面板还没有 SSH 密钥（请运行 `panel ssh-keygen`），或保险库是上锁状态。", http.StatusBadRequest)
		return
	}
	script, err := ops.PrepareJumpScript(pub, allowedDestinations(s.Store.Snapshot()), strings.TrimSpace(r.FormValue("from")))
	if err != nil {
		s.renderEgress(w, r, egressPageData{}, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "egress-script", "", true)
	s.renderEgress(w, r, egressPageData{Script: script}, "", "", http.StatusOK)
}

// egressTest opens a TCP connection to every node's service port through the egress host.
func (s *Server) egressTest(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	if s.Egress == nil || !s.Egress.Configured() {
		s.renderEgress(w, r, egressPageData{}, "", "尚未设置出口跳板机。", http.StatusBadRequest)
		return
	}
	var rows []testRow
	for _, n := range s.Store.Snapshot().Nodes {
		row := testRow{Node: n.Name, Addr: n.Addr()}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		t0 := time.Now()
		c, err := s.Egress.DialContext(ctx, "tcp", n.Addr())
		cancel()
		row.Took = time.Since(t0).Round(time.Millisecond).String()
		if err != nil {
			row.Err = err.Error()
		} else {
			row.OK = true
			c.Close()
		}
		rows = append(rows, row)
	}
	s.log(r, "egress-test", fmt.Sprintf("%d node(s)", len(rows)), true)
	s.renderEgress(w, r, egressPageData{Tests: rows}, "", "", http.StatusOK)
}

var _ = egress.ErrNotConfirmed
