package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gamec/panel/internal/auth"
	"gamec/panel/internal/store"
)

// Changing what was entered before, instead of deleting and adding it again.

func (s *Server) routesEdit(mux *http.ServeMux) {
	mux.HandleFunc("POST /cluster/{id}/edit", s.need(true, s.clusterEdit))
	mux.HandleFunc("POST /cluster/{id}/target/{idx}/edit", s.need(true, s.targetEdit))
	mux.HandleFunc("POST /cluster/{id}/node/{nid}/edit", s.need(true, s.nodeEdit))
}

func validOrigin(o string) error {
	if o == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(o)
	p, perr := strconv.Atoi(port)
	if err != nil || perr != nil || p < 1 || p > 65535 || host == "" || strings.ContainsAny(host, " /\"'<>") {
		return fmt.Errorf("源站地址要写成 IP:端口，比如 203.0.113.5:10443")
	}
	return nil
}

func (s *Server) clusterEdit(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	origin := strings.TrimSpace(r.FormValue("origin"))
	valid, err1 := strconv.Atoi(r.FormValue("valid_days"))
	renew, err2 := strconv.Atoi(r.FormValue("renew_days"))
	proxyV2 := r.FormValue("proxy_v2") == "on"
	fail := func(msg string) { s.renderCluster(w, r, id, "", msg, http.StatusBadRequest) }
	switch {
	case !clusterNameRe.MatchString(name):
		fail("名称必须是 1-60 个字符，且不能包含 < > \" ' &。")
		return
	case err1 != nil || err2 != nil:
		fail("有效期和续期天数必须是数字。")
		return
	}
	if err := validOrigin(origin); err != nil {
		fail(err.Error())
		return
	}
	var originChanged bool
	err := s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil {
			return fmt.Errorf("没有这个渠道")
		}
		for _, o := range st.Clusters {
			if o.ID != id && o.Name == name {
				return fmt.Errorf("已经有一个叫「%s」的渠道了", name)
			}
		}
		originChanged = c.Origin != origin
		c.Name, c.Origin, c.ValidDays, c.RenewBeforeDays, c.ProxyV2 = name, origin, valid, renew, proxyV2
		return nil
	})
	if err != nil {
		fail(friendlyStoreError(err))
		return
	}
	s.log(r, "cluster-edit", fmt.Sprintf("cluster=%s name=%s origin=%s proxy_v2=%v valid=%d renew=%d", id, safe(name), safe(origin), proxyV2, valid, renew), true)
	if originChanged && origin != "" {
		if c := s.Store.Snapshot().Cluster(id); c != nil {
			go s.checkOrigin(context.Background(), c)
		}
	}
	s.back(w, r, id, "渠道设置已保存。")
}

// targetFromForm reads the domain fields shared by adding and changing a domain.
func (s *Server) targetFromForm(r *http.Request) (store.DNSTarget, error) {
	t := store.DNSTarget{Provider: r.FormValue("provider"), Zone: strings.ToLower(strings.TrimSpace(r.FormValue("zone"))),
		Name: strings.ToLower(strings.TrimSpace(r.FormValue("dns_name"))), CredRef: strings.TrimSpace(r.FormValue("cred_ref"))}
	if t.Provider == "manual" {
		t.CredRef = ""
	} else if t.CredRef == "" {
		t.CredRef = "main"
	}
	if t.Provider == "manual" && t.Zone == "" { // a manual target needs no account; take the last two labels
		if f := strings.Split(t.Name, "."); len(f) >= 2 {
			t.Zone = strings.Join(f[len(f)-2:], ".")
		}
	}
	if t.Provider == "cloudflare" && t.Zone == "" { // Cloudflare: the panel finds the domain itself
		zone, err := s.detectZone(r.Context(), t.CredRef, t.Name)
		if err != nil {
			return t, err
		}
		t.Zone = zone
	}
	return t, nil
}

func (s *Server) targetEdit(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	idx, _ := strconv.Atoi(r.PathValue("idx"))
	old := strings.TrimSpace(r.FormValue("old_name"))
	t, err := s.targetFromForm(r)
	if err != nil {
		s.renderCluster(w, r, id, "", err.Error(), http.StatusBadRequest)
		return
	}
	err = s.Store.Mutate(func(st *store.State) error {
		c := st.Cluster(id)
		if c == nil || idx < 0 || idx >= len(c.Targets) || c.Targets[idx].Name != old {
			return fmt.Errorf("这个域名刚刚被别人改过或移除了，请刷新页面再试")
		}
		c.Targets[idx] = t
		return nil
	})
	if err != nil {
		s.renderCluster(w, r, id, "", friendlyStoreError(err), http.StatusBadRequest)
		return
	}
	s.log(r, "target-edit", fmt.Sprintf("cluster=%s %s -> %s %s", id, safe(old), t.Provider, t.Name), true)
	s.back(w, r, id, "域名已修改。请「立即更新名单」一次，把名单写到新的地方。")
}

func (s *Server) nodeEdit(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	c, n, ok := s.lookup(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	name, host := strings.TrimSpace(r.FormValue("name")), strings.TrimSpace(r.FormValue("host"))
	pin := strings.TrimSpace(r.FormValue("pin"))
	port, perr := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	if perr != nil {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", "端口必须是数字。", http.StatusBadRequest)
		return
	}
	var moved bool
	err := s.Store.Mutate(func(st *store.State) error {
		x := st.Node(n.ID)
		if x == nil {
			return fmt.Errorf("这个节点刚刚被删除了")
		}
		moved = x.Host != host || x.Port != port || x.Pin != pin
		if x.Host != host {
			x.HostKey = "" // another address may be another machine: its SSH key must be confirmed again
		}
		x.Name, x.Host, x.Port, x.Pin = name, host, port, pin
		return nil
	})
	if err != nil {
		s.renderNode(w, r, nodePageData{Cluster: c, Node: n}, "", friendlyStoreError(err), http.StatusBadRequest)
		return
	}
	if moved { // what was learnt about the old address says nothing about the new one
		s.Mon.Forget(n.ID)
		if x := s.Store.Snapshot().Node(n.ID); x != nil {
			go s.Mon.ProbeAll(context.Background(), []*store.Node{x})
		}
	}
	s.log(r, "node-edit", fmt.Sprintf("node=%s name=%s addr=%s", n.ID, safe(name), net.JoinHostPort(host, strconv.Itoa(port))), true)
	msg := "节点已修改。"
	if moved {
		msg += "地址或指纹变了：它要重新连续通过 5 次检查才会进名单，之后自动维护会更新名单。"
	}
	http.Redirect(w, r, "/cluster/"+c.ID+"/node/"+n.ID+"?ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

// friendlyStoreError explains the store's validation messages, which are written for logs, in Chinese.
func friendlyStoreError(err error) string {
	m := err.Error()
	switch {
	case strings.Contains(m, "is listed twice"):
		return "这个地址和端口已经被另一个节点用了（一个地址只能属于一个渠道）。"
	case strings.Contains(m, "the pin must be"):
		return "证书指纹不对：应该是 44 个字符、以 = 结尾的一串。"
	case strings.Contains(m, "is not a valid host"):
		return "服务器地址不对：请填 IP 或域名。"
	case strings.Contains(m, "port out of range"):
		return "端口要在 1 到 65535 之间。"
	case strings.Contains(m, "node name must be"):
		return "节点名称要 1-60 个字符。"
	case strings.Contains(m, "valid days must be"):
		return "名单有效天数要在 2 到 90 之间。"
	case strings.Contains(m, "renew-before must be"):
		return "续期天数至少 1 天，而且要比有效天数少。"
	case strings.Contains(m, "bad DNS name or zone"):
		return "域名格式不对，比如应该是 cfg.example.com。"
	case strings.Contains(m, "is not inside"):
		return "完整域名必须在主域名下面，比如 cfg.example.com 在 example.com 下面。"
	case strings.Contains(m, "credential reference"):
		return "授权名称只能用小写英文、数字、- 和 _。"
	case strings.Contains(m, "is used twice"):
		return "已经有同名的渠道了。"
	}
	return m
}
