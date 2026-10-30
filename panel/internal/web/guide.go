package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"gamec/panel/internal/auth"
	"gamec/panel/internal/dns"
	"gamec/panel/internal/store"
)

// ---------------------------------------------------------------- Cloudflare tokens

func (s *Server) cfZones(ctx context.Context, token string) ([]string, error) {
	if s.CFZones != nil {
		return s.CFZones(ctx, token)
	}
	return dns.CloudflareZones(ctx, token, dns.Options{})
}

// cfProblem turns what Cloudflare (or the network) said into something a person can act on.
func cfProblem(err error) string {
	m := err.Error()
	switch {
	case strings.Contains(m, "6003") || strings.Contains(m, "9109") || strings.Contains(m, "1000") ||
		strings.Contains(m, "10000") || strings.Contains(m, "HTTP 401") || strings.Contains(m, "HTTP 403") ||
		strings.Contains(strings.ToLower(m), "invalid"):
		return "Cloudflare 不认这个令牌：可能没有拷贝完整、已被撤销，或权限不够。请重新创建一个，权限选「区域 → DNS → 编辑」。"
	case strings.Contains(m, "no such host") || strings.Contains(m, "timeout") || strings.Contains(m, "dial") || strings.Contains(m, "deadline"):
		return "连不上 Cloudflare（网络问题），稍后再试一次。细节：" + m
	}
	return m
}

type tokenResult struct {
	Ref     string
	OK      bool
	Zones   []string
	Message string
}

// checkToken proves a stored Cloudflare token works and says which domains it can manage.
func (s *Server) checkToken(ctx context.Context, ref string) tokenResult {
	res := tokenResult{Ref: ref}
	tok, ok, err := s.Vault.Get("dns/" + ref + "/api_token")
	if err != nil || !ok || tok == "" {
		res.Message = "找不到名为「" + ref + "」的令牌，请先在上面粘贴并保存。"
		return res
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	zones, err := s.cfZones(cctx, tok)
	if err != nil {
		res.Message = cfProblem(err)
		return res
	}
	if len(zones) == 0 {
		res.Message = "令牌有效，但它目前一个域名都管不了。创建令牌时请把你的域名加进「区域资源」。"
		return res
	}
	res.OK, res.Zones = true, zones
	return res
}

// detectZone finds which of the token's domains a full name belongs to, so nobody has to type a zone or an id.
func (s *Server) detectZone(ctx context.Context, ref, name string) (string, error) {
	if s.Vault.Sealed() {
		return "", fmt.Errorf("保险库是上锁状态，请先解锁，面板才能用令牌去查你的域名")
	}
	res := s.checkToken(ctx, ref)
	if !res.OK {
		return "", fmt.Errorf("%s", res.Message)
	}
	best := ""
	for _, z := range res.Zones {
		if (name == z || strings.HasSuffix(name, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	if best == "" {
		return "", fmt.Errorf("这个令牌管理的域名里没有「%s」所属的那一个。它能管理：%s", name, strings.Join(res.Zones, "、"))
	}
	return best, nil
}

// ---------------------------------------------------------------- the "domain access" page

type credInfo struct {
	Ref      string
	Fields   []string
	HasToken bool
}

type secretsData struct {
	Creds  []credInfo
	Result *tokenResult
}

func (s *Server) renderSecrets(w http.ResponseWriter, r *http.Request, flash, errMsg string, res *tokenResult, status int) {
	d := secretsData{Result: res}
	if !s.Vault.Sealed() {
		all, _ := s.Vault.Names()
		by := map[string]*credInfo{}
		for _, n := range all {
			f := strings.Split(n, "/")
			if len(f) != 3 || f[0] != "dns" {
				continue
			}
			ci := by[f[1]]
			if ci == nil {
				ci = &credInfo{Ref: f[1]}
				by[f[1]] = ci
			}
			ci.Fields = append(ci.Fields, f[2])
			if f[2] == "api_token" {
				ci.HasToken = true
			}
		}
		for _, ci := range by {
			sort.Strings(ci.Fields)
			d.Creds = append(d.Creds, *ci)
		}
		sort.Slice(d.Creds, func(i, j int) bool { return d.Creds[i].Ref < d.Creds[j].Ref })
	}
	s.render(w, r, "secrets.html", page{Title: "域名授权", Flash: flash, Error: errMsg, Data: d}, status)
}

func (s *Server) secretsPage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.renderSecrets(w, r, r.URL.Query().Get("ok"), "", nil, http.StatusOK)
}

func (s *Server) secretSet(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	ref, field, value := strings.TrimSpace(r.FormValue("ref")), r.FormValue("field"), strings.TrimSpace(r.FormValue("value"))
	if ref == "" {
		ref = "main"
	}
	if s.Vault.Sealed() {
		s.renderSecrets(w, r, "", "保险库是上锁状态，请先解锁。", nil, http.StatusBadRequest)
		return
	}
	if !credRefRe.MatchString(ref) || !credField[field] || value == "" || len(value) > 4096 {
		s.renderSecrets(w, r, "", "名称只能用小写英文、数字、- 和 _；值不能是空的。", nil, http.StatusBadRequest)
		return
	}
	if err := s.Vault.Set("dns/"+ref+"/"+field, value); err != nil {
		s.renderSecrets(w, r, "", err.Error(), nil, http.StatusBadRequest)
		return
	}
	s.log(r, "secret-set", "dns/"+ref+"/"+field, true) // the value is never logged
	if field == "api_token" {
		res := s.checkToken(r.Context(), ref)
		s.log(r, "secret-test", fmt.Sprintf("dns/%s/api_token ok=%v", ref, res.OK), res.OK)
		if res.OK {
			s.renderSecrets(w, r, "已保存，而且令牌可以用。", "", &res, http.StatusOK)
		} else {
			s.renderSecrets(w, r, "已保存。", "但测试没通过：令牌可能有问题，见下方说明。", &res, http.StatusOK)
		}
		return
	}
	http.Redirect(w, r, "/secrets?ok="+url.QueryEscape("已保存。这个值之后不会再显示。"), http.StatusSeeOther)
}

func (s *Server) secretTest(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	ref := strings.TrimSpace(r.FormValue("ref"))
	if s.Vault.Sealed() {
		s.renderSecrets(w, r, "", "保险库是上锁状态，请先解锁。", nil, http.StatusBadRequest)
		return
	}
	if !credRefRe.MatchString(ref) {
		s.renderSecrets(w, r, "", "名称不正确。", nil, http.StatusBadRequest)
		return
	}
	res := s.checkToken(r.Context(), ref)
	s.log(r, "secret-test", fmt.Sprintf("dns/%s/api_token ok=%v", ref, res.OK), res.OK)
	s.renderSecrets(w, r, "", "", &res, http.StatusOK)
}

// ---------------------------------------------------------------- "what to do next"

type step struct {
	Done  bool
	Title string
	Hint  string
	Href  string
	Link  string
}

func (s *Server) credNames() map[string]bool {
	out := map[string]bool{}
	if s.Vault.Sealed() {
		return out
	}
	all, _ := s.Vault.Names()
	for _, n := range all {
		out[n] = true
	}
	return out
}

// steps lists what a channel needs before players can find its nodes, in the order to do it.
func (s *Server) steps(st store.State, c *store.Cluster, row clusterRow) []step {
	have := s.credNames()
	anyCred := false
	for n := range have {
		if strings.HasPrefix(n, "dns/") {
			anyCred = true
		}
	}
	var real, missing []string
	for _, t := range c.Targets {
		if t.Provider == "manual" {
			continue
		}
		real = append(real, t.Name)
		field := map[string]string{"cloudflare": "api_token", "spaceship": "api_key", "aliyun": "access_key_id"}[t.Provider]
		if !have["dns/"+t.CredRef+"/"+field] {
			missing = append(missing, t.CredRef)
		}
	}
	steps := []step{
		{Done: !s.Vault.Sealed(), Title: "解锁保险库", Hint: "保险库上锁时，面板不能更新名单。每次面板重新启动都要解锁一次。", Href: "/unseal", Link: "去解锁"},
	}
	credHint := "到 Cloudflare 建一个只管你域名的令牌，贴进来，面板会马上帮你测试。"
	if len(missing) > 0 && s.Vault.Sealed() == false {
		credHint = "写入位置用到的授权「" + strings.Join(missing, "、") + "」还没保存。" + credHint
	}
	steps = append(steps,
		step{Done: anyCred && len(missing) == 0, Title: "粘贴 Cloudflare 令牌", Hint: credHint, Href: "/secrets", Link: "去贴令牌"},
		step{Done: len(real) > 0, Title: "选好要写入哪些域名", Hint: "名单会写成这些域名下的一条记录，App 靠它找到节点。", Href: "#targets", Link: "去设置"},
		step{Done: row.All > 0, Title: "加入节点", Hint: fmt.Sprintf("目前 %d 个节点，其中 %d 个检查正常。至少要有一个正常的节点。", row.All, row.OK), Href: "#nodes", Link: "去加入"},
		step{Done: !c.Last.At.IsZero() && !c.Last.Manual && c.Last.Verified, Title: "把名单写进域名", Hint: "面板签好名单、写进域名，再从外面读一遍确认。之后它会自动续期。", Href: "#publish", Link: "去更新"},
	)
	for i := range steps {
		if strings.HasPrefix(steps[i].Href, "#") {
			steps[i].Href = "/cluster/" + c.ID + steps[i].Href
		}
	}
	return steps
}

func nextStep(ss []step) *step {
	for i := range ss {
		if !ss[i].Done {
			return &ss[i]
		}
	}
	return nil
}
