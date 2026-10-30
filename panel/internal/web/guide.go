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
		return "Cloudflare 不認這個令牌：可能沒有複製完整、已被撤銷，或權限不夠。請重新建立一個，權限選「區域 → DNS → 編輯」。"
	case strings.Contains(m, "no such host") || strings.Contains(m, "timeout") || strings.Contains(m, "dial") || strings.Contains(m, "deadline"):
		return "連不上 Cloudflare（網路問題），稍後再試一次。細節：" + m
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
		res.Message = "找不到名為「" + ref + "」的令牌，請先在上面貼上並儲存。"
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
		res.Message = "令牌有效，但它目前一個域名都管不了。建立令牌時請把你的域名加進「區域資源」。"
		return res
	}
	res.OK, res.Zones = true, zones
	return res
}

// detectZone finds which of the token's domains a full name belongs to, so nobody has to type a zone or an id.
func (s *Server) detectZone(ctx context.Context, ref, name string) (string, error) {
	if s.Vault.Sealed() {
		return "", fmt.Errorf("保險庫是上鎖狀態，請先解鎖，面板才能用令牌去查你的域名")
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
		return "", fmt.Errorf("這個令牌管理的域名裡沒有「%s」所屬的那一個。它能管理：%s", name, strings.Join(res.Zones, "、"))
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
	s.render(w, r, "secrets.html", page{Title: "域名授權", Flash: flash, Error: errMsg, Data: d}, status)
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
		s.renderSecrets(w, r, "", "保險庫是上鎖狀態，請先解鎖。", nil, http.StatusBadRequest)
		return
	}
	if !credRefRe.MatchString(ref) || !credField[field] || value == "" || len(value) > 4096 {
		s.renderSecrets(w, r, "", "名稱只能用小寫英文、數字、- 和 _；值不能是空的。", nil, http.StatusBadRequest)
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
			s.renderSecrets(w, r, "已儲存，而且令牌可以用。", "", &res, http.StatusOK)
		} else {
			s.renderSecrets(w, r, "已儲存。", "但測試沒通過：令牌可能有問題，見下方說明。", &res, http.StatusOK)
		}
		return
	}
	http.Redirect(w, r, "/secrets?ok="+url.QueryEscape("已儲存。這個值之後不會再顯示。"), http.StatusSeeOther)
}

func (s *Server) secretTest(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	ref := strings.TrimSpace(r.FormValue("ref"))
	if s.Vault.Sealed() {
		s.renderSecrets(w, r, "", "保險庫是上鎖狀態，請先解鎖。", nil, http.StatusBadRequest)
		return
	}
	if !credRefRe.MatchString(ref) {
		s.renderSecrets(w, r, "", "名稱不正確。", nil, http.StatusBadRequest)
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
		{Done: !s.Vault.Sealed(), Title: "解鎖保險庫", Hint: "保險庫上鎖時，面板不能更新名單。每次面板重新啟動都要解鎖一次。", Href: "/unseal", Link: "去解鎖"},
	}
	credHint := "到 Cloudflare 建一個只管你域名的令牌，貼進來，面板會馬上幫你測試。"
	if len(missing) > 0 && s.Vault.Sealed() == false {
		credHint = "寫入位置用到的授權「" + strings.Join(missing, "、") + "」還沒儲存。" + credHint
	}
	steps = append(steps,
		step{Done: anyCred && len(missing) == 0, Title: "貼上 Cloudflare 令牌", Hint: credHint, Href: "/secrets", Link: "去貼令牌"},
		step{Done: len(real) > 0, Title: "選好要寫入哪些域名", Hint: "名單會寫成這些域名下的一條記錄，App 靠它找到節點。", Href: "#targets", Link: "去設定"},
		step{Done: row.All > 0, Title: "加入節點", Hint: fmt.Sprintf("目前 %d 個節點，其中 %d 個檢查正常。至少要有一個正常的節點。", row.All, row.OK), Href: "#nodes", Link: "去加入"},
		step{Done: !c.Last.At.IsZero() && !c.Last.Manual && c.Last.Verified, Title: "把名單寫進域名", Hint: "面板簽好名單、寫進域名，再從外面讀一遍確認。之後它會自動續期。", Href: "#publish", Link: "去更新"},
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
