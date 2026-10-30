package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func fakeZones(zs ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return zs, nil }
}

func TestSavingATokenTestsItAndSaysWhichDomainsItManages(t *testing.T) {
	e := newEnv(t, false)
	a := e.admin()
	e.s.CFZones = fakeZones("example.com", "other.uk")
	_, body, _ := a.post("/secrets", url.Values{"csrf": {a.csrf()}, "ref": {"main"}, "field": {"api_token"}, "value": {"tok"}}, nil)
	for _, want := range []string{"令牌可以用", "example.com", "other.uk"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestABadTokenIsSavedButExplainedInPlainWords(t *testing.T) {
	e := newEnv(t, false)
	a := e.admin()
	e.s.CFZones = func(context.Context, string) ([]string, error) {
		return nil, errors.New("cloudflare: 6003 Invalid request headers")
	}
	_, body, _ := a.post("/secrets", url.Values{"csrf": {a.csrf()}, "ref": {"main"}, "field": {"api_token"}, "value": {"bad"}}, nil)
	if !strings.Contains(body, "令牌有問題") || !strings.Contains(body, "Cloudflare 不認這個令牌") || strings.Contains(body, "6003") {
		t.Fatal("a rejected token should get a plain explanation, not an API error code")
	}
}

func TestTheTestButtonChecksAStoredToken(t *testing.T) {
	e := newEnv(t, false)
	a := e.admin()
	e.vault.Set("dns/main/api_token", "tok")
	e.s.CFZones = fakeZones("example.com")
	_, body, _ := a.post("/secrets/test", url.Values{"csrf": {a.csrf()}, "ref": {"main"}}, nil)
	if !strings.Contains(body, "令牌可以用") {
		t.Fatal("test failed")
	}
	_, body, _ = a.post("/secrets/test", url.Values{"csrf": {a.csrf()}, "ref": {"nothere"}}, nil)
	if !strings.Contains(body, "找不到名為") {
		t.Fatal("a missing token should say so")
	}
}

func TestCloudflareDomainIsFoundWithoutTypingAZone(t *testing.T) {
	e := newEnv(t, false)
	a := e.admin()
	cl := e.seedCluster("official")
	e.vault.Set("dns/main/api_token", "tok")
	e.s.CFZones = fakeZones("example.com", "deep.example.com")
	st, _, _ := a.post("/cluster/"+cl.ID+"/target", url.Values{"csrf": {a.csrf()}, "provider": {"cloudflare"}, "dns_name": {"cfg.deep.example.com"}}, nil)
	if st != http.StatusSeeOther {
		t.Fatalf("%d", st)
	}
	var got string
	for _, tg := range e.st.Snapshot().Cluster(cl.ID).Targets {
		if tg.Name == "cfg.deep.example.com" {
			got = tg.Zone + "|" + tg.CredRef
		}
	}
	if got != "deep.example.com|main" {
		t.Fatalf("zone/credential not filled in: %q", got)
	}
}

func TestADomainTheTokenCannotManageIsRefusedClearly(t *testing.T) {
	e := newEnv(t, false)
	a := e.admin()
	cl := e.seedCluster("official")
	e.vault.Set("dns/main/api_token", "tok")
	e.s.CFZones = fakeZones("example.com")
	st, body, _ := a.post("/cluster/"+cl.ID+"/target", url.Values{"csrf": {a.csrf()}, "provider": {"cloudflare"}, "dns_name": {"cfg.stranger.org"}}, nil)
	if st != http.StatusBadRequest || !strings.Contains(body, "example.com") || !strings.Contains(body, "沒有") {
		t.Fatalf("%d", st)
	}
}

func TestTheChannelPageListsWhatToDoNextInOrder(t *testing.T) {
	e := newEnv(t, false)
	a := e.admin()
	cl := e.seedCluster("official")
	_, body, _ := a.get("/cluster/" + cl.ID)
	for _, want := range []string{"解鎖保險庫", "貼上 Cloudflare 令牌", "選好要寫入哪些域名", "加入節點", "把名單寫進域名", "還差"} {
		if !strings.Contains(body, want) {
			t.Errorf("the checklist is missing %q", want)
		}
	}
	_, dash, _ := a.get("/")
	if !strings.Contains(dash, "下一步") {
		t.Fatal("the dashboard should point at the next step")
	}
}
