package engine

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gamec/edge/shieldlist"
	"gamec/panel/internal/audit"
	"gamec/panel/internal/dns"
	"gamec/panel/internal/store"
	"gamec/panel/internal/vault"
)

const pin = "c65StCewbul2pPTQFu2ZuxI3TLhWb6lxMQacqAJDYoE="

// ---------------------------------------------------------------- fakes

type fakeProv struct {
	mu     sync.Mutex
	calls  [][]string // writes of the list
	next   [][]string // writes of the next names (at dw2.<name>)
	fail   error
	manual bool
	ctxErr []error // ctx.Err() as each write saw it
}

func (f *fakeProv) Name() string { return "fake" }
func (f *fakeProv) ReplaceTXT(ctx context.Context, _, fqdn string, values []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(fqdn, shieldlist.NextLabel+".") {
		f.next = append(f.next, append([]string(nil), values...))
		return f.fail
	}
	f.ctxErr = append(f.ctxErr, ctx.Err())
	f.calls = append(f.calls, append([]string(nil), values...))
	if f.manual {
		return dns.ErrManual
	}
	return f.fail
}
func (f *fakeProv) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }
func (f *fakeProv) last() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

type fakeVerifier struct{ err error }

func (v fakeVerifier) Verify(context.Context, string, *ecdsa.PublicKey, int64) error { return v.err }

type env struct {
	t    *testing.T
	v    *vault.Vault
	st   *store.Store
	au   *audit.Log
	auth string
	pub  *Publisher
	mon  *Monitor
	sch  *Scheduler
	now  time.Time
	prov map[string]*fakeProv // by target name
	ver  *fakeVerifier
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Create(filepath.Join(dir, "vault.json"), "test passphrase 123")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open(filepath.Join(dir, "state.json"))
	auPath := filepath.Join(dir, "audit.log")
	au, _ := audit.Open(auPath)
	e := &env{t: t, v: v, st: st, au: au, auth: auPath, now: time.Unix(1_800_000_000, 0), prov: map[string]*fakeProv{}}
	e.ver = &fakeVerifier{}
	e.pub = &Publisher{Vault: v, Store: st, Audit: au, Verifier: fakeVerifierPtr{e}, Now: func() time.Time { return e.now },
		Provider: func(tg store.DNSTarget) (dns.Provider, error) {
			p := e.prov[tg.Name]
			if p == nil {
				p = &fakeProv{manual: tg.Provider == "manual"}
				e.prov[tg.Name] = p
			}
			return p, nil
		}}
	e.mon = NewMonitor(nil)
	e.sch = NewScheduler(e.pub, e.mon, st)
	e.sch.Now = func() time.Time { return e.now }
	return e
}

type fakeVerifierPtr struct{ e *env }

func (f fakeVerifierPtr) Verify(ctx context.Context, n string, k *ecdsa.PublicKey, iat int64) error {
	return f.e.ver.err
}

func (e *env) addCluster(name string, targets ...store.DNSTarget) *store.Cluster {
	e.t.Helper()
	if len(targets) == 0 {
		targets = []store.DNSTarget{{Provider: "cloudflare", Zone: "example.com", Name: "_gs-" + strings.ToLower(name) + ".example.com", CredRef: "main"}}
	}
	c := &store.Cluster{ID: store.NewID(), Name: name, ValidDays: 30, RenewBeforeDays: 10, Targets: targets, AutoPublish: true}
	if err := e.st.Mutate(func(s *store.State) error { s.Clusters = append(s.Clusters, c); return nil }); err != nil {
		e.t.Fatal(err)
	}
	k, _ := shieldlist.GenerateKey()
	enc, _ := shieldlist.PrivateKeyB64(k)
	if err := e.v.Set(SigningKeyName(c.ID), enc); err != nil {
		e.t.Fatal(err)
	}
	return c
}

var nextHost = 1

func (e *env) addNode(c *store.Cluster, name string) *store.Node {
	e.t.Helper()
	nextHost++
	n := &store.Node{ID: store.NewID(), ClusterID: c.ID, Name: name, Host: fmt.Sprintf("10.9.%d.%d", nextHost/250, nextHost%250+1), Port: 30800, Pin: pin, Enabled: true}
	if err := e.st.Mutate(func(s *store.State) error { s.Nodes = append(s.Nodes, n); return nil }); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) healthy(n *store.Node, times int) {
	for i := 0; i < times; i++ {
		e.mon.Record(n.ID, ProbeResult{At: e.now, OK: true})
	}
}
func (e *env) failing(n *store.Node, times int) {
	for i := 0; i < times; i++ {
		e.mon.Record(n.ID, ProbeResult{At: e.now, Err: "down"})
	}
}
func (e *env) cluster(id string) *store.Cluster { return e.st.Snapshot().Cluster(id) }
func (e *env) active(c *store.Cluster) []*store.Node {
	return e.st.Snapshot().Active(c.ID, e.now)
}
func (e *env) provFor(c *store.Cluster) *fakeProv {
	p := e.prov[c.Targets[0].Name]
	if p == nil {
		p = &fakeProv{}
		e.prov[c.Targets[0].Name] = p
	}
	return p
}

// ---------------------------------------------------------------- publisher

func TestPublishSignsAndSendsAVerifiableList(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official")
	a, b := e.addNode(c, "hk-1"), e.addNode(c, "hk-2")

	res, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{a, b}, "alice", "10.0.0.5", "manual")
	if err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	sent := e.provFor(c).last()
	if len(sent) == 0 {
		t.Fatal("nothing was sent to the DNS provider")
	}
	got := e.cluster(c.ID)
	pk, err := shieldlist.ParsePublicKeyB64(got.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := shieldlist.VerifyRecords(sent, pk, e.now)
	if err != nil {
		t.Fatalf("the records that were sent do not verify with the cluster's public key: %v", err)
	}
	if len(pl.Nodes) != 2 {
		t.Fatalf("nodes in the list: %+v", pl.Nodes)
	}
	if got.Last.NodesKey != store.NodesKey([]*store.Node{a, b}) || got.Last.Exp-got.Last.Iat != 30*24*3600 || !got.Last.Verified {
		t.Fatalf("what was recorded: %+v", got.Last)
	}
	if n, err := audit.Verify(e.auth); err != nil || n != 1 {
		t.Fatalf("audit n=%d err=%v", n, err)
	}
	es, _ := audit.Tail(e.auth, 1)
	if es[0].User != "alice" || es[0].IP != "10.0.0.5" || es[0].Action != "publish" || !es[0].OK {
		t.Fatalf("audit entry: %+v", es[0])
	}
}

// The admin reloading the page cancels the request; the DNS change must still run to the end, or a provider
// can be stopped between removing the old records and adding the new ones.
func TestPublishWritesDNSEvenWhenTheCallerHasGoneAway(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official")
	a := e.addNode(c, "hk-1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.pub.Publish(ctx, c.ID, []*store.Node{a}, "alice", "10.0.0.5", "manual")
	p := e.provFor(c)
	if p.count() != 1 || p.ctxErr[0] != nil {
		t.Fatalf("writes=%d, the write saw ctx error %v", p.count(), p.ctxErr)
	}
}

func TestPublishRefusesAnEmptyList(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official")
	if _, err := e.pub.Publish(context.Background(), c.ID, nil, "alice", "", "x"); err == nil {
		t.Fatal("an empty list was published")
	}
	if e.provFor(c).count() != 0 {
		t.Fatal("the provider was called")
	}
}

func TestPublishNeedsAnUnsealedVaultAndAKey(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official")
	n := e.addNode(c, "a")
	e.v.Delete(SigningKeyName(c.ID))
	if _, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{n}, "a", "", "x"); err == nil || !strings.Contains(err.Error(), "no signing key") {
		t.Fatalf("got %v", err)
	}
	e.v.Seal()
	if _, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{n}, "a", "", "x"); !errors.Is(err, vault.ErrSealed) {
		t.Fatalf("got %v", err)
	}
	if e.provFor(c).count() != 0 {
		t.Fatal("something was sent without a key")
	}
}

func TestManualTargetKeepsTheRecordsForPasting(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official", store.DNSTarget{Provider: "manual", Zone: "example.com", Name: "_gs.example.com"})
	n := e.addNode(c, "a")
	res, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{n}, "alice", "", "x")
	if err != nil || !res.Manual || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	last := e.cluster(c.ID).Last
	if !last.Manual || len(last.Records) == 0 || last.Verified {
		t.Fatalf("%+v", last)
	}
}

func TestAFailingTargetFailsThePublishAndLeavesTheRecordUntouched(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official",
		store.DNSTarget{Provider: "cloudflare", Zone: "a.com", Name: "_gs.a.com", CredRef: "a"},
		store.DNSTarget{Provider: "spaceship", Zone: "b.com", Name: "_gs.b.com", CredRef: "b"})
	n := e.addNode(c, "a")
	e.prov["_gs.b.com"] = &fakeProv{fail: errors.New("HTTP 500")}
	res, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{n}, "alice", "", "x")
	if err == nil || res.OK {
		t.Fatalf("a failing target must fail the publish: %v %+v", err, res)
	}
	if !strings.Contains(err.Error(), "_gs.b.com") {
		t.Fatalf("the error should name the failing target: %v", err)
	}
	if e.prov["_gs.a.com"].count() != 1 {
		t.Fatal("the healthy target should still have received the list")
	}
	if e.cluster(c.ID).Last.NodesKey != "" {
		t.Fatal("a half-done publish was recorded as done; it would never be retried")
	}
}

func TestEveryTargetGetsTheSameRecords(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official",
		store.DNSTarget{Provider: "cloudflare", Zone: "a.com", Name: "_gs.a.com", CredRef: "a"},
		store.DNSTarget{Provider: "aliyun", Zone: "b.com", Name: "_gs.b.com", CredRef: "b"})
	n := e.addNode(c, "a")
	if _, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{n}, "alice", "", "x"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(e.prov["_gs.a.com"].last(), "|") != strings.Join(e.prov["_gs.b.com"].last(), "|") {
		t.Fatal("two domains of one cluster must carry the identical signed list")
	}
}

func TestAListThatCannotBeReadBackIsReportedButNotFatal(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official")
	n := e.addNode(c, "a")
	e.ver.err = errors.New("DNS still serves the previous list")
	res, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{n}, "alice", "", "x")
	if err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	if res.Targets[0].Verified || res.Targets[0].VerifyErr == "" {
		t.Fatalf("%+v", res.Targets[0])
	}
	if e.cluster(c.ID).Last.Verified {
		t.Fatal("an unverified publish was marked verified")
	}
}

func TestClustersSignWithTheirOwnKeys(t *testing.T) {
	e := newEnv(t)
	a, b := e.addCluster("official"), e.addCluster("channel-a")
	na, nb := e.addNode(a, "a1"), e.addNode(b, "b1")
	e.pub.Publish(context.Background(), a.ID, []*store.Node{na}, "x", "", "t")
	e.pub.Publish(context.Background(), b.ID, []*store.Node{nb}, "x", "", "t")
	pkA, _ := shieldlist.ParsePublicKeyB64(e.cluster(a.ID).PublicKey)
	pkB, _ := shieldlist.ParsePublicKeyB64(e.cluster(b.ID).PublicKey)
	if pkA.Equal(pkB) {
		t.Fatal("two clusters share a signing key")
	}
	if _, err := shieldlist.VerifyRecords(e.provFor(a).last(), pkB, e.now); err == nil {
		t.Fatal("a list for one channel verifies under another channel's key")
	}
	if _, err := shieldlist.VerifyRecords(e.provFor(a).last(), pkA, e.now); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------- reading it back from outside

func TestDoHVerifierWaitsForDNSToCatchUp(t *testing.T) {
	k, _ := shieldlist.GenerateKey()
	old, _ := shieldlist.BuildRecords(k, []shieldlist.Node{{H: "1.1.1.1", P: 1, K: pin}}, time.Now().Add(-time.Hour), 24*time.Hour)
	fresh, _ := shieldlist.BuildRecords(k, []shieldlist.Node{{H: "2.2.2.2", P: 1, K: pin}}, time.Now(), 24*time.Hour)
	var mu sync.Mutex
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		polls++
		recs := fresh
		if polls <= 2 {
			recs = old // DNS has not caught up yet
		}
		mu.Unlock()
		var ans []map[string]any
		for _, rec := range recs {
			ans = append(ans, map[string]any{"type": 16, "data": `"` + rec[:len(rec)/2] + `" "` + rec[len(rec)/2:] + `"`})
		}
		json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": ans})
	}))
	defer srv.Close()
	v := &DoHVerifier{URLs: []string{srv.URL}, Timeout: 5 * time.Second, Interval: 20 * time.Millisecond}
	if err := v.Verify(context.Background(), "_gs.example.com", &k.PublicKey, time.Now().Unix()-1); err != nil {
		t.Fatalf("should succeed once DNS serves the new list: %v", err)
	}
	if polls < 3 {
		t.Fatalf("it accepted the old list (polls=%d)", polls)
	}
}

func TestDoHVerifierGivesUpWithAReason(t *testing.T) {
	k, _ := shieldlist.GenerateKey()
	other, _ := shieldlist.GenerateKey()
	recs, _ := shieldlist.BuildRecords(other, []shieldlist.Node{{H: "1.1.1.1", P: 1, K: pin}}, time.Now(), time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ans []map[string]any
		for _, rec := range recs {
			ans = append(ans, map[string]any{"type": 16, "data": `"` + rec + `"`})
		}
		json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": ans})
	}))
	defer srv.Close()
	v := &DoHVerifier{URLs: []string{srv.URL}, Timeout: 200 * time.Millisecond, Interval: 20 * time.Millisecond}
	err := v.Verify(context.Background(), "_gs.example.com", &k.PublicKey, 0)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("a list signed by the wrong key must not count as published: %v", err)
	}
}

// ---------------------------------------------------------------- monitor

func TestNodeIsEjectedAfterConsecutiveFailuresOnly(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	n := e.addNode(c, "a")
	for i := 0; i < 20; i++ { // alternating never reaches 5 in a row
		e.healthy(n, 1)
		e.failing(n, 1)
	}
	if e.mon.Health(n.ID).Ejected {
		t.Fatal("a flapping node was ejected on scattered failures")
	}
	e.healthy(n, 1) // the loop ended on a failure, so start the count from a clean slate
	e.failing(n, 4)
	if e.mon.Health(n.ID).Ejected {
		t.Fatal("ejected after 4")
	}
	e.failing(n, 1)
	if !e.mon.Health(n.ID).Ejected {
		t.Fatal("not ejected after 5 failures in a row")
	}
}

func TestEjectedNodeReturnsOnlyAfterSustainedSuccess(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	n := e.addNode(c, "a")
	e.failing(n, 5)
	e.healthy(n, 4)
	if !e.mon.Health(n.ID).Ejected {
		t.Fatal("readmitted after only 4 successes")
	}
	e.failing(n, 1)
	e.healthy(n, 4)
	if !e.mon.Health(n.ID).Ejected {
		t.Fatal("a failure must restart the count")
	}
	e.healthy(n, 1)
	if e.mon.Health(n.ID).Ejected {
		t.Fatal("not readmitted after 5 successes in a row")
	}
}

func TestDecideRules(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	old, fresh, bad := e.addNode(c, "old"), e.addNode(c, "fresh"), e.addNode(c, "bad")
	active := []*store.Node{old, fresh, bad}
	published := map[string]bool{old.Key(): true, bad.Key(): true}

	e.healthy(old, 1)
	e.healthy(fresh, 4) // not enough to be added
	e.failing(bad, 5)   // ejected
	d := e.mon.Decide(active, published)
	if got := store.NodesKey(d.Nodes); got != store.NodesKey([]*store.Node{old}) {
		t.Fatalf("expected only the old node, got %s", got)
	}
	e.healthy(fresh, 1) // now 5
	d = e.mon.Decide(active, published)
	if got := store.NodesKey(d.Nodes); got != store.NodesKey([]*store.Node{old, fresh}) {
		t.Fatalf("the proven new node should join, got %s", got)
	}
}

func TestMonitoringNeverEmptiesTheList(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	a, b := e.addNode(c, "a"), e.addNode(c, "b")
	e.failing(a, 10)
	e.failing(b, 10)
	d := e.mon.Decide([]*store.Node{a, b}, map[string]bool{a.Key(): true, b.Key(): true})
	if len(d.Nodes) != 2 || d.Note == "" {
		t.Fatalf("every node failing at once means a problem on the panel's side; the list must stay: %+v", d)
	}
	if d := e.mon.Decide([]*store.Node{a, b}, map[string]bool{}); len(d.Nodes) != 0 {
		t.Fatalf("with nothing published and nothing proven there is nothing to announce: %+v", d)
	}
}

// ---------------------------------------------------------------- scheduler

func firstPublish(e *env, c *store.Cluster, nodes ...*store.Node) {
	e.t.Helper()
	if _, err := e.pub.Publish(context.Background(), c.ID, nodes, "alice", "", "first"); err != nil {
		e.t.Fatal(err)
	}
}

func TestSchedulerLeavesAnUnchangedHealthyClusterAlone(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	a, b := e.addNode(c, "a"), e.addNode(c, "b")
	firstPublish(e, c, a, b)
	e.healthy(a, 10)
	e.healthy(b, 10)
	before := e.provFor(c).count()
	for i := 0; i < 5; i++ {
		e.now = e.now.Add(time.Minute)
		e.sch.Tick(context.Background())
	}
	if e.provFor(c).count() != before {
		t.Fatal("it republished although nothing changed")
	}
}

func TestSchedulerRemovesADeadNodeAndAddsItBackWhenProven(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	a, b := e.addNode(c, "a"), e.addNode(c, "b")
	firstPublish(e, c, a, b)
	e.healthy(a, 10)
	e.healthy(b, 10)

	e.failing(b, 5)
	e.sch.Tick(context.Background())
	pk, _ := shieldlist.ParsePublicKeyB64(e.cluster(c.ID).PublicKey)
	pl, err := shieldlist.VerifyRecords(e.provFor(c).last(), pk, e.now)
	if err != nil || len(pl.Nodes) != 1 || pl.Nodes[0].H != a.Host {
		t.Fatalf("the dead node should be gone from the list: %+v %v", pl, err)
	}

	e.healthy(b, 4)
	e.sch.Tick(context.Background())
	pl, _ = shieldlist.VerifyRecords(e.provFor(c).last(), pk, e.now)
	if len(pl.Nodes) != 1 {
		t.Fatal("a node that has passed 4 probes must not be re-added yet")
	}
	e.healthy(b, 1)
	e.sch.Tick(context.Background())
	pl, _ = shieldlist.VerifyRecords(e.provFor(c).last(), pk, e.now)
	if len(pl.Nodes) != 2 {
		t.Fatalf("the recovered node should be back: %+v", pl.Nodes)
	}
}

func TestSchedulerAnnouncesANewNodeOnlyAfterItProvesItself(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	a := e.addNode(c, "a")
	firstPublish(e, c, a)
	e.healthy(a, 10)
	n := e.addNode(c, "new")
	before := e.provFor(c).count()
	e.healthy(n, 4)
	e.sch.Tick(context.Background())
	if e.provFor(c).count() != before {
		t.Fatal("announced a node that has only passed 4 probes")
	}
	e.healthy(n, 1)
	e.sch.Tick(context.Background())
	if e.provFor(c).count() != before+1 {
		t.Fatal("the proven node was not announced")
	}
}

func TestSchedulerRenewsBeforeExpiry(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x") // valid 30 days, renew 10 days before
	a := e.addNode(c, "a")
	firstPublish(e, c, a)
	e.healthy(a, 10)
	e.now = e.now.Add(19 * 24 * time.Hour) // 11 days left
	e.sch.Tick(context.Background())
	if e.provFor(c).count() != 1 {
		t.Fatal("renewed too early")
	}
	e.now = e.now.Add(2 * 24 * time.Hour) // 9 days left
	e.sch.Tick(context.Background())
	if e.provFor(c).count() != 2 {
		t.Fatal("did not renew inside the renewal window")
	}
	if e.cluster(c.ID).Last.Exp <= e.now.Add(25*24*time.Hour).Unix() {
		t.Fatal("the renewed list does not have a fresh validity")
	}
}

func TestSchedulerDoesNothingWhileAutoPublishIsOffOrTheVaultIsSealed(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	a := e.addNode(c, "a")
	firstPublish(e, c, a)
	e.healthy(a, 10)
	b := e.addNode(c, "b")
	e.healthy(b, 10)
	before := e.provFor(c).count()

	e.st.Mutate(func(s *store.State) error { s.Cluster(c.ID).AutoPublish = false; return nil })
	e.sch.Tick(context.Background())
	if e.provFor(c).count() != before {
		t.Fatal("published although automatic publishing is off")
	}
	e.st.Mutate(func(s *store.State) error { s.Cluster(c.ID).AutoPublish = true; return nil })
	e.v.Seal()
	e.sch.Tick(context.Background())
	if e.provFor(c).count() != before {
		t.Fatal("tried to publish with a sealed vault")
	}
}

func TestSchedulerBacksOffAfterAFailure(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	a, b := e.addNode(c, "a"), e.addNode(c, "b")
	firstPublish(e, c, a)
	e.healthy(a, 10)
	e.healthy(b, 10)
	p := e.provFor(c)
	p.fail = errors.New("HTTP 503")
	before := p.count()

	e.sch.Tick(context.Background()) // fails
	if p.count() != before+1 {
		t.Fatal("did not try")
	}
	e.now = e.now.Add(4 * time.Minute)
	e.sch.Tick(context.Background())
	if p.count() != before+1 {
		t.Fatal("retried inside the backoff")
	}
	e.now = e.now.Add(2 * time.Minute) // 6 min after the failure
	e.sch.Tick(context.Background())   // fails again, delay doubles to 10 min
	if p.count() != before+2 {
		t.Fatal("did not retry after the backoff")
	}
	e.now = e.now.Add(8 * time.Minute)
	e.sch.Tick(context.Background())
	if p.count() != before+2 {
		t.Fatal("the delay did not double")
	}
	if !strings.Contains(e.sch.Note(c.ID), "后重试") {
		t.Fatalf("operators should be told: %q", e.sch.Note(c.ID))
	}
	p.fail = nil
	e.now = e.now.Add(3 * time.Minute)
	e.sch.Tick(context.Background())
	if e.cluster(c.ID).Last.NodesKey != store.NodesKey([]*store.Node{a, b}) {
		t.Fatal("it never recovered once the provider worked again")
	}
}

func TestTemporaryShutdownRemovesANodeAndItComesBackByItself(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("x")
	a, b := e.addNode(c, "a"), e.addNode(c, "b")
	firstPublish(e, c, a, b)
	e.healthy(a, 10)
	e.healthy(b, 10)

	e.st.Mutate(func(s *store.State) error { s.Node(b.ID).DisabledUntil = e.now.Add(30 * time.Minute); return nil })
	e.sch.Tick(context.Background())
	pk, _ := shieldlist.ParsePublicKeyB64(e.cluster(c.ID).PublicKey)
	pl, _ := shieldlist.VerifyRecords(e.provFor(c).last(), pk, e.now)
	if len(pl.Nodes) != 1 {
		t.Fatalf("the node should be out during its shutdown: %+v", pl.Nodes)
	}
	e.now = e.now.Add(31 * time.Minute)
	e.healthy(b, 5)
	e.sch.Tick(context.Background())
	pl, _ = shieldlist.VerifyRecords(e.provFor(c).last(), pk, e.now)
	if len(pl.Nodes) != 2 {
		t.Fatalf("the node should be back once the shutdown ended: %+v", pl.Nodes)
	}
}

func TestSchedulerTouchesOnlyTheClusterThatChanged(t *testing.T) {
	e := newEnv(t)
	a, b := e.addCluster("official"), e.addCluster("channel-a")
	a1, b1 := e.addNode(a, "a1"), e.addNode(b, "b1")
	firstPublish(e, a, a1)
	firstPublish(e, b, b1)
	e.healthy(a1, 10)
	e.healthy(b1, 10)
	beforeA, beforeB := e.provFor(a).count(), e.provFor(b).count()

	a2 := e.addNode(a, "a2")
	e.healthy(a2, 5)
	e.sch.Tick(context.Background())
	if e.provFor(a).count() != beforeA+1 {
		t.Fatal("cluster A was not updated")
	}
	if e.provFor(b).count() != beforeB {
		t.Fatal("a change in one channel republished another channel")
	}
}

func TestActiveNodesAreNeverMixedAcrossClusters(t *testing.T) {
	e := newEnv(t)
	a, b := e.addCluster("official"), e.addCluster("channel-a")
	a1 := e.addNode(a, "a1")
	e.addNode(b, "b1")
	if got := e.active(a); len(got) != 1 || got[0].ID != a1.ID {
		t.Fatalf("%v", got)
	}
}

// The names to read next time go in their own record at dw2.<name>, so the list itself stays small enough for
// a plain DNS answer; both are signed and, for a sealed cluster, sealed.
func TestPublishCarriesTheTargetNamesAsNextAndCanSealTheList(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official")
	a := e.addNode(c, "hk-1")

	res, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{a}, "alice", "", "x")
	if err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	pk, _ := shieldlist.ParsePublicKeyB64(e.cluster(c.ID).PublicKey)
	sent := e.provFor(c).last()
	if _, err := shieldlist.VerifyRecords(sent, pk, e.now); err != nil || len(sent) != 1 {
		t.Fatalf("%v %v", err, sent)
	}
	if size := shieldlist.AnswerSize(c.Targets[0].Name, len(sent[0])); size > 512 {
		t.Fatalf("the answer would be %d bytes", size)
	}
	p := e.provFor(c)
	nl, err := shieldlist.VerifyNextRecords(p.next[len(p.next)-1], pk, e.now, nil)
	if err != nil || len(nl.Names) != 1 || nl.Names[0] != c.Targets[0].Name {
		t.Fatalf("%v next=%+v", err, nl)
	}

	// sealed: the key lives in the vault, the plain check no longer reads it
	seal, _ := shieldlist.NewSealKey()
	if err := e.v.Set(SealKeyName(c.ID), base64.StdEncoding.EncodeToString(seal)); err != nil {
		t.Fatal(err)
	}
	e.st.Mutate(func(s *store.State) error { s.Cluster(c.ID).Sealed = true; return nil })
	if res, err = e.pub.Publish(context.Background(), c.ID, []*store.Node{a}, "alice", "", "x"); err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	sent = e.provFor(c).last()
	if _, err := shieldlist.VerifyRecords(sent, pk, e.now); err == nil {
		t.Fatal("sealed list readable without the key")
	}
	if _, err := shieldlist.VerifyNextRecords(p.next[len(p.next)-1], pk, e.now, nil); err == nil {
		t.Fatal("sealed next names readable without the key")
	}
	if _, err := shieldlist.VerifyRecordsSealed(sent, pk, e.now, seal); err != nil {
		t.Fatal(err)
	}
}

func TestPublishRefusesToSealWithoutAKey(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official")
	a := e.addNode(c, "hk-1")
	e.st.Mutate(func(s *store.State) error { s.Cluster(c.ID).Sealed = true; return nil })
	if _, err := e.pub.Publish(context.Background(), c.ID, []*store.Node{a}, "alice", "", "x"); err == nil {
		t.Fatal("published a plain list for a cluster that must be sealed")
	}
}

// More nodes than fit in one plain DNS answer: the ones already published stay, the rest wait, and the
// choice does not change from one round to the next.
func TestFitKeepsTheListSmallAndStable(t *testing.T) {
	e := newEnv(t)
	c := e.addCluster("official")
	var nodes []*store.Node
	for i := 0; i < 20; i++ {
		nodes = append(nodes, e.addNode(c, fmt.Sprintf("n%02d", i)))
	}
	cl := e.cluster(c.ID)
	max := shieldlist.MaxCompactNodes(cl.Targets[0].Name, false)
	cl.Last.NodesKey = store.NodesKey(nodes[15:]) // five published already
	got := Fit(cl, nodes)
	if len(got) != max {
		t.Fatalf("kept %d, want %d", len(got), max)
	}
	for _, n := range nodes[15:] {
		if !strings.Contains(store.NodesKey(got), n.Key()) {
			t.Errorf("%s was published and should stay", n.Name)
		}
	}
	if store.NodesKey(Fit(cl, nodes)) != store.NodesKey(got) {
		t.Error("the choice changed between two rounds")
	}
	if len(Fit(cl, nodes[:3])) != 3 {
		t.Error("a short list is kept as it is")
	}
}
