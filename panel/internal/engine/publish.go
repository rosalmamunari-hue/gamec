package engine

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"gamec/edge/shieldlist"
	"gamec/panel/internal/audit"
	"gamec/panel/internal/dns"
	"gamec/panel/internal/store"
	"gamec/panel/internal/vault"
)

// Secret names in the vault.
func SigningKeyName(clusterID string) string { return "cluster/" + clusterID + "/signing_key" }
func NodeSecretName(clusterID string) string { return "cluster/" + clusterID + "/node_secret" }
func SealKeyName(clusterID string) string    { return "cluster/" + clusterID + "/seal_key" }

// Verifier checks, from outside, that what was published can be read back and verifies.
type Verifier interface {
	Verify(ctx context.Context, fqdn string, pub *ecdsa.PublicKey, wantIat int64) error
}

// SealedVerifier is a Verifier that can also read back a sealed list.
type SealedVerifier interface {
	VerifySealed(ctx context.Context, fqdn string, pub *ecdsa.PublicKey, wantIat int64, sealKey []byte) error
}

type TargetResult struct {
	Target    store.DNSTarget `json:"target"`
	Manual    bool            `json:"manual"`
	Err       string          `json:"err,omitempty"`
	Verified  bool            `json:"verified"`
	VerifyErr string          `json:"verify_err,omitempty"`
}

type Result struct {
	ClusterID string         `json:"cluster_id"`
	Nodes     []string       `json:"nodes"`
	Records   []string       `json:"records"`
	Iat       int64          `json:"iat"`
	Exp       int64          `json:"exp"`
	Targets   []TargetResult `json:"targets"`
	OK        bool           `json:"ok"`     // nothing went wrong (manual targets count as fine)
	Manual    bool           `json:"manual"` // at least one target waits for the records to be pasted
}

type Publisher struct {
	Vault    *vault.Vault
	Store    *store.Store
	Audit    *audit.Log
	Provider func(store.DNSTarget) (dns.Provider, error)
	Verifier Verifier
	Now      func() time.Time

	locks sync.Map
}

func (p *Publisher) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Publisher) lock(id string) *sync.Mutex {
	m, _ := p.locks.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func nodeLabels(nodes []*store.Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Addr()
	}
	sort.Strings(out)
	return out
}

// Preview signs nothing and sends nothing; it shows what would be published.
func (p *Publisher) Preview(clusterID string, nodes []*store.Node) ([]string, error) {
	if len(nodes) == 0 {
		return nil, errors.New("no nodes to publish")
	}
	st := p.Store.Snapshot()
	c := st.Cluster(clusterID)
	if c == nil {
		return nil, errors.New("no such cluster")
	}
	return nodeLabels(nodes), nil
}

// Publish signs the list for `nodes`, sends it to every DNS target of the cluster and checks it from outside.
// Only one publish per cluster runs at a time.
func (p *Publisher) Publish(ctx context.Context, clusterID string, nodes []*store.Node, actor, ip, reason string) (Result, error) {
	mu := p.lock(clusterID)
	mu.Lock()
	defer mu.Unlock()

	res := Result{ClusterID: clusterID}
	st := p.Store.Snapshot()
	c := st.Cluster(clusterID)
	if c == nil {
		return res, errors.New("no such cluster")
	}
	fail := func(err error) (Result, error) {
		p.log(actor, ip, "publish", fmt.Sprintf("cluster=%s reason=%q error=%v", c.Name, reason, err), false)
		return res, err
	}
	if len(nodes) == 0 {
		return fail(errors.New("refusing to publish an empty node list: every player would lose the way in"))
	}
	if p.Vault.Sealed() {
		return fail(vault.ErrSealed)
	}
	raw, ok, err := p.Vault.Get(SigningKeyName(clusterID))
	if err != nil {
		return fail(err)
	}
	if !ok {
		return fail(errors.New("this cluster has no signing key in the vault"))
	}
	key, err := shieldlist.ParsePrivateKeyB64(raw)
	if err != nil {
		return fail(fmt.Errorf("signing key: %w", err))
	}

	list := make([]shieldlist.Node, len(nodes))
	for i, n := range nodes {
		list[i] = shieldlist.Node{H: n.Host, P: n.Port, K: n.Pin}
	}
	now := p.now()
	valid := time.Duration(c.ValidDays) * 24 * time.Hour
	opts := shieldlist.Options{Next: targetNames(c.Targets)}
	if c.Sealed {
		rawSeal, ok, err := p.Vault.Get(SealKeyName(clusterID))
		if err != nil {
			return fail(err)
		}
		if !ok {
			return fail(errors.New("this cluster is set to encrypt its list but has no key in the vault"))
		}
		if opts.SealKey, err = base64.StdEncoding.DecodeString(strings.TrimSpace(rawSeal)); err != nil {
			return fail(fmt.Errorf("seal key: %w", err))
		}
	}
	recs, err := shieldlist.BuildRecordsOpts(key, list, now, valid, opts)
	if err != nil {
		return fail(err)
	}
	if _, err := shieldlist.VerifyRecordsSealed(recs, &key.PublicKey, now, opts.SealKey); err != nil {
		return fail(fmt.Errorf("self-check of the signed list failed: %w", err))
	}
	res.Nodes, res.Records, res.Iat, res.Exp = nodeLabels(nodes), recs, now.Unix(), now.Add(valid).Unix()

	res.OK = true
	for _, t := range c.Targets {
		tr := TargetResult{Target: t}
		prov, err := p.Provider(t)
		if err != nil {
			tr.Err = err.Error()
		} else if err := prov.ReplaceTXT(ctx, t.Zone, t.Name, recs); errors.Is(err, dns.ErrManual) {
			tr.Manual = true
			res.Manual = true
		} else if err != nil {
			tr.Err = err.Error()
		} else if p.Verifier != nil {
			var verr error
			if sv, ok := p.Verifier.(SealedVerifier); ok && opts.SealKey != nil {
				verr = sv.VerifySealed(ctx, t.Name, &key.PublicKey, res.Iat, opts.SealKey)
			} else {
				verr = p.Verifier.Verify(ctx, t.Name, &key.PublicKey, res.Iat)
			}
			if verr != nil {
				tr.VerifyErr = verr.Error()
			} else {
				tr.Verified = true
			}
		}
		if tr.Err != "" {
			res.OK = false
		}
		res.Targets = append(res.Targets, tr)
	}

	// The cluster's record of "what is published" only moves forward when nothing failed, so a half-done
	// publish is retried instead of being mistaken for done.
	if res.OK {
		verified := true
		for _, t := range res.Targets {
			if !t.Manual && !t.Verified {
				verified = false
			}
		}
		summary := "published"
		if res.Manual {
			summary = "signed; waiting for the records to be pasted at the manual target"
		} else if !verified {
			summary = "published, but could not yet be read back from outside"
		}
		if err := p.Store.Mutate(func(s *store.State) error {
			cc := s.Cluster(clusterID)
			cc.PublicKey = shieldlist.PublicKeyB64(&key.PublicKey)
			cc.Last = store.Published{
				At: now, Iat: res.Iat, Exp: res.Exp, NodesKey: store.NodesKey(nodes), Nodes: res.Nodes,
				Result: summary, Verified: verified && !res.Manual, Manual: res.Manual,
			}
			if res.Manual {
				cc.Last.Records = recs
			}
			return nil
		}); err != nil {
			return fail(fmt.Errorf("could not record the result: %w", err))
		}
	}
	p.log(actor, ip, "publish", describe(c.Name, reason, res), res.OK)
	if !res.OK {
		var msgs []string
		for _, t := range res.Targets {
			if t.Err != "" {
				msgs = append(msgs, t.Target.Name+": "+t.Err)
			}
		}
		return res, errors.New(strings.Join(msgs, "; "))
	}
	return res, nil
}

func describe(cluster, reason string, r Result) string {
	var ts []string
	for _, t := range r.Targets {
		s := t.Target.Provider + ":" + t.Target.Name
		switch {
		case t.Err != "":
			s += " FAILED(" + t.Err + ")"
		case t.Manual:
			s += " manual"
		case t.Verified:
			s += " verified"
		default:
			s += " unverified(" + t.VerifyErr + ")"
		}
		ts = append(ts, s)
	}
	return fmt.Sprintf("cluster=%s reason=%q nodes=%s targets=[%s]", cluster, reason, strings.Join(r.Nodes, ","), strings.Join(ts, "; "))
}

func (p *Publisher) log(user, ip, action, detail string, ok bool) {
	if p.Audit != nil {
		p.Audit.Append(audit.Entry{User: user, IP: ip, Action: action, Detail: detail, OK: ok})
	}
}

// ---------------------------------------------------------------- reading it back from outside

// DoHVerifier asks public DoH resolvers for the TXT records and checks signature, freshness and issue time,
// waiting for DNS to catch up.
type DoHVerifier struct {
	URLs     []string
	HTTP     *http.Client
	Timeout  time.Duration
	Interval time.Duration
	Now      func() time.Time
}

func DefaultVerifier() *DoHVerifier {
	return &DoHVerifier{
		URLs:    []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/resolve", "https://223.5.5.5/resolve"},
		Timeout: 3 * time.Minute, Interval: 10 * time.Second,
	}
}

func (v *DoHVerifier) query(ctx context.Context, base, name string) ([]string, error) {
	hc := v.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?name="+url.QueryEscape(name)+"&type=TXT", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		Status int
		Answer []struct {
			Type int
			Data string
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	var out []string
	for _, a := range r.Answer {
		if a.Type == 16 {
			out = append(out, shieldlist.JoinTxtStrings(a.Data))
		}
	}
	return out, nil
}

func (v *DoHVerifier) Verify(ctx context.Context, fqdn string, pub *ecdsa.PublicKey, wantIat int64) error {
	return v.VerifySealed(ctx, fqdn, pub, wantIat, nil)
}

// VerifySealed is Verify for a list sealed with sealKey.
func (v *DoHVerifier) VerifySealed(ctx context.Context, fqdn string, pub *ecdsa.PublicKey, wantIat int64, sealKey []byte) error {
	now := v.Now
	if now == nil {
		now = time.Now
	}
	deadline := time.Now().Add(v.Timeout)
	var last error
	for {
		for _, u := range v.URLs {
			recs, err := v.query(ctx, u, fqdn)
			if err != nil {
				last = err
				continue
			}
			pl, err := shieldlist.VerifyRecordsSealed(recs, pub, now(), sealKey)
			if err != nil {
				last = err
				continue
			}
			if pl.Iat < wantIat {
				last = fmt.Errorf("DNS still serves the previous list (issued %d, want %d)", pl.Iat, wantIat)
				continue
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not visible from outside after %s: %v", v.Timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(v.Interval):
		}
	}
}

// targetNames are the names the apps should read the list from next time: every place the list is written to.
func targetNames(ts []store.DNSTarget) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range ts {
		if t.Name != "" && !seen[t.Name] {
			seen[t.Name] = true
			out = append(out, t.Name)
		}
	}
	return out
}
