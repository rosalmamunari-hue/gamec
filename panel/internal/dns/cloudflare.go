package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Cloudflare DNS API v4 with an API token that has "Zone / DNS / Edit" on the one zone.
// Existing records are updated in place, so there is no moment without a list.
type cloudflare struct {
	token, base string
	hc          *http.Client
	zoneIDs     map[string]string
}

func newCloudflare(token string, opt Options) *cloudflare {
	base := opt.BaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	return &cloudflare{token: token, base: base, hc: opt.client(), zoneIDs: map[string]string{}}
}

func (c *cloudflare) Name() string { return "cloudflare" }

type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *cloudflare) do(ctx context.Context, method, path string, q url.Values, body any) (json.RawMessage, error) {
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	b, err := call(c.hc, req)
	if err != nil {
		return nil, err
	}
	var env cfEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("cloudflare: unexpected reply: %w", err)
	}
	if !env.Success {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return nil, fmt.Errorf("cloudflare: %s", strings.Join(msgs, "; "))
	}
	return env.Result, nil
}

func (c *cloudflare) zoneID(ctx context.Context, zone string) (string, error) {
	if id, ok := c.zoneIDs[zone]; ok {
		return id, nil
	}
	raw, err := c.do(ctx, http.MethodGet, "/zones", url.Values{"name": {zone}}, nil)
	if err != nil {
		return "", err
	}
	var zs []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &zs); err != nil || len(zs) == 0 {
		return "", fmt.Errorf("cloudflare: zone %s not found for this token", zone)
	}
	c.zoneIDs[zone] = zs[0].ID
	return zs[0].ID, nil
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

func (c *cloudflare) ReplaceTXT(ctx context.Context, zone, fqdn string, values []string) error {
	if _, err := rel(fqdn, zone); err != nil {
		return err
	}
	zid, err := c.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	raw, err := c.do(ctx, http.MethodGet, "/zones/"+zid+"/dns_records",
		url.Values{"type": {"TXT"}, "name": {fqdn}, "per_page": {"100"}}, nil)
	if err != nil {
		return fmt.Errorf("reading current records: %w", err)
	}
	var recs []cfRecord
	if err := json.Unmarshal(raw, &recs); err != nil {
		return err
	}
	var mine []cfRecord
	for _, r := range recs {
		r.Content = strings.Trim(r.Content, `"`) // Cloudflare shows TXT content quoted
		if ours(r.Content) {
			mine = append(mine, r)
		}
	}
	oldVals := make([]string, len(mine))
	for i, r := range mine {
		oldVals[i] = r.Content
	}
	stale, missing := diff(oldVals, values)
	if len(stale) == 0 && len(missing) == 0 {
		return nil
	}
	// Reuse the stale records for the missing values (an in-place update), then create or delete the rest.
	staleIDs := []string{}
	used := map[string]int{}
	for _, v := range stale {
		used[v]++
	}
	for _, r := range mine {
		if used[r.Content] > 0 {
			used[r.Content]--
			staleIDs = append(staleIDs, r.ID)
		}
	}
	body := func(v string) cfRecord { return cfRecord{Type: "TXT", Name: fqdn, Content: v, TTL: 60} }
	i := 0
	for ; i < len(missing) && i < len(staleIDs); i++ {
		if _, err := c.do(ctx, http.MethodPut, "/zones/"+zid+"/dns_records/"+staleIDs[i], nil, body(missing[i])); err != nil {
			return fmt.Errorf("updating a record: %w", err)
		}
	}
	for ; i < len(missing); i++ {
		if _, err := c.do(ctx, http.MethodPost, "/zones/"+zid+"/dns_records", nil, body(missing[i])); err != nil {
			return fmt.Errorf("adding a record: %w", err)
		}
	}
	for j := len(missing); j < len(staleIDs); j++ {
		if _, err := c.do(ctx, http.MethodDelete, "/zones/"+zid+"/dns_records/"+staleIDs[j], nil, nil); err != nil {
			return fmt.Errorf("removing an old record: %w", err)
		}
	}
	return nil
}
