package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Spaceship (spaceship.com) DNS API. Written from the shape used by third-party integrations
// (https://spaceship.dev/api/v1/dns/records/{zone}, X-API-Key / X-API-Secret, take/skip paging,
// PUT {"force":true,"items":[...]}, DELETE [...]); not yet exercised against the real service.
type spaceship struct {
	key, secret, base string
	hc                *http.Client
	opt               Options
}

func newSpaceship(key, secret string, opt Options) *spaceship {
	base := opt.BaseURL
	if base == "" {
		base = "https://spaceship.dev"
	}
	return &spaceship{key: key, secret: secret, base: base, hc: opt.client(), opt: opt}
}

func (s *spaceship) Name() string { return "spaceship" }

func (s *spaceship) do(ctx context.Context, method, zone string, q url.Values, body any) ([]byte, error) {
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
	u := s.base + "/api/v1/dns/records/" + url.PathEscape(zone)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", s.key)
	req.Header.Set("X-API-Secret", s.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return call(s.hc, req)
}

type ssItem struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Text  string `json:"text,omitempty"`
	TTL   int    `json:"ttl,omitempty"`
}

func (i ssItem) value() string {
	if i.Value != "" {
		return i.Value
	}
	return i.Text
}

func (s *spaceship) list(ctx context.Context, zone, short string) ([]string, error) {
	var out []string
	const take = 500
	for skip := 0; ; {
		b, err := s.do(ctx, http.MethodGet, zone, url.Values{"take": {strconv.Itoa(take)}, "skip": {strconv.Itoa(skip)}}, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Items []ssItem `json:"items"`
			Total int      `json:"total"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return nil, fmt.Errorf("spaceship: unexpected reply: %w", err)
		}
		for _, it := range page.Items {
			if it.Type == "TXT" && it.Name == short && ours(it.value()) {
				out = append(out, it.value())
			}
		}
		skip += len(page.Items)
		if len(page.Items) == 0 || skip >= page.Total {
			return out, nil
		}
	}
}

func (s *spaceship) ReplaceTXT(ctx context.Context, zone, fqdn string, values []string) error {
	short, err := rel(fqdn, zone)
	if err != nil {
		return err
	}
	old, err := s.list(ctx, zone, short)
	if err != nil {
		return fmt.Errorf("reading current records: %w", err)
	}
	stale, missing := diff(old, values)
	if len(stale) == 0 && len(missing) == 0 {
		return nil
	}
	if len(stale) > 0 {
		del := make([]ssItem, 0, len(stale))
		for _, v := range stale {
			del = append(del, ssItem{Type: "TXT", Name: short, Value: v})
		}
		if _, err := s.do(ctx, http.MethodDelete, zone, nil, del); err != nil {
			return fmt.Errorf("removing old records: %w", err)
		}
	}
	if len(missing) > 0 {
		put := func(vs []string) error {
			items := make([]ssItem, 0, len(vs))
			for _, v := range vs {
				items = append(items, ssItem{Type: "TXT", Name: short, Value: v, TTL: 60})
			}
			_, err := s.do(ctx, http.MethodPut, zone, nil, map[string]any{"force": true, "items": items})
			return err
		}
		var perr error
		for attempt := 0; attempt < 3; attempt++ {
			if perr = put(missing); perr == nil {
				return nil
			}
			s.opt.sleep(time.Duration(attempt+1) * time.Second)
		}
		// The old records are already gone; put them back so the apps keep a working list.
		if len(stale) > 0 {
			put(stale)
		}
		return fmt.Errorf("adding new records failed (old ones restored if possible): %w", perr)
	}
	return nil
}
