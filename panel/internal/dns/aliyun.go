package dns

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Alibaba Cloud DNS (Alidns), RPC style with signature version 1.0 (HMAC-SHA1). Written from the public
// signing rules; not yet exercised against the real service. The free edition's minimum TTL is 600 s, so
// a change takes up to ten minutes to spread, longer than the 60 s the other providers use.
type aliyun struct {
	id, secret, base string
	hc               *http.Client
	opt              Options
}

func newAliyun(id, secret string, opt Options) *aliyun {
	base := opt.BaseURL
	if base == "" {
		base = "https://alidns.aliyuncs.com"
	}
	return &aliyun{id: id, secret: secret, base: base, hc: opt.client(), opt: opt}
}

func (a *aliyun) Name() string { return "aliyun" }

// percentEncode is the encoding Alibaba's signature uses: RFC 3986 unreserved characters stay as they are.
func percentEncode(s string) string {
	var sb strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

func (a *aliyun) signedQuery(action string, params map[string]string) string {
	p := map[string]string{
		"Action": action, "Format": "JSON", "Version": "2015-01-09", "AccessKeyId": a.id,
		"SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0",
		"Timestamp": a.opt.now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	p["SignatureNonce"] = hex.EncodeToString(nonce)
	for k, v := range params {
		p[k] = v
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(p[k]))
	}
	canonical := strings.Join(parts, "&")
	toSign := "GET&" + percentEncode("/") + "&" + percentEncode(canonical)
	m := hmac.New(sha1.New, []byte(a.secret+"&"))
	m.Write([]byte(toSign))
	sig := base64.StdEncoding.EncodeToString(m.Sum(nil))
	return canonical + "&Signature=" + percentEncode(sig)
}

func (a *aliyun) do(ctx context.Context, action string, params map[string]string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/?"+a.signedQuery(action, params), nil)
	if err != nil {
		return nil, err
	}
	b, err := call(a.hc, req)
	if err != nil {
		return nil, fmt.Errorf("aliyun %s: %w", action, err)
	}
	var e struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if json.Unmarshal(b, &e) == nil && e.Code != "" {
		return nil, fmt.Errorf("aliyun %s: %s: %s", action, e.Code, e.Message)
	}
	return b, nil
}

type aliRecord struct {
	RecordID string `json:"RecordId"`
	RR       string `json:"RR"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
}

func (a *aliyun) ReplaceTXT(ctx context.Context, zone, fqdn string, values []string) error {
	rr, err := rel(fqdn, zone)
	if err != nil {
		return err
	}
	raw, err := a.do(ctx, "DescribeDomainRecords", map[string]string{
		"DomainName": zone, "RRKeyWord": rr, "TypeKeyWord": "TXT", "SearchMode": "EXACT", "PageSize": "500",
	})
	if err != nil {
		return fmt.Errorf("reading current records: %w", err)
	}
	var reply struct {
		DomainRecords struct {
			Record []aliRecord `json:"Record"`
		} `json:"DomainRecords"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return fmt.Errorf("aliyun: unexpected reply: %w", err)
	}
	var mine []aliRecord
	for _, r := range reply.DomainRecords.Record {
		if r.Type == "TXT" && r.RR == rr && ours(r.Value) {
			mine = append(mine, r)
		}
	}
	oldVals := make([]string, len(mine))
	for i, r := range mine {
		oldVals[i] = r.Value
	}
	stale, missing := diff(oldVals, values)
	if len(stale) == 0 && len(missing) == 0 {
		return nil
	}
	used := map[string]int{}
	for _, v := range stale {
		used[v]++
	}
	var staleIDs []string
	for _, r := range mine {
		if used[r.Value] > 0 {
			used[r.Value]--
			staleIDs = append(staleIDs, r.RecordID)
		}
	}
	i := 0
	for ; i < len(missing) && i < len(staleIDs); i++ {
		if _, err := a.do(ctx, "UpdateDomainRecord", map[string]string{
			"RecordId": staleIDs[i], "RR": rr, "Type": "TXT", "Value": missing[i], "TTL": "600"}); err != nil {
			return err
		}
	}
	for ; i < len(missing); i++ {
		if _, err := a.do(ctx, "AddDomainRecord", map[string]string{
			"DomainName": zone, "RR": rr, "Type": "TXT", "Value": missing[i], "TTL": "600"}); err != nil {
			return err
		}
	}
	for j := len(missing); j < len(staleIDs); j++ {
		if _, err := a.do(ctx, "DeleteDomainRecord", map[string]string{"RecordId": staleIDs[j]}); err != nil {
			return err
		}
	}
	return nil
}

var _ = url.PathEscape
