// Package dns publishes the signed node list as TXT records at a DNS provider.
//
// Every provider implements one call: make the list's TXT records ("<i>/<n>:...") at a name exactly equal to the given
// values. Other TXT records on the same name (SPF, verification tokens) are never touched.
package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gamec/edge/shieldlist"
)

// ErrManual is returned by the manual provider: the records must be pasted by hand.
var ErrManual = errors.New("this DNS target is manual: publish the records yourself")

// ours says whether a TXT value is one the panel manages: a list record in either format, or a next-names
// record. The names the panel writes to are its own, so a long base64url value there is one of ours.
func ours(v string) bool { return shieldlist.IsRecord(v) || shieldlist.LooksCompact(v) }

type Provider interface {
	Name() string
	ReplaceTXT(ctx context.Context, zone, fqdn string, values []string) error
}

// Creds looks a credential up by its vault name.
type Creds func(name string) (string, error)

// Options lets tests point a provider at a fake server.
type Options struct {
	HTTP    *http.Client
	BaseURL string
	Sleep   func(time.Duration)
	Now     func() time.Time
}

func (o Options) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (o Options) sleep(d time.Duration) {
	if o.Sleep != nil {
		o.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Supported lists the provider names New accepts.
var Supported = []string{"manual", "spaceship", "cloudflare", "aliyun"}

// New builds a provider. Credentials are read from the vault as dns/<credRef>/<field>.
func New(provider, credRef string, creds Creds, opt Options) (Provider, error) {
	get := func(field string) (string, error) {
		v, err := creds("dns/" + credRef + "/" + field)
		if err != nil {
			return "", err
		}
		if v == "" {
			return "", fmt.Errorf("credential dns/%s/%s is not set", credRef, field)
		}
		return v, nil
	}
	switch provider {
	case "manual":
		return manual{}, nil
	case "spaceship":
		k, err := get("api_key")
		if err != nil {
			return nil, err
		}
		s, err := get("api_secret")
		if err != nil {
			return nil, err
		}
		return newSpaceship(k, s, opt), nil
	case "cloudflare":
		t, err := get("api_token")
		if err != nil {
			return nil, err
		}
		return newCloudflare(t, opt), nil
	case "aliyun":
		id, err := get("access_key_id")
		if err != nil {
			return nil, err
		}
		sec, err := get("access_key_secret")
		if err != nil {
			return nil, err
		}
		return newAliyun(id, sec, opt), nil
	}
	return nil, fmt.Errorf("unknown DNS provider %q", provider)
}

type manual struct{}

func (manual) Name() string { return "manual" }
func (manual) ReplaceTXT(context.Context, string, string, []string) error {
	return ErrManual
}

// rel turns a full name into the name relative to its zone; the zone itself is "@".
func rel(fqdn, zone string) (string, error) {
	fqdn, zone = strings.TrimSuffix(strings.ToLower(fqdn), "."), strings.TrimSuffix(strings.ToLower(zone), ".")
	if fqdn == zone {
		return "@", nil
	}
	if !strings.HasSuffix(fqdn, "."+zone) {
		return "", fmt.Errorf("%s is not inside %s", fqdn, zone)
	}
	return strings.TrimSuffix(fqdn, "."+zone), nil
}

// diff splits want into what is missing and old into what is stale (as multisets of values).
func diff(old, want []string) (stale, missing []string) {
	count := map[string]int{}
	for _, v := range old {
		count[v]++
	}
	for _, v := range want {
		if count[v] > 0 {
			count[v]--
		} else {
			missing = append(missing, v)
		}
	}
	for _, v := range old {
		if count[v] > 0 {
			count[v]--
			stale = append(stale, v)
		}
	}
	return
}

const maxBody = 4 << 20

// call sends a request and returns the body; any status of 300 or more is an error carrying the reply.
func call(hc *http.Client, req *http.Request) ([]byte, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return b, fmt.Errorf("%s %s: HTTP %d: %s", req.Method, req.URL.Path, resp.StatusCode, msg)
	}
	return b, nil
}
