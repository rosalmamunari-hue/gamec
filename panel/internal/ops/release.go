package ops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const maxProgram = 100 << 20

var (
	tagRe   = regexp.MustCompile(`^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(-[a-z0-9.]{1,20})?$`)
	assetRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,60}$`)
)

// Releases downloads programs from a release page and checks them against the checksum list published with
// the release before they can be used.
type Releases struct {
	// Base is like https://github.com/OWNER/REPO/releases/download (no trailing slash).
	Base string
	HTTP *http.Client
}

func (r *Releases) client() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (r *Releases) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than the %d MB limit", url, limit>>20)
	}
	return b, nil
}

// Fetch downloads `asset` of release `tag` and verifies it against SHA256SUMS.txt of the same release.
func (r *Releases) Fetch(ctx context.Context, tag, asset string) (Binary, error) {
	if !strings.HasPrefix(r.Base, "https://") && !strings.HasPrefix(r.Base, "http://127.0.0.1") {
		return Binary{}, errors.New("the release address must be https")
	}
	if !tagRe.MatchString(tag) {
		return Binary{}, fmt.Errorf("%q is not a release tag like v0.1.0", tag)
	}
	if !assetRe.MatchString(asset) {
		return Binary{}, fmt.Errorf("%q is not a valid file name", asset)
	}
	base := strings.TrimRight(r.Base, "/") + "/" + tag + "/"
	sums, err := r.get(ctx, base+"SHA256SUMS.txt", 1<<20)
	if err != nil {
		return Binary{}, fmt.Errorf("the checksum list: %w", err)
	}
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			want = strings.ToLower(f[0])
		}
	}
	if !shaRe.MatchString(want) {
		return Binary{}, fmt.Errorf("%s has no checksum in the release's SHA256SUMS.txt", asset)
	}
	data, err := r.get(ctx, base+asset, maxProgram)
	if err != nil {
		return Binary{}, err
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != want {
		return Binary{}, errors.New("the download does not match the release's checksum; it was not used")
	}
	return Binary{Data: data, SHA256: want, Label: tag}, nil
}

// Latest asks which release is the newest, from the redirect of <repo>/releases/latest. It only reads a
// name; nothing from that release is used before Fetch has checked it.
func (r *Releases) Latest(ctx context.Context) (string, error) {
	base := strings.TrimRight(r.Base, "/")
	if !strings.HasSuffix(base, "/releases/download") || !strings.HasPrefix(base, "https://") {
		return "", errors.New("the release address does not look like https://github.com/OWNER/REPO/releases/download")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, strings.TrimSuffix(base, "/download")+"/latest", nil)
	if err != nil {
		return "", err
	}
	c := *r.client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	tag := loc[strings.LastIndex(loc, "/")+1:]
	if !tagRe.MatchString(tag) {
		return "", fmt.Errorf("could not tell the newest release from %q", loc)
	}
	return tag, nil
}
