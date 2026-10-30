package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodID = "device-1234567890abcdef"

type fixture struct {
	srv    *httptest.Server
	pub    ed25519.PublicKey
	secret []byte
	dir    string
}

func newFixture(t *testing.T, nodesJSON string, ipMax, devMax int) *fixture {
	t.Helper()
	dir := t.TempDir()
	nodes := filepath.Join(dir, "nodes.json")
	if err := os.WriteFile(nodes, []byte(nodesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{
		secret:     []byte("test-secret"),
		signKey:    priv,
		nodesPath:  nodes,
		bannedPath: filepath.Join(dir, "banned.txt"),
		ipLimit:    newWindow(time.Minute, ipMax),
		devLimit:   newWindow(time.Minute, devMax),
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &fixture{srv: ts, pub: pub, secret: s.secret, dir: dir}
}

func (f *fixture) post(id string) *http.Response {
	body, _ := json.Marshal(map[string]string{"device_id": id})
	resp, err := http.Post(f.srv.URL+"/v1/session", "application/json", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	return resp
}

const twoNodes = `[
 {"host":"1.1.1.1","port":30800,"pin":"pinA"},
 {"host":"2.2.2.2","port":30800,"pin":"pinB","enabled":false},
 {"host":"3.3.3.3","port":30800,"pin":"pinC","enabled":true}
]`

func TestSessionIsSignedAndTokenMatchesEdgeFormat(t *testing.T) {
	f := newFixture(t, twoNodes, 100, 100)
	resp := f.post(goodID)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var env Envelope
	json.NewDecoder(resp.Body).Decode(&env)
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	sig, _ := base64.StdEncoding.DecodeString(env.Sig)
	if !ed25519.Verify(f.pub, raw, sig) {
		t.Fatal("signature does not verify")
	}
	var p Payload
	json.Unmarshal(raw, &p)
	if len(p.Nodes) != 2 || p.Nodes[0].Pin != "pinA" || p.Nodes[1].Pin != "pinC" {
		t.Fatalf("disabled node should be filtered out, got %+v", p.Nodes)
	}
	parts := strings.Split(p.Token, ".")
	if len(parts) != 3 || parts[0] != goodID {
		t.Fatalf("token shape: %q", p.Token)
	}
	// Recompute exactly as the edge does.
	if want := MakeToken(f.secret, parts[0], time.Unix(atoi(parts[1]), 0)); want != p.Token {
		t.Fatal("token HMAC mismatch")
	}
	if p.ExpiresAt-p.IssuedAt != int64(tokenLifetime.Seconds()) {
		t.Fatalf("lifetime %d", p.ExpiresAt-p.IssuedAt)
	}
}

func atoi(s string) int64 {
	var n int64
	for _, c := range s {
		n = n*10 + int64(c-'0')
	}
	return n
}

func TestTamperedPayloadFailsVerification(t *testing.T) {
	f := newFixture(t, twoNodes, 100, 100)
	resp := f.post(goodID)
	defer resp.Body.Close()
	var env Envelope
	json.NewDecoder(resp.Body).Decode(&env)
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	raw = bytes.Replace(raw, []byte("pinA"), []byte("pinX"), 1)
	sig, _ := base64.StdEncoding.DecodeString(env.Sig)
	if ed25519.Verify(f.pub, raw, sig) {
		t.Fatal("a modified node list must not verify")
	}
}

func TestBadDeviceIDsRejected(t *testing.T) {
	f := newFixture(t, twoNodes, 100, 100)
	for _, id := range []string{"", "short", "has.dot.in.it.1234567890", "has space 1234567890abc", strings.Repeat("a", 65)} {
		resp := f.post(id)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("id %q: status %d, want 400", id, resp.StatusCode)
		}
	}
}

func TestPerDeviceLimit(t *testing.T) {
	f := newFixture(t, twoNodes, 100, 3)
	for i := 0; i < 3; i++ {
		resp := f.post(goodID)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
	resp := f.post(goodID)
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("4th request: %d, want 429", resp.StatusCode)
	}
	resp = f.post("another-device-abcdef0123")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("a different device should not be limited: %d", resp.StatusCode)
	}
}

func TestPerIPLimitStopsDeviceIDChurn(t *testing.T) {
	f := newFixture(t, twoNodes, 3, 100)
	codes := []int{}
	for i := 0; i < 5; i++ {
		resp := f.post("churn-device-" + strings.Repeat("x", i+4))
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[2] != 200 || codes[3] != 429 || codes[4] != 429 {
		t.Fatalf("codes %v: fresh device ids from one IP must still hit the IP limit", codes)
	}
}

func TestBannedDevice(t *testing.T) {
	f := newFixture(t, twoNodes, 100, 100)
	os.WriteFile(filepath.Join(f.dir, "banned.txt"), []byte("someone-else-abcdef01\n"+goodID+"\n"), 0o600)
	resp := f.post(goodID)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("banned device: %d, want 403", resp.StatusCode)
	}
}

func TestNoUsableNodes(t *testing.T) {
	f := newFixture(t, `[{"host":"1.1.1.1","port":1,"pin":"p","enabled":false}]`, 100, 100)
	resp := f.post(goodID)
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
}

func TestOnlyPost(t *testing.T) {
	f := newFixture(t, twoNodes, 100, 100)
	resp, _ := http.Get(f.srv.URL + "/v1/session")
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("GET: %d, want 405", resp.StatusCode)
	}
}
