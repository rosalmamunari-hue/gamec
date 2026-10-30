// Control service: hands a device a short-lived edge token plus the current node list.
//
// The response is signed with Ed25519. Apps embed only the signing PUBLIC key and refuse any node
// list whose signature does not verify, so a hijacked connection cannot steer players to fake nodes.
//
// Identity model (device-id version): the app generates a random id once and sends it. That proves
// nothing about who the player is; abuse is limited by per-IP and per-device rate limits and a ban list.
package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const tokenLifetime = 4 * time.Minute // edge accepts +-5 min; stay inside that window

var deviceIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

type NodeInfo struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Pin  string `json:"pin"`
}

type nodeEntry struct {
	NodeInfo
	Enabled *bool `json:"enabled"` // omitted = enabled
}

type Payload struct {
	Nodes     []NodeInfo `json:"nodes"`
	Token     string     `json:"token"`
	IssuedAt  int64      `json:"issued_at"`
	ExpiresAt int64      `json:"expires_at"`
}

type Envelope struct {
	Payload string `json:"payload"` // base64 of the JSON Payload (exact bytes that were signed)
	Sig     string `json:"sig"`     // base64 Ed25519 signature over those bytes
}

// MakeToken must match the edge node: "<uid>.<unix ts>.<hex hmac-sha256(secret, uid.ts)>".
func MakeToken(secret []byte, uid string, now time.Time) string {
	body := uid + "." + strconv.FormatInt(now.Unix(), 10)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(body))
	return body + "." + hex.EncodeToString(m.Sum(nil))
}

// window is a fixed-window counter per key.
type window struct {
	mu    sync.Mutex
	n     map[string]int
	start time.Time
	per   time.Duration
	max   int
}

func newWindow(per time.Duration, max int) *window {
	return &window{n: map[string]int{}, start: time.Now(), per: per, max: max}
}

func (w *window) allow(key string, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Sub(w.start) >= w.per {
		w.n = map[string]int{}
		w.start = now
	}
	w.n[key]++
	return w.n[key] <= w.max
}

type Server struct {
	secret     []byte
	signKey    ed25519.PrivateKey
	nodesPath  string
	bannedPath string
	ipLimit    *window
	devLimit   *window

	mu       sync.Mutex
	cacheAt  time.Time
	cacheVal []NodeInfo
	cacheErr error
}

func (s *Server) nodes() ([]NodeInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.cacheAt) < 5*time.Second {
		return s.cacheVal, s.cacheErr
	}
	s.cacheAt = time.Now()
	s.cacheVal, s.cacheErr = loadNodes(s.nodesPath)
	return s.cacheVal, s.cacheErr
}

func loadNodes(path string) ([]NodeInfo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var all []nodeEntry
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var out []NodeInfo
	for _, n := range all {
		if n.Enabled != nil && !*n.Enabled {
			continue
		}
		out = append(out, n.NodeInfo)
	}
	return out, nil
}

func (s *Server) banned(id string) bool {
	if s.bannedPath == "" {
		return false
	}
	b, err := os.ReadFile(s.bannedPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == id {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host // X-Forwarded-For is deliberately not trusted
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now()
	if !s.ipLimit.allow(clientIP(r), now) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !deviceIDRe.MatchString(req.DeviceID) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.banned(req.DeviceID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.devLimit.allow(req.DeviceID, now) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	nodes, err := s.nodes()
	if err != nil || len(nodes) == 0 {
		log.Printf("no usable nodes: %v", err)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	pl, _ := json.Marshal(Payload{
		Nodes:     nodes,
		Token:     MakeToken(s.secret, req.DeviceID, now),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(tokenLifetime).Unix(),
	})
	env := Envelope{
		Payload: base64.StdEncoding.EncodeToString(pl),
		Sig:     base64.StdEncoding.EncodeToString(ed25519.Sign(s.signKey, pl)),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(env)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/session", s.handleSession)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux
}

func loadSignKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("sign key must be a base64-encoded 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func genKey(path string) {
	if _, err := os.Stat(path); err == nil {
		log.Fatalf("%s already exists; refusing to overwrite (the app embeds the matching public key)", path)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Println("private seed written to", path, "(keep secret, never ship in the app)")
	fmt.Println("public key (embed in the app):", base64.StdEncoding.EncodeToString(pub))
}

func main() {
	var (
		listen     = flag.String("listen", ":8080", "listen address")
		nodesPath  = flag.String("nodes", "nodes.json", "node list file")
		secretFile = flag.String("secret-file", "", "file holding the edge token secret")
		keyFile    = flag.String("sign-key", "", "Ed25519 signing key file")
		bannedPath = flag.String("banned", "", "optional file of banned device ids, one per line")
		cert       = flag.String("cert", "", "TLS cert (PEM); empty = plain HTTP")
		key        = flag.String("key", "", "TLS key (PEM)")
		gen        = flag.String("gen-key", "", "generate a signing key at this path and print the public key")
		ipMax      = flag.Int("ip-limit", 30, "max session requests per IP per minute")
		devMax     = flag.Int("device-limit", 10, "max session requests per device per minute")
	)
	flag.Parse()
	if *gen != "" {
		genKey(*gen)
		return
	}
	if *secretFile == "" || *keyFile == "" {
		log.Fatal("-secret-file and -sign-key are required (use -gen-key to create a signing key)")
	}
	secret, err := os.ReadFile(*secretFile)
	if err != nil {
		log.Fatal(err)
	}
	sk, err := loadSignKey(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := loadNodes(*nodesPath); err != nil {
		log.Fatal(err)
	}
	s := &Server{
		secret:     []byte(strings.TrimSpace(string(secret))),
		signKey:    sk,
		nodesPath:  *nodesPath,
		bannedPath: *bannedPath,
		ipLimit:    newWindow(time.Minute, *ipMax),
		devLimit:   newWindow(time.Minute, *devMax),
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	log.Println("control listening on", *listen)
	if *cert != "" {
		log.Fatal(srv.ListenAndServeTLS(*cert, *key))
	}
	log.Fatal(srv.ListenAndServe())
}
