// Control service: hands a device a short-lived edge token plus the current node list.
//
// The response is signed with ECDSA P-256 (supported natively on Android, iOS and Go). Apps embed only the signing PUBLIC key and refuse any node
// list whose signature does not verify, so a hijacked connection cannot steer players to fake nodes.
//
// Identity model (device-id version): the app generates a random id once and sends it. That proves
// nothing about who the player is; abuse is limited by per-IP and per-device rate limits and a ban list.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
	Sig     string `json:"sig"`     // base64 ASN.1/DER ECDSA-P256 signature over SHA-256(those bytes)
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
	signKey    *ecdsa.PrivateKey
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
	digest := sha256.Sum256(pl)
	sig, err := ecdsa.SignASN1(rand.Reader, s.signKey, digest[:])
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	env := Envelope{
		Payload: base64.StdEncoding.EncodeToString(pl),
		Sig:     base64.StdEncoding.EncodeToString(sig),
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

// The signing key file holds base64(DER SEC1 EC private key).
func loadSignKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("sign key must be base64")
	}
	k, err := x509.ParseECPrivateKey(der)
	if err != nil || k.Curve != elliptic.P256() {
		return nil, errors.New("sign key must be a P-256 EC private key")
	}
	return k, nil
}

func genKey(path string) {
	if _, err := os.Stat(path); err == nil {
		log.Fatalf("%s already exists; refusing to overwrite (the app embeds the matching public key)", path)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(der)+"\n"), 0o600); err != nil {
		log.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	fmt.Println("private key written to", path, "(keep secret, never ship in the app)")
	fmt.Println("public key (embed in the app):", base64.StdEncoding.EncodeToString(pub))
}

func main() {
	var (
		listen     = flag.String("listen", ":8080", "listen address")
		nodesPath  = flag.String("nodes", "nodes.json", "node list file")
		secretFile = flag.String("secret-file", "", "file holding the edge token secret")
		keyFile    = flag.String("sign-key", "", "ECDSA P-256 signing key file")
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
