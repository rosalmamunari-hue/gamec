// signlist signs the node list OFFLINE and prints it as DNS TXT records.
//
// Run it on your own computer; the signing private key must never be placed on a server. Apps embed only
// the public key and refuse any list whose signature does not verify, so DNS spoofing can at worst make
// the list unavailable, never redirect players.
//
//	signlist -gen-key list.key                       create the signing key, print the public key
//	signlist -key list.key -nodes nodes.json         print TXT records (add each as a TXT record)
//	signlist -key list.key -nodes nodes.json -serve 127.0.0.1:8053   fake DoH server for tests
//
// nodes.json: [{"host":"1.2.3.4","port":30800,"pin":"<from gencert>","enabled":true}, ...]
//
// Record format: "gs1:<i>/<n>:<chunk>"; the chunks joined are base64url(payload) "." base64url(signature),
// where signature is ASN.1 ECDSA P-256 over SHA-256(payload) and payload is
// {"v":1,"iat":unix,"exp":unix,"nodes":[{"h":host,"p":port,"k":pin}]}.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const chunkSize = 200 // keeps every record comfortably inside one 255-byte TXT string

type listNode struct {
	H string `json:"h"`
	P int    `json:"p"`
	K string `json:"k"`
}

type listPayload struct {
	V     int        `json:"v"`
	Iat   int64      `json:"iat"`
	Exp   int64      `json:"exp"`
	Nodes []listNode `json:"nodes"`
}

type nodeFile struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Pin     string `json:"pin"`
	Enabled *bool  `json:"enabled"`
}

func loadNodes(path string) ([]listNode, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var all []nodeFile
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	var out []listNode
	for _, n := range all {
		if n.Enabled != nil && !*n.Enabled {
			continue
		}
		if n.Host == "" || n.Port <= 0 || n.Port > 65535 || n.Pin == "" {
			return nil, fmt.Errorf("incomplete node entry: %+v", n)
		}
		out = append(out, listNode{n.Host, n.Port, n.Pin})
	}
	if len(out) == 0 {
		return nil, errors.New("no enabled nodes")
	}
	return out, nil
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("key file must be base64")
	}
	k, err := x509.ParseECPrivateKey(der)
	if err != nil || k.Curve != elliptic.P256() {
		return nil, errors.New("key must be a P-256 EC private key")
	}
	return k, nil
}

func publicKeyB64(k *ecdsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return base64.StdEncoding.EncodeToString(der)
}

// buildRecords signs the list and splits it into TXT record values.
func buildRecords(k *ecdsa.PrivateKey, nodes []listNode, now time.Time, valid time.Duration) ([]string, error) {
	payload, err := json.Marshal(listPayload{V: 1, Iat: now.Unix(), Exp: now.Add(valid).Unix(), Nodes: nodes})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	body := enc.EncodeToString(payload) + "." + enc.EncodeToString(sig)

	var chunks []string
	for len(body) > chunkSize {
		chunks = append(chunks, body[:chunkSize])
		body = body[chunkSize:]
	}
	chunks = append(chunks, body)
	recs := make([]string, len(chunks))
	for i, c := range chunks {
		recs[i] = fmt.Sprintf("gs1:%d/%d:%s", i+1, len(chunks), c)
	}
	return recs, nil
}

// verifyRecords reassembles the records and checks the signature (what the apps do).
func verifyRecords(records []string, pub *ecdsa.PublicKey, now time.Time) (*listPayload, error) {
	parts := map[int]string{}
	total := 0
	for _, r := range records {
		if !strings.HasPrefix(r, "gs1:") {
			continue
		}
		f := strings.SplitN(r[4:], ":", 2)
		if len(f) != 2 {
			continue
		}
		pos := strings.SplitN(f[0], "/", 2)
		if len(pos) != 2 {
			continue
		}
		i, err1 := strconv.Atoi(pos[0])
		n, err2 := strconv.Atoi(pos[1])
		if err1 != nil || err2 != nil || i < 1 || i > n {
			continue
		}
		total = n
		parts[i] = f[1]
	}
	if total == 0 || len(parts) != total {
		return nil, errors.New("incomplete record set")
	}
	idx := make([]int, 0, total)
	for i := range parts {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var sb strings.Builder
	for _, i := range idx {
		sb.WriteString(parts[i])
	}
	f := strings.SplitN(sb.String(), ".", 2)
	if len(f) != 2 {
		return nil, errors.New("malformed list")
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(f[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(f[1])
	if err1 != nil || err2 != nil {
		return nil, errors.New("malformed base64")
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil, errors.New("signature invalid")
	}
	var p listPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.V != 1 || len(p.Nodes) == 0 {
		return nil, errors.New("bad payload")
	}
	if now.Unix() > p.Exp {
		return nil, errors.New("list expired")
	}
	return &p, nil
}

// dohHandler answers like Cloudflare's JSON DoH API; each record is returned as two quoted strings
// ("part1" "part2"), the way long TXT values appear there.
func dohHandler(records []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "TXT" {
			http.Error(w, "only TXT", http.StatusBadRequest)
			return
		}
		type answer struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		}
		var ans []answer
		for _, rec := range records {
			half := len(rec) / 2
			ans = append(ans, answer{r.URL.Query().Get("name"), 16, 60, `"` + rec[:half] + `" "` + rec[half:] + `"`})
		}
		w.Header().Set("Content-Type", "application/dns-json")
		json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": ans})
	})
}

func main() {
	gen := flag.String("gen-key", "", "create a list signing key at this path and print the public key")
	keyPath := flag.String("key", "", "list signing key file")
	nodesPath := flag.String("nodes", "nodes.json", "node list file")
	days := flag.Int("valid-days", 30, "how long the signed list stays valid")
	serve := flag.String("serve", "", "also serve the records as a fake DoH server on this address (tests)")
	flag.Parse()

	if *gen != "" {
		if _, err := os.Stat(*gen); err == nil {
			log.Fatalf("%s already exists; refusing to overwrite (apps embed the matching public key)", *gen)
		}
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(k)
		if err := os.WriteFile(*gen, []byte(base64.StdEncoding.EncodeToString(der)+"\n"), 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Println("private key written to", *gen, "(keep it OFF the servers)")
		fmt.Println("public key (embed in the app):", publicKeyB64(k))
		return
	}

	if *keyPath == "" {
		log.Fatal("-key is required (create one with -gen-key)")
	}
	k, err := loadKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	nodes, err := loadNodes(*nodesPath)
	if err != nil {
		log.Fatal(err)
	}
	recs, err := buildRecords(k, nodes, time.Now(), time.Duration(*days)*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := verifyRecords(recs, &k.PublicKey, time.Now()); err != nil {
		log.Fatalf("self-check failed: %v", err)
	}

	fmt.Printf("Add these %d TXT record(s) under one name (e.g. _gs.yourdomain.com), TTL 60:\n\n", len(recs))
	for _, r := range recs {
		fmt.Println(r)
	}
	fmt.Printf("\nvalid until %s, %d node(s)\n", time.Now().Add(time.Duration(*days)*24*time.Hour).Format("2006-01-02"), len(nodes))

	if *serve != "" {
		fmt.Println("serving fake DoH on", *serve)
		mux := http.NewServeMux()
		mux.Handle("/dns-query", dohHandler(recs))
		log.Fatal(http.ListenAndServe(*serve, mux))
	}
}
