// signlist signs the node list OFFLINE and prints it as DNS TXT records.
//
// Run it on your own computer; the signing private key must never be placed on a server that does not need
// it. Apps embed only the public key and refuse any list whose signature does not verify, so DNS spoofing
// can at worst make the list unavailable, never redirect players.
//
//	signlist -gen-key list.key                       create the signing key, print the public key
//	signlist -key list.key -nodes nodes.json         print TXT records (add each as a TXT record)
//	signlist -key list.key -nodes nodes.json -serve 127.0.0.1:8053   fake DoH server for tests
//	signlist -check _gs.example.com -pub <key>       fetch the published records over DoH and verify them
//
// nodes.json: [{"host":"1.2.3.4","port":30800,"pin":"<from gencert>","enabled":true}, ...]
//
// The format itself lives in the shieldlist package, shared with the control panel.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"gamec/edge/shieldlist"
)

type nodeFile struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Pin     string `json:"pin"`
	Enabled *bool  `json:"enabled"`
}

func loadNodes(path string) ([]shieldlist.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var all []nodeFile
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	var out []shieldlist.Node
	for _, n := range all {
		if n.Enabled != nil && !*n.Enabled {
			continue
		}
		if n.Host == "" || n.Port <= 0 || n.Port > 65535 || n.Pin == "" {
			return nil, fmt.Errorf("incomplete node entry: %+v", n)
		}
		out = append(out, shieldlist.Node{H: n.Host, P: n.Port, K: n.Pin})
	}
	if len(out) == 0 {
		return nil, errors.New("no enabled nodes")
	}
	return out, nil
}

func loadKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
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

// checkDNS fetches the published records the way an app does and verifies them.
func checkDNS(name, pub, doh string) {
	if pub == "" {
		log.Fatal("-check needs -pub <base64 public key>")
	}
	pk, err := shieldlist.ParsePublicKeyB64(pub)
	if err != nil {
		log.Fatal("bad -pub: ", err)
	}
	req, _ := http.NewRequest("GET", doh+"?name="+name+"&type=TXT", nil)
	req.Header.Set("accept", "application/dns-json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		log.Fatal("DoH request failed: ", err)
	}
	defer resp.Body.Close()
	var reply struct {
		Status int
		Answer []struct {
			Type int
			TTL  int
			Data string
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		log.Fatal("DoH reply is not JSON: ", err)
	}
	var recs []string
	for _, a := range reply.Answer {
		if a.Type == 16 {
			recs = append(recs, shieldlist.JoinTxtStrings(a.Data))
		}
	}
	fmt.Printf("DoH status %d, %d TXT record(s) at %s\n", reply.Status, len(recs), name)
	p, err := shieldlist.VerifyRecords(recs, pk, time.Now())
	if err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
	fmt.Printf("ok   signature valid, signed %s, expires %s (%d days left)\n",
		time.Unix(p.Iat, 0).Format("2006-01-02 15:04"), time.Unix(p.Exp, 0).Format("2006-01-02"),
		int(time.Until(time.Unix(p.Exp, 0)).Hours()/24))
	for _, n := range p.Nodes {
		fmt.Printf("     node %s:%d pin %s\n", n.H, n.P, n.K)
	}
}

func main() {
	gen := flag.String("gen-key", "", "create a list signing key at this path and print the public key")
	keyPath := flag.String("key", "", "list signing key file")
	nodesPath := flag.String("nodes", "nodes.json", "node list file")
	days := flag.Int("valid-days", 30, "how long the signed list stays valid")
	serve := flag.String("serve", "", "also serve the records as a fake DoH server on this address (tests)")
	checkName := flag.String("check", "", "fetch this DNS name's TXT records over DoH and verify them (needs -pub)")
	pubKey := flag.String("pub", "", "base64 public key to verify against (with -check)")
	dohURL := flag.String("doh", "https://cloudflare-dns.com/dns-query", "DoH JSON endpoint (with -check)")
	flag.Parse()

	if *checkName != "" {
		checkDNS(*checkName, *pubKey, *dohURL)
		return
	}

	if *gen != "" {
		if _, err := os.Stat(*gen); err == nil {
			log.Fatalf("%s already exists; refusing to overwrite (apps embed the matching public key)", *gen)
		}
		k, err := shieldlist.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		enc, _ := shieldlist.PrivateKeyB64(k)
		if err := os.WriteFile(*gen, []byte(enc+"\n"), 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Println("private key written to", *gen, "(keep it OFF the servers)")
		fmt.Println("public key (embed in the app):", shieldlist.PublicKeyB64(&k.PublicKey))
		return
	}

	if *keyPath == "" {
		log.Fatal("-key is required (create one with -gen-key)")
	}
	raw, err := loadKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	k, err := shieldlist.ParsePrivateKeyB64(raw)
	if err != nil {
		log.Fatal(err)
	}
	nodes, err := loadNodes(*nodesPath)
	if err != nil {
		log.Fatal(err)
	}
	valid := time.Duration(*days) * 24 * time.Hour
	recs, err := shieldlist.BuildRecords(k, nodes, time.Now(), valid)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := shieldlist.VerifyRecords(recs, &k.PublicKey, time.Now()); err != nil {
		log.Fatalf("self-check failed: %v", err)
	}

	fmt.Printf("Add these %d TXT record(s) under one name (e.g. _gs.yourdomain.com), TTL 60:\n\n", len(recs))
	for _, r := range recs {
		fmt.Println(r)
	}
	fmt.Printf("\nvalid until %s, %d node(s)\n", time.Now().Add(valid).Format("2006-01-02"), len(nodes))

	if *serve != "" {
		fmt.Println("serving fake DoH on", *serve)
		mux := http.NewServeMux()
		mux.Handle("/dns-query", dohHandler(recs))
		log.Fatal(http.ListenAndServe(*serve, mux))
	}
}
