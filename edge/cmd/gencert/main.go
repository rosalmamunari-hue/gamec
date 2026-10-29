// gencert creates a long-lived TLS key + certificate for an edge node and prints the
// pin (base64 SHA-256 of the public key) to put into the client's Node.pinSha256.
//
// The pin covers the KEY, not the certificate: if key.pem already exists it is reused,
// so you can renew the certificate later without shipping a new app.
//
//	go run ./cmd/gencert -host 1.2.3.4 -host node1.example.com -out certs/node1
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type hosts []string

func (h *hosts) String() string     { return strings.Join(*h, ",") }
func (h *hosts) Set(v string) error { *h = append(*h, v); return nil }

func main() {
	var hs hosts
	flag.Var(&hs, "host", "IP or domain of the node (repeatable)")
	out := flag.String("out", "certs/node", "output directory")
	days := flag.Int("days", 3650, "certificate validity in days")
	flag.Parse()
	if len(hs) == 0 {
		log.Fatal("at least one -host is required")
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		log.Fatal(err)
	}
	keyPath := filepath.Join(*out, "key.pem")
	certPath := filepath.Join(*out, "cert.pem")

	key := loadOrCreateKey(keyPath)

	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hs[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hs {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	writePEM(certPath, "CERTIFICATE", der, 0o644)

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	pin := base64.StdEncoding.EncodeToString(sum[:])

	fmt.Println("cert:", certPath)
	fmt.Println("key: ", keyPath, "(keep private, never ship in the app)")
	fmt.Println("pin: ", pin)
	fmt.Printf("\nClient:  Node(\"%s\", 30800, \"%s\")\n", hs[0], pin)
	fmt.Printf("Server:  edge -cert %s -key %s\n", certPath, keyPath)
}

func loadOrCreateKey(path string) *ecdsa.PrivateKey {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			log.Fatalf("%s is not valid PEM", path)
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("reusing existing key (pin unchanged)")
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(k)
	writePEM(path, "EC PRIVATE KEY", der, 0o600)
	return k
}

func writePEM(path, typ string, der []byte, mode os.FileMode) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode); err != nil {
		log.Fatal(err)
	}
}
