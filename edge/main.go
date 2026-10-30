// Edge node: accepts TLS 1.3 connections, checks an HMAC token, then relays
// to the hidden origin server. Origin should only allow this node's IP.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	listen   = flag.String("listen", ":30800", "listen address")
	origin   = flag.String("origin", "127.0.0.1:9000", "hidden origin address")
	secret   = flag.String("secret", "change-me", "token HMAC secret")
	certFile = flag.String("cert", "", "TLS cert (PEM); empty = self-signed for dev")
	keyFile  = flag.String("key", "", "TLS key (PEM)")
	maxPerIP = flag.Int("max-per-ip", 20, "max concurrent connections per IP")
	tokenTTL = flag.Duration("token-ttl", 5*time.Minute, "token validity window")
)

type limiter struct {
	mu sync.Mutex
	n  map[string]int
}

func (l *limiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[ip] >= *maxPerIP {
		return false
	}
	l.n[ip]++
	return true
}

func (l *limiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[ip]--; l.n[ip] <= 0 {
		delete(l.n, ip)
	}
}

// Token format: "<uid>.<unix ts>.<hex hmac-sha256(secret, uid.ts)>"
func MakeToken(secret, uid string, now time.Time) string {
	body := uid + "." + strconv.FormatInt(now.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return body + "." + hex.EncodeToString(m.Sum(nil))
}

func checkToken(tok string, now time.Time) bool {
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return false
	}
	ts, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > *tokenTTL || d < -*tokenTTL {
		return false
	}
	want := MakeToken(*secret, p[0], time.Unix(ts, 0))
	return hmac.Equal([]byte(want), []byte(tok))
}

func selfSigned() tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gamec-edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func handle(c net.Conn, lim *limiter) {
	defer c.Close()
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	if !lim.acquire(ip) {
		return
	}
	defer lim.release(ip)

	// First frame: 2-byte big-endian length + token. Short deadline stops slow-loris.
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 || n > 256 {
		return
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	if isTokenRequest(buf) {
		handleTokenRequest(c, ip, buf)
		return
	}
	if !checkToken(string(buf), time.Now()) {
		log.Printf("reject %s: bad token", ip)
		return
	}
	c.SetReadDeadline(time.Time{})

	up, err := net.DialTimeout("tcp", *origin, 3*time.Second)
	if err != nil {
		log.Printf("origin dial: %v", err)
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func main() {
	flag.Parse()
	var cert tls.Certificate
	if *certFile != "" {
		var err error
		if cert, err = tls.LoadX509KeyPair(*certFile, *keyFile); err != nil {
			log.Fatal(err)
		}
	} else {
		cert = selfSigned()
		log.Println("using self-signed dev cert")
	}
	ln, err := tls.Listen("tcp", *listen, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("edge listening on", *listen, "-> origin", *origin)
	lim := &limiter{n: map[string]int{}}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, lim)
	}
}
