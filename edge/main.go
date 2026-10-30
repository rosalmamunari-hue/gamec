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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	listen     = flag.String("listen", ":30800", "listen address")
	origin     = flag.String("origin", "127.0.0.1:9000", "hidden origin address")
	secret     = flag.String("secret", "", "token HMAC secret (visible to local users in the process list: prefer -secret-file)")
	secretFile = flag.String("secret-file", "", "file holding the token HMAC secret")
	certFile   = flag.String("cert", "", "TLS cert (PEM)")
	keyFile    = flag.String("key", "", "TLS key (PEM)")
	dev        = flag.Bool("dev", false, "allow running without -cert, on a throwaway self-signed key (tests only)")
	maxPerIP   = flag.Int("max-per-ip", 20, "max concurrent connections per IP (per /64 for IPv6)")
	maxConns   = flag.Int("max-conns", 10000, "max concurrent connections in total")
	idle       = flag.Duration("idle-timeout", 10*time.Minute, "close a relay after this long with no data either way; 0 = never")
	tokenTTL   = flag.Duration("token-ttl", 5*time.Minute, "token validity window")
)

const minSecretLen = 16

// limitKey is what the per-IP limits count: the address, or for IPv6 its /64, since one host usually holds a
// whole /64 and could otherwise get around the limits by changing address.
func limitKey(ip string) string {
	a := net.ParseIP(ip)
	if a == nil || a.To4() != nil {
		return ip
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// loadSecret takes -secret-file, else -secret, and refuses a missing, default or short one: with a weak secret
// anyone can make their own tokens and skip every limit.
func loadSecret() (string, error) {
	s := *secret
	if *secretFile != "" {
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			return "", err
		}
		s = strings.TrimSpace(string(b))
	}
	switch {
	case s == "":
		return "", fmt.Errorf("a token secret is required (-secret-file)")
	case s == "change-me" || len(s) < minSecretLen:
		return "", fmt.Errorf("the token secret must be at least %d characters and not the example value", minSecretLen)
	}
	return s, nil
}

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
	addr, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	ip := limitKey(addr)
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
		log.Printf("reject %s: bad token", addr)
		return
	}
	c.SetReadDeadline(time.Time{})

	up, err := net.DialTimeout("tcp", *origin, 3*time.Second)
	if err != nil {
		log.Printf("origin dial: %v", err)
		return
	}
	defer up.Close()
	relay(c, up, *idle)
}

// relay copies both ways until both are done. A side that finishes sending is half-closed towards the other,
// so a reply still on its way gets through; an error closes everything. With idle > 0 a relay that carries no
// data either way for that long is closed, so silent connections cannot hold origin slots forever.
func relay(client, up net.Conn, idle time.Duration) {
	var mu sync.Mutex
	last := time.Now()
	touch := func() { mu.Lock(); last = time.Now(); mu.Unlock() }
	quiet := func() time.Duration { mu.Lock(); defer mu.Unlock(); return time.Since(last) }
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			if idle > 0 {
				src.SetReadDeadline(time.Now().Add(idle))
			}
			n, err := src.Read(buf)
			if n > 0 {
				touch()
				if idle > 0 {
					dst.SetWriteDeadline(time.Now().Add(idle))
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					client.Close()
					up.Close()
					return
				}
			}
			if err == nil {
				continue
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() && quiet() < idle {
				continue // only this direction was quiet; the other one is busy
			}
			if err == io.EOF {
				if cw, ok := dst.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
					return
				}
			}
			client.Close()
			up.Close()
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { pipe(up, client); done <- struct{}{} }()
	go func() { pipe(client, up); done <- struct{}{} }()
	<-done
	<-done
}

func main() {
	flag.Parse()
	s, err := loadSecret()
	if err != nil {
		log.Fatal(err)
	}
	*secret = s
	var cert tls.Certificate
	switch {
	case *certFile != "":
		if cert, err = tls.LoadX509KeyPair(*certFile, *keyFile); err != nil {
			log.Fatal(err)
		}
	case *dev:
		cert = selfSigned()
		log.Println("using a throwaway self-signed cert (-dev): no app will accept this node")
	default:
		log.Fatal("-cert and -key are required (make them with cmd/gencert), or -dev for a local test")
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
	slots := make(chan struct{}, *maxConns)
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Fatal(err)
			}
			// e.g. out of file descriptors: wait instead of spinning, like net/http
			if backoff = min(max(2*backoff, 5*time.Millisecond), time.Second); backoff == time.Second {
				log.Printf("accept: %v", err)
			}
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		select {
		case slots <- struct{}{}:
		default:
			c.Close() // full: refuse at once rather than queue
			continue
		}
		go func() { defer func() { <-slots }(); handle(c, lim) }()
	}
}
