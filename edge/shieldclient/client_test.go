package shieldclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNode speaks just enough of the node protocol: token requests and a relay it keeps open.
type fakeNode struct {
	addr string
	pin  string
	seen atomic.Int32
}

func startFakeNode(t *testing.T) *fakeNode {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	sum := sha256.Sum256(spki)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	n := &fakeNode{addr: ln.Addr().String(), pin: base64.StdEncoding.EncodeToString(sum[:])}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.seen.Add(1)
			go func() {
				defer c.Close()
				var h [2]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(h[:]))
				io.ReadFull(c, body)
				if strings.HasPrefix(string(body), "GET-TOKEN ") {
					reply := `{"token":"t.1.abc","expires_at":123}`
					binary.BigEndian.PutUint16(h[:], uint16(len(reply)))
					c.Write(append(h[:], reply...))
					return
				}
				if string(body) == "good-token" {
					time.Sleep(2 * time.Second) // keep the relay open
				}
			}()
		}
	}()
	return n
}

// counting dials directly but records every use, standing in for a proxy.
type counting struct{ n atomic.Int32 }

func (c *counting) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.n.Add(1)
	return DirectDial(ctx, network, addr)
}

func TestPinnedDialAcceptsOnlyTheRightKey(t *testing.T) {
	n := startFakeNode(t)
	c, hs, err := Dial(n.addr, n.pin, 3*time.Second)
	if err != nil || hs <= 0 {
		t.Fatal(err)
	}
	c.Close()
	if _, _, err := Dial(n.addr, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 3*time.Second); err == nil || !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("a wrong pin must be refused: %v", err)
	}
}

func TestEveryConnectionGoesThroughTheGivenDialer(t *testing.T) {
	n := startFakeNode(t)
	via := &counting{}
	if _, _, err := RequestTokenVia(via.dial, n.addr, n.pin, "device-1234567890abcdef", 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := via.n.Load(); got != 1 {
		t.Fatalf("requesting a token used %d connection(s) through the dialer, want 1", got)
	}
	ok, err := OriginReachableVia(via.dial, n.addr, n.pin, "good-token", 300*time.Millisecond, 3*time.Second)
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if got := via.n.Load(); got != 2 {
		t.Fatalf("opening a relay did not go through the dialer: %d", got)
	}
	if _, _, err := DialVia(via.dial, n.addr, n.pin, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if via.n.Load() != 3 || n.seen.Load() != 3 {
		t.Fatalf("dialer saw %d, node saw %d", via.n.Load(), n.seen.Load())
	}
}

func TestADialerThatFailsFailsTheWholeCall(t *testing.T) {
	n := startFakeNode(t)
	broken := func(context.Context, string, string) (net.Conn, error) { return nil, io.ErrClosedPipe }
	if _, _, err := RequestTokenVia(broken, n.addr, n.pin, "device-1234567890abcdef", time.Second); err == nil {
		t.Fatal("it must not fall back to a direct connection")
	}
	if _, err := OriginReachableVia(broken, n.addr, n.pin, "x", 100*time.Millisecond, time.Second); err == nil {
		t.Fatal("it must not fall back to a direct connection")
	}
	if n.seen.Load() != 0 {
		t.Fatalf("the node saw %d direct connection(s) although the dialer was broken", n.seen.Load())
	}
}

func TestTokenAndRelayThroughTheNodeProtocol(t *testing.T) {
	n := startFakeNode(t)
	tok, exp, err := RequestToken(n.addr, n.pin, "device-1234567890abcdef", 3*time.Second)
	if err != nil || tok != "t.1.abc" || exp != 123 {
		t.Fatalf("%q %d %v", tok, exp, err)
	}
	if ok, err := OriginReachable(n.addr, n.pin, "good-token", 300*time.Millisecond, 3*time.Second); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, err := OriginReachable(n.addr, n.pin, "bad-token", time.Second, 3*time.Second); ok || err == nil {
		t.Fatalf("a node that closes the relay must read as unreachable: %v %v", ok, err)
	}
}
