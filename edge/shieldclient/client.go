// Package shieldclient speaks the edge node's protocol from Go: pinned TLS 1.3, the token frame, and the
// GET-TOKEN request. It is what the control panel uses to check nodes; the apps implement the same protocol.
//
// Every function has a "Via" form that takes the function used to open the TCP connection, so a caller can
// send everything through a proxy or an SSH jump host and the node sees that address instead of its own.
package shieldclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// DialFunc opens a TCP connection. Nothing in this package opens one any other way.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DirectDial connects from this machine.
func DirectDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func pinned(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // trust is decided by the pin below, not by a CA
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(spki)
			if base64.StdEncoding.EncodeToString(sum[:]) != pin {
				return errors.New("pin mismatch")
			}
			return nil
		},
	}
}

// DialVia opens a TLS 1.3 connection over `dial` and accepts only the certificate whose public key matches pin.
// The returned duration covers the whole setup (connecting and the TLS handshake).
func DialVia(dial DialFunc, addr, pin string, timeout time.Duration) (*tls.Conn, time.Duration, error) {
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, err
	}
	c := tls.Client(raw, pinned(pin))
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, 0, err
	}
	return c, time.Since(t0), nil
}

// FetchPinVia connects to a node without checking its key and returns the pin of the key it presents. It is
// for showing an administrator what a newly installed node presents, to compare with what the node's own
// installer printed; a client must never trust a pin learnt this way.
func FetchPinVia(dial DialFunc, addr string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	var pin string
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // only reading the key, to be confirmed by a person
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(spki)
			pin = base64.StdEncoding.EncodeToString(sum[:])
			return nil
		},
	}
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		return "", err
	}
	c.Close()
	return pin, nil
}

// Dial is DialVia from this machine.
func Dial(addr, pin string, timeout time.Duration) (*tls.Conn, time.Duration, error) {
	return DialVia(DirectDial, addr, pin, timeout)
}

func writeFrame(c net.Conn, body []byte) error {
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(body)))
	_, err := c.Write(append(h[:], body...))
	return err
}

// expire closes c after d unless stop is called first, and says whether it fired. Connections that come
// through an SSH jump host ignore deadlines, so a read that must not wait forever needs this as well.
func expire(c net.Conn, d time.Duration) (stop func(), fired func() bool) {
	var f atomic.Bool
	t := time.AfterFunc(d, func() { f.Store(true); c.Close() })
	return func() { t.Stop() }, f.Load
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func readFrame(c net.Conn, timeout time.Duration) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	stop, fired := expire(c, timeout+time.Second)
	defer stop()
	b, err := readFrameInner(c)
	if err != nil && fired() {
		err = timeoutErr{}
	}
	return b, err
}

func readFrameInner(c net.Conn) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(h[:])
	if n == 0 || n > 4096 {
		return nil, fmt.Errorf("bad frame length %d", n)
	}
	body := make([]byte, n)
	_, err := io.ReadFull(c, body)
	return body, err
}

// RequestTokenVia asks the node for a token: one connection, "GET-TOKEN <device id>", one JSON frame back.
func RequestTokenVia(dial DialFunc, addr, pin, deviceID string, timeout time.Duration) (token string, expiresAt int64, err error) {
	c, _, err := DialVia(dial, addr, pin, timeout)
	if err != nil {
		return "", 0, err
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(timeout))
	if err := writeFrame(c, []byte("GET-TOKEN "+deviceID)); err != nil {
		return "", 0, err
	}
	body, err := readFrame(c, timeout)
	if err != nil {
		return "", 0, fmt.Errorf("no answer (refused, rate limited or an old node version): %w", err)
	}
	var r struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Token == "" {
		return "", 0, fmt.Errorf("bad token reply %q", body)
	}
	return r.Token, r.ExpiresAt, nil
}

func RequestToken(addr, pin, deviceID string, timeout time.Duration) (string, int64, error) {
	return RequestTokenVia(DirectDial, addr, pin, deviceID, timeout)
}

// OriginReachableVia opens a relay with the token and reports whether the node keeps it open for `hold`.
// A node closes the connection at once if the token is wrong or it cannot reach the origin, so a connection
// that stays open means the whole path through the node works.
func OriginReachableVia(dial DialFunc, addr, pin, token string, hold, timeout time.Duration) (bool, error) {
	c, _, err := DialVia(dial, addr, pin, timeout)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if err := writeFrame(c, []byte(token)); err != nil {
		return false, err
	}
	c.SetReadDeadline(time.Now().Add(hold))
	stop, fired := expire(c, hold+500*time.Millisecond)
	defer stop()
	_, err = c.Read(make([]byte, 1))
	if err != nil && fired() {
		return true, nil
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true, nil // nothing arrived and nothing closed: the relay is open
	}
	if err == nil {
		return true, nil // the origin sent something
	}
	return false, fmt.Errorf("node closed the relay: %w", err)
}

func OriginReachable(addr, pin, token string, hold, timeout time.Duration) (bool, error) {
	return OriginReachableVia(DirectDial, addr, pin, token, hold, timeout)
}
