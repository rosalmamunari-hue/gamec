// Package shieldclient speaks the edge node's protocol from Go: pinned TLS 1.3, the token frame, and the
// GET-TOKEN request. It is what the control panel uses to check nodes; the apps implement the same protocol.
package shieldclient

import (
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
	"time"
)

// Dial opens a TLS 1.3 connection and accepts only the certificate whose public key matches pin.
func Dial(addr, pin string, timeout time.Duration) (*tls.Conn, time.Duration, error) {
	t0 := time.Now()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
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
	})
	if err != nil {
		return nil, 0, err
	}
	return c, time.Since(t0), nil
}

func writeFrame(c net.Conn, body []byte) error {
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(body)))
	_, err := c.Write(append(h[:], body...))
	return err
}

func readFrame(c net.Conn, timeout time.Duration) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
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

// RequestToken asks the node for a token: one connection, "GET-TOKEN <device id>", one JSON frame back.
func RequestToken(addr, pin, deviceID string, timeout time.Duration) (token string, expiresAt int64, err error) {
	c, _, err := Dial(addr, pin, timeout)
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

// OriginReachable opens a relay with the token and reports whether the node keeps it open for `hold`.
// A node closes the connection at once if the token is wrong or it cannot reach the origin, so a connection
// that stays open means the whole path through the node works.
func OriginReachable(addr, pin, token string, hold time.Duration, timeout time.Duration) (bool, error) {
	c, _, err := Dial(addr, pin, timeout)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if err := writeFrame(c, []byte(token)); err != nil {
		return false, err
	}
	c.SetReadDeadline(time.Now().Add(hold))
	_, err = c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true, nil // nothing arrived and nothing closed: the relay is open
	}
	if err == nil {
		return true, nil // the origin sent something
	}
	return false, fmt.Errorf("node closed the relay: %w", err)
}
