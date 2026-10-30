// probe checks a deployed node end to end: TLS 1.3, public-key pin, token acceptance, token rejection.
//
//	go run ./cmd/probe -addr 1.2.3.4:30800 -pin <base64> -secret <secret>
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

func token(secret string, ts time.Time) string {
	body := "probe." + strconv.FormatInt(ts.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return body + "." + hex.EncodeToString(m.Sum(nil))
}

func dial(addr, pin, tok string) (*tls.Conn, time.Duration, error) {
	t0 := time.Now()
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // trust is decided by the pin below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			spki, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
			sum := sha256.Sum256(spki)
			if base64.StdEncoding.EncodeToString(sum[:]) != pin {
				return fmt.Errorf("pin mismatch")
			}
			return nil
		},
	})
	if err != nil {
		return nil, 0, err
	}
	rtt := time.Since(t0)
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(tok)))
	c.Write(append(h[:], tok...))
	return c, rtt, nil
}

// requestToken sends "GET-TOKEN <id>" and reads the node's one-frame JSON answer.
func requestToken(addr, pin, id string) (string, error) {
	c2, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			spki, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
			sum := sha256.Sum256(spki)
			if base64.StdEncoding.EncodeToString(sum[:]) != pin {
				return fmt.Errorf("pin mismatch")
			}
			return nil
		},
	})
	if err != nil {
		return "", err
	}
	defer c2.Close()
	msg := "GET-TOKEN " + id
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(msg)))
	c2.Write(append(h[:], msg...))
	c2.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.ReadFull(c2, h[:]); err != nil {
		return "", fmt.Errorf("no answer (old node version?): %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(h[:]))
	if _, err := io.ReadFull(c2, body); err != nil {
		return "", err
	}
	var r struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Token == "" {
		return "", fmt.Errorf("bad reply %q", body)
	}
	return r.Token, nil
}

// stays reports whether the server keeps the connection open for a short while.
func stays(c *tls.Conn) bool {
	c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

func main() {
	addr := flag.String("addr", "", "host:port")
	pin := flag.String("pin", "", "expected key pin")
	secret := flag.String("secret", "", "token secret")
	given := flag.String("token", "", "use this token as the valid one (e.g. issued by the control service)")
	flag.Parse()

	valid := *given
	if valid == "" {
		valid = token(*secret, time.Now())
	}
	c, rtt, err := dial(*addr, *pin, valid)
	if err != nil {
		fmt.Println("FAIL connect/pin:", err)
		os.Exit(1)
	}
	fmt.Printf("ok   TLS1.3 + pin verified, handshake %v\n", rtt.Round(time.Millisecond))
	if stays(c) {
		fmt.Println("ok   valid token accepted (connection held open to origin)")
	} else {
		fmt.Println("FAIL valid token: connection closed (origin unreachable or token wrong)")
	}
	c.Close()

	c, _, err = dial(*addr, *pin, token("wrong-secret", time.Now()))
	if err != nil {
		fmt.Println("FAIL second connect:", err)
		os.Exit(1)
	}
	if stays(c) {
		fmt.Println("FAIL bad token was NOT rejected")
	} else {
		fmt.Println("ok   bad token rejected")
	}
	c.Close()

	// token issued by the node itself (needs the node to run the new version)
	if tok, err := requestToken(*addr, *pin, "probe-device-0123456789"); err != nil {
		fmt.Println("FAIL node-issued token:", err)
	} else if c, _, err := dial(*addr, *pin, tok); err != nil {
		fmt.Println("FAIL connect with node-issued token:", err)
	} else {
		if stays(c) {
			fmt.Println("ok   node issues a token and accepts it")
		} else {
			fmt.Println("FAIL node-issued token was not accepted")
		}
		c.Close()
	}

	if _, _, err := dial(*addr, "AAAA", "x"); err != nil {
		fmt.Println("ok   wrong pin refused by client")
	} else {
		fmt.Println("FAIL wrong pin was accepted")
	}
}
