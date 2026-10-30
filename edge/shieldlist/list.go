// Package shieldlist builds, signs and verifies the node list that is published as DNS TXT records.
//
// Record format: "<i>/<n>:<chunk>"; the chunks joined are base64url(payload) "." base64url(signature),
// where signature is ASN.1 ECDSA P-256 over SHA-256(payload) and payload is
// {"v":1,"iat":unix,"exp":unix,"nodes":[{"h":host,"p":port,"k":pin}]}.
// The apps (Android, iOS) implement the verifying side of exactly this format.
package shieldlist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ChunkSize keeps every record comfortably inside one 255-byte TXT string.
const ChunkSize = 200

// Node is one entry of the list.
type Node struct {
	H string `json:"h"` // host
	P int    `json:"p"` // port
	K string `json:"k"` // pin: base64(SHA-256(SubjectPublicKeyInfo))
}

// Payload is the signed content.
type Payload struct {
	V     int    `json:"v"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Nodes []Node `json:"nodes"`
}

// GenerateKey makes a new signing key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PrivateKeyB64 encodes a key as base64(DER SEC1), the format of the key files.
func PrivateKeyB64(k *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// ParsePrivateKeyB64 is the inverse of PrivateKeyB64.
func ParsePrivateKeyB64(s string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("key must be base64")
	}
	k, err := x509.ParseECPrivateKey(der)
	if err != nil || k.Curve != elliptic.P256() {
		return nil, errors.New("key must be a P-256 EC private key")
	}
	return k, nil
}

// PublicKeyB64 is the key to embed in the apps: base64(X.509 SubjectPublicKeyInfo).
func PublicKeyB64(pub *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return base64.StdEncoding.EncodeToString(der)
}

// ParsePublicKeyB64 is the inverse of PublicKeyB64.
func ParsePublicKeyB64(s string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("public key must be base64")
	}
	k, err := x509.ParsePKIXPublicKey(der)
	pk, ok := k.(*ecdsa.PublicKey)
	if err != nil || !ok || pk.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 public key")
	}
	return pk, nil
}

// BuildRecords signs the list and splits it into TXT record values.
func BuildRecords(k *ecdsa.PrivateKey, nodes []Node, now time.Time, valid time.Duration) ([]string, error) {
	if len(nodes) == 0 {
		return nil, errors.New("refusing to sign an empty node list")
	}
	payload, err := json.Marshal(Payload{V: 1, Iat: now.Unix(), Exp: now.Add(valid).Unix(), Nodes: nodes})
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
	for len(body) > ChunkSize {
		chunks = append(chunks, body[:ChunkSize])
		body = body[ChunkSize:]
	}
	chunks = append(chunks, body)
	recs := make([]string, len(chunks))
	for i, c := range chunks {
		recs[i] = fmt.Sprintf("%d/%d:%s", i+1, len(chunks), c)
	}
	return recs, nil
}

var recordRe = regexp.MustCompile(`^[0-9]{1,3}/[0-9]{1,3}:`)

// IsRecord says whether a TXT value is one of the list's records (the "<i>/<n>:" lead-in). Other TXT values
// at the same name are none of our business.
func IsRecord(v string) bool { return recordRe.MatchString(v) }

// VerifyRecords reassembles the records and checks the signature and expiry (what the apps do).
// Records that do not look like "<i>/<n>:" are ignored.
func VerifyRecords(records []string, pub *ecdsa.PublicKey, now time.Time) (*Payload, error) {
	parts := map[int]string{}
	total := 0
	for _, r := range records {
		if !IsRecord(r) {
			continue
		}
		f := strings.SplitN(r, ":", 2)
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
	var p Payload
	if err := json.Unmarshal(payload, &p); err != nil || p.V != 1 || len(p.Nodes) == 0 {
		return nil, errors.New("bad payload")
	}
	if now.Unix() > p.Exp {
		return nil, errors.New("list expired")
	}
	return &p, nil
}

// JoinTxtStrings turns the DoH presentation `"part1" "part2"` of one TXT value into part1part2.
func JoinTxtStrings(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `"`) {
		return s
	}
	var sb strings.Builder
	in, esc := false, false
	for _, c := range s {
		switch {
		case in && esc:
			sb.WriteRune(c)
			esc = false
		case in && c == '\\':
			esc = true
		case in && c == '"':
			in = false
		case in:
			sb.WriteRune(c)
		case c == '"':
			in = true
		}
	}
	return sb.String()
}
