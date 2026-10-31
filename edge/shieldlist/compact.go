package shieldlist

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"
)

// The compact format keeps the record small enough for a plain DNS answer (512 bytes) and makes it look like
// noise: there is no lead-in, and the record starts with the signature, which differs on every publish.
//
// A record is base64url (no padding) of
//
//	signature(64) || content
//
// where content is the payload, or nonce(12) || AES-256-GCM(payload) when the list is sealed, and the
// signature is ECDSA P-256 as r||s (32 bytes each) over SHA-256(CompactDomain || payload). The payload is
//
//	version(1)=2  kind(1)  iat(4)  exp(4)  count(1)  entries
//
// big-endian, kind 1 = node list, entry = family(1: 4 or 6) address(4 or 16) port(2) pin(16, the first 16
// bytes of SHA-256(SubjectPublicKeyInfo)); kind 2 = next names, entry = length(1) name.
//
// The node list sits at the name the apps read; the next names sit at NextName(that name), so the list
// itself stays small. Records that are not ours (SPF, site verification) live happily next to them: an app
// keeps only the values that verify.

// CompactDomain separates these signatures from any other use of the key.
const CompactDomain = "gamec compact list v2\x00"

const (
	kindList = 1
	kindNext = 2
	pinLen   = 16
	sigLen   = 64
	headLen  = 11
)

// NextLabel is the label in front of a list name where its next names are published.
const NextLabel = "dw2"

// NextName is where the next names for the list at name are published.
func NextName(name string) string { return NextLabel + "." + strings.TrimSuffix(name, ".") }

// NextList is the signed list of names the apps should read from next time.
type NextList struct {
	Iat, Exp int64
	Names    []string
}

var nameRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$`)

func signCompact(k *ecdsa.PrivateKey, payload []byte, sealKey []byte) (string, error) {
	digest := sha256.Sum256(append([]byte(CompactDomain), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		return "", err
	}
	body := make([]byte, sigLen, sigLen+len(payload)+40)
	r.FillBytes(body[:32])
	s.FillBytes(body[32:64])
	content := payload
	if sealKey != nil {
		aead, err := gcm(sealKey)
		if err != nil {
			return "", err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
		content = aead.Seal(nonce, nonce, payload, nil)
	}
	return base64.RawURLEncoding.EncodeToString(append(body, content...)), nil
}

// checkTimes refuses times the 4-byte fields cannot hold (they would wrap around into the past).
func checkTimes(now time.Time, valid time.Duration) error {
	if now.Unix() < 0 || valid < 0 || now.Add(valid).Unix() > math.MaxUint32 {
		return errors.New("the list times must lie between 1970 and 2106")
	}
	return nil
}

func header(kind byte, now time.Time, valid time.Duration, count int) []byte {
	h := make([]byte, headLen)
	h[0], h[1] = 2, kind
	binary.BigEndian.PutUint32(h[2:], uint32(now.Unix()))
	binary.BigEndian.PutUint32(h[6:], uint32(now.Add(valid).Unix()))
	h[10] = byte(count)
	return h
}

// BuildCompact signs the node list as one compact record. Hosts must be IP addresses.
func BuildCompact(k *ecdsa.PrivateKey, nodes []Node, now time.Time, valid time.Duration, sealKey []byte) (string, error) {
	if len(nodes) == 0 {
		return "", errors.New("refusing to sign an empty node list")
	}
	if len(nodes) > 255 {
		return "", errors.New("too many nodes")
	}
	if err := checkTimes(now, valid); err != nil {
		return "", err
	}
	p := header(kindList, now, valid, len(nodes))
	for _, n := range nodes {
		ip := net.ParseIP(n.H)
		if ip == nil {
			return "", fmt.Errorf("%s is not an IP address: the compact list holds addresses only", n.H)
		}
		if n.P < 1 || n.P > 65535 {
			return "", fmt.Errorf("%s: port out of range", n.H)
		}
		pin, err := base64.StdEncoding.DecodeString(n.K)
		if err != nil || len(pin) < pinLen {
			return "", fmt.Errorf("%s: the pin is not base64 of a SHA-256", n.H)
		}
		if v4 := ip.To4(); v4 != nil {
			p = append(p, 4)
			p = append(p, v4...)
		} else {
			p = append(p, 6)
			p = append(p, ip.To16()...)
		}
		p = binary.BigEndian.AppendUint16(p, uint16(n.P))
		p = append(p, pin[:pinLen]...)
	}
	return signCompact(k, p, sealKey)
}

// BuildNextRecord signs the names the apps should read the list from next time.
func BuildNextRecord(k *ecdsa.PrivateKey, names []string, now time.Time, valid time.Duration, sealKey []byte) (string, error) {
	if len(names) == 0 || len(names) > 20 {
		return "", errors.New("give 1-20 next names")
	}
	if err := checkTimes(now, valid); err != nil {
		return "", err
	}
	p := header(kindNext, now, valid, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !nameRe.MatchString(n) || len(n) > 253 {
			return "", fmt.Errorf("%q is not a DNS name", n)
		}
		p = append(p, byte(len(n)))
		p = append(p, n...)
	}
	return signCompact(k, p, sealKey)
}

var compactRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// LooksCompact says whether a TXT value has the shape of a compact record (the DNS providers use it to tell
// the records they manage from other TXT values at the same name; the name is ours, so a long base64url
// value there is ours too).
func LooksCompact(v string) bool { return len(v) >= 100 && len(v) <= 4000 && compactRe.MatchString(v) }

// openCompact checks one value and returns its payload, of the given kind, or an error.
func openCompact(v string, pub *ecdsa.PublicKey, sealKey []byte, kind byte) ([]byte, error) {
	if !LooksCompact(v) {
		return nil, errors.New("not a compact record")
	}
	body, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(body) < sigLen+headLen {
		return nil, errors.New("malformed compact record")
	}
	sig, payload := body[:sigLen], body[sigLen:]
	if sealKey != nil {
		if aead, err := gcm(sealKey); err != nil {
			return nil, err
		} else if len(payload) > aead.NonceSize() {
			if plain, err := aead.Open(nil, payload[:aead.NonceSize()], payload[aead.NonceSize():], nil); err == nil {
				payload = plain // otherwise it was not sealed: the signature decides
			}
		}
	}
	digest := sha256.Sum256(append([]byte(CompactDomain), payload...))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, errors.New("signature invalid")
	}
	if len(payload) < headLen || payload[0] != 2 || payload[1] != kind {
		return nil, errors.New("not this kind of record")
	}
	return payload, nil
}

func times(p []byte) (iat, exp int64) {
	return int64(binary.BigEndian.Uint32(p[2:])), int64(binary.BigEndian.Uint32(p[6:]))
}

// parseCompactList reads a verified list payload.
func parseCompactList(p []byte) (*Payload, error) {
	iat, exp := times(p)
	out := &Payload{V: 2, Iat: iat, Exp: exp}
	rest := p[headLen:]
	for i := 0; i < int(p[10]); i++ {
		if len(rest) < 1 {
			return nil, errors.New("short list")
		}
		size := map[byte]int{4: 4, 6: 16}[rest[0]]
		if size == 0 || len(rest) < 1+size+2+pinLen {
			return nil, errors.New("bad node entry")
		}
		ip := net.IP(append([]byte(nil), rest[1:1+size]...))
		port := int(binary.BigEndian.Uint16(rest[1+size:]))
		pin := rest[1+size+2 : 1+size+2+pinLen]
		out.Nodes = append(out.Nodes, Node{H: ip.String(), P: port, K: base64.StdEncoding.EncodeToString(pin)})
		rest = rest[1+size+2+pinLen:]
	}
	if len(rest) != 0 || len(out.Nodes) == 0 {
		return nil, errors.New("bad list length")
	}
	return out, nil
}

// VerifyNextRecords finds, among the TXT values at a NextName, the newest valid next list.
func VerifyNextRecords(records []string, pub *ecdsa.PublicKey, now time.Time, sealKey []byte) (*NextList, error) {
	var best *NextList
	lastErr := errors.New("no next list")
	for _, v := range records {
		p, err := openCompact(v, pub, sealKey, kindNext)
		if err != nil {
			if LooksCompact(v) {
				lastErr = err
			}
			continue
		}
		iat, exp := times(p)
		nl := &NextList{Iat: iat, Exp: exp}
		rest := p[headLen:]
		ok := true
		for i := 0; i < int(p[10]); i++ {
			if len(rest) < 1 || len(rest) < 1+int(rest[0]) {
				ok = false
				break
			}
			nl.Names = append(nl.Names, string(rest[1:1+int(rest[0])]))
			rest = rest[1+int(rest[0]):]
		}
		if !ok || len(rest) != 0 || len(nl.Names) == 0 {
			lastErr = errors.New("bad next list")
			continue
		}
		if now.Unix() > exp {
			lastErr = errors.New("next list expired")
			continue
		}
		if best == nil || nl.Iat > best.Iat {
			best = nl
		}
	}
	if best == nil {
		return nil, lastErr
	}
	return best, nil
}

// AnswerSize estimates the size of a plain DNS answer carrying one TXT value of the given length at name.
func AnswerSize(name string, valueLen int) int {
	q := 12 + len(strings.TrimSuffix(name, ".")) + 2 + 4 // header and question
	return q + 12 + valueLen + (valueLen+254)/255        // answer: name pointer, type, class, ttl, length, strings
}

// CompactLen is the length of a compact list record with n IPv4 nodes.
func CompactLen(n int, sealed bool) int {
	b := sigLen + headLen + n*(1+4+2+pinLen)
	if sealed {
		b += 12 + 16
	}
	return (b*8 + 5) / 6
}

// MaxCompactNodes is how many IPv4 nodes fit in one plain (512-byte) DNS answer at name.
func MaxCompactNodes(name string, sealed bool) int {
	n := 0
	for AnswerSize(name, CompactLen(n+1, sealed)) <= 512 {
		n++
	}
	return n
}
