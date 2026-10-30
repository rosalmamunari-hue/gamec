package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Token issuing: a client that has no token yet opens the normal TLS connection and, as its first frame,
// sends "GET-TOKEN <device id>". The node answers with one frame of JSON and closes. This replaces a
// separate control server. The device id proves nothing about the player; abuse is bounded by per-IP and
// per-device rate limits and a ban list.

const (
	tokenRequestPrefix = "GET-TOKEN "
	issuedLifetime     = 4 * time.Minute // inside the +-tokenTTL window that checkToken accepts
)

var (
	bannedFile    = flag.String("banned", "", "optional file of banned device ids, one per line")
	ipTokenLimit  = flag.Int("token-ip-limit", 30, "max token requests per IP per minute")
	devTokenLimit = flag.Int("token-device-limit", 10, "max token requests per device per minute")

	deviceIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	ipWindow   = newWindow(time.Minute)
	devWindow  = newWindow(time.Minute)
)

// window is a fixed-window counter per key.
type window struct {
	mu    sync.Mutex
	n     map[string]int
	start time.Time
	per   time.Duration
}

func newWindow(per time.Duration) *window {
	return &window{n: map[string]int{}, start: time.Now(), per: per}
}

func (w *window) allow(key string, max int, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Sub(w.start) >= w.per {
		w.n = map[string]int{}
		w.start = now
	}
	w.n[key]++
	return w.n[key] <= max
}

func isBanned(id string) bool {
	if *bannedFile == "" {
		return false
	}
	b, err := os.ReadFile(*bannedFile)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == id {
			return true
		}
	}
	return false
}

func isTokenRequest(first []byte) bool {
	return bytes.HasPrefix(first, []byte(tokenRequestPrefix))
}

// handleTokenRequest answers a GET-TOKEN frame. Refusals just close the connection, giving nothing away.
func handleTokenRequest(c net.Conn, ip string, first []byte) {
	id := string(first[len(tokenRequestPrefix):])
	now := time.Now()
	if !deviceIDRe.MatchString(id) ||
		!ipWindow.allow(ip, *ipTokenLimit, now) ||
		!devWindow.allow(id, *devTokenLimit, now) ||
		isBanned(id) {
		return
	}
	body, _ := json.Marshal(struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}{MakeToken(*secret, id, now), now.Add(issuedLifetime).Unix()})

	c.SetWriteDeadline(now.Add(5 * time.Second))
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(body)))
	c.Write(append(h[:], body...))
}
