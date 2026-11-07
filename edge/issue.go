package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
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
	refusalLog = newWindow(time.Minute) // a flood of refusals must not flood the journal
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
// exempt (-allow-ips) skips the per-address and per-device limits; the device id must still be valid and not
// banned.
func handleTokenRequest(c net.Conn, ip string, exempt bool, first []byte) {
	id := string(first[len(tokenRequestPrefix):])
	now := time.Now()
	why := ""
	switch {
	case !deviceIDRe.MatchString(id):
		why = "bad device id"
	case !exempt && !ipWindow.allow(ip, *ipTokenLimit, now):
		why = "address over -token-ip-limit"
	case !exempt && !devWindow.allow(id, *devTokenLimit, now):
		why = "device over -token-device-limit"
	case isBanned(id):
		why = "banned device"
	}
	if why != "" {
		stats.refuse("token_refused")
		if refusalLog.allow("", refusalLogPerMinute, now) {
			log.Printf("token refused %s: %s (device %s)", ip, why, shortID(id))
		}
		return
	}
	stats.tokens.Add(1)
	body, _ := json.Marshal(struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}{MakeToken(*secret, id, now), now.Add(issuedLifetime).Unix()})

	c.SetWriteDeadline(now.Add(5 * time.Second))
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(body)))
	c.Write(append(h[:], body...))
}

const refusalLogPerMinute = 20

// shortID is enough of a device id to tell devices apart in the log, and no more.
func shortID(id string) string {
	if len(id) > 8 {
		id = id[:8] + "…"
	}
	return strconv.Quote(id)
}
