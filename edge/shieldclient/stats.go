package shieldclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Stats: the panel opens the normal TLS connection and, as its first frame, sends
// "GET-STATS <unix ts>.<hex hmac-sha256(secret, "gamec stats\x00" ts)>". The node answers with one frame of
// JSON (NodeStats) and closes. Only someone holding the node's token secret can ask; anyone else gets the
// connection closed, the same as for a bad token. The MAC has its own prefix, so a stats request can never
// pass as a relay token or the other way round.

const StatsRequestPrefix = "GET-STATS "

// StatsTopIPs is the most client addresses a node lists in NodeStats.Top.
const StatsTopIPs = 20

// NodeStats is what a node reports about its traffic. Counters run from when the node program started.
type NodeStats struct {
	At       int64  `json:"at"`
	Started  int64  `json:"started"`
	Version  string `json:"version,omitempty"`
	MaxConns int    `json:"max_conns"`
	MaxPerIP int    `json:"max_per_ip"`

	Active  int `json:"active"`  // relays open now
	Devices int `json:"devices"` // distinct devices among them
	IPs     int `json:"ips"`     // distinct client addresses among them (per /64 for IPv6)

	Relays    uint64 `json:"relays"`     // relays opened
	Tokens    uint64 `json:"tokens"`     // tokens issued
	BytesUp   uint64 `json:"bytes_up"`   // players to origin
	BytesDown uint64 `json:"bytes_down"` // origin to players

	// Refused counts connections turned away, by reason: bad_token, per_ip, full, token_refused,
	// no_frame (closed or timed out before the first frame, scanners mostly), origin (origin unreachable).
	Refused map[string]uint64 `json:"refused"`

	// Top lists the client addresses holding the most relays now, most first.
	Top []IPLoad `json:"top,omitempty"`
}

type IPLoad struct {
	IP      string `json:"ip"`
	Relays  int    `json:"relays"`
	Devices int    `json:"devices"`
}

func statsMAC(secret string, ts int64) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("gamec stats\x00" + strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(m.Sum(nil))
}

// StatsRequest is the first frame that asks a node for its stats.
func StatsRequest(secret string, now time.Time) string {
	ts := now.Unix()
	return StatsRequestPrefix + strconv.FormatInt(ts, 10) + "." + statsMAC(secret, ts)
}

// CheckStatsRequest reports whether frame is a stats request made with secret within window of now.
func CheckStatsRequest(frame, secret string, now time.Time, window time.Duration) bool {
	rest, ok := strings.CutPrefix(frame, StatsRequestPrefix)
	if !ok {
		return false
	}
	tsText, mac, ok := strings.Cut(rest, ".")
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > window || d < -window {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(statsMAC(secret, ts)))
}

// FetchStatsVia asks a node for its stats. A node too old to know the request just closes the connection.
func FetchStatsVia(dial DialFunc, addr, pin, secret string, timeout time.Duration) (*NodeStats, error) {
	c, _, err := DialVia(dial, addr, pin, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(timeout))
	if err := writeFrame(c, []byte(StatsRequest(secret, time.Now()))); err != nil {
		return nil, err
	}
	body, err := readFrame(c, timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoStats, err)
	}
	var st NodeStats
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("bad stats reply: %w", err)
	}
	return &st, nil
}

// ErrNoStats means the node closed without answering: an old node version, or a different token secret.
var ErrNoStats = errors.New("the node gave no stats (an older node version, or a different token secret)")
