package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const devID = "device-1234567890abcdef"

// requestToken sends GET-TOKEN and returns the issued token, or "" if the node closed without answering.
func requestToken(t *testing.T, addr, id string) string {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := tokenRequestPrefix + id
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(msg)))
	c.Write(append(h[:], msg...))

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return ""
	}
	body := make([]byte, binary.BigEndian.Uint16(h[:]))
	if _, err := io.ReadFull(c, body); err != nil {
		return ""
	}
	var r struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("bad reply %q: %v", body, err)
	}
	if want := time.Now().Add(issuedLifetime).Unix(); r.ExpiresAt < want-5 || r.ExpiresAt > want+5 {
		t.Fatalf("expires_at %d, want about %d", r.ExpiresAt, want)
	}
	return r.Token
}

func resetIssuing() {
	ipWindow = newWindow(time.Minute)
	devWindow = newWindow(time.Minute)
	*ipTokenLimit, *devTokenLimit, *bannedFile = 30, 10, ""
}

func TestIssuedTokenWorksForRelay(t *testing.T) {
	resetIssuing()
	addr := startEdge(t)
	tok := requestToken(t, addr, devID)
	if tok == "" {
		t.Fatal("no token issued")
	}
	c := dial(t, addr, tok)
	defer c.Close()
	if !echoWorks(c) {
		t.Fatal("the token the node issued must be accepted by the same node")
	}
}

func TestBadDeviceIDGetsNoToken(t *testing.T) {
	resetIssuing()
	addr := startEdge(t)
	for _, id := range []string{"", "short", "has.dot.in.it.1234567890", "has space 1234567890abc"} {
		if tok := requestToken(t, addr, id); tok != "" {
			t.Errorf("id %q was issued a token", id)
		}
	}
}

func TestPerDeviceTokenLimit(t *testing.T) {
	resetIssuing()
	*devTokenLimit = 2
	addr := startEdge(t)
	for i := 0; i < 2; i++ {
		if requestToken(t, addr, devID) == "" {
			t.Fatalf("request %d should be answered", i)
		}
	}
	if requestToken(t, addr, devID) != "" {
		t.Fatal("3rd request for the same device should be refused")
	}
	if requestToken(t, addr, "another-device-abcdef0123") == "" {
		t.Fatal("a different device must not be limited")
	}
}

func TestPerIPTokenLimitStopsDeviceIDChurn(t *testing.T) {
	resetIssuing()
	*ipTokenLimit = 3
	addr := startEdge(t)
	got := []bool{}
	for i := 0; i < 5; i++ {
		got = append(got, requestToken(t, addr, "churn-device-"+string(rune('a'+i))+"xxxxxxxxxx") != "")
	}
	if !got[0] || !got[1] || !got[2] || got[3] || got[4] {
		t.Fatalf("answered=%v: fresh device ids from one IP must still hit the IP limit", got)
	}
}

func TestBannedDeviceGetsNoToken(t *testing.T) {
	resetIssuing()
	f := filepath.Join(t.TempDir(), "banned.txt")
	os.WriteFile(f, []byte("someone-abcdef0123456789\n"+devID+"\n"), 0o600)
	*bannedFile = f
	defer func() { *bannedFile = "" }()
	addr := startEdge(t)
	if requestToken(t, addr, devID) != "" {
		t.Fatal("banned device was issued a token")
	}
}
