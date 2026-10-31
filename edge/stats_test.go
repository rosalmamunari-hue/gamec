package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"gamec/edge/shieldclient"
)

// startEdgePinned is startEdge with a certificate whose pin is known, so shieldclient can talk to it.
func startEdgePinned(t *testing.T) (addr, pin string) {
	t.Helper()
	*origin = startEcho(t)
	*secret = "test-secret"
	cert := selfSigned()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	sum := sha256.Sum256(spki)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	lim := &limiter{n: map[string]int{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c, lim)
		}
	}()
	return ln.Addr().String(), base64.StdEncoding.EncodeToString(sum[:])
}

func fetchStats(t *testing.T, addr, pin, secret string) (*shieldclient.NodeStats, error) {
	t.Helper()
	return shieldclient.FetchStatsVia(shieldclient.DirectDial, addr, pin, secret, 3*time.Second)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("timed out waiting until " + what)
}

func TestStatsShowOpenRelaysAndTraffic(t *testing.T) {
	stats = newCounters()
	addr, pin := startEdgePinned(t)

	a := dial(t, addr, MakeToken("test-secret", "device-a", time.Now()))
	defer a.Close()
	b := dial(t, addr, MakeToken("test-secret", "device-b", time.Now()))
	if !echoWorks(a) || !echoWorks(b) {
		t.Fatal("relays should work")
	}
	bad := dial(t, addr, MakeToken("other", "device-c", time.Now()))
	if echoWorks(bad) {
		t.Fatal("bad token relayed")
	}
	bad.Close()

	st, err := fetchStats(t, addr, pin, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	if st.Active != 2 || st.Devices != 2 || st.IPs != 1 || st.Relays != 2 {
		t.Fatalf("active %d devices %d ips %d relays %d, want 2 2 1 2", st.Active, st.Devices, st.IPs, st.Relays)
	}
	if st.BytesUp < 8 || st.BytesDown < 8 {
		t.Fatalf("bytes up %d down %d, want at least the two pings each way", st.BytesUp, st.BytesDown)
	}
	if st.Refused["bad_token"] != 1 {
		t.Fatalf("refused %v, want one bad_token", st.Refused)
	}
	if len(st.Top) != 1 || st.Top[0].IP != "127.0.0.1" || st.Top[0].Relays != 2 || st.Top[0].Devices != 2 {
		t.Fatalf("top %+v", st.Top)
	}
	if st.MaxConns != *maxConns || st.MaxPerIP != *maxPerIP || st.Started == 0 {
		t.Fatalf("limits or start time missing: %+v", st)
	}

	b.Close()
	waitFor(t, "the closed relay is no longer counted", func() bool {
		st, err := fetchStats(t, addr, pin, "test-secret")
		return err == nil && st.Active == 1 && st.Devices == 1
	})
}

func TestStatsNeedTheSecret(t *testing.T) {
	stats = newCounters()
	addr, pin := startEdgePinned(t)
	if _, err := fetchStats(t, addr, pin, "not-the-secret"); !errors.Is(err, shieldclient.ErrNoStats) {
		t.Fatalf("err %v, want ErrNoStats", err)
	}
	// an old request (replayed later) is refused too
	c := dial(t, addr, shieldclient.StatsRequest("test-secret", time.Now().Add(-time.Hour)))
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c.Read(make([]byte, 10)); n != 0 {
		t.Fatal("an expired stats request was answered")
	}
}

func TestAStatsRequestIsNotARelayToken(t *testing.T) {
	*secret = "test-secret"
	req := shieldclient.StatsRequest("test-secret", time.Now())
	if _, ok := checkToken(req, time.Now()); ok {
		t.Fatal("a stats request passed as a token")
	}
	if shieldclient.CheckStatsRequest(MakeToken("test-secret", "x", time.Now()), "test-secret", time.Now(), time.Minute) {
		t.Fatal("a token passed as a stats request")
	}
}
