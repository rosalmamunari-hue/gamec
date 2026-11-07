package main

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestAnAllowedAddressSkipsTheRateLimitsButNotTheChecks(t *testing.T) {
	resetIssuing()
	addr := startEdge(t)
	*maxPerIP, *ipTokenLimit, *devTokenLimit = 2, 2, 3
	var err error
	if allowed, err = parseAllow("192.0.2.0/24, 127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	defer func() { *maxPerIP, allowed = 20, nil; resetIssuing() }()

	var open []*tls.Conn
	for i := 0; i < 5; i++ { // more than -max-per-ip at once
		c := dial(t, addr, MakeToken("test-secret", "u", time.Now()))
		if !echoWorks(c) {
			t.Fatalf("conn %d from an allowed address was refused", i)
		}
		open = append(open, c)
	}
	for _, c := range open {
		c.Close()
	}
	for i, id := range []string{"device-aaaaaaaaaaaaaaaa1", "device-aaaaaaaaaaaaaaaa2", "device-aaaaaaaaaaaaaaaa3", "device-aaaaaaaaaaaaaaaa4"} {
		if requestToken(t, addr, id) == "" { // more than -token-ip-limit
			t.Fatalf("token %d for an allowed address was refused", i)
		}
	}
	for i := 0; i < 5; i++ { // more than -token-device-limit
		if requestToken(t, addr, devID) == "" {
			t.Fatalf("token %d for one device at an allowed address was refused", i)
		}
	}
	if requestToken(t, addr, "bad id") != "" {
		t.Fatal("an allowed address still needs a valid device id")
	}
	c := dial(t, addr, "not a token")
	if echoWorks(c) {
		t.Fatal("an allowed address still needs a valid token")
	}
	c.Close()

	allowed = nil
	for _, a := range []string{"127.0.0.1", "::ffff:127.0.0.1"} {
		if isAllowed(a) {
			t.Fatalf("%s allowed with an empty list", a)
		}
	}
	allowed, _ = parseAllow("127.0.0.1")
	if !isAllowed("::ffff:127.0.0.1") || isAllowed("127.0.0.2") || isAllowed("garbage") {
		t.Fatal("matching")
	}
	if _, err := parseAllow("1.2.3.4,nope"); err == nil {
		t.Fatal("a bad entry was accepted")
	}
}
