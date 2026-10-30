package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func manyNodes(n int) []listNode {
	var out []listNode
	for i := 0; i < n; i++ {
		out = append(out, listNode{"10.0.0." + string(rune('1'+i)), 30800, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg="})
	}
	return out
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	k := key(t)
	recs, err := buildRecords(k, manyNodes(3), time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := verifyRecords(recs, &k.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 3 || p.Nodes[0].H != "10.0.0.1" || p.Nodes[0].P != 30800 {
		t.Fatalf("payload %+v", p)
	}
}

func TestRecordsAreShortEnoughForOneTXTString(t *testing.T) {
	recs, _ := buildRecords(key(t), manyNodes(5), time.Now(), time.Hour)
	if len(recs) < 2 {
		t.Fatalf("5 nodes should need several records, got %d", len(recs))
	}
	for _, r := range recs {
		if len(r) > 255 {
			t.Fatalf("record is %d bytes, over the 255-byte TXT string limit", len(r))
		}
		body := r[strings.LastIndex(r, ":")+1:]
		if strings.ContainsAny(body, "\" \\+/=") {
			t.Fatalf("record data contains characters that are awkward in DNS panels: %q", body)
		}
	}
}

func TestRecordOrderDoesNotMatter(t *testing.T) {
	k := key(t)
	recs, _ := buildRecords(k, manyNodes(5), time.Now(), time.Hour)
	for i, j := 0, len(recs)-1; i < j; i, j = i+1, j-1 {
		recs[i], recs[j] = recs[j], recs[i]
	}
	if _, err := verifyRecords(recs, &k.PublicKey, time.Now()); err != nil {
		t.Fatalf("DNS returns records in any order: %v", err)
	}
}

func TestTamperedListIsRejected(t *testing.T) {
	k := key(t)
	recs, _ := buildRecords(k, manyNodes(2), time.Now(), time.Hour)
	b := []byte(recs[0])
	b[len(b)-10] ^= 1 // flip one character inside the signed body
	recs[0] = string(b)
	if _, err := verifyRecords(recs, &k.PublicKey, time.Now()); err == nil {
		t.Fatal("a modified list must not verify")
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	recs, _ := buildRecords(key(t), manyNodes(2), time.Now(), time.Hour)
	if _, err := verifyRecords(recs, &key(t).PublicKey, time.Now()); err == nil {
		t.Fatal("a list signed by another key must not verify")
	}
}

func TestMissingChunkIsRejected(t *testing.T) {
	k := key(t)
	recs, _ := buildRecords(k, manyNodes(5), time.Now(), time.Hour)
	if _, err := verifyRecords(recs[1:], &k.PublicKey, time.Now()); err == nil {
		t.Fatal("an incomplete record set must not be accepted")
	}
}

func TestExpiredListIsRejected(t *testing.T) {
	k := key(t)
	recs, _ := buildRecords(k, manyNodes(2), time.Now().Add(-48*time.Hour), time.Hour)
	if _, err := verifyRecords(recs, &k.PublicKey, time.Now()); err == nil {
		t.Fatal("an expired list must be rejected (stops replay of an old list)")
	}
}

func TestIgnoresUnrelatedTXTRecords(t *testing.T) {
	k := key(t)
	recs, _ := buildRecords(k, manyNodes(2), time.Now(), time.Hour)
	recs = append(recs, "v=spf1 -all", "google-site-verification=abc")
	if _, err := verifyRecords(recs, &k.PublicKey, time.Now()); err != nil {
		t.Fatalf("other TXT records on the name must not break parsing: %v", err)
	}
}

func TestDohHandlerShape(t *testing.T) {
	recs := []string{"gs1:1/1:abcdefghij"}
	srv := httptest.NewServer(dohHandler(recs))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/?name=x.example&type=TXT")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Status int
		Answer []struct {
			Type int
			Data string
		}
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Status != 0 || len(out.Answer) != 1 || out.Answer[0].Type != 16 ||
		out.Answer[0].Data != `"gs1:1/1:a" "bcdefghij"` {
		t.Fatalf("unexpected DoH reply: %+v", out)
	}
}
