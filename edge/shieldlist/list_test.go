package shieldlist

import (
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func manyNodes(n int) []Node {
	var out []Node
	for i := 0; i < n; i++ {
		out = append(out, Node{"10.0.0." + string(rune('1'+i)), 30800, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg="})
	}
	return out
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	k := key(t)
	recs, err := BuildRecords(k, manyNodes(3), time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyRecords(recs, &k.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 3 || p.Nodes[0].H != "10.0.0.1" || p.Nodes[0].P != 30800 {
		t.Fatalf("payload %+v", p)
	}
}

func TestEmptyListIsNeverSigned(t *testing.T) {
	k := key(t)
	if _, err := BuildRecords(k, nil, time.Now(), time.Hour); err == nil {
		t.Fatal("an empty node list would lock every player out; it must be refused")
	}
}

func TestRecordsAreShortEnoughForOneTXTString(t *testing.T) {
	recs, _ := BuildRecords(key(t), manyNodes(5), time.Now(), time.Hour)
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
	recs, _ := BuildRecords(k, manyNodes(5), time.Now(), time.Hour)
	for i, j := 0, len(recs)-1; i < j; i, j = i+1, j-1 {
		recs[i], recs[j] = recs[j], recs[i]
	}
	if _, err := VerifyRecords(recs, &k.PublicKey, time.Now()); err != nil {
		t.Fatalf("DNS returns records in any order: %v", err)
	}
}

func TestTamperedListIsRejected(t *testing.T) {
	k := key(t)
	recs, _ := BuildRecords(k, manyNodes(2), time.Now(), time.Hour)
	b := []byte(recs[0])
	b[len(b)-10] ^= 1
	recs[0] = string(b)
	if _, err := VerifyRecords(recs, &k.PublicKey, time.Now()); err == nil {
		t.Fatal("a modified list must not verify")
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	recs, _ := BuildRecords(key(t), manyNodes(2), time.Now(), time.Hour)
	if _, err := VerifyRecords(recs, &key(t).PublicKey, time.Now()); err == nil {
		t.Fatal("a list signed by another key must not verify")
	}
}

func TestMissingChunkIsRejected(t *testing.T) {
	k := key(t)
	recs, _ := BuildRecords(k, manyNodes(5), time.Now(), time.Hour)
	if _, err := VerifyRecords(recs[1:], &k.PublicKey, time.Now()); err == nil {
		t.Fatal("an incomplete record set must not be accepted")
	}
}

func TestExpiredListIsRejected(t *testing.T) {
	k := key(t)
	recs, _ := BuildRecords(k, manyNodes(2), time.Now().Add(-48*time.Hour), time.Hour)
	if _, err := VerifyRecords(recs, &k.PublicKey, time.Now()); err == nil {
		t.Fatal("an expired list must be rejected (stops replay of an old list)")
	}
}

func TestIgnoresUnrelatedTXTRecords(t *testing.T) {
	k := key(t)
	recs, _ := BuildRecords(k, manyNodes(2), time.Now(), time.Hour)
	recs = append(recs, "v=spf1 -all", "google-site-verification=abc")
	if _, err := VerifyRecords(recs, &k.PublicKey, time.Now()); err != nil {
		t.Fatalf("other TXT records on the name must not break parsing: %v", err)
	}
}

func TestKeyEncodingRoundTrips(t *testing.T) {
	k := key(t)
	enc, err := PrivateKeyB64(k)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivateKeyB64(enc)
	if err != nil || !back.Equal(k) {
		t.Fatalf("private key did not survive: %v", err)
	}
	pub, err := ParsePublicKeyB64(PublicKeyB64(&k.PublicKey))
	if err != nil || !pub.Equal(&k.PublicKey) {
		t.Fatalf("public key did not survive: %v", err)
	}
	if _, err := ParsePrivateKeyB64("not base64!"); err == nil {
		t.Fatal("garbage must be rejected")
	}
}

func TestJoinTxtStrings(t *testing.T) {
	cases := map[string]string{
		`"abc" "def"`:   "abcdef",
		`"gs1:1/1:xyz"`: "gs1:1/1:xyz",
		`plain`:         "plain",
		`"a\"b"`:        `a"b`,
		`  "x"  "y"  `:  "xy",
	}
	for in, want := range cases {
		if got := JoinTxtStrings(in); got != want {
			t.Errorf("JoinTxtStrings(%q) = %q, want %q", in, got, want)
		}
	}
}
