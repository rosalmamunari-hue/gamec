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

func TestAShortListIsOneBareRecord(t *testing.T) {
	k := key(t)
	recs, _ := BuildRecords(k, manyNodes(5), time.Now(), time.Hour)
	if len(recs) != 1 {
		t.Fatalf("5 nodes should fit in one record, got %d", len(recs))
	}
	r := recs[0]
	if strings.Contains(r, ":") || strings.ContainsAny(r, "\" \\+/=") || !IsRecord(r) {
		t.Fatalf("a bare record has no lead-in and only DNS-friendly characters: %q", r)
	}
	if len(r) > 2000 {
		t.Fatalf("record is %d bytes; many DNS panels stop at 2048", len(r))
	}
	if _, err := VerifyRecords(recs, &k.PublicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestALongListIsSplitIntoNumberedRecords(t *testing.T) {
	k := key(t)
	recs, _ := BuildRecords(k, manyNodes(60), time.Now(), time.Hour)
	if len(recs) < 2 {
		t.Fatalf("60 nodes should need several records, got %d", len(recs))
	}
	for _, r := range recs {
		if !recordRe.MatchString(r) || len(r) > ChunkSize+10 {
			t.Fatalf("bad record %d bytes: %.30s", len(r), r)
		}
	}
	if _, err := VerifyRecords(recs, &k.PublicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestRecordOrderDoesNotMatter(t *testing.T) {
	k := key(t)
	recs, _ := BuildRecords(k, manyNodes(60), time.Now(), time.Hour)
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
	recs, _ := BuildRecords(k, manyNodes(60), time.Now(), time.Hour)
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
		`"abc" "def"`:  "abcdef",
		`"1/1:xyz"`:    "1/1:xyz",
		`plain`:        "plain",
		`"a\"b"`:       `a"b`,
		`  "x"  "y"  `: "xy",
	}
	for in, want := range cases {
		if got := JoinTxtStrings(in); got != want {
			t.Errorf("JoinTxtStrings(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNextNamesAreSignedAndReturned(t *testing.T) {
	k := key(t)
	recs, err := BuildRecordsOpts(k, manyNodes(2), time.Now(), time.Hour, Options{Next: []string{"a.example.com", "b.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyRecords(recs, &k.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Next) != 2 || p.Next[1] != "b.example.org" {
		t.Fatalf("next: %v", p.Next)
	}
}

func TestASealedListIsUnreadableWithoutTheKeyAndVerifiesWithIt(t *testing.T) {
	k := key(t)
	seal, _ := NewSealKey()
	recs, err := BuildRecordsOpts(k, manyNodes(3), time.Now(), time.Hour, Options{SealKey: seal, Next: []string{"a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if strings.Contains(r, "10.0.0.") {
			t.Fatal("node address visible in a sealed record")
		}
	}
	if !IsRecord(recs[0]) {
		t.Fatal("a sealed record must still look like one of ours (the panel replaces only those)")
	}
	if _, err := VerifyRecords(recs, &k.PublicKey, time.Now()); err == nil {
		t.Fatal("a sealed list verified without the key")
	}
	other, _ := NewSealKey()
	if _, err := VerifyRecordsSealed(recs, &k.PublicKey, time.Now(), other); err == nil {
		t.Fatal("a sealed list verified with the wrong key")
	}
	p, err := VerifyRecordsSealed(recs, &k.PublicKey, time.Now(), seal)
	if err != nil || len(p.Nodes) != 3 || p.Next[0] != "a.example.com" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestAnUnsealedListStillVerifiesForAnAppThatHasTheKey(t *testing.T) {
	k := key(t)
	seal, _ := NewSealKey()
	recs, _ := BuildRecords(k, manyNodes(2), time.Now(), time.Hour)
	if _, err := VerifyRecordsSealed(recs, &k.PublicKey, time.Now(), seal); err != nil {
		t.Fatal(err)
	}
}

func TestATamperedSealedListIsRejected(t *testing.T) {
	k := key(t)
	seal, _ := NewSealKey()
	recs, _ := BuildRecordsOpts(k, manyNodes(2), time.Now(), time.Hour, Options{SealKey: seal})
	r := []byte(recs[0])
	r[40] ^= 1
	if r[40] == '.' || r[40] == 0 {
		r[40] = 'A'
	}
	if _, err := VerifyRecordsSealed([]string{string(r)}, &k.PublicKey, time.Now(), seal); err == nil {
		t.Fatal("tampered sealed list accepted")
	}
}

func TestAppConfigSealsAndOpens(t *testing.T) {
	c := AppConfig{Name: "wap.example.com", Fallbacks: []string{"b.example.org"}, PublicKey: "PUB", ListKey: "KEY"}
	blob, err := SealConfig("hunter2", c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, "example") {
		t.Fatal("names visible in the sealed config")
	}
	got, err := OpenConfig("hunter2", blob)
	if err != nil || got.Name != c.Name || got.Fallbacks[0] != "b.example.org" || got.ListKey != "KEY" {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := OpenConfig("wrong", blob); err == nil {
		t.Fatal("opened with the wrong passphrase")
	}
	if _, err := SealConfig("", c); err == nil {
		t.Fatal("sealed with an empty passphrase")
	}
}

// During an update the old and the new record sets can be published side by side for a moment. The checks
// that say "players can read this" must judge such a mix the way the apps do.
func TestMixedRecordSetsAreJudgedLikeTheApps(t *testing.T) {
	k := key(t)
	now := time.Now()
	short, _ := BuildRecords(k, manyNodes(1), now.Add(-time.Minute), time.Hour) // one bare record
	long, _ := BuildRecords(k, manyNodes(60), now, time.Hour)                   // numbered records
	if len(short) != 1 || len(long) < 2 {
		t.Fatalf("setup: %d %d", len(short), len(long))
	}
	p, err := VerifyRecords(append(append([]string{}, long...), short...), &k.PublicKey, now)
	if err != nil || len(p.Nodes) != 60 {
		t.Fatalf("a bare record next to a numbered set: the newest complete one must win, got %v %v", p, err)
	}

	older, _ := BuildRecords(k, manyNodes(60), now.Add(-time.Minute), time.Hour)
	if len(older) != len(long) {
		t.Skip("the two lists split into different numbers of records")
	}
	if _, err := VerifyRecords(append(append([]string{}, older...), long...), &k.PublicKey, now); err == nil {
		t.Fatal("two lists of the same shape at once: the apps refuse this, so must the check")
	}
}
