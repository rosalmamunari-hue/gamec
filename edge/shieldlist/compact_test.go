package shieldlist

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

var compactNodes = []Node{
	{H: "47.243.177.67", P: 48860, K: "DkiaHrX6/4RgIaVLObJBLPoPdwVI0qKNxddmemWaV9w="},
	{H: "47.76.67.157", P: 30522, K: "O16v+J3Ysb+CLyxboxN8TP+mch9yTOw+E4E7MP8+RjU="},
	{H: "2001:db8::7", P: 23198, K: "c65StCewbul2pPTQFu2ZuxI3TLhWb6lxMQacqAJDYoE="},
}

func shortPin(full string) string {
	b, _ := base64.StdEncoding.DecodeString(full)
	return base64.StdEncoding.EncodeToString(b[:16])
}

func TestACompactListRoundTripsPlainAndSealed(t *testing.T) {
	k, _ := GenerateKey()
	now := time.Unix(1_800_000_000, 0)
	seal, _ := NewSealKey()
	for _, key := range [][]byte{nil, seal} {
		rec, err := BuildCompact(k, compactNodes, now, 30*24*time.Hour, key)
		if err != nil {
			t.Fatal(err)
		}
		// other people's TXT values at the same name are ignored
		p, err := VerifyRecordsSealed([]string{"v=spf1 -all", rec, "google-site-verification=abc"}, &k.PublicKey, now, key)
		if err != nil {
			t.Fatalf("sealed=%v: %v", key != nil, err)
		}
		if p.Iat != now.Unix() || p.Exp != now.Add(30*24*time.Hour).Unix() || len(p.Nodes) != 3 {
			t.Fatalf("%+v", p)
		}
		for i, n := range p.Nodes {
			if n.H != compactNodes[i].H || n.P != compactNodes[i].P || n.K != shortPin(compactNodes[i].K) {
				t.Errorf("node %d: %+v", i, n)
			}
		}
		if key != nil {
			if _, err := VerifyRecordsSealed([]string{rec}, &k.PublicKey, now, nil); err == nil {
				t.Error("a sealed list must not be readable without the key")
			}
			if strings.Contains(rec, "47") && strings.Contains(string(mustDecode(rec)), "\x2f\xf3\xb1\x43") {
				t.Error("the sealed record shows an address")
			}
		}
	}
}

func mustDecode(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

func TestACompactRecordIsRejectedWhenAnythingIsWrong(t *testing.T) {
	k, _ := GenerateKey()
	other, _ := GenerateKey()
	now := time.Unix(1_800_000_000, 0)
	rec, _ := BuildCompact(k, compactNodes, now, time.Hour, nil)
	if _, err := VerifyRecordsSealed([]string{rec}, &other.PublicKey, now, nil); err == nil {
		t.Error("another key's list was accepted")
	}
	if _, err := VerifyRecordsSealed([]string{rec}, &k.PublicKey, now.Add(2*time.Hour), nil); err == nil {
		t.Error("an expired list was accepted")
	}
	b := mustDecode(rec)
	b[len(b)-1] ^= 1 // one bit of a pin
	if _, err := VerifyRecordsSealed([]string{base64.RawURLEncoding.EncodeToString(b)}, &k.PublicKey, now, nil); err == nil {
		t.Error("a changed list was accepted")
	}
	next, _ := BuildNextRecord(k, []string{"a.example.com", "b.example.net"}, now, time.Hour, nil)
	if _, err := VerifyRecordsSealed([]string{next}, &k.PublicKey, now, nil); err == nil {
		t.Error("a next-names record must not pass as a node list")
	}
	if _, err := VerifyNextRecords([]string{rec}, &k.PublicKey, now, nil); err == nil {
		t.Error("a node list must not pass as next names")
	}
	if _, err := BuildCompact(k, compactNodes, now, 100*365*24*time.Hour, nil); err == nil {
		t.Error("an expiry past 2106 would wrap into the past")
	}
	if _, err := BuildCompact(k, []Node{{H: "node.example.com", P: 1, K: compactNodes[0].K}}, now, time.Hour, nil); err == nil {
		t.Error("names cannot go into the compact list")
	}
}

func TestTheNewestCompactListWinsAndMixesWithTheOldFormat(t *testing.T) {
	k, _ := GenerateKey()
	t0 := time.Unix(1_800_000_000, 0)
	old, _ := BuildRecords(k, compactNodes[:1], t0, 48*time.Hour)
	a, _ := BuildCompact(k, compactNodes[:2], t0.Add(time.Minute), 48*time.Hour, nil)
	b, _ := BuildCompact(k, compactNodes, t0.Add(2*time.Minute), 48*time.Hour, nil)
	p, err := VerifyRecordsSealed(append(old, b, a), &k.PublicKey, t0.Add(time.Hour), nil)
	if err != nil || len(p.Nodes) != 3 {
		t.Fatalf("%v %+v", err, p)
	}
	p, err = VerifyRecordsSealed(append([]string{a}, old...), &k.PublicKey, t0.Add(time.Hour), nil)
	if err != nil || p.V != 2 {
		t.Fatalf("the compact list is newer than the old one: %v %+v", err, p)
	}
}

func TestNextNamesRoundTrip(t *testing.T) {
	k, _ := GenerateKey()
	now := time.Unix(1_800_000_000, 0)
	seal, _ := NewSealKey()
	names := []string{"wap.apq.2xfh6vdq.cc", "update.dpz.vr8cn2tl.uk"}
	for _, key := range [][]byte{nil, seal} {
		rec, err := BuildNextRecord(k, names, now, time.Hour, key)
		if err != nil {
			t.Fatal(err)
		}
		nl, err := VerifyNextRecords([]string{"other", rec}, &k.PublicKey, now, key)
		if err != nil || strings.Join(nl.Names, ",") != strings.Join(names, ",") || nl.Iat != now.Unix() {
			t.Fatalf("%v %+v", err, nl)
		}
	}
	if NextName("wap.apq.2xfh6vdq.cc.") != "dw2.wap.apq.2xfh6vdq.cc" {
		t.Error(NextName("wap.apq.2xfh6vdq.cc."))
	}
	if _, err := BuildNextRecord(k, []string{"bad name"}, now, time.Hour, nil); err == nil {
		t.Error("a bad name was accepted")
	}
}

// The point of the format: it fits a plain DNS answer, looks like noise, and is skipped by apps of the
// first format (v0.4.0), which would otherwise give up on a name holding two lists they cannot tell apart.
func TestACompactRecordIsSmallLooksRandomAndOldAppsSkipIt(t *testing.T) {
	k, _ := GenerateKey()
	seal, _ := NewSealKey()
	now := time.Now()
	nodes := []Node{compactNodes[0], compactNodes[1], {H: "47.76.206.15", P: 23198, K: compactNodes[2].K}}
	a, _ := BuildCompact(k, nodes, now, time.Hour, nil)
	b, _ := BuildCompact(k, nodes, now, time.Hour, nil)
	if a[:20] == b[:20] {
		t.Error("two publishes of the same list should not start alike")
	}
	if len(a) != CompactLen(3, false) {
		t.Errorf("length %d, CompactLen says %d", len(a), CompactLen(3, false))
	}
	s, _ := BuildCompact(k, nodes, now, time.Hour, seal)
	if len(s) != CompactLen(3, true) {
		t.Errorf("sealed length %d, CompactLen says %d", len(s), CompactLen(3, true))
	}
	const name = "wap.apq.2xfh6vdq.cc"
	if AnswerSize(name, len(s)) > 512 {
		t.Errorf("3 sealed nodes need %d bytes", AnswerSize(name, len(s)))
	}
	if n := MaxCompactNodes(name, true); n < 9 {
		t.Errorf("only %d sealed nodes fit", n)
	}
	oldBare := regexp.MustCompile(`^[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$`)
	oldChunk := regexp.MustCompile(`^[0-9]{1,3}/[0-9]{1,3}:`)
	for _, r := range []string{a, s} {
		if oldBare.MatchString(r) || oldChunk.MatchString(r) || IsRecord(r) {
			t.Error("an old app would take the compact record for one of its own")
		}
	}
	// what a 512-byte answer leaves at the real name today
	t.Logf("3 nodes: %d chars (answer %d bytes), sealed %d chars (answer %d bytes); max %d plain / %d sealed",
		len(a), AnswerSize(name, len(a)), len(s), AnswerSize(name, len(s)), MaxCompactNodes(name, false), MaxCompactNodes(name, true))
}

// TestPrintCompactVectors prints records made with a fixed key, for the Kotlin and Swift tests:
//
//	GAMEC_VECTORS=1 go test ./shieldlist -run TestPrintCompactVectors -v
func TestPrintCompactVectors(t *testing.T) {
	if os.Getenv("GAMEC_VECTORS") == "" {
		t.Skip("set GAMEC_VECTORS=1 to print the cross-language vectors")
	}
	k, _ := GenerateKey()
	seal, _ := NewSealKey()
	now := time.Unix(1_800_000_000, 0)
	valid := 50 * 365 * 24 * time.Hour // the 4-byte times reach 2106
	list, _ := BuildCompact(k, compactNodes, now, valid, nil)
	sealed, _ := BuildCompact(k, compactNodes, now, valid, seal)
	next, _ := BuildNextRecord(k, []string{"a.example.com", "b.example.net"}, now, valid, nil)
	fmt.Printf("pub    = %s\nseal   = %s\nlist   = %s\nsealed = %s\nnext   = %s\n", PublicKeyB64(&k.PublicKey),
		base64.StdEncoding.EncodeToString(seal), list, sealed, next)
	for _, n := range compactNodes {
		fmt.Printf("pin16 %s = %s\n", n.H, shortPin(n.K))
	}
}
