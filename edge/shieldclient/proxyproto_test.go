package shieldclient

import (
	"bufio"
	"bytes"
	"net/netip"
	"testing"
)

func TestProxyV2RoundTrip(t *testing.T) {
	for _, c := range []struct{ src, dst string }{
		{"203.0.113.9:51000", "198.51.100.1:30800"},
		{"[2001:db8::9]:51000", "[2001:db8::1]:30800"},
		{"203.0.113.9:51000", "[2001:db8::1]:30800"}, // mixed: written as IPv6, read back as the same addresses
	} {
		src, dst := netip.MustParseAddrPort(c.src), netip.MustParseAddrPort(c.dst)
		b := AppendProxyV2(nil, src, dst)
		r := bufio.NewReader(bytes.NewReader(append(b, "game"...)))
		if ok, _ := HasProxyV2(r); !ok {
			t.Fatal("signature not seen")
		}
		h, err := ReadProxyV2(r)
		if err != nil || h.Local || h.Src != src || h.Dst != dst {
			t.Fatalf("%s: %+v %v", c.src, h, err)
		}
		rest := make([]byte, 4)
		if n, _ := r.Read(rest); string(rest[:n]) != "game" {
			t.Fatal("the stream after the header was eaten")
		}
	}
	h, err := ReadProxyV2(bytes.NewReader(AppendProxyV2Local(nil)))
	if err != nil || !h.Local {
		t.Fatal(h, err)
	}
}

func TestProxyV2SkipsTLVsAndRefusesJunk(t *testing.T) {
	src, dst := netip.MustParseAddrPort("1.2.3.4:5"), netip.MustParseAddrPort("6.7.8.9:10")
	b := AppendProxyV2(nil, src, dst)
	b[15] += 7 // a TLV from an anti-DDoS front, 7 more bytes
	b = append(b, 0xE0, 0, 4, 'a', 'b', 'c', 'd')
	r := bytes.NewReader(append(b, 'X'))
	if h, err := ReadProxyV2(r); err != nil || h.Src != src {
		t.Fatal(h, err)
	}
	if x, _ := r.ReadByte(); x != 'X' {
		t.Fatal("TLV not skipped")
	}
	if _, err := ReadProxyV2(bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))); err == nil {
		t.Fatal("junk read as a header")
	}
}
