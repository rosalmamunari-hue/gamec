package shieldclient

import (
	"bufio"
	"bytes"
	"testing"
)

func TestReadProxyV1(t *testing.T) {
	// what gnetway gets today from Gcore, followed by what a node with -proxy-v1 adds
	r := bufio.NewReader(bytes.NewReader([]byte("PROXY TCP4 47.243.177.67 193.239.179.128 34832 10443\r\nPROXY TCP4 198.51.100.7 10.0.0.5 51000 48860\r\nrest of it")))
	for _, want := range []string{"47.243.177.67:34832", "198.51.100.7:51000"} {
		if ok, _ := HasProxy(r); !ok {
			t.Fatal("header not seen")
		}
		h, err := ReadProxy(r)
		if err != nil || h.Src.String() != want {
			t.Fatal(h, err)
		}
	}
	if ok, _ := HasProxy(r); ok {
		t.Fatal("the stream was taken for a header")
	}
	for _, bad := range []string{
		"PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n",
		"PROXY TCP4 x 5.6.7.8 1 2\r\n",
		"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n",
		"PROXY TCP4 1.2.3.4 5.6.7.8 1 70000\r\n",
	} {
		if _, err := ReadProxyV1(bufio.NewReader(bytes.NewReader([]byte(bad)))); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if h, err := ReadProxyV1(bufio.NewReader(bytes.NewReader([]byte("PROXY UNKNOWN\r\n")))); err != nil || !h.Local {
		t.Fatal(h, err)
	}
	// both versions are told apart
	v2 := bufio.NewReader(bytes.NewReader(AppendProxyV2Local(nil)))
	if ok, _ := HasProxy(v2); !ok {
		t.Fatal("v2 not seen")
	}
	if h, err := ReadProxy(v2); err != nil || !h.Local {
		t.Fatal(h, err)
	}
}
