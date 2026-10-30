package engine

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"gamec/panel/internal/store"
)

// The prober is only worth anything if it agrees with the real node program. This builds the edge node and
// runs it for real.
func TestRealProberAgainstTheRealEdgeNode(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH")
	}
	dir := t.TempDir()
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	build := func(pkg, out string) string {
		bin := filepath.Join(dir, out+ext)
		cmd := exec.Command(goBin, "build", "-o", bin, pkg)
		cmd.Dir = filepath.Join("..", "..", "..", "edge")
		if o, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", pkg, err, o)
		}
		return bin
	}
	edgeBin, gencertBin := build(".", "edge"), build("./cmd/gencert", "gencert")

	out, err := exec.Command(gencertBin, "-host", "127.0.0.1", "-out", filepath.Join(dir, "certs")).CombinedOutput()
	if err != nil {
		t.Fatalf("gencert: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`pin:\s+(\S+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("no pin in %s", out)
	}
	pin := m[1]

	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	defer origin.Close()

	free, _ := net.Listen("tcp", "127.0.0.1:0")
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()

	edge := exec.Command(edgeBin, "-listen", "127.0.0.1:"+strconv.Itoa(port), "-origin", origin.Addr().String(),
		"-cert", filepath.Join(dir, "certs", "cert.pem"), "-key", filepath.Join(dir, "certs", "key.pem"), "-secret", "real-test-secret")
	stderr, _ := edge.StderrPipe()
	if err := edge.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { edge.Process.Kill(); edge.Wait() }()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
		}
	}()
	for i := 0; ; i++ {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if i > 50 {
			t.Fatal("the edge node did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}

	node := store.Node{ID: "abcd1234", Host: "127.0.0.1", Port: port, Pin: pin}
	prober := RealProber{Timeout: 5 * time.Second, Hold: 400 * time.Millisecond}
	ctx := context.Background()

	r := prober.Probe(ctx, node)
	if !r.OK || !r.TokenOK || !r.RelayOK || r.Handshake <= 0 {
		t.Fatalf("a healthy node was judged unhealthy: %+v", r)
	}

	bad := node
	bad.Pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if r := prober.Probe(ctx, bad); r.OK || !strings.Contains(r.Err, "connect") {
		t.Fatalf("a node with the wrong pin must be refused: %+v", r)
	}

	origin.Close() // the node can now not reach the game server
	r = prober.Probe(ctx, node)
	if r.OK || !r.TokenOK || r.RelayOK {
		t.Fatalf("a node that cannot reach its origin must fail the relay check: %+v", r)
	}
	if !strings.Contains(r.Err, "origin") {
		t.Fatalf("the reason should name the origin: %q", r.Err)
	}

	_ = os.Stdout
}
