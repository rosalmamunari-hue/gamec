package egress

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

type fakeJump struct {
	t      sshx.Target
	dials  atomic.Int32
	closed atomic.Bool
	err    error
}

func (f *fakeJump) DialContext(context.Context, string, string) (net.Conn, error) {
	f.dials.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	c, _ := net.Pipe()
	return c, nil
}
func (f *fakeJump) Close() error { f.closed.Store(true); return nil }

const fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func setup(t *testing.T, cfg *store.Egress) (*Egress, *[]*fakeJump, *store.Store) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if cfg != nil {
		if err := st.Mutate(func(s *store.State) error { s.Egress = cfg; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	made := &[]*fakeJump{}
	pemKey, _, _ := sshx.GenerateKey("x")
	signer, _ := sshx.ParseSigner(pemKey)
	e := &Egress{Store: st, Signer: func() (ssh.Signer, error) { return signer, nil },
		NewJump: func(tg sshx.Target) Jumper { j := &fakeJump{t: tg}; *made = append(*made, j); return j }}
	return e, made, st
}

func TestWithoutAnEgressHostConnectionsAreDirect(t *testing.T) {
	e, made, _ := setup(t, nil)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()
	c, err := e.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(*made) != 0 || e.Configured() {
		t.Fatal("a jump connection was made without being configured")
	}
}

func TestWithAnEgressHostEverythingGoesThroughIt(t *testing.T) {
	e, made, _ := setup(t, &store.Egress{Addr: "203.0.113.7:22", User: "gamec-jump", HostKey: fp})
	for i := 0; i < 3; i++ {
		c, err := e.DialContext(context.Background(), "tcp", "198.51.100.1:30800")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if len(*made) != 1 || (*made)[0].dials.Load() != 3 {
		t.Fatalf("expected one jump connection used three times, got %d jump(s)", len(*made))
	}
	tg := (*made)[0].t
	if tg.Addr != "203.0.113.7:22" || tg.User != "gamec-jump" || tg.HostKey != fp || tg.Signer == nil {
		t.Fatalf("%+v", tg)
	}
	if !e.Configured() {
		t.Fatal("not reported as configured")
	}
}

func TestAnUnconfirmedHostKeyMeansNothingIsSentAtAll(t *testing.T) {
	e, made, _ := setup(t, &store.Egress{Addr: "203.0.113.7:22", User: "gamec-jump"})
	if _, err := e.DialContext(context.Background(), "tcp", "198.51.100.1:30800"); !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("got %v", err)
	}
	if len(*made) != 0 {
		t.Fatal("a jump connection was made to a host whose key is unconfirmed")
	}
}

func TestNeverFallsBackToADirectConnection(t *testing.T) {
	direct, _ := net.Listen("tcp", "127.0.0.1:0")
	defer direct.Close()
	var hits atomic.Int32
	go func() {
		for {
			c, err := direct.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	e, made, _ := setup(t, &store.Egress{Addr: "203.0.113.7:22", User: "gamec-jump", HostKey: fp})
	// the jump host is unreachable
	e.NewJump = func(tg sshx.Target) Jumper {
		j := &fakeJump{t: tg, err: errors.New("the egress host is down")}
		*made = append(*made, j)
		return j
	}
	if c, err := e.DialContext(context.Background(), "tcp", direct.Addr().String()); err == nil {
		c.Close()
		t.Fatal("connected although the egress host is down")
	}
	// the key is not available (vault sealed)
	e2, _, _ := setup(t, &store.Egress{Addr: "203.0.113.7:22", User: "gamec-jump", HostKey: fp})
	e2.Signer = func() (ssh.Signer, error) { return nil, errors.New("vault is sealed") }
	if c, err := e2.DialContext(context.Background(), "tcp", direct.Addr().String()); err == nil || !strings.Contains(err.Error(), "sealed") {
		if c != nil {
			c.Close()
		}
		t.Fatalf("got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the destination received a direct connection: the panel's address would have been exposed")
	}
}

func TestChangingTheConfigurationReplacesTheJumpConnection(t *testing.T) {
	e, made, st := setup(t, &store.Egress{Addr: "203.0.113.7:22", User: "gamec-jump", HostKey: fp})
	c, _ := e.DialContext(context.Background(), "tcp", "198.51.100.1:30800")
	c.Close()
	st.Mutate(func(s *store.State) error { s.Egress.Addr = "203.0.113.8:22"; return nil })
	c, _ = e.DialContext(context.Background(), "tcp", "198.51.100.1:30800")
	c.Close()
	if len(*made) != 2 || !(*made)[0].closed.Load() || (*made)[1].t.Addr != "203.0.113.8:22" {
		t.Fatalf("the old jump connection was kept after the address changed (%d made)", len(*made))
	}
	st.Mutate(func(s *store.State) error { s.Egress = nil; return nil })
	if e.Configured() {
		t.Fatal("still configured after removal")
	}
}

func TestEgressConfigurationIsValidated(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "state.json"))
	for what, e := range map[string]store.Egress{
		"no port":     {Addr: "203.0.113.7", User: "u"},
		"port 0":      {Addr: "203.0.113.7:0", User: "u"},
		"bad host":    {Addr: "bad host!:22", User: "u"},
		"bad account": {Addr: "203.0.113.7:22", User: "root user"},
		"bad hostkey": {Addr: "203.0.113.7:22", User: "u", HostKey: "SHA256:short"},
	} {
		e := e
		if err := st.Mutate(func(s *store.State) error { s.Egress = &e; return nil }); err == nil {
			t.Errorf("%s accepted", what)
		}
	}
	good := store.Egress{Addr: "jump.example.com:2222", User: "gamec-jump", HostKey: fp}
	if err := st.Mutate(func(s *store.State) error { s.Egress = &good; return nil }); err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}
}
