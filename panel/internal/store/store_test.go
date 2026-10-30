package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const pin = "c65StCewbul2pPTQFu2ZuxI3TLhWb6lxMQacqAJDYoE="

func cluster(name string) *Cluster {
	return &Cluster{ID: NewID(), Name: name, ValidDays: 30, RenewBeforeDays: 10,
		Targets: []DNSTarget{{Provider: "manual", Zone: "example.com", Name: "_gs.example.com"}}}
}

func node(c *Cluster, name, host string, port int) *Node {
	return &Node{ID: NewID(), ClusterID: c.ID, Name: name, Host: host, Port: port, Pin: pin, Enabled: true}
}

func open(t *testing.T) *Store {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	s, _ := Open(p)
	c := cluster("official")
	if err := s.Mutate(func(st *State) error {
		st.Clusters = append(st.Clusters, c)
		st.Nodes = append(st.Nodes, node(c, "hk-1", "1.2.3.4", 30800))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	st := s2.Snapshot()
	if len(st.Clusters) != 1 || len(st.Nodes) != 1 || st.Nodes[0].Host != "1.2.3.4" {
		t.Fatalf("%+v", st)
	}
}

func TestInvalidChangeLeavesStateUntouched(t *testing.T) {
	s := open(t)
	c := cluster("official")
	s.Mutate(func(st *State) error { st.Clusters = append(st.Clusters, c); return nil })
	err := s.Mutate(func(st *State) error {
		st.Nodes = append(st.Nodes, node(c, "bad", "1.2.3.4", 99999))
		return nil
	})
	if err == nil {
		t.Fatal("port 99999 accepted")
	}
	if len(s.Snapshot().Nodes) != 0 {
		t.Fatal("a rejected change was kept")
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	s := open(t)
	c := cluster("official")
	s.Mutate(func(st *State) error { st.Clusters = append(st.Clusters, c); return nil })
	snap := s.Snapshot()
	snap.Clusters[0].Name = "hacked"
	if s.Snapshot().Clusters[0].Name != "official" {
		t.Fatal("snapshot shares memory with the store")
	}
}

func TestNodeValidation(t *testing.T) {
	c := cluster("official")
	bad := map[string]*Node{
		"empty host":  node(c, "a", "", 30800),
		"bad host":    node(c, "a", "not a host!", 30800),
		"port 0":      node(c, "a", "1.2.3.4", 0),
		"short pin":   {ID: NewID(), ClusterID: c.ID, Name: "a", Host: "1.2.3.4", Port: 1, Pin: "abc", Enabled: true},
		"unknown cl.": {ID: NewID(), ClusterID: "deadbeef", Name: "a", Host: "1.2.3.4", Port: 1, Pin: pin},
		"empty name":  node(c, "  ", "1.2.3.4", 30800),
	}
	for what, n := range bad {
		st := State{Clusters: []*Cluster{c}, Nodes: []*Node{n}}
		if err := st.Validate(); err == nil {
			t.Errorf("%s accepted", what)
		}
	}
	good := State{Clusters: []*Cluster{c}, Nodes: []*Node{node(c, "a", "node1.example.com", 30800), node(c, "b", "2001:db8::1", 30800)}}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid nodes rejected: %v", err)
	}
}

func TestOneAddressBelongsToOneCluster(t *testing.T) {
	a, b := cluster("official"), cluster("channel-a")
	st := State{Clusters: []*Cluster{a, b}, Nodes: []*Node{node(a, "x", "1.2.3.4", 30800), node(b, "y", "1.2.3.4", 30800)}}
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Fatalf("the same address in two clusters must be refused, got %v", err)
	}
	st.Nodes[1].Port = 30801 // same server, another instance: fine
	if err := st.Validate(); err != nil {
		t.Fatalf("same host with another port is a separate instance: %v", err)
	}
}

func TestClusterValidation(t *testing.T) {
	mk := func(f func(*Cluster)) State {
		c := cluster("x")
		f(c)
		return State{Clusters: []*Cluster{c}}
	}
	cases := map[string]State{
		"no targets":        mk(func(c *Cluster) { c.Targets = nil }),
		"unknown provider":  mk(func(c *Cluster) { c.Targets[0].Provider = "godaddy" }),
		"name outside zone": mk(func(c *Cluster) { c.Targets[0].Name = "_gs.other.org" }),
		"renew >= valid":    mk(func(c *Cluster) { c.RenewBeforeDays = 30 }),
		"valid too long":    mk(func(c *Cluster) { c.ValidDays = 400 }),
		"missing cred ref":  mk(func(c *Cluster) { c.Targets[0].Provider = "cloudflare"; c.Targets[0].CredRef = "" }),
		"bad dns name":      mk(func(c *Cluster) { c.Targets[0].Name = "_gs.exa mple.com" }),
	}
	for what, st := range cases {
		if err := st.Validate(); err == nil {
			t.Errorf("%s accepted", what)
		}
	}
	two := State{Clusters: []*Cluster{cluster("same"), cluster("same")}}
	if err := two.Validate(); err == nil {
		t.Error("two clusters with one name accepted")
	}
}

func TestActiveHonoursEnabledAndTemporaryShutdown(t *testing.T) {
	c := cluster("official")
	now := time.Now()
	on := node(c, "on", "1.1.1.1", 1)
	off := node(c, "off", "1.1.1.2", 1)
	off.Enabled = false
	temp := node(c, "temp", "1.1.1.3", 1)
	temp.DisabledUntil = now.Add(10 * time.Minute)
	st := State{Clusters: []*Cluster{c}, Nodes: []*Node{on, off, temp}}

	got := st.Active(c.ID, now)
	if len(got) != 1 || got[0].Name != "on" {
		t.Fatalf("now: %v", names(got))
	}
	got = st.Active(c.ID, now.Add(11*time.Minute))
	if len(got) != 2 {
		t.Fatalf("a temporary shutdown must end by itself, got %v", names(got))
	}
}

func names(ns []*Node) []string {
	var o []string
	for _, n := range ns {
		o = append(o, n.Name)
	}
	return o
}

func TestClustersDoNotSeeEachOthersNodes(t *testing.T) {
	a, b := cluster("official"), cluster("channel-a")
	st := State{Clusters: []*Cluster{a, b}, Nodes: []*Node{node(a, "a1", "1.1.1.1", 1), node(b, "b1", "2.2.2.2", 1)}}
	if got := st.NodesOf(a.ID); len(got) != 1 || got[0].Name != "a1" {
		t.Fatalf("%v", names(got))
	}
}

func TestNodesKeyIgnoresOrderButNotContent(t *testing.T) {
	c := cluster("x")
	a, b := node(c, "a", "1.1.1.1", 1), node(c, "b", "2.2.2.2", 1)
	if NodesKey([]*Node{a, b}) != NodesKey([]*Node{b, a}) {
		t.Fatal("order must not matter")
	}
	b2 := *b
	b2.Pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if NodesKey([]*Node{a, b}) == NodesKey([]*Node{a, &b2}) {
		t.Fatal("a changed pin must change the key (the list has to be re-signed)")
	}
}

func TestRefusesAnInconsistentFileOnLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	writeFile(t, p, `{"clusters":[],"nodes":[{"id":"aaaaaaaa","cluster_id":"bbbbbbbb","name":"x","host":"1.2.3.4","port":1,"pin":"`+pin+`"}]}`)
	if _, err := Open(p); err == nil {
		t.Fatal("a node pointing at a missing cluster was loaded")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSSHFieldsAreValidated(t *testing.T) {
	c := cluster("official")
	mk := func(f func(*Node)) State {
		n := node(c, "a", "1.2.3.4", 30800)
		f(n)
		return State{Clusters: []*Cluster{c}, Nodes: []*Node{n}}
	}
	bad := map[string]State{
		"user with a space":     mk(func(n *Node) { n.SSHUser = "root user" }),
		"user with a semicolon": mk(func(n *Node) { n.SSHUser = "x;rm" }),
		"upper case user":       mk(func(n *Node) { n.SSHUser = "Root" }),
		"ssh port 70000":        mk(func(n *Node) { n.SSHUser = "u"; n.SSHPort = 70000 }),
		"unit sshd":             mk(func(n *Node) { n.Unit = "sshd" }),
		"unit with a path":      mk(func(n *Node) { n.Unit = "gamec-edge/../x" }),
		"short host key":        mk(func(n *Node) { n.HostKey = "SHA256:abc" }),
		"md5 host key":          mk(func(n *Node) { n.HostKey = "MD5:aa:bb:cc" }),
	}
	for what, st := range bad {
		if err := st.Validate(); err == nil {
			t.Errorf("%s accepted", what)
		}
	}
	ok := mk(func(n *Node) {
		n.SSHUser, n.SSHPort, n.Unit = "gamec-ops", 22, "gamec-edge-channel-a"
		n.HostKey = "SHA256:" + strings.Repeat("A", 43)
	})
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid SSH settings refused: %v", err)
	}
	n := ok.Nodes[0]
	if n.UnitName() != "gamec-edge-channel-a" || n.SSHAddr() != "1.2.3.4:22" || !n.SSHConfigured() {
		t.Fatalf("%s %s %v", n.UnitName(), n.SSHAddr(), n.SSHConfigured())
	}
	plain := node(c, "p", "5.6.7.8", 30800)
	if plain.UnitName() != "gamec-edge" || plain.SSHConfigured() {
		t.Fatal("defaults are wrong")
	}
	v6 := node(c, "v6", "2001:db8::1", 30800)
	v6.SSHPort = 2222
	if v6.SSHAddr() != "[2001:db8::1]:2222" {
		t.Fatalf("IPv6 needs brackets: %s", v6.SSHAddr())
	}
}
