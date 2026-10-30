// Package store holds the panel's configuration: clusters (one per release channel) and their nodes.
//
// A cluster is everything one group of apps needs: its own origin, DNS names, signing key and token secret
// (the keys live in the vault under cluster/<id>/...), and its own set of nodes. Clusters never share nodes,
// keys or records, so a problem or a leaked key in one channel cannot touch another.
package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gamec/panel/internal/atomicfile"
)

var (
	idRe      = regexp.MustCompile(`^[a-f0-9]{8}$`)
	dnsNameRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	credRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	unitRe    = regexp.MustCompile(`^gamec-edge[a-z0-9-]{0,40}$`)
	userRe    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	hostKeyRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	providers = map[string]bool{"manual": true, "spaceship": true, "cloudflare": true, "aliyun": true}
)

// DNSTarget is one place a cluster's list is published. A cluster can have several (for example two
// domains at two providers) so that losing one domain does not hide the nodes.
type DNSTarget struct {
	Provider string `json:"provider"` // manual | spaceship | cloudflare | aliyun
	Zone     string `json:"zone"`     // the registered domain, e.g. example.com
	Name     string `json:"name"`     // the full name holding the records, e.g. _gs.example.com
	CredRef  string `json:"cred_ref"` // vault secrets are dns/<cred_ref>/...
}

// Published describes the last list that was signed and sent out.
type Published struct {
	At       time.Time `json:"at"`
	Iat      int64     `json:"iat"`
	Exp      int64     `json:"exp"`
	NodesKey string    `json:"nodes_key"` // sorted host:port:pin of the nodes in it
	Nodes    []string  `json:"nodes"`
	Result   string    `json:"result"`
	Verified bool      `json:"verified"`
	Manual   bool      `json:"manual"` // records are waiting to be pasted by hand
	Records  []string  `json:"records,omitempty"`
}

type Cluster struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Origin          string      `json:"origin"` // where its nodes forward to; informational
	Targets         []DNSTarget `json:"targets"`
	ValidDays       int         `json:"valid_days"`        // how long each signed list is valid
	RenewBeforeDays int         `json:"renew_before_days"` // re-sign this long before it expires
	AutoPublish     bool        `json:"auto_publish"`      // after a first manual publish
	PublicKey       string      `json:"public_key"`        // for the apps; the private key is in the vault
	Sealed          bool        `json:"sealed,omitempty"`  // encrypt the published list (key in the vault)
	Notes           string      `json:"notes,omitempty"`
	Created         time.Time   `json:"created"`
	Last            Published   `json:"last"`
}

type Node struct {
	ID            string    `json:"id"`
	ClusterID     string    `json:"cluster_id"`
	Name          string    `json:"name"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	Pin           string    `json:"pin"`
	Enabled       bool      `json:"enabled"`
	DisabledUntil time.Time `json:"disabled_until,omitempty"` // temporary removal that ends by itself
	SSHUser       string    `json:"ssh_user,omitempty"`       // the restricted account the panel logs in as
	SSHPort       int       `json:"ssh_port,omitempty"`       // 0 means 22
	Unit          string    `json:"unit,omitempty"`           // systemd unit of the edge service; empty means gamec-edge
	HostKey       string    `json:"host_key,omitempty"`       // SHA256 fingerprint an administrator confirmed
	Notes         string    `json:"notes,omitempty"`
	Created       time.Time `json:"created"`
}

func (n *Node) Addr() string { return net.JoinHostPort(n.Host, fmt.Sprint(n.Port)) }

// UnitName is the systemd unit of this node's edge service.
func (n *Node) UnitName() string {
	if n.Unit == "" {
		return "gamec-edge"
	}
	return n.Unit
}

// SSHAddr is where the panel connects to manage the node.
func (n *Node) SSHAddr() string {
	port := n.SSHPort
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(n.Host, fmt.Sprint(port))
}

// SSHConfigured says whether the node has what the panel needs to manage it over SSH.
func (n *Node) SSHConfigured() bool { return n.SSHUser != "" }

// Key identifies what a client would connect to; it is what changes when the published list must change.
func (n *Node) Key() string { return n.Addr() + ":" + n.Pin }

// Egress is the jump host every connection from the panel to a node is sent through, so the nodes see its
// address and never the panel's.
type Egress struct {
	Addr    string `json:"addr"` // host:port of its SSH service
	User    string `json:"user"`
	HostKey string `json:"host_key"` // confirmed SHA256 fingerprint; empty means not confirmed yet
}

type State struct {
	Clusters []*Cluster `json:"clusters"`
	Nodes    []*Node    `json:"nodes"`
	Egress   *Egress    `json:"egress,omitempty"`
}

func (s State) Cluster(id string) *Cluster {
	for _, c := range s.Clusters {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (s State) Node(id string) *Node {
	for _, n := range s.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

func (s State) NodesOf(clusterID string) []*Node {
	var out []*Node
	for _, n := range s.Nodes {
		if n.ClusterID == clusterID {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Active is the nodes of a cluster that are switched on right now (enabled and not in a temporary
// shutdown). Health-based removal is decided separately, by the monitor.
func (s State) Active(clusterID string, now time.Time) []*Node {
	var out []*Node
	for _, n := range s.NodesOf(clusterID) {
		if n.Enabled && !now.Before(n.DisabledUntil) {
			out = append(out, n)
		}
	}
	return out
}

// NodesKey is the sorted identity of a set of nodes.
func NodesKey(nodes []*Node) string {
	keys := make([]string, 0, len(nodes))
	for _, n := range nodes {
		keys = append(keys, n.Key())
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func NewID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func validPin(p string) bool {
	b, err := base64.StdEncoding.DecodeString(p)
	return err == nil && len(b) == 32
}

func validHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	return dnsNameRe.MatchString(strings.ToLower(h))
}

// Validate checks the whole state; it runs after every change.
func (s State) Validate() error {
	seen := map[string]bool{}
	names := map[string]bool{}
	for _, c := range s.Clusters {
		if !idRe.MatchString(c.ID) || seen[c.ID] {
			return fmt.Errorf("cluster %q: bad or duplicate id", c.Name)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Name) == "" || len(c.Name) > 60 {
			return errors.New("cluster name must be 1-60 characters")
		}
		if names[c.Name] {
			return fmt.Errorf("cluster name %q is used twice", c.Name)
		}
		names[c.Name] = true
		if c.ValidDays < 2 || c.ValidDays > 90 {
			return fmt.Errorf("cluster %q: valid days must be 2-90", c.Name)
		}
		if c.RenewBeforeDays < 1 || c.RenewBeforeDays >= c.ValidDays {
			return fmt.Errorf("cluster %q: renew-before must be at least 1 and less than the validity", c.Name)
		}
		if len(c.Targets) == 0 {
			return fmt.Errorf("cluster %q needs at least one DNS target", c.Name)
		}
		for _, t := range c.Targets {
			if !providers[t.Provider] {
				return fmt.Errorf("cluster %q: unknown DNS provider %q", c.Name, t.Provider)
			}
			if !dnsNameRe.MatchString(t.Name) || !dnsNameRe.MatchString(t.Zone) {
				return fmt.Errorf("cluster %q: bad DNS name or zone", c.Name)
			}
			if t.Name != t.Zone && !strings.HasSuffix(t.Name, "."+t.Zone) {
				return fmt.Errorf("cluster %q: %s is not inside %s", c.Name, t.Name, t.Zone)
			}
			if t.Provider != "manual" && !credRefRe.MatchString(t.CredRef) {
				return fmt.Errorf("cluster %q: credential reference %q is not valid", c.Name, t.CredRef)
			}
		}
	}
	if e := s.Egress; e != nil {
		host, port, err := net.SplitHostPort(e.Addr)
		p, perr := strconv.Atoi(port)
		if err != nil || perr != nil || p < 1 || p > 65535 || !validHost(host) {
			return fmt.Errorf("the egress address %q is not host:port", e.Addr)
		}
		if !userRe.MatchString(e.User) {
			return fmt.Errorf("%q is not a valid egress account name", e.User)
		}
		if e.HostKey != "" && !hostKeyRe.MatchString(e.HostKey) {
			return errors.New("the egress host key fingerprint is not valid")
		}
	}
	nodeIDs := map[string]bool{}
	addrs := map[string]bool{}
	for _, n := range s.Nodes {
		if !idRe.MatchString(n.ID) || nodeIDs[n.ID] {
			return fmt.Errorf("node %q: bad or duplicate id", n.Name)
		}
		nodeIDs[n.ID] = true
		if s.Cluster(n.ClusterID) == nil {
			return fmt.Errorf("node %q belongs to a cluster that does not exist", n.Name)
		}
		if strings.TrimSpace(n.Name) == "" || len(n.Name) > 60 {
			return errors.New("node name must be 1-60 characters")
		}
		if !validHost(n.Host) {
			return fmt.Errorf("node %q: %q is not a valid host", n.Name, n.Host)
		}
		if n.Port < 1 || n.Port > 65535 {
			return fmt.Errorf("node %q: port out of range", n.Name)
		}
		if !validPin(n.Pin) {
			return fmt.Errorf("node %q: the pin must be base64 of 32 bytes (44 characters)", n.Name)
		}
		if n.SSHUser != "" && !userRe.MatchString(n.SSHUser) {
			return fmt.Errorf("node %q: %q is not a valid account name", n.Name, n.SSHUser)
		}
		if n.SSHPort < 0 || n.SSHPort > 65535 {
			return fmt.Errorf("node %q: SSH port out of range", n.Name)
		}
		if n.Unit != "" && !unitRe.MatchString(n.Unit) {
			return fmt.Errorf("node %q: the service name must look like gamec-edge or gamec-edge-<name>", n.Name)
		}
		if n.HostKey != "" && !hostKeyRe.MatchString(n.HostKey) {
			return fmt.Errorf("node %q: the host key fingerprint is not valid", n.Name)
		}
		if addrs[n.Addr()] {
			return fmt.Errorf("%s is listed twice; a node address belongs to one cluster only", n.Addr())
		}
		addrs[n.Addr()] = true
	}
	return nil
}

type Store struct {
	mu   sync.RWMutex
	path string
	st   State
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("state file: %w", err)
	}
	if err := s.st.Validate(); err != nil {
		return nil, fmt.Errorf("state file is inconsistent: %w", err)
	}
	return s, nil
}

func clone(s State) State {
	b, _ := json.Marshal(s)
	var out State
	json.Unmarshal(b, &out)
	return out
}

// Snapshot is a private copy; changing it changes nothing.
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.st)
}

// Mutate applies fn to a copy, validates the result and saves it atomically. If anything fails the stored
// state is left exactly as it was.
func (s *Store) Mutate(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.st)
	if err := fn(&next); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.Write(s.path, b, 0o600); err != nil {
		return err
	}
	s.st = next
	return nil
}
