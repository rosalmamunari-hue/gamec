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
	"gamec/panel/internal/notify"
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
	// NextRecords go at the dw2. name in front of each target (the names to read from next time).
	NextRecords []string `json:"next_records,omitempty"`
}

type Cluster struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Origin          string      `json:"origin"` // where its nodes forward to; informational
	ProxyV2         bool        `json:"proxy_v2,omitempty"` // nodes start each origin connection with a PROXY v2 header naming the player
	ProxyV1         bool        `json:"proxy_v1,omitempty"` // the same with a PROXY v1 (text) header
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

// ProxyHeader is the header new nodes send the origin: "v1", "v2" or "" (none).
func (c *Cluster) ProxyHeader() string {
	switch {
	case c.ProxyV2:
		return "v2"
	case c.ProxyV1:
		return "v1"
	}
	return ""
}

// Relay is a plain forwarder between some of a cluster's nodes and its origin, for when the nodes cannot (or
// should not) reach the origin directly:
//
//	player -> node -> relay -> origin (or the anti-DDoS front in front of it)
//
// It runs realip -pass: connections go on byte for byte, so the node's PROXY header still reaches the origin.
// Only the nodes that use it may connect; the panel keeps that list on the relay (nodectl relay-allow).
type Relay struct {
	ID        string    `json:"id"`
	ClusterID string    `json:"cluster_id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`   // where the nodes connect
	Target    string    `json:"target"` // host:port it passes connections to
	SSHPort   int       `json:"ssh_port,omitempty"`
	HostKey   string    `json:"host_key,omitempty"` // confirmed SHA256 fingerprint
	Notes     string    `json:"notes,omitempty"`
	Created   time.Time `json:"created"`
}

func (r *Relay) Addr() string { return net.JoinHostPort(r.Host, fmt.Sprint(r.Port)) }

// AsNode is the relay as the SSH management code sees a server: the same restricted account and checks.
func (r *Relay) AsNode() Node {
	return Node{ID: r.ID, ClusterID: r.ClusterID, Name: r.Name, Host: r.Host, Port: r.Port, SSHUser: "gamec-ops", SSHPort: r.SSHPort, HostKey: r.HostKey}
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
	RelayID       string    `json:"relay_id,omitempty"`       // the relay it forwards through; empty: straight to the origin
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

// Alerts says where to send word when something needs a person. It is kept here and not in the vault on
// purpose: the most important alert is "the vault is locked", which could not be sent if this were locked too.
type Alerts struct {
	To          []notify.Destination `json:"to"`
	RemindHours int                  `json:"remind_hours"` // repeat an unsolved problem this often; 0 = never
}

type State struct {
	Clusters []*Cluster `json:"clusters"`
	Nodes    []*Node    `json:"nodes"`
	Relays   []*Relay   `json:"relays,omitempty"`
	Egress   *Egress    `json:"egress,omitempty"`
	Alerts   *Alerts    `json:"alerts,omitempty"`
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

func (s State) Relay(id string) *Relay {
	for _, r := range s.Relays {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (s State) RelaysOf(clusterID string) []*Relay {
	var out []*Relay
	for _, r := range s.Relays {
		if r.ClusterID == clusterID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// NodesVia is the nodes that forward through a relay.
func (s State) NodesVia(relayID string) []*Node {
	var out []*Node
	for _, n := range s.Nodes {
		if relayID != "" && n.RelayID == relayID {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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
		if c.ProxyV1 && c.ProxyV2 {
			return fmt.Errorf("cluster %q: pick one PROXY header version", c.Name)
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
	if a := s.Alerts; a != nil {
		if len(a.To) > 10 {
			return errors.New("at most 10 alert destinations")
		}
		for _, d := range a.To {
			if err := d.Validate(); err != nil {
				return err
			}
		}
		if a.RemindHours < 0 || a.RemindHours > 168 {
			return errors.New("reminders must be 0-168 hours apart")
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
		if n.RelayID != "" {
			if r := s.Relay(n.RelayID); r == nil || r.ClusterID != n.ClusterID {
				return fmt.Errorf("node %q forwards through a relay that is not in its cluster", n.Name)
			}
		}
	}
	for _, r := range s.Relays {
		if !idRe.MatchString(r.ID) || nodeIDs[r.ID] {
			return fmt.Errorf("relay %q: bad or duplicate id", r.Name)
		}
		nodeIDs[r.ID] = true
		if s.Cluster(r.ClusterID) == nil {
			return fmt.Errorf("relay %q belongs to a cluster that does not exist", r.Name)
		}
		if strings.TrimSpace(r.Name) == "" || len(r.Name) > 60 {
			return errors.New("relay name must be 1-60 characters")
		}
		if net.ParseIP(r.Host) == nil {
			return fmt.Errorf("relay %q: %q is not an IP address", r.Name, r.Host)
		}
		if r.Port < 1 || r.Port > 65535 || r.SSHPort < 0 || r.SSHPort > 65535 {
			return fmt.Errorf("relay %q: port out of range", r.Name)
		}
		host, port, err := net.SplitHostPort(r.Target)
		p, perr := strconv.Atoi(port)
		if err != nil || perr != nil || p < 1 || p > 65535 || !validHost(host) {
			return fmt.Errorf("relay %q: the target %q is not host:port", r.Name, r.Target)
		}
		if r.HostKey != "" && !hostKeyRe.MatchString(r.HostKey) {
			return fmt.Errorf("relay %q: the host key fingerprint is not valid", r.Name)
		}
		if addrs[r.Addr()] {
			return fmt.Errorf("%s is used twice", r.Addr())
		}
		addrs[r.Addr()] = true
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
