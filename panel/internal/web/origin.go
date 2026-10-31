package web

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gamec/panel/internal/auth"
	"gamec/panel/internal/store"
)

// The origin (the game server the nodes forward to) should accept connections from the nodes only: if
// anybody can reach it, anybody who learns its address can skip the nodes altogether. The panel cannot see
// the origin's firewall, but it can try to connect from where it stands, which is "somewhere on the
// internet". If that works, the origin is open to the world (unless the panel's own address is allowed).

type originResult struct {
	At   time.Time
	Open bool   // the panel could connect: it is reachable from the internet
	Err  string // why it could not connect (expected when the firewall is right)
}

type originChecks struct {
	mu  sync.Mutex
	res map[string]originResult // by cluster id
}

// DialOrigin opens a plain TCP connection to an origin; nil means a direct connection from this machine.
// It is deliberately not sent through the egress host: the question is whether the origin is open to the
// internet, and the panel is a machine on the internet.
type dialOriginFunc func(ctx context.Context, addr string) (net.Conn, error)

func (s *Server) originState(clusterID string) originResult {
	s.origins.mu.Lock()
	defer s.origins.mu.Unlock()
	return s.origins.res[clusterID]
}

// checkOrigin tries to connect to the cluster's origin and remembers the answer.
func (s *Server) checkOrigin(ctx context.Context, c *store.Cluster) originResult {
	r := originResult{At: s.now()}
	if c.Origin == "" {
		return r
	}
	dial := s.DialOrigin
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dial(cctx, c.Origin)
	if err == nil {
		conn.Close()
		r.Open = true
	} else {
		r.Err = err.Error()
		if strings.Contains(r.Err, "refused") {
			r.Err = "连接被拒绝"
		} else if strings.Contains(r.Err, "timeout") || strings.Contains(r.Err, "deadline") {
			r.Err = "连接超时（被防火墙挡住了）"
		}
	}
	s.origins.mu.Lock()
	if s.origins.res == nil {
		s.origins.res = map[string]originResult{}
	}
	s.origins.res[c.ID] = r
	s.origins.mu.Unlock()
	return r
}

// CheckOrigins checks every cluster's origin; the server runs it now and then.
func (s *Server) CheckOrigins(ctx context.Context) {
	for _, c := range s.Store.Snapshot().Clusters {
		if ctx.Err() != nil {
			return
		}
		s.checkOrigin(ctx, c)
	}
}

func (s *Server) originCheckNow(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id := r.PathValue("id")
	c := s.Store.Snapshot().Cluster(id)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	if c.Origin == "" {
		s.renderCluster(w, r, id, "", "先在「渠道设置」里填上源站地址。", http.StatusBadRequest)
		return
	}
	res := s.checkOrigin(r.Context(), c)
	s.log(r, "origin-check", "cluster="+c.Name+" open="+map[bool]string{true: "yes", false: "no"}[res.Open], true)
	if res.Open {
		s.renderCluster(w, r, id, "", "源站对公网开放：面板直接连上了 "+c.Origin+"。请把源站的防火墙改成只放行节点的 IP。", http.StatusOK)
		return
	}
	s.back(w, r, id, "源站从外面连不上（"+res.Err+"），这是对的：只有节点能连到它。")
}
