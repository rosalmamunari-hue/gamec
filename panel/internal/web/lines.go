package web

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gamec/panel/internal/notify"
	"gamec/panel/internal/store"
)

// Lines: a node can forward along several paths to the origin (-origin a,b: the anti-DDoS front, then a
// backup), and from v0.5.6 it reports each one in its stats. The panel adds them up per channel, so that a
// line going down shows on the pages and is sent as an alert, without anyone reading a node's log.

// lineView is one -origin address as the nodes of a channel see it.
type lineView struct {
	Addr     string
	Nodes    int       // nodes that reported it
	Down     int       // of them, how many cannot reach it now
	DownFrom time.Time // the earliest a node lost it, while it is down somewhere
	LastErr  string
	LastFail time.Time
	Fails    uint64 // failed tries, summed over the nodes since their start
	Used     uint64
}

func (l lineView) Status() string {
	switch {
	case l.Down == 0:
		return "ok"
	case l.Down < l.Nodes:
		return "partial"
	}
	return "down"
}

// linesFresh is how old a node's report may be and still count.
const linesFresh = 3 * time.Minute

// clusterLines adds up the latest reports of the channel's nodes, in the order the nodes list the addresses.
func (s *Server) clusterLines(st store.State, c *store.Cluster) []lineView {
	now := s.now()
	byAddr := map[string]*lineView{}
	rank := map[string]int{}
	for _, n := range st.NodesOf(c.ID) {
		t := s.traffic.get(n.ID)
		if t.Last == nil || now.Sub(t.LastAt) > linesFresh {
			continue
		}
		for i, o := range t.Last.Origins {
			l := byAddr[o.Addr]
			if l == nil {
				l = &lineView{Addr: o.Addr}
				byAddr[o.Addr] = l
				rank[o.Addr] = i
			}
			rank[o.Addr] = min(rank[o.Addr], i)
			l.Nodes++
			l.Fails += o.Fails
			l.Used += o.Used
			if o.LastFail != 0 {
				if f := time.Unix(o.LastFail, 0); f.After(l.LastFail) {
					l.LastFail, l.LastErr = f, o.LastErr
				}
			}
			if !o.Up {
				l.Down++
				if f := time.Unix(o.DownFrom, 0); o.DownFrom != 0 && (l.DownFrom.IsZero() || f.Before(l.DownFrom)) {
					l.DownFrom = f
				}
			}
		}
	}
	out := make([]lineView, 0, len(byAddr))
	for _, l := range byAddr {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Addr] != rank[out[j].Addr] {
			return rank[out[i].Addr] < rank[out[j].Addr]
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

// lineConditions are the alerts for a channel's lines: one per line some node cannot reach. With no other line
// working, players cannot get in at all.
func (s *Server) lineConditions(st store.State, c *store.Cluster) []notify.Condition {
	lines := s.clusterLines(st, c)
	var cs []notify.Condition
	for _, l := range lines {
		if l.Down == 0 {
			continue
		}
		var others []string
		for _, o := range lines {
			if o.Addr != l.Addr && o.Down < o.Nodes {
				others = append(others, o.Addr)
			}
		}
		text := fmt.Sprintf("渠道「%s」的节点连不上源站线路 %s（%d/%d 个节点）", c.Name, l.Addr, l.Down, l.Nodes)
		if !l.DownFrom.IsZero() {
			text += "，从 " + showClock(l.DownFrom) + " 开始"
		}
		bad := len(others) == 0
		if bad {
			text += "。没有能用的备用线路，经这些节点的玩家现在连不上。"
		} else {
			text += "。节点已经改走 " + strings.Join(others, "、") + "，玩家不受影响。"
		}
		if l.LastErr != "" {
			text += "（" + friendlyDialErr(l.LastErr) + "）"
		}
		cs = append(cs, notify.Condition{Key: c.ID + ":line:" + l.Addr, Bad: bad, Text: text})
	}
	return cs
}

// friendlyDialErr says a node's dial error in words.
func friendlyDialErr(e string) string {
	switch {
	case strings.Contains(e, "timeout"):
		return "连接超时：线路不通，或者对方没有回应"
	case strings.Contains(e, "refused"):
		return "连接被拒绝：对方端口没在监听"
	case strings.Contains(e, "no route") || strings.Contains(e, "unreachable"):
		return "网络不通"
	case strings.Contains(e, "reset"):
		return "连接被重置"
	}
	return e
}
