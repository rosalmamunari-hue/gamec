package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"gamec/panel/internal/store"
)

// Scheduler is the unattended part: every tick it looks at each cluster and publishes when the list has to
// change (a node went out or came in) or is close to expiring.
type Scheduler struct {
	Pub   *Publisher
	Mon   *Monitor
	Store *store.Store
	Now   func() time.Time

	// After a failed publish the next automatic try waits Backoff, doubling up to MaxBackoff.
	Backoff    time.Duration
	MaxBackoff time.Duration

	mu    sync.Mutex
	retry map[string]*retryState
	notes map[string]string
}

type retryState struct {
	next  time.Time
	delay time.Duration
}

func NewScheduler(pub *Publisher, mon *Monitor, st *store.Store) *Scheduler {
	return &Scheduler{Pub: pub, Mon: mon, Store: st, Backoff: 5 * time.Minute, MaxBackoff: time.Hour,
		retry: map[string]*retryState{}, notes: map[string]string{}}
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Note is the latest thing the scheduler wants an operator to know about a cluster.
func (s *Scheduler) Note(clusterID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.notes[clusterID]
}

func (s *Scheduler) setNote(id, n string) {
	s.mu.Lock()
	s.notes[id] = n
	s.mu.Unlock()
}

func keySet(key string) map[string]bool {
	out := map[string]bool{}
	if key == "" {
		return out
	}
	for _, k := range strings.Split(key, ",") {
		out[k] = true
	}
	return out
}

// Tick makes one round of decisions.
func (s *Scheduler) Tick(ctx context.Context) {
	if s.Pub.Vault.Sealed() {
		return // nothing can be signed; the dashboard says so
	}
	now := s.now()
	st := s.Store.Snapshot()
	for _, c := range st.Clusters {
		if !c.AutoPublish {
			s.setNote(c.ID, "这个渠道的自动维护是关着的")
			continue
		}
		active := st.Active(c.ID, now)
		dec := s.Mon.Decide(active, keySet(c.Last.NodesKey))
		if len(dec.Nodes) == 0 {
			s.setNote(c.ID, dec.Note)
			continue
		}
		wantKey := store.NodesKey(dec.Nodes)
		var why string
		switch {
		case wantKey != c.Last.NodesKey:
			why = "the set of nodes changed"
		case c.Last.Exp > 0 && time.Unix(c.Last.Exp, 0).Sub(now) < time.Duration(c.RenewBeforeDays)*24*time.Hour:
			why = fmt.Sprintf("the list expires in less than %d days", c.RenewBeforeDays)
		default:
			s.setNote(c.ID, dec.Note)
			continue
		}

		s.mu.Lock()
		rs := s.retry[c.ID]
		wait := rs != nil && now.Before(rs.next)
		s.mu.Unlock()
		if wait {
			continue
		}

		_, err := s.Pub.Publish(ctx, c.ID, dec.Nodes, "scheduler", "", why)
		s.mu.Lock()
		if err != nil {
			if rs == nil {
				rs = &retryState{delay: s.Backoff}
				s.retry[c.ID] = rs
			} else {
				rs.delay *= 2
				if rs.delay > s.MaxBackoff {
					rs.delay = s.MaxBackoff
				}
			}
			rs.next = now.Add(rs.delay)
			s.notes[c.ID] = fmt.Sprintf("自动更新名单失败（%s），%s后重试", err, humanDelay(rs.delay))
		} else {
			delete(s.retry, c.ID)
			s.notes[c.ID] = dec.Note
		}
		s.mu.Unlock()
	}
}

// Run ticks until ctx ends.
func (s *Scheduler) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func humanDelay(d time.Duration) string {
	if d >= time.Hour {
		return fmt.Sprintf("%d 小时", int(d.Hours()))
	}
	return fmt.Sprintf("%d 分钟", int(d.Minutes()))
}
