package notify

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Condition is a problem as it stands right now. Key identifies it across checks; Text says it.
type Condition struct {
	Key   string
	Text  string
	Bad   bool          // players are or soon will be affected (otherwise: something to look at)
	After time.Duration // how long it must last before anyone is told (rides out short blips)
}

// Alerter remembers which problems are open and decides what to say about them.
type Alerter struct {
	Remind time.Duration // say again about a problem that is still there after this long; 0 = never

	mu   sync.Mutex
	open map[string]*openProblem
	log  []Sent
}

type openProblem struct {
	c         Condition
	since     time.Time
	announced bool
	lastSent  time.Time
}

// Sent is a message the alerter produced, kept for the panel to show.
type Sent struct {
	At   time.Time
	Text string
	Err  string // why it could not be delivered, if it could not
}

// Update compares what is wrong now with what was wrong before and returns the messages to send.
func (a *Alerter) Update(now time.Time, conds []Condition) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.open == nil {
		a.open = map[string]*openProblem{}
	}
	var out []string
	current := map[string]bool{}
	for _, c := range conds {
		current[c.Key] = true
		p := a.open[c.Key]
		if p == nil {
			p = &openProblem{c: c, since: now}
			a.open[c.Key] = p
		}
		p.c.Text, p.c.Bad = c.Text, c.Bad
		switch {
		case !p.announced && now.Sub(p.since) >= c.After:
			p.announced, p.lastSent = true, now
			out = append(out, mark(c.Bad)+c.Text)
		case p.announced && a.Remind > 0 && now.Sub(p.lastSent) >= a.Remind:
			p.lastSent = now
			out = append(out, mark(c.Bad)+"仍未解决（已持续 "+lasting(now.Sub(p.since))+"）："+c.Text)
		}
	}
	var gone []string
	for k := range a.open {
		if !current[k] {
			gone = append(gone, k)
		}
	}
	sort.Strings(gone)
	for _, k := range gone {
		p := a.open[k]
		delete(a.open, k)
		if p.announced {
			out = append(out, "✅ 已恢复（持续了 "+lasting(now.Sub(p.since))+"）："+p.c.Text)
		}
	}
	return out
}

func mark(bad bool) string {
	if bad {
		return "🔴 "
	}
	return "🟡 "
}

func lasting(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d 小时", int(d.Hours()))
	}
	return fmt.Sprintf("%d 天", int(d.Hours()/24))
}

// SetRemind changes how often an unsolved problem is repeated.
func (a *Alerter) SetRemind(d time.Duration) {
	a.mu.Lock()
	a.Remind = d
	a.mu.Unlock()
}

// Record keeps a sent message for the panel's "recent alerts" list (the newest 30).
func (a *Alerter) Record(s Sent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.log = append(a.log, s)
	if len(a.log) > 30 {
		a.log = a.log[len(a.log)-30:]
	}
}

// Recent returns the kept messages, newest first.
func (a *Alerter) Recent() []Sent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Sent, len(a.log))
	for i, s := range a.log {
		out[len(a.log)-1-i] = s
	}
	return out
}

// Open is how many problems are open right now, announced or not.
func (a *Alerter) Open() []Condition {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Condition
	for _, p := range a.open {
		out = append(out, p.c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
