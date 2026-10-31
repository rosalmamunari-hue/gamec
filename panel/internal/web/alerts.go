package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gamec/panel/internal/audit"
	"gamec/panel/internal/auth"
	"gamec/panel/internal/notify"
	"gamec/panel/internal/store"
)

// Alerts: the panel watches for what needs a person and sends word to Telegram or a group robot, so that a
// locked vault or a dead node is not found out only when players complain.

func (s *Server) routesAlerts(mux *http.ServeMux) {
	mux.HandleFunc("GET /alerts", s.need(true, s.alertsPage))
	mux.HandleFunc("POST /alerts/add", s.need(true, s.alertsAdd))
	mux.HandleFunc("POST /alerts/{idx}/delete", s.need(true, s.alertsDelete))
	mux.HandleFunc("POST /alerts/test", s.need(true, s.alertsTest))
	mux.HandleFunc("POST /alerts/chats", s.need(true, s.alertsChats))
	mux.HandleFunc("POST /alerts/settings", s.need(true, s.alertsSettings))
}

func (s *Server) sender() *notify.Sender {
	if s.Notifier != nil {
		return s.Notifier
	}
	return &notify.Sender{}
}

func (s *Server) alerter() *notify.Alerter {
	s.alertOnce.Do(func() {
		if s.Alerter == nil {
			s.Alerter = &notify.Alerter{}
		}
	})
	return s.Alerter
}

// alertConditions is everything that is wrong right now and worth telling someone about.
func (s *Server) alertConditions() []notify.Condition {
	var cs []notify.Condition
	if s.Vault.Sealed() {
		cs = append(cs, notify.Condition{Key: "sealed", Bad: true, After: 3 * time.Minute,
			Text: "保险库上锁了（面板重启过？）。上锁期间名单不会续期，到期后玩家会全部连不上。请登录面板解锁。"})
	}
	st := s.Store.Snapshot()
	now := s.now()
	for _, c := range st.Clusters {
		if c.Last.At.IsZero() { // not in use yet: its setup checklist says what is missing
			continue
		}
		row := s.clusterRow(st, c)
		ch := "渠道「" + c.Name + "」"
		exp := time.Unix(c.Last.Exp, 0)
		switch {
		case exp.Before(now):
			cs = append(cs, notify.Condition{Key: c.ID + ":expired", Bad: true, Text: ch + "的名单已经过期，玩家找不到节点！请马上在面板里更新名单。"})
		case exp.Sub(now) < time.Duration(c.RenewBeforeDays)*24*time.Hour && (!c.AutoPublish || s.Vault.Sealed()):
			cs = append(cs, notify.Condition{Key: c.ID + ":expiring", Bad: true, Text: ch + "的名单" + row.Expiry + "就到期了，而自动续期没在运行。请手动更新名单。"})
		}
		if row.All > 0 && row.OK == 0 {
			cs = append(cs, notify.Condition{Key: c.ID + ":nonode", Bad: true, After: 3 * time.Minute, Text: ch + "没有任何节点通过检查，玩家可能连不上。"})
		}
		for _, n := range row.Nodes {
			if n.Status == "fail" || n.Status == "ejected" {
				cs = append(cs, notify.Condition{Key: "node:" + n.N.ID, After: 5 * time.Minute,
					Text: fmt.Sprintf("%s的节点 %s（%s）%s", ch, n.N.Name, n.N.Addr(), n.Detail)})
			}
		}
		if c.AutoPublish && strings.HasPrefix(row.Note, "自动更新名单失败") {
			cs = append(cs, notify.Condition{Key: c.ID + ":publish", Bad: true, After: 10 * time.Minute, Text: ch + row.Note})
		}
		if s.originState(c.ID).Open {
			cs = append(cs, notify.Condition{Key: c.ID + ":origin", Text: ch + "的源站 " + c.Origin + " 对公网开放，别人可以绕过节点直接打源站。"})
		}
	}
	return cs
}

// checkAlerts looks once and sends what has to be said.
func (s *Server) checkAlerts(ctx context.Context) {
	msgs := s.alerter().Update(s.now(), s.alertConditions())
	if len(msgs) == 0 {
		return
	}
	var to []notify.Destination
	if a := s.Store.Snapshot().Alerts; a != nil {
		to = a.To
	}
	for _, m := range msgs {
		sent := notify.Sent{At: s.now(), Text: m}
		if len(to) == 0 {
			sent.Err = "没有设置通知方式，没发出去"
		} else if err := s.sender().SendAll(ctx, to, m); err != nil {
			sent.Err = err.Error()
		}
		s.alerter().Record(sent)
		if s.Audit != nil {
			s.Audit.Append(audit.Entry{User: "system", Action: "alert", Detail: m + map[bool]string{true: "", false: " | 发送失败：" + sent.Err}[sent.Err == ""], OK: sent.Err == ""})
		}
	}
}

// RunBackground does the panel's own periodic work until ctx ends: alerts every minute, origin checks every
// quarter of an hour.
func (s *Server) RunBackground(ctx context.Context) {
	if a := s.Store.Snapshot().Alerts; a != nil {
		s.alerter().SetRemind(time.Duration(a.RemindHours) * time.Hour)
	} else {
		s.alerter().SetRemind(6 * time.Hour)
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastOrigin := time.Time{}
	for {
		if time.Since(lastOrigin) > 15*time.Minute {
			s.CheckOrigins(ctx)
			lastOrigin = time.Now()
		}
		s.checkAlerts(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ---------------------------------------------------------------- the page

type alertsData struct {
	To          []notify.Destination
	RemindHours int
	Recent      []notify.Sent
	Open        []notify.Condition
	Chats       []notify.Chat // after "find my chat"
	Token       string        // the token the chats were looked up with, to save with the chosen one
	Kind        string        // the tab to show
}

func (s *Server) renderAlerts(w http.ResponseWriter, r *http.Request, d alertsData, flash, errMsg string, status int) {
	d.RemindHours = 6
	if a := s.Store.Snapshot().Alerts; a != nil {
		d.To, d.RemindHours = a.To, a.RemindHours
	}
	d.Recent, d.Open = s.alerter().Recent(), s.alerter().Open()
	if d.Kind == "" {
		d.Kind = "robot"
	}
	if flash == "" {
		flash = r.URL.Query().Get("ok")
	}
	s.render(w, r, "alerts.html", page{Title: "告警通知", Lead: "出问题时（节点挂了、名单快到期、面板重启后没解锁…）自动发消息给你。",
		Flash: flash, Error: errMsg, Data: d}, status)
}

func (s *Server) alertsPage(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	s.renderAlerts(w, r, alertsData{}, "", "", http.StatusOK)
}

func destFromForm(r *http.Request) notify.Destination {
	return notify.Destination{Kind: r.FormValue("kind"), URL: strings.TrimSpace(r.FormValue("url")),
		Token: strings.TrimSpace(r.FormValue("token")), ChatID: strings.TrimSpace(r.FormValue("chat_id"))}
}

func (s *Server) alertsAdd(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	d := destFromForm(r)
	kind := map[bool]string{true: "telegram", false: "robot"}[d.Kind == "telegram"]
	if err := d.Validate(); err != nil {
		s.renderAlerts(w, r, alertsData{Kind: kind}, "", err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// a destination that cannot receive the test message would stay silent when it matters
	if err := s.sender().Send(ctx, d, "测试消息：面板以后会把告警发到这里。"); err != nil {
		s.log(r, "alerts-save", "add "+d.Kind+" failed the test: "+err.Error(), false)
		s.renderAlerts(w, r, alertsData{Kind: kind}, "", "发测试消息失败，没有保存："+err.Error(), http.StatusBadGateway)
		return
	}
	err := s.Store.Mutate(func(st *store.State) error {
		if st.Alerts == nil {
			st.Alerts = &store.Alerts{RemindHours: 6}
		}
		st.Alerts.To = append(st.Alerts.To, d)
		return nil
	})
	if err != nil {
		s.renderAlerts(w, r, alertsData{Kind: kind}, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "alerts-save", "add "+d.Label(), true)
	http.Redirect(w, r, "/alerts?ok="+url.QueryEscape("已添加。测试消息已经发出去了，去看看收到没有。"), http.StatusSeeOther)
}

func (s *Server) alertsDelete(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	idx, _ := strconv.Atoi(r.PathValue("idx"))
	label := r.FormValue("label")
	err := s.Store.Mutate(func(st *store.State) error {
		if st.Alerts == nil || idx < 0 || idx >= len(st.Alerts.To) || st.Alerts.To[idx].Label() != label {
			return fmt.Errorf("列表刚刚变过，没有删除任何东西。请刷新页面再试")
		}
		st.Alerts.To = append(st.Alerts.To[:idx], st.Alerts.To[idx+1:]...)
		return nil
	})
	if err != nil {
		s.renderAlerts(w, r, alertsData{}, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.log(r, "alerts-save", "remove "+safe(label), true)
	http.Redirect(w, r, "/alerts?ok="+url.QueryEscape("已删除。"), http.StatusSeeOther)
}

func (s *Server) alertsTest(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	a := s.Store.Snapshot().Alerts
	if a == nil || len(a.To) == 0 {
		s.renderAlerts(w, r, alertsData{}, "", "还没有设置任何通知方式。", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := s.sender().SendAll(ctx, a.To, "测试消息：告警通知是通的。")
	s.log(r, "alerts-test", fmt.Sprintf("to %d destinations", len(a.To)), err == nil)
	if err != nil {
		s.renderAlerts(w, r, alertsData{}, "", "有的没发出去："+err.Error(), http.StatusBadGateway)
		return
	}
	s.renderAlerts(w, r, alertsData{}, "测试消息已经发到所有地方，去看看收到没有。", "", http.StatusOK)
}

// alertsChats finds the chat id for a Telegram bot: the person writes to the bot, then presses the button.
func (s *Server) alertsChats(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	tok := strings.TrimSpace(r.FormValue("token"))
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	chats, err := s.sender().TelegramChats(ctx, tok)
	d := alertsData{Kind: "telegram", Token: tok, Chats: chats}
	if err != nil {
		s.renderAlerts(w, r, alertsData{Kind: "telegram"}, "", "问 Telegram 失败："+err.Error(), http.StatusBadGateway)
		return
	}
	if len(chats) == 0 {
		s.renderAlerts(w, r, d, "", "机器人还没收到任何消息。先在 Telegram 里给它发一句话（或在拉它进的群里发一句），再点一次。", http.StatusOK)
		return
	}
	s.renderAlerts(w, r, d, "", "", http.StatusOK)
}

func (s *Server) alertsSettings(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	h, err := strconv.Atoi(r.FormValue("remind_hours"))
	if err != nil || h < 0 || h > 168 {
		s.renderAlerts(w, r, alertsData{}, "", "提醒间隔要在 0 到 168 小时之间。", http.StatusBadRequest)
		return
	}
	if err := s.Store.Mutate(func(st *store.State) error {
		if st.Alerts == nil {
			st.Alerts = &store.Alerts{}
		}
		st.Alerts.RemindHours = h
		return nil
	}); err != nil {
		s.renderAlerts(w, r, alertsData{}, "", err.Error(), http.StatusBadRequest)
		return
	}
	s.alerter().SetRemind(time.Duration(h) * time.Hour)
	s.log(r, "alerts-save", fmt.Sprintf("remind every %d hours", h), true)
	http.Redirect(w, r, "/alerts?ok="+url.QueryEscape("已保存。"), http.StatusSeeOther)
}
