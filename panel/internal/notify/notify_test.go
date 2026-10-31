package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const token = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"

func TestEachRobotGetsTheShapeItExpects(t *testing.T) {
	var got map[string]any
	var path string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		got = nil
		json.Unmarshal(b, &got)
		if strings.HasPrefix(r.URL.Path, "/bot") {
			io.WriteString(w, `{"ok":true}`)
			return
		}
		io.WriteString(w, `{"errcode":0,"code":0}`)
	}))
	defer srv.Close()
	s := &Sender{HTTP: srv.Client(), TelegramAPI: srv.URL}
	ctx := context.Background()
	check := func(d Destination, want string) {
		t.Helper()
		if err := s.Send(ctx, d, "hello"); err != nil {
			t.Fatalf("%s: %v", d.Kind, err)
		}
		b, _ := json.Marshal(got)
		if !strings.Contains(string(b), want) || !strings.Contains(string(b), "告警") {
			t.Errorf("%s sent %s", d.Kind, b)
		}
	}
	check(Destination{Kind: "feishu", URL: srv.URL + "/f"}, `"msg_type":"text"`)
	check(Destination{Kind: "dingtalk", URL: srv.URL + "/d"}, `"msgtype":"text"`)
	check(Destination{Kind: "wecom", URL: srv.URL + "/w"}, `"content":"【gamec 告警】hello"`)
	check(Destination{Kind: "json", URL: srv.URL + "/j"}, `"text":"【gamec 告警】hello"`)
	check(Destination{Kind: "telegram", Token: token, ChatID: "-1001"}, `"chat_id":"-1001"`)
	if path != "/bot"+token+"/sendMessage" {
		t.Errorf("telegram path %s", path)
	}
}

func TestARefusalInsideA200IsAnError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"errcode":310000,"errmsg":"keywords not in content"}`)
	}))
	defer srv.Close()
	s := &Sender{HTTP: srv.Client()}
	err := s.Send(context.Background(), Destination{Kind: "dingtalk", URL: srv.URL + "/x"}, "hi")
	if err == nil || !strings.Contains(err.Error(), "keywords") {
		t.Fatalf("%v", err)
	}
}

func TestErrorsDoNotShowTheBotToken(t *testing.T) {
	s := &Sender{TelegramAPI: "https://127.0.0.1:1", HTTP: &http.Client{Timeout: time.Second}}
	err := s.Send(context.Background(), Destination{Kind: "telegram", Token: token, ChatID: "1"}, "hi")
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("%v", err)
	}
}

func TestTelegramChatsListsWhoWroteToTheBot(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true,"result":[{"message":{"chat":{"id":42,"first_name":"Ann","username":"ann"}}},
			{"message":{"chat":{"id":-100777,"title":"ops"}}},{"message":{"chat":{"id":42,"first_name":"Ann"}}}]}`)
	}))
	defer srv.Close()
	s := &Sender{HTTP: srv.Client(), TelegramAPI: srv.URL}
	chats, err := s.TelegramChats(context.Background(), token)
	if err != nil || len(chats) != 2 || chats[0].ID != "42" || chats[1].Title != "ops" {
		t.Fatalf("%v %+v", err, chats)
	}
}

func TestDestinationsAreChecked(t *testing.T) {
	for _, d := range []Destination{
		{Kind: "telegram", Token: "nope", ChatID: "1"},
		{Kind: "telegram", Token: token, ChatID: "abc"},
		{Kind: "feishu", URL: "http://open.feishu.cn/x"},
		{Kind: "feishu", URL: "https://a b/"},
		{Kind: "sms", URL: "https://x/"},
	} {
		if d.Validate() == nil {
			t.Errorf("accepted %+v", d)
		}
	}
	if err := (Destination{Kind: "telegram", Token: token, ChatID: "-100123"}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestTheAlerterWaitsRemindsAndSaysWhenItIsOver(t *testing.T) {
	a := &Alerter{Remind: 6 * time.Hour}
	t0 := time.Unix(1_800_000_000, 0)
	down := Condition{Key: "n1", Text: "hk-1 挂了", Bad: true, After: 3 * time.Minute}
	if m := a.Update(t0, []Condition{down}); len(m) != 0 {
		t.Fatalf("too early: %v", m)
	}
	if m := a.Update(t0.Add(time.Minute), nil); len(m) != 0 {
		t.Fatalf("a blip that never got announced must not be 'recovered': %v", m)
	}
	a.Update(t0.Add(2*time.Minute), []Condition{down})
	m := a.Update(t0.Add(5*time.Minute), []Condition{down})
	if len(m) != 1 || !strings.Contains(m[0], "🔴") || !strings.Contains(m[0], "hk-1") {
		t.Fatalf("announce: %v", m)
	}
	if m := a.Update(t0.Add(6*time.Minute), []Condition{down}); len(m) != 0 {
		t.Fatalf("said twice: %v", m)
	}
	if m := a.Update(t0.Add(6*time.Hour+6*time.Minute), []Condition{down}); len(m) != 1 || !strings.Contains(m[0], "仍未解决") {
		t.Fatalf("remind: %v", m)
	}
	if m := a.Update(t0.Add(7*time.Hour), nil); len(m) != 1 || !strings.Contains(m[0], "已恢复") {
		t.Fatalf("recover: %v", m)
	}
}
