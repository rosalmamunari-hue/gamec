// Package notify tells people when something needs them: it sends messages to a Telegram chat and to group
// robots (Feishu, DingTalk, WeCom, or any service that takes a JSON post), and it decides when to send, so
// that a problem is announced once, reminded about now and then, and its end is announced too.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Prefix starts every message. DingTalk robots can be set to accept only messages with a keyword: "告警".
const Prefix = "【gamec 告警】"

// Destination is one place messages go to.
type Destination struct {
	Kind   string `json:"kind"`              // telegram | feishu | dingtalk | wecom | json
	URL    string `json:"url,omitempty"`     // the robot's address (not for telegram)
	Token  string `json:"token,omitempty"`   // the Telegram bot token
	ChatID string `json:"chat_id,omitempty"` // the Telegram chat
}

var (
	telegramTokenRe = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,50}$`)
	chatIDRe        = regexp.MustCompile(`^-?[0-9]{1,20}$`)
	robotURLRe      = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[\x21-\x7e]{0,500}$`)
	kinds           = map[string]bool{"telegram": true, "feishu": true, "dingtalk": true, "wecom": true, "json": true}
)

// Validate says what is wrong with a destination, in words for the person who typed it.
func (d Destination) Validate() error {
	if !kinds[d.Kind] {
		return fmt.Errorf("不认识的通知方式 %q", d.Kind)
	}
	if d.Kind == "telegram" {
		if !telegramTokenRe.MatchString(d.Token) {
			return errors.New("Telegram 机器人令牌不对：应该像 123456789:AAH... 这样，是 BotFather 给你的那一串")
		}
		if !chatIDRe.MatchString(d.ChatID) {
			return errors.New("Telegram 的 Chat ID 应该是一串数字（群组的是负数）")
		}
		return nil
	}
	if !robotURLRe.MatchString(d.URL) {
		return errors.New("机器人的网址要以 https:// 开头，整串复制过来")
	}
	return nil
}

// Label is how a destination is shown, without its secret parts.
func (d Destination) Label() string {
	switch d.Kind {
	case "telegram":
		return "Telegram（Chat " + d.ChatID + "）"
	case "feishu":
		return "飞书群机器人"
	case "dingtalk":
		return "钉钉群机器人"
	case "wecom":
		return "企业微信群机器人"
	}
	if u, err := url.Parse(d.URL); err == nil {
		return "Webhook（" + u.Host + "）"
	}
	return "Webhook"
}

// Sender delivers messages. TelegramAPI is the Bot API's address (changed by tests).
type Sender struct {
	HTTP        *http.Client
	TelegramAPI string
}

func (s *Sender) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (s *Sender) api() string {
	if s.TelegramAPI != "" {
		return strings.TrimRight(s.TelegramAPI, "/")
	}
	return "https://api.telegram.org"
}

func (s *Sender) post(ctx context.Context, addr string, body any) ([]byte, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, scrub(err, addr)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return out, fmt.Errorf("HTTP %d: %s", resp.StatusCode, short(out))
	}
	return out, nil
}

// scrub keeps a bot token or robot key, which are in the address, out of error messages that get shown.
func scrub(err error, addr string) error {
	m := strings.ReplaceAll(err.Error(), addr, "(地址)")
	return errors.New(m)
}

func short(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Send delivers text to one destination.
func (s *Sender) Send(ctx context.Context, d Destination, text string) error {
	text = Prefix + text
	var body any
	switch d.Kind {
	case "telegram":
		out, err := s.post(ctx, s.api()+"/bot"+d.Token+"/sendMessage", map[string]any{"chat_id": d.ChatID, "text": text, "disable_web_page_preview": true})
		if err != nil {
			return err
		}
		var r struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		if json.Unmarshal(out, &r) == nil && !r.OK {
			return fmt.Errorf("Telegram: %s", r.Description)
		}
		return nil
	case "feishu":
		body = map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
	case "dingtalk", "wecom":
		body = map[string]any{"msgtype": "text", "text": map[string]string{"content": text}}
	default:
		body = map[string]any{"text": text}
	}
	out, err := s.post(ctx, d.URL, body)
	if err != nil {
		return err
	}
	// these robots answer 200 with an error code inside when they refuse a message
	var r struct {
		Code    *int   `json:"code"`
		ErrCode *int   `json:"errcode"`
		Msg     string `json:"msg"`
		ErrMsg  string `json:"errmsg"`
	}
	if json.Unmarshal(out, &r) == nil {
		if r.Code != nil && *r.Code != 0 {
			return fmt.Errorf("机器人拒绝了消息：%d %s", *r.Code, r.Msg)
		}
		if r.ErrCode != nil && *r.ErrCode != 0 {
			return fmt.Errorf("机器人拒绝了消息：%d %s", *r.ErrCode, r.ErrMsg)
		}
	}
	return nil
}

// SendAll delivers text everywhere and reports every failure.
func (s *Sender) SendAll(ctx context.Context, ds []Destination, text string) error {
	var errs []error
	for _, d := range ds {
		if err := s.Send(ctx, d, text); err != nil {
			errs = append(errs, fmt.Errorf("%s：%w", d.Label(), err))
		}
	}
	return errors.Join(errs...)
}

// Chat is a Telegram chat the bot has seen a message in.
type Chat struct {
	ID    string
	Title string
}

// TelegramChats lists the chats that recently wrote to the bot, so nobody has to dig out a chat id: write
// anything to the bot (or in a group it is in), then ask.
func (s *Sender) TelegramChats(ctx context.Context, token string) ([]Chat, error) {
	if !telegramTokenRe.MatchString(token) {
		return nil, errors.New("Telegram 机器人令牌不对")
	}
	out, err := s.post(ctx, s.api()+"/bot"+token+"/getUpdates", map[string]any{"limit": 50})
	if err != nil {
		return nil, err
	}
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      []struct {
			Message *struct {
				Chat struct {
					ID        int64  `json:"id"`
					Title     string `json:"title"`
					FirstName string `json:"first_name"`
					Username  string `json:"username"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, err
	}
	if !r.OK {
		return nil, fmt.Errorf("Telegram: %s", r.Description)
	}
	seen := map[string]bool{}
	var chats []Chat
	for i := len(r.Result) - 1; i >= 0; i-- { // newest first
		m := r.Result[i].Message
		if m == nil {
			continue
		}
		id := fmt.Sprint(m.Chat.ID)
		if seen[id] {
			continue
		}
		seen[id] = true
		title := m.Chat.Title
		if title == "" {
			title = strings.TrimSpace(m.Chat.FirstName + " @" + m.Chat.Username)
		}
		chats = append(chats, Chat{ID: id, Title: title})
	}
	return chats, nil
}
