package web

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"rsc.io/qr"

	"gamec/panel/internal/auth"
)

// Accounts: everyone changes their own password here; administrators also add and remove accounts. Adding
// one shows its authenticator code once, as a QR code to scan, instead of a secret to copy from a terminal.

func (s *Server) routesAccount(mux *http.ServeMux) {
	mux.HandleFunc("GET /account", s.need(false, s.accountPage))
	mux.HandleFunc("POST /account/password", s.need(false, s.accountPassword))
	mux.HandleFunc("POST /account/users", s.need(true, s.accountAdd))
	mux.HandleFunc("POST /account/users/delete", s.need(true, s.accountDelete))
}

type accountData struct {
	Me       string
	Users    []auth.Info
	New      string       // the account just added
	NewQR    template.URL // its authenticator QR code, as a data: image
	NewKey   string       // the same secret, for typing in by hand
	MinChars int
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, sess *auth.Session, d accountData, flash, errMsg string, status int) {
	d.Me, d.MinChars = sess.User, auth.MinPassword
	if sess.Role == auth.Admin {
		d.Users = s.Users.List(s.now())
	}
	if flash == "" {
		flash = r.URL.Query().Get("ok")
	}
	title := "我的账号"
	if sess.Role == auth.Admin {
		title = "账号与密码"
	}
	s.render(w, r, "account.html", page{Title: title, Flash: flash, Error: errMsg, Data: d}, status)
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	s.renderAccount(w, r, sess, accountData{}, "", "", http.StatusOK)
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	next := r.FormValue("new")
	if next != r.FormValue("again") {
		s.renderAccount(w, r, sess, accountData{}, "", "两次输入的新密码不一样。", http.StatusBadRequest)
		return
	}
	if !s.lim.allow("password:"+sess.User, s.now()) {
		s.renderAccount(w, r, sess, accountData{}, "", "尝试次数过多，请等几分钟再试。", http.StatusTooManyRequests)
		return
	}
	err := s.Users.ChangePassword(sess.User, r.FormValue("current"), r.FormValue("code"), next, s.now())
	if err != nil {
		s.log(r, "password-change", "", false)
		msg := "当前密码或验证码不对。"
		if len(next) < auth.MinPassword {
			msg = fmt.Sprintf("新密码至少要 %d 个字符。", auth.MinPassword)
		} else if errors.Is(err, auth.ErrLocked) {
			msg = "账号暂时被锁定了，请过一会儿再试。"
		}
		s.renderAccount(w, r, sess, accountData{}, "", msg, http.StatusBadRequest)
		return
	}
	s.log(r, "password-change", "", true)
	// every session of this account ends, the one that changed it too: log in again with the new password
	s.Sessions.DestroyUser(sess.User)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.Secure})
	http.Redirect(w, r, "/login?ok="+url.QueryEscape("密码已修改，请用新密码登录。"), http.StatusSeeOther)
}

func (s *Server) accountAdd(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	name := strings.TrimSpace(r.FormValue("name"))
	role := auth.Role(r.FormValue("role"))
	pw := r.FormValue("password")
	secret, err := s.Users.Add(name, role, pw, s.now())
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "password must be"):
			msg = fmt.Sprintf("密码至少要 %d 个字符。", auth.MinPassword)
		case strings.Contains(msg, "already exists"):
			msg = "已经有这个账号了。"
		case strings.Contains(msg, "user name"):
			msg = "账号名要 1-40 个字符，不能有空格和特殊符号。"
		}
		s.renderAccount(w, r, sess, accountData{}, "", msg, http.StatusBadRequest)
		return
	}
	s.log(r, "user-add", fmt.Sprintf("user=%s role=%s", safe(name), role), true)
	d := accountData{New: name, NewKey: secret}
	if code, err := qr.Encode(auth.TOTPURI("gamec 面板", name, secret), qr.M); err == nil {
		code.Scale = 6
		d.NewQR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()))
	}
	s.renderAccount(w, r, sess, d, "账号已添加。", "", http.StatusOK)
}

func (s *Server) accountDelete(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	name := r.FormValue("name")
	if name == sess.User {
		s.renderAccount(w, r, sess, accountData{}, "", "不能删除自己正在用的账号。", http.StatusBadRequest)
		return
	}
	if err := s.Users.Delete(name); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "last administrator") {
			msg = "这是最后一个管理员，不能删除。"
		}
		s.renderAccount(w, r, sess, accountData{}, "", msg, http.StatusBadRequest)
		return
	}
	s.Sessions.DestroyUser(name)
	s.log(r, "user-delete", "user="+safe(name), true)
	http.Redirect(w, r, "/account?ok="+url.QueryEscape("账号「"+name+"」已删除，它已登录的地方也都退出了。"), http.StatusSeeOther)
}
