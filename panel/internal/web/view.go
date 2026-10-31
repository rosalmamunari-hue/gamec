package web

import (
	"strings"
	"time"

	"gamec/panel/internal/engine"
)

// Words and colours the pages use for states, kept in one place so every page says the same thing.

func statusColor(status string) string {
	switch status {
	case "ok":
		return "green"
	case "fail", "ejected":
		return "red"
	case "paused":
		return "yellow"
	}
	return "secondary"
}

func statusWord(status string) string {
	switch status {
	case "ok":
		return "正常"
	case "fail":
		return "检查失败"
	case "ejected":
		return "已拿掉"
	case "paused":
		return "暂停中"
	case "off":
		return "已停用"
	}
	return "等待检查"
}

// levelColor is the Tabler colour of a channel's overall state.
func levelColor(level string) string {
	switch level {
	case "ok":
		return "success"
	case "warn":
		return "warning"
	case "bad":
		return "danger"
	}
	return "primary"
}

// probeProblem says in plain words which part of a probe failed.
func probeProblem(r engine.ProbeResult) string {
	e := r.Err
	switch {
	case e == "":
		if r.TokenOK && !r.RelayOK {
			return "节点连不上源站（游戏服务器）"
		}
		return "原因不明"
	case strings.HasPrefix(e, "connect: "):
		d := strings.TrimPrefix(e, "connect: ")
		switch {
		case strings.Contains(d, "pin mismatch"):
			return "证书指纹对不上（节点重装过，或者有人冒充）"
		case strings.Contains(d, "refused"):
			return "端口没开（节点程序没在运行，或者端口填错了）"
		case strings.Contains(d, "timeout"), strings.Contains(d, "deadline"):
			return "连接超时（服务器关机、防火墙挡住或网络不通）"
		}
		return "连不上节点：" + d
	case strings.HasPrefix(e, "token: "):
		return "节点不肯发令牌：" + strings.TrimPrefix(e, "token: ")
	case strings.HasPrefix(e, "origin: "):
		return "节点连不上源站：" + strings.TrimPrefix(e, "origin: ")
	}
	return e
}

// actionWords turns the audit log's action codes into words. The code is still shown next to it.
var actionWords = map[string]string{
	"login": "登录", "login-failed": "登录失败", "login-throttled": "登录被限流", "logout": "退出登录",
	"csrf-rejected": "拒绝了来路不明的请求", "forbidden": "没有权限的操作", "start": "面板启动",
	"unseal": "解锁保险库", "cluster-create": "创建渠道", "cluster-edit": "修改渠道设置",
	"node-add": "加入节点", "node-edit": "修改节点", "node-delete": "删除节点", "node-enable": "启用/停用节点",
	"node-pause": "暂停节点", "node-resume": "取消暂停", "node-install-script": "生成节点安装脚本", "auto-publish": "开关自动维护",
	"seal-list": "开关加密名单", "publish": "更新名单", "target-add": "加入域名", "target-edit": "修改域名",
	"target-delete": "移除域名", "secret-set": "保存授权", "secret-test": "测试授权",
	"hostkey-trust": "确认服务器指纹", "ssh-settings": "修改远程登录设置", "ssh-check": "查看节点状态",
	"ssh-start": "启动节点程序", "ssh-stop": "停止节点程序", "ssh-restart": "重启节点程序",
	"ssh-stop-for": "临时停止节点程序", "ssh-upgrade": "升级节点", "upgrade-all": "升级全部节点",
	"ssh-script": "生成服务器准备脚本", "ssh-keygen": "生成面板密钥", "get-secret": "读取密钥（命令行）",
	"egress-set": "设置出口中转", "egress-remove": "取消出口中转", "egress-hostkey": "确认中转机指纹",
	"egress-script": "生成中转机脚本", "egress-test": "测试出口中转", "import-cluster": "导入渠道",
	"set-secret": "写入密钥（命令行）", "alerts-save": "修改告警设置", "alerts-test": "发送测试告警",
	"alert": "发出告警", "origin-check": "检查源站", "user-add": "添加账号", "user-delete": "删除账号",
	"password-change": "修改密码",
}

func actionWord(code string) string {
	if w, ok := actionWords[code]; ok {
		return w
	}
	return code
}

func providerName(p string) string {
	switch p {
	case "cloudflare":
		return "Cloudflare"
	case "spaceship":
		return "Spaceship"
	case "aliyun":
		return "阿里云"
	case "manual":
		return "手动"
	}
	return p
}

func daysLeft(now time.Time, exp int64) int {
	d := time.Unix(exp, 0).Sub(now)
	if d <= 0 {
		return 0
	}
	return int(d.Hours() / 24)
}

// dict builds a map for passing several values to a sub-template.
func dict(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}
