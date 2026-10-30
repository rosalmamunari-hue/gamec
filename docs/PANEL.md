# 控制面板

面板做三件事，全部自动：**盯着节点**（定时探测）、**维护节点列表**（坏的摘掉、好的加上）、**把签名好的列表发布到 DNS 并在到期前续期**。
手动的部分只有：加节点、第一次发布、故障时看一眼。

```
 节点（多台）◀── 定时探测 ──┐
                             │
 面板 ──签名──▶ DNS（Spaceship / Cloudflare / 阿里云 / 手动）──▶ App 查到列表
   │
   ├─ 加密保险库：签名私钥、令牌密钥、DNS 凭据
   └─ 审计日志：每个操作都记，防篡改
```

## 先说清楚它的风险

面板拿着**签名私钥**和 **DNS 凭据**。谁控制了面板，谁就能把所有玩家引到假节点。所以：

| 防护 | 做法 |
|---|---|
| 登录 | 用户名加密码（argon2id）加**二次验证码（TOTP）**，缺一不可；5 次失败锁 15 分钟；每个 IP 10 分钟最多 10 次 |
| 会话 | 空闲 30 分钟、最长 12 小时失效；Cookie 为 HttpOnly + SameSite=Strict（HTTPS 下加 Secure） |
| 改动 | 每个修改都要 CSRF 令牌，并且拒绝来自其他站点的请求；只读账号一律改不了 |
| 保险库 | 私钥、密钥、凭据加密存放（scrypt + AES-256-GCM）。**口令不落盘**，面板重启后是"封存"状态，管理员在网页里输入口令才打开。磁盘或备份泄露不会泄露密钥 |
| 凭据只写 | 网页上能设置、替换凭据，**永远读不出来**；令牌密钥只在创建集群时显示一次 |
| 审计 | 每个操作（含失败、被拒的）记下谁、从哪个 IP、做了什么；每条带前一条的哈希，删改调换都会被发现（`panel verify-audit`） |
| 页面 | 严格的内容安全策略，页面里没有内联脚本和样式；用户输入全部转义 |

**这些防不住的**：面板所在的机器被完全攻破（攻击者可以在内存里拿到已解封的密钥）、管理员的电脑和验证码设备一起丢失。
所以请：面板单独一台机器、不放节点上、只开 HTTPS、尽量加 IP 白名单或放在 VPN 后面、不用的时候可以点"封存"（重启服务即封存）。

## 多集群（渠道服分开）

一个**集群** = 一个渠道：自己的源站、DNS 名字、**签名密钥**、**令牌密钥**、节点。集群之间完全隔离：

- 渠道 A 的包里写渠道 A 的 DNS 名字和公钥，查不到也验不了渠道 B 的列表（测试已覆盖）。
- 渠道 A 的密钥泄露，渠道 B 不受影响。
- 一个地址（IP:端口）只能属于一个集群；同一台服务器可以跑多个实例（不同端口），各属于不同集群。
- 一个渠道的节点变化只会重新发布这个渠道。

每个集群的每个节点实例，用的是**这个集群自己的令牌密钥**（节点的 `-secret`）和自己的源站（`-origin`）。

## 部署

### 1. 准备一台机器

单独的一台，不要放节点上。Linux，Go 编译好的单个可执行文件即可（`panel`），不需要数据库。

```sh
cd panel && go build -o panel .
```

### 2. 初始化

```sh
export PANEL_DATA=/var/lib/gamec-panel      # 数据目录，建议权限 700
./panel init                                # 设保险库口令（至少 12 位）。写下来，丢了密钥就找不回
./panel adduser -name alice -role admin     # 设密码，并拿到验证码密钥，加到手机的验证器 App 里
./panel adduser -name bob   -role viewer    # 只读账号，随意加
```

### 3. 把现有集群导进来（不换密钥，现有 App 不用动）

```sh
./panel import-cluster -name official -origin 203.0.113.5:10443 \
    -provider spaceship -zone example.com -dns-name _gs.example.com -cred-ref main \
    -signing-key-file list.key -node-secret-file secret.txt
```

导入完立刻把 `list.key` 和 `secret.txt` 从这台机器和你的电脑上安全保管（至少别留在面板这台机器上）。
公钥和之前一样，所以已经发出去的 App 照常工作。

新集群也可以直接在网页上创建，会生成**全新**的密钥。

### 4. 设置 DNS 凭据

在网页 **DNS credentials** 里填，或命令行：

```sh
echo -n "$TOKEN" | ./panel set-secret -name dns/main/api_token
```

| 服务商 | 需要的字段 | 建议权限 |
|---|---|---|
| Cloudflare | `api_token` | 只给这一个域名的"DNS 编辑" |
| Spaceship | `api_key`、`api_secret` | 只开 DNS 读写 |
| 阿里云 | `access_key_id`、`access_key_secret` | 用子账号，只授 Alidns 权限 |
| 手动 | 不需要 | 面板生成记录，你自己去粘贴 |

### 5. 运行（systemd + HTTPS 反向代理）

`/etc/systemd/system/gamec-panel.service`：

```ini
[Unit]
Description=gamec control panel
After=network-online.target

[Service]
User=gamec-panel
Environment=PANEL_DATA=/var/lib/gamec-panel
ExecStart=/opt/gamec-panel/panel serve -listen 127.0.0.1:8080 -secure -trust-proxy
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/gamec-panel
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

用 Caddy 做 HTTPS（自动申请证书，需要一个面板用的域名，比如 `panel.example.com` 指向这台机器）：

```
panel.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

- `-secure`：告诉面板外面是 HTTPS（Cookie 加 Secure，发 HSTS）。
- `-trust-proxy`：从 `X-Forwarded-For` 取客户端 IP（审计日志和限速用）。**只有面板只能通过 Caddy 访问时才开**，所以面板务必只监听 127.0.0.1。
- 启动后保险库是封存的：浏览器登录，在 **Unseal** 页输入口令。每次重启都要做一次。
  （不想手动解封可以用 `-unseal-at-start` 加 `PANEL_PASSPHRASE_FILE`，但这样口令就在服务器上有一份文件，安全性明显下降，不建议。）

### 6. 备份

备份 `PANEL_DATA` 整个目录（`vault.json`、`state.json`、`users.json`、`audit.log`）。`vault.json` 是加密的，
备份泄露不等于密钥泄露，但**口令必须另外安全保管**。

## 日常使用

**第一次发布**：集群页 → 加节点 → 等节点显示"ok" → **Sign and publish now**。发布成功后自动发布才可以打开。

**自动发布规则**（每 30 秒检查一次）：

| 情况 | 动作 |
|---|---|
| 一个节点**连续 5 次探测失败**（约 5 分钟） | 从列表里摘掉，重新签名发布 |
| 摘掉的节点**连续 5 次探测成功** | 加回来 |
| 新加的节点 | 连续 5 次探测成功才会被公布 |
| 列表离过期不到 N 天（默认 10） | 重新签名发布 |
| **所有节点同时失败** | **不改动**。这更可能是面板这边的网络问题，不是所有节点同时挂了 |
| 没有任何节点可用 | **绝不发布空列表** |
| 发布失败 | 5、10、20、40、60 分钟逐步退避重试，并在页面上提示 |

**测试节点上下线**：节点行的 **Pause (min)** 把节点临时摘掉 N 分钟，到点自动恢复；**Switch off** 是一直摘掉直到你打开。
这只是把节点从列表里去掉，**不会**真的停掉节点上的程序。要真的停，登录那台服务器 `systemctl stop gamec-edge`。

**发布之后**面板会通过公共 DoH 把记录读回来验签，页面显示"verified"。DNS 传播需要时间，最长等 3 分钟。

## 目前没有做、或者没有验证的

请不要当它已经做完了：

1. **Spaceship 和阿里云的适配器只对着我写的模拟服务器测过。** 接口格式来自公开文档和第三方代码，不是官方原文，也没有用真实账号验证。
   Cloudflare 同样只对着模拟服务器测过，但它的接口最常见、我最有把握。
   **正式用之前，请先用一个临时的测试记录名（比如 `_gs-test`）在真实账号上试一次。**
2. **不能登录服务器操作节点**：没有"在面板里重启节点、看节点日志、升级节点版本、新增节点自动部署"。目前加节点只是登记地址和公钥，节点程序要自己部署。（SSH 管理是下一步。）
3. 探测只从面板所在机器发出。看不到"从国内到节点是否可达"。
4. 会话保存在内存里，面板重启后所有人需要重新登录。
5. 只有一个面板实例，面板自己挂了不会告警（节点和已发布的列表不受影响，只是不再自动维护）。建议给面板的 `/login` 页加一个外部可用性监控。
6. 邮件、短信、IM 告警还没有。
7. 没有在真实浏览器里手点过；界面是用请求级测试验证的，样式可能需要调整。

## 命令速查

```
panel init                          创建保险库
panel adduser -name N -role admin   加用户（admin 或 viewer）
panel import-cluster ...            导入已有的签名密钥和令牌密钥
panel set-secret -name dns/main/api_token    存凭据
panel get-secret -name cluster/<id>/node_secret    读密钥（会写审计）
panel verify-audit                  检查审计日志是否被改过
panel serve [-listen A] [-secure] [-trust-proxy] [-probe-interval 1m] [-tick 30s]
```
