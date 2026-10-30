# Android 接入指南

给要把游戏盾 SDK 接进安卓游戏的同事。读完这一页应该就能接上；接不上先看最后的「排查」。

## 先弄清楚它做什么

```
游戏的 TCP 连接 ──▶ 127.0.0.1:端口（SDK 在本机开的代理）──▶ 加密隧道 ──▶ 边缘节点 ──▶ 游戏服务器
```

你的游戏**不再连真实服务器地址**，而是连 SDK 给你的本机端口。SDK 负责：找到可用节点、测速选最快的、建立加密连接、
节点连不上时自动重试和换节点。真实服务器地址配置在**节点上**，游戏里不需要也不应该再出现它。

## 开始前要向运维要两样东西

| 要什么 | 是什么 | 例子 |
|---|---|---|
| **DNS 名字** | 存放节点列表的 TXT 记录所在的名字 | `_gs.example.com` |
| **公钥** | 用来校验节点列表签名的公钥（Base64 一长串，`MFkw` 开头） | `MFkwEwYHKoZIzj0C...` |

这两样都不是机密，可以写在代码里。**不要**向运维要节点 IP，节点是 SDK 自己从 DNS 里查的，不用也不该写死。

## 第 1 步：加入依赖

1. 从发布页下载 `gamec-shield-vX.Y.Z.aar`，放进 `app/libs/`。
2. `app/build.gradle.kts`：

```kotlin
dependencies {
    implementation(files("libs/gamec-shield-vX.Y.Z.aar"))
}
```

- 最低 Android 10（API 29），因为需要系统自带的 TLS 1.3。低于这个版本的设备连不上，需要另想办法。
- AAR 没有其他依赖（需要 Kotlin 标准库，Kotlin 项目本来就有）。
- `INTERNET` 权限 AAR 里已经声明，会自动合并，不用再加。
- 不需要改 `networkSecurityConfig`，也不需要开 `usesCleartextTraffic`：游戏连本机代理的是普通 TCP，不走 HTTP 栈。
- 混淆（R8/ProGuard）不需要额外规则，SDK 里没有反射。

## 第 2 步：启动 SDK

在游戏**需要联网之前**启动一次，整个进程只要一个实例。建议在后台线程里调用。

```kotlin
object Shield {
    @Volatile private var client: ShieldClient? = null
    @Volatile var port: Int = 0
        private set

    @Synchronized
    fun start(app: Application) {
        if (client != null) return
        val discovery = DiscoveryConfig(
            name = "_gs.example.com",                    // 运维给的 DNS 名字
            publicKey = "MFkwEwYHKoZIzj0C...",           // 运维给的公钥
            deviceId = DeviceId.getOrCreate(app),        // 每个安装一个随机 ID，自动保存
            store = PrefsListStore(app),                 // 记住上次的节点列表，DNS 暂时不通时也能启动
        )
        val cfg = ShieldConfig(
            discovery = discovery,
            listener = object : ShieldListener {
                override fun onConnected(node: String) { Log.i("Shield", "已连接 $node") }
                override fun onRetrying(attempt: Int) { Log.w("Shield", "重连中，第 $attempt 次") }
                override fun onConnectFailed() { Log.e("Shield", "重试用尽，放弃") }
                override fun onConnectionLost(reason: String) { Log.w("Shield", "连接丢失：$reason") }
            },
        )
        val c = ShieldClient(cfg)
        port = c.start()          // 返回本机端口，之后游戏就连它
        client = c
    }

    @Synchronized
    fun stop() {
        client?.stop()
        client = null
    }
}
```

调用方：

```kotlin
Thread { Shield.start(application) }.start()   // 或协程 Dispatchers.IO
```

说明：
- `start()` 只是在本机开一个监听，**不会联网**，很快返回；节点列表在后台查。
- 一个 `ShieldClient` 只能 `start()` 一次。`stop()` 之后要用就新建一个。
- **监听器的回调不在主线程**。要更新界面请自己切回主线程。

## 第 3 步：让游戏连本机端口

把游戏里原来连服务器的地方，从「服务器地址:端口」改成 `127.0.0.1:Shield.port`：

```kotlin
val socket = Socket()
socket.connect(InetSocketAddress("127.0.0.1", Shield.port), 5000)
// 后面和原来一样读写
```

如果游戏用的是 Netty、自己的 NDK 网络库等，同样只是把目标地址改成这个本机地址。**协议本身一个字节都不用改**，
SDK 是透明转发的。

两个容易漏的地方：
- 游戏**自己**如果在 TCP 上又做了 TLS（连服务器时校验域名），现在目标变成了 `127.0.0.1`，域名校验会失败，
  需要把 SNI/期望主机名手动设成原来的服务器域名。
- 游戏里如果有「从服务器下发新地址再连」的逻辑，下发的地址也要走本机端口，否则会绕过盾。

## 第 4 步：处理断线重连（游戏侧必须有）

SDK 能做的：**新建连接时**，所有节点都连不上就在后台重试 15 秒（期间你的 `connect()` 看起来就是「连得慢」），
并且自动避开坏节点。

SDK **做不到**的：一条已经建立的连接，在节点掉线或手机切网（Wi-Fi 换 4G）时无缝续上。这种情况连接会断，
**游戏需要用自己原有的断线重连逻辑重新 `connect` 到 `127.0.0.1:同一个端口`**，那次重连会自动选到可用节点。

另外一个行为要知道：如果游戏**发了数据但 20 秒内没收到任何回应**，SDK 会主动关掉这条连接，让游戏尽快发现并重连
（否则死连接可能要几分钟才被系统发现）。如果你们的协议存在「客户端长时间只发不收」的场景，可以调大或关闭：

```kotlin
ShieldConfig(discovery = discovery, deadAfterUnansweredMs = 0)   // 0 = 关闭
```

## 常用配置

都写在 `ShieldConfig(...)` 里，不填就用默认值，一般不用动：

| 参数 | 默认 | 说明 |
|---|---|---|
| `connectRetryWindowMs` | 15000 | 连不上节点时，在后台重试多久才放弃。0 = 立刻失败 |
| `deadAfterUnansweredMs` | 20000 | 发了数据多久没回应就判定连接已死。0 = 关闭 |
| `connectTimeoutMs` | 3000 | 连单个节点的超时 |
| `localPort` | 0 | 本机端口，0 = 系统分配。需要固定端口时才设置 |

`DiscoveryConfig` 里还有 `dohProviders` / `dotServers`（查 DNS 用的公共服务器，都用 IP 地址）。默认带了 Google、
Cloudflare、阿里。**如果玩家主要在国内，国外的两家可能连不上，阿里 `223.5.5.5` 是国内可用的那个**；
需要的话可以只保留阿里的，或再加别的国内 DoH/DoT。

## 手机退到后台、被系统杀掉

SDK 的本机代理和你的游戏在同一个进程里：
- 进程被系统杀掉，代理随之消失，下次启动重新 `Shield.start()` 即可（节点列表有缓存，启动很快）。
- 进程还在但本机代理出了问题（连 `127.0.0.1:port` 时被拒绝），做法是 `Shield.stop()` 后再 `Shield.start()`。
- 厂商系统对后台的限制不一，这块**没有做过实机验证**，请在目标机型上实测。

## 怎么验证接对了

1. 装上包，打开游戏，确认能进游戏、能正常玩。
2. 看日志：`onConnected` 打出节点地址，说明走通了。
3. 开飞行模式再关掉：应该看到 `onRetrying`，网络恢复后自动连上。
4. 让运维把某个节点停掉：新建连接应该仍然成功（自动换了别的节点）。
5. 用抓包工具（比如在电脑上抓手机流量）确认**游戏没有再直连服务器 IP**。

## 排查

| 现象 | 最可能的原因 |
|---|---|
| 一直 `onRetrying`，最后 `onConnectFailed` | 手机查不到 DNS 记录，或节点全挂。先让运维确认记录有没有过期、节点是否在线；换一个网络（Wi-Fi/流量）试 |
| 一直连不上，但别的网络可以 | DNS 服务器被屏蔽。检查 `dohProviders` / `dotServers` 里有没有当地可用的 |
| 能连上，但立刻被断开 | token 被节点拒绝。检查手机时间是否正确（时间偏差超过约 5 分钟会被拒绝） |
| 玩一阵被断开，日志里有 `no response for 20s` | 触发了死连接检测。游戏确实没收到回应（网络问题），或者协议是长时间不回应的类型，需要调大 `deadAfterUnansweredMs` |
| `start()` 抛 `already started` | 同一个 `ShieldClient` 启动了两次，改成单例 |
| `start()` 抛端口占用 | 设置了固定 `localPort` 而端口被占，改回 0 |
| 游戏自己的 TLS 报域名不匹配 | 见第 3 步，手动设置 SNI/主机名 |

## 当前已知限制（接入前请知悉）

- **只支持 TCP**，不支持 UDP；也不能把多个游戏连接合并成一条隧道。
- **一组节点只转发到一个固定的源站**。游戏如果有多个区服、不同地址的服务器，需要运维为每个源站单独部署一组节点，
  并各用一个 DNS 名字，SDK 里用不同的 `name` 分别启动。
- 节点列表带有效期，运维需要定期更新；过期后 SDK 会拒绝使用，所有玩家会同时连不上。接入方不用处理，但请知道这件事。
- 只在 Android 15 模拟器上做过真机级测试；Android 10 到 14 和各厂商定制系统**没有实测**。
- 没有在中国大陆网络里测过。
- 节点本身是普通云主机，**不能单独扛大流量 DDoS**，需要配合云厂商的防护。
