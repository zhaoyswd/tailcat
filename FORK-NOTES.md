# 为什么用这份 tailcat 构建？和官方版有什么区别

这份构建（`github.com/zhaoyswd/tailcat` 的 Releases，版本号形如 `v0.6.0-udp.N`）是
**官方 v0.6.0 源码 + 少量针对「出口节点」的补丁**。CLI 用法与官方完全兼容，新增的都是可选参数，
不传就与官方行为一致（除了下面第 1、3 项是修正官方问题）。

---

## 你需要这份构建吗

如果你要跑**出口节点**（`tailcat serve … exit-node`），并且碰到下面任意一条，就需要：

- 客户端依赖 **DNS / QUIC / 其它 UDP 流量** —— 官方出口不转发 UDP，这些会全部失效（包含域名解析）；
- 你希望出口的**公网端口稳定**，好写防火墙规则或做端口映射；
- 你在 **macOS** 上跑出口 —— 官方 Release 只提供 linux/windows（官方文档里 macOS 走 Homebrew，版本也不含下面这些修正）；
- 你是**把 tailcat 嵌进自己程序**的开发者，需要在网络切换后就地重新选路。

只做「TCP 端口转发」这种最简单场景的话，官方版够用。

---

## 我们改了什么

### 1. 出口节点现在会转发 UDP（官方只转发 TCP）

**问题**：官方 `serve exit-node` 只注册 `OnTCPForward`。隧道内的 UDP 包到服务端后被丢弃，
客户端表现为「隧道通了、TCP 能用，但 UDP 有去无回」——最直接的后果是**域名解析不了**（DNS 走 UDP），
于是网页打不开；QUIC、游戏、部分即时通信同样受影响。

**实测**（用官方容器、同一把 key）：

| 服务端 | 同一个 UDP 端到端测试 |
|---|---|
| 官方 `serve exit-node` | ❌ 6 秒无应答（同通道的 TCP 连接正常，排除测试方法问题） |
| 加上这三行补丁的构建 | ✅ 0.00 秒收到 66 字节应答，服务端日志 `udp forward -> …` |

同一现象在真实链路上也复现过：客户端侧 102 个 UDP 上行包、**0 个下行包**。

**改动**：在 exit-node 分支补上 `OnUDPForward`（用官方库自带的 `ProxyPacketConns` 做双向转发），
约三行。已提上游 [PR #107](https://github.com/tailscale/tailcat/pull/107)（带一个
`TestServeExitNodeUDP`：在官方 main 上以 `i/o timeout` 失败、打上补丁即通过），合并后即可回到官方版。

### 2. 新增 `--listen-port`：把本地 UDP 端口固定下来（默认仍是随机）

**问题**：出口的 UDP 端口每次启动都随机。所有「按端口写的规则」都指望不上：
路由器端口映射、防火墙放行、本机代理分流，重启一次就全部失效。

**用法**：

```bash
tailcat --listen-port=41641 serve --key=exit.key exit-node
# 等价的环境变量（命令行优先）：
TAILCAT_LISTEN_PORT=41641 tailcat serve --key=exit.key exit-node
```

端口建议选在 `32768–60999`（Linux 临时端口池）**之外**，避免与系统自己分配的端口撞车。

### 3. 自动申请并向对端通告「稳定的公网端点」（默认开启）

**问题**：出口公布的地址来自 STUN 学到的 **NAT 临时映射**，每次重启都换一个（实测同一台机器
`38079 → 53108 → 55310 → 56016 …`，都落在临时端口池里）。对端缓存的直连地址随之作废，
需要重新打洞；在蜂窝这类本来就难打洞的网络上，成功率明显下降，表现为「有时能直连、有时只能走中继」。

**改动**：出口启动后会用 UPnP 向路由器申请一条
`外部 UDP 端口 → 本机 UDP 端口（--listen-port）` 的映射，每 30 分钟续期，
然后把「公网 IP : 该端口」连同原有端点一起通告给对端 —— 对端于是有一个**不随重启变化**的地址可连。

```
UPnP: 已建立端口映射 外部 UDP 41641 → 192.168.3.12:41641（对端将拿到公网IP:41641）
advertise: 通告固定公网端点 114.242.60.128:41641
```

- 路由器把**别的**外部端口转发到 `--listen-port` 时，用 `--advertise-port=<外部端口>` 声明；
- 不想要它动你的路由器：`TAILCAT_NO_UPNP=1`；
- 申请失败不会静默：日志会明确写原因，并提示你可以手动转发。

> 为什么不用 tailscale 生态里现成的 portmapper？它会先给设备「打分」
> （要求 `GetStatusInfo`、`GetExternalIPAddress` 有合理返回，且只在若干常见控制路径上探测），
> 遇到实现不规范的家用路由器会**直接放弃且不报错** —— 实测有一台路由器
> `GetExternalIPAddress` 返回空值、控制路径是私有的 `/ctrlu/<uuid>/…`，官方 portmapper 就此不用了，
> 外面看上去就是「UPnP 明明开着却没用」。我们这段代码只做两件必要的事（SSDP 发现 IGD + AddPortMapping），
> 失败会明确报错，并且不依赖外部实现的行为差异。

### 4. `--forward-via-proxy`：把「被转发的流量」交给上游代理，同时保留直连打洞

**问题**：出口主机上常同时跑着一个 TUN 型代理（Surge / Clash 等增强模式）做分流。两种做法都有代价：

| 做法 | 后果（实测） |
|---|---|
| 让代理接管路由（TUN 开） | 出口的 UDP 被代理用**自己的 socket** 重发 ⇒ STUN 学到的是代理的映射（实测 `v4a` 端口从 `41641` 变成随机的 `55557/65132`）⇒ 对端拿到的地址打不进来，客户端只能长期走 DERP 中继 |
| 让代理别碰（TUN 关） | 打洞恢复正常，但**被转发的用户流量也不再经代理** ⇒ 境外站点直连超时（日志里 `error proxying to …: connect: operation timed out`） |

**改动**：`--forward-via-proxy` 让转发的 TCP 显式经代理拨出，**tailcat 自己的打洞 socket 保持直连** —— 两个目标同时满足。
支持 `socks5://`（SOCKS5 CONNECT）与 `http://`（HTTP CONNECT）。

```bash
# 出口本机代理监听：Surge 的 *:6153(SOCKS5) / *:6152(HTTP)，Clash 的 mixed-port 同理
tailcat --listen-port=41641 --forward-via-proxy=socks5://127.0.0.1:6153 serve --key=exit.key exit-node
# 环境变量（命令行优先）：TAILCAT_FORWARD_PROXY
```

**效果 / 判据**（都可以自查）：

- 出口 `netcheck` 的 `v4a`/`v6a` 端口仍应**等于 `--listen-port`**（说明打洞 socket 没被代理改写）；
- 对端日志出现 `link: via=direct`（而不是 `via=derp`）；
- 出口日志里 `error proxying` 计数为 0；
- 代理侧能看到这些转发连接（Surge/Clash 的连接日志里按策略走，境内直连、境外走代理）。

**注意**：本参数只影响**被转发**的流量；隧道内的 UDP（QUIC 等）仍按原样由出口直连转发，
不适合走代理的 UDP 场景（多数代理不支持 UDP ASSOCIATE，实测 Surge 6.9.0 的本地 SOCKS5 直接回 `05 07`）。
DNS 建议在客户端侧做分流解析（客户端决定哪些域名走境外 DoH）。

---

## 兼容性与混用

- **CLI 参数、地址格式、线协议**与官方 v0.6.0 完全兼容；新增参数都有默认值。
- **客户端 ↔ 出口 可以混用**，但要注意：
  - 出口用**我们的构建** → UDP 正常，客户端什么都不用改；
  - 出口用**官方构建** → UDP 仍然不可用，此时需要客户端自己应对（例如 DNS 改走 TCP 承载，
    或干脆把出口换成我们的构建）。
- 平台：与官方相同的 linux/windows 目标，另加**官方 Release 没有的 macOS**
  （`darwin/arm64`、`darwin/amd64`）。

---

## 获取与使用

```bash
# 1) 取二进制：Releases 里按平台下载（macOS 下解压后可能需要去掉 quarantine 标记）
#    https://github.com/zhaoyswd/tailcat/releases  （tag 形如 v0.6.0-udp.N）
xattr -d com.apple.quarantine ./tailcat   # 仅 macOS

# 2) 生成一把固定区域的密钥（区域不固定会导致地址随选路漂移）
tailcat genkey --region=list                 # 看看有哪些区域
tailcat genkey --region=304 --fixed-region --key=exit.key

# 3) 启动出口（日志里的 tcp… 地址就是给客户端用的）
tailcat --verbose --listen-port=41641 serve --key=exit.key exit-node
```

- 路由器支持 UPnP 的话，端口映射会自动建好（看日志确认）；
- 不支持就手动在路由器上做一条 `UDP 41641 → 出口主机:41641` 的转发；
- 若出口主机前面还有一层 TUN 型代理（Clash/Surge 之类）：让代理的 **TUN 保持关闭**（或至少别劫持 tailcat 的 UDP），
  否则 STUN 学到的会是代理的地址、UPnP 也发现不了网关；转发流量若要经代理，用 `--forward-via-proxy=…`。

---

## 与上游的关系

- 改动都基于官方源码，逐个提上游：UDP 转发（PR #107）已在审，其余（`--listen-port`、`--advertise-port`、
  固定端点通告与自动 UPnP、`--forward-via-proxy`）也都是通用能力、可单独提交。
- 上游合并后会逐步从本 fork 去掉重复补丁；fork 只保留上游尚未合并的部分。
- 构建完全来自官方源码 + 上述补丁，没有其它来源。

### 变更历史（相对官方 v0.6.0）

| 版本 | 变化 |
|---|---|
| `v0.6.0-udp.8` | 代码结构整理（CLI 专用代码移出共享文件，功能同 .7），便于跟上游长期对齐 |
| `v0.6.0-udp.7` | 去掉 `--dns-doh`（改由客户端侧做 DNS 分流解析）与库里的 `Client.Rebind`；保留 `--listen-port`、`--advertise-port`、自动 UPnP 与固定端点通告、exit-node UDP 转发、`--forward-via-proxy` |
| `v0.6.0-udp.6` | 新增 `--forward-via-proxy` / `--dns-doh` |
| `v0.6.0-udp.4`–`.5` | 自动 UPnP 端口映射与固定公网端点通告；端口改成正式参数 |
| `v0.6.0-udp.1`–`.3` | exit-node UDP 转发；固定源端口 |

> 2026-09-11 文档更正：**官方 macOS 版通过 Homebrew 安装**（homebrew-core，`brew install tailcat`，实测 stable 0.6.0 bottled）；
> GitHub Release 只有 linux/windows。brew 那份不含本 fork 的出口侧增强。
