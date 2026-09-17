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
约三行。该修复**已合并进上游 main**（[PR #107](https://github.com/tailscale/tailcat/pull/107)，2026-09-13，
未改写，含我们在官方 main 上以 `i/o timeout` 失败、打上补丁即通过的 `TestServeExitNodeUDP`）；
不过它还没进任何上游发行版（最新 release 仍是 v0.6.0），所以本 fork 目前继续带着这段补丁 —— 等下一个上游 tag
之后就能回到官方版。

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

**注意**：本参数只影响**被转发**的 TCP；被转发的 UDP 见下一条。

### 5. `--forward-udp`：被转发的 UDP 也能经代理（先探测再决定）

**问题**：上一条只让 TCP 走代理，被转发的 UDP（QUIC、游戏、纯 UDP 服务）是**直连写死**的
（`net.DialUDP`），出口侧没有代理可走。

**改动**：新增 SOCKS5 的 UDP 客户端（`UDP ASSOCIATE` + 按 RFC1928 逐包封装），并在启动/首次用到时
**探测代理是否真的能承载 UDP**：`REP=0x07/0x02` 是确定性否定；`REP=0` 只算"声称支持"，还要发一个
STUN Binding 请求确认数据确实被中继（**字面 IP** 目标、校验 magic cookie 与事务 ID）。结论按代理端点缓存。

| `--forward-udp` | 行为 |
|---|---|
| `auto`（默认） | 第一次需要转发 UDP 时探测：能承载就经代理，不能就**回落直出并在日志里写明原因** |
| `on` | 必须经代理，探测不通过就**启动即失败**（不静默降级） |
| `off` | 不做 UDP 代理（等于以前的行为） |

```bash
tailcat --listen-port=41641 --forward-via-proxy=socks5://127.0.0.1:1080 --forward-udp=auto \
        serve --key=exit.key exit-node
# 环境变量（命令行优先）：TAILCAT_FORWARD_UDP
```

**前提**：代理服务端**必须支持 UDP** —— 只有 `socks5://` 能承载（HTTP 代理没有这个通道）。
**Surge 6.9.0 的 SOCKS5 入站不支持**（实测 `REP=0x07`），所以指向它时会判"不支持"并回落直出（与以前行为一致）；
**mihomo / sing-box / Xray 的 socks 入站原生支持**。

**判据**（三行日志，都能 grep）：

```
forward-udp: 代理 127.0.0.1:1080 支持 UDP（探针 172.238.7.124:3478 收到可校验应答（…））—— 被转发的 UDP 走 经代理
forward-udp: 代理 127.0.0.1:6153 不支持 UDP（UDP ASSOCIATE 被拒：不支持该命令（0x07，…））—— 被转发的 UDP 走 直出
udp forward -> 1.1.1.1:443 (via socks5://127.0.0.1:1080)      # 每条流自己说明路径
```

**代理不支持、可自证**的时候，日志里也会写 `direct(代理不支持 UDP：…)`；**探测本身失败**（连不上代理）
同样回落直出并把原因写进 `via`。排障可以用 `socks-udp-check.py`（见仓库 docs）。

### 7. `--bind-interface`：出口自己的流量绑物理网卡，绕开同机 TUN 型代理（v0.6.0-udp.13 起，默认关）

**问题**：出口主机上跑着 TUN 型代理（Surge 增强模式、clash/sing-box tun 等）时，代理把 utun 设为
全局默认路由，未绑定 socket 的 UDP 会被代理**用它自己的 socket 重发**——对端看到的源端口与 IP
都不是你的 ⇒ STUN 学到代理的映射、打洞永远建不起来，双方只能走中继。

**用法**：

```bash
tailcat --listen-port=41641 --bind-interface=physical serve --key=exit.key exit-node   # 自动探测绑定
tailcat --bind-interface=en0 serve …        # 钉死指定网卡（仍会先探测验证）
# 默认 off（什么都不做）；环境变量 TAILCAT_BIND_PROBE_DNS 可覆盖探针目标
```

**机制**：候选物理网卡逐个「绑定后向公共 anycast DNS（223.5.5.5/119.29.29.29/1.1.1.1）发探测」
验证——应答必须事务 ID 匹配**且**来源等于所查服务器（路由器劫持 :53 代答不算）；赢家落地后
macOS 用 `IP_BOUND_IF`、Linux 用 `SO_BINDTODEVICE`（需 CAP_NET_RAW）把打洞 UDP 与 DERP TCP
一起钉到该网卡。**全不通 = 保持现状不绑定**（绝不因此起不来）；换网/网卡拔插自动重评估
（30 秒粘性窗口防抖）。判据日志一行：
`bind-interface: physical → en0（目标=…:53,… 候选[en0:13ms] 解析=en0）`，其后 netcheck 的
`v4a` 应等于 `<真实公网IP>:<监听端口>`。

**平台差异**：macOS 完整支持（含多网卡时按探测 + netmon 解析选优）；Linux 的绑定目标取
netmon 的默认路由解析、探测只做验证门控（无重定向旋钮），且需 root/CAP_NET_RAW。
实测（macOS + Surge 增强模式开）：绑定后 `v4a` 从 `<代理IP>:<随机端口>` 变为
`114.242.60.128:<监听端口>`——蜂窝直连恢复。

### 6. 地址端点提示：出口把「直连候选」烤进地址（默认开启，v0.6.0-udp.11 起）

**问题**：客户端能多快走上直连，取决于它**什么时候知道出口的公网端点**。默认要等出口经 DERP 发来
端点通告（CallMeMaybe）——那一发不重发、还依赖出口的 STUN 已完成，丢一次整段会话可能一直挂在中继上。

**改动**：出口启动后自动观测自身网络（STUN 映射与观测次数、是否随目标变化、本机接口公网 IP、
UPnP/静态映射端口、外部端口与监听端口是否一致），把**验证过的稳定端点**作为可选字段编进打印的
地址里（CBOR 键 `e`，向后兼容——官方客户端/老版本会忽略该字段，老地址编码逐字节不变）。客户端
从第一个包起就有直连候选，探测与经 DERP 的注册**并发**。注册仍走 DERP（那是服务端认识客户端的
唯一途径），DERP 兜底完整保留。

三档自动判定（无需配置，启动日志一行判据 `endpoint-hint: 档=… v4a=… 端口自洽=… mappedPort=… mapvarydest=… 观测次数=… v6=…`）：

| 档 | 判据 | 处理 |
|---|---|---|
| ① 可信 | 显式外部端口（`--advertise-port`）/ UPnP·NAT-PMP·PCP 映射 / 本机网卡就是公网 IP | 写入地址 |
| ② 尽力 | 锥形 NAT 只有 STUN 临时映射；或全局 IPv6 | 写入并标注 |
| ③ 剔除 | 对称 NAT；或**钉了 `--listen-port` 而 STUN 端口对不上**（源端口被代理/中间层改写——此时 STUN 报的 IP 也可能是代理出口 IP） | 不写入，地址与官方形态一致 |

地址是**两段式**打印的：启动时先打不含提示的地址（不等异步的 STUN/UPnP），观测齐了再打一次带提示的
（`# 🐈 Server listening with endpoint hints: …`）并重写 `TAILCAT_ADDR_FILE`。**重启出口后提示串随最新观测
重算**——key 不变、老地址永远可用，但要拿新提示需重新分发地址。客户端持有 7 天时效，过期候选直接忽略。

```bash
# 关闭：地址回到无提示形态
tailcat --endpoint-hint=false serve --key=exit.key exit-node
# 手动追加候选（出口自己观测不到稳定端点、但你确切知道一个时）：
tailcat --endpoint=203.0.113.4:41641 serve --key=exit.key exit-node
```

---

### 8. 地址里的「能力标记」：让客户端知道这份出口能做什么（v0.6.0-udp.18 起）

官方 tailcat 的地址里没有任何「我是哪个构建」的信息，客户端只能连上去试。这份构建在
**serve / genkey 打印的地址**里多写两个字段：

- **能力位**：`UDP 转发` / `agent 网关`（App 的 codex、opencode 会话） / `固定端口+UPnP` / `转发经代理`；
- **构建号**：`-ldflags` 注入的版本（`v0.6.0-udp.18` 这种）；非发行版构建写成 `dev`，免得伪版本号撑长地址。

于是「官方版还是增强版」变成地址本身的事实，配套的 App（tier）据此把只有增强版才有的
功能入口置灰，点按给出解释。

```bash
# 打印出的地址里带标记（比无标记地址长约 15 个字符）
tailcat serve --key=exit.key exit-node

# 自己看一眼解出来的内容（官方二进制也能解析：未知字段被忽略）
tailcat parse "tcp…"
#   → "Caps": 15, "Build": "v0.6.0-udp.18"
```

**要知道的代价**：能力位参与地址编码 ⇒ 同一个 key 在**官方版与增强版下打印的地址串不同**。
升级到本版本后，客户端里要**重新粘贴一次地址**，标记才会生效（旧地址照旧能连，只是没有标记）。
想关掉标记（回到与官方逐字节一致的地址形态）目前没有开关——地址里带标记是这份构建的
默认行为，客户端靠它决定功能入口的可用性。

## 兼容性与混用

- **CLI 参数、地址格式、线协议**与官方 v0.6.0 完全兼容；新增参数都有默认值。
  地址新多出来的「能力标记」字段是**可选字段**：官方二进制解析带标记的地址正常（未知字段被忽略，
  实测官方 v0.6.0 `tailcat parse` 通过），我们解析官方地址也正常（得到「无标记」）。
- **客户端 ↔ 出口 可以混用**，但要注意：
  - 出口用**我们的构建** → UDP 正常，客户端什么都不用改；
  - 出口用**官方构建** → UDP 仍然不可用，此时需要客户端自己应对（例如 DNS 改走 TCP 承载，
    或干脆把出口换成我们的构建）。
- 平台：与官方相同的 linux/windows 目标，另加**官方 Release 没有的 macOS**
  （`darwin/arm64`、`darwin/amd64`）。

---

## 获取与使用

```bash
# 1) 取二进制：Releases 里按平台下载（curl/wget 下载的 macOS 产物解压即跑，
#    Go 链接器自动打了 ad-hoc 签名；浏览器下载的去 quarantine：
#    xattr -d com.apple.quarantine ./tailcat）
#    https://github.com/zhaoyswd/tailcat/releases  （tag 形如 v0.6.0-udp.N）

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

- 改动都基于官方源码，逐个提上游：UDP 转发（PR #107）**已合并进上游 main**（2026-09-13，未改写），其余（`--listen-port`、`--advertise-port`、
  固定端点通告与自动 UPnP、`--forward-via-proxy`、`--forward-udp`）也都是通用能力、可单独提交。
- 上游合并后会逐步从本 fork 去掉重复补丁；fork 只保留上游尚未合并的部分。
- 构建完全来自官方源码 + 上述补丁，没有其它来源。

### 依赖补丁怎么交付：**route A（已决策，2026-09-17）**

除本 fork 自己的补丁外，出口还需要一份 **`tailscale.com`（magicsock）依赖补丁** —— 「零 DERP 直连」的
服务端半边：出口要能接受并回应「netmap 里没有的 key」的 WireGuard 握手（tailcat 无控制面，出口就是靠
这次握手认识客户端的），并在 netmap 提升时保留学到的直连地址（`v0.6.0-udp.18` 起）。

**决定**：继续走 **route A** —— 补丁与脚本随仓库（`tools/modcache-patches/` +
`tools/apply-modcache-patches.sh`），被改的源码在 module cache 里，**CI 构建前显式打补丁 + 校验**
（`.github/workflows/binaries.yml` 的 "Apply modcache patches" 步；smoke 阶段再用 `strings` 验二进制里
真的带着补丁 —— 漏打补丁照样编译成功、只是能力静默消失，光看构建是否绿挡不住）。**不做** route B
（fork 一个 tailscale 仓 + `replace`）/ route C（内联进仓库），**等 route A 出问题再说**。
触发条件、代价与将来怎么做（含「被 `replace` 的那份 go.mod 的 `go` 指令要 ≤1.24」这个坑）记在
tier 仓库 `tools/tailcat/PATCHES.md` §2.10 的「交付路线决策」小节 —— 这里是同一决策在出口侧的落地说明。

补丁的**唯一真源在 tier 仓库**（`tools/tailcat/modcache-patches/0001-magicsock-direct-bootstrap.patch`），
本仓库 `tools/modcache-patches/` 下是副本：升级 tailscale 时先改 tier 那份、`patch --dry-run` 验两版
锚点，再同步过来。

### 这次构建基于哪个上游

`udp-binaries` 分支已经 **rebase 到上游 `main`**（`tailscale/tailcat`，2026-09-14 同步，基于 v0.6.0 之后的
4 个提交：`Server.Listen` 库 API、Windows 本地端口修复、我们那份 exit-node UDP 转发补丁、CHANGELOG 更新）。
所以本 fork 的产物 = 上游 main + 下面列出的少数增量（`--listen-port` / `--advertise-port` / 稳定公网端点通告与
自动 UPnP / `--forward-via-proxy` / `--forward-udp` / 地址端点提示），**UDP 转发那段已经回到上游代码**、不再是我们的补丁。
二进制里 `--version` 的 `v0.6.0-N-g<sha>` 就是这个基线的描述。

### 变更历史（相对官方 v0.6.0）

| 版本 | 变化 |
|---|---|
| `v0.6.0-udp.18`（待发） | 地址带**能力标记**（第 8 节）：能力位 + 构建号，客户端据此分辨增强版/官方版；`--files` 留空改为「家目录 + 可写」；agent 网关增 hub 级 `files/root`（把 files 宿主根下发给 App） |
| `v0.6.0-udp.13` | 新增 **`--bind-interface`（出口物理上行绑定，默认 off）**：第 7 节——`physical` 用 DNS anycast 探针逐候选验证后把出口自己的 socket（打洞 UDP + DERP TCP）绑到物理网卡，绕开同机 TUN 型代理的源端口改写 |
| `v0.6.0-udp.12` | 地址改**单次打印**：分档验证完成前不发地址，之后恰好一条（有提示打提示版，没有就打原版形态）——替代 udp.11 的两段式（两条 token 容易拿错）；`--endpoint-hint=false` 立即打原版 |
| `v0.6.0-udp.11` | 新增**地址端点提示**（第 6 节）：出口自动观测自身网络、按三档判定把直连候选编进地址（`--endpoint-hint=false` 关、`--endpoint=` 手动追加），客户端从首包起就有直连候选；格式向后兼容（官方客户端忽略新字段） |
| `v0.6.0-udp.10` | 分支 rebase 到上游 main（含已合并的 exit-node UDP 转发）：产物 = 上游 main + 本 fork 的 5 项增量，代码差异从"一堆补丁"降到 10 个文件；CI 改成只在打 tag / 手动触发时构建 |
| `v0.6.0-udp.9` | 新增 `--forward-udp`：被转发的 UDP 也能经代理（SOCKS5 UDP ASSOCIATE + 能力探测，`auto` 不支持则回落直出） |
| `v0.6.0-udp.8` | 代码结构整理（CLI 专用代码移出共享文件，功能同 .7），便于跟上游长期对齐 |
| `v0.6.0-udp.7` | 去掉 `--dns-doh`（改由客户端侧做 DNS 分流解析）与库里的 `Client.Rebind`；保留 `--listen-port`、`--advertise-port`、自动 UPnP 与固定端点通告、exit-node UDP 转发、`--forward-via-proxy` |
| `v0.6.0-udp.6` | 新增 `--forward-via-proxy` / `--dns-doh` |
| `v0.6.0-udp.4`–`.5` | 自动 UPnP 端口映射与固定公网端点通告；端口改成正式参数 |
| `v0.6.0-udp.1`–`.3` | exit-node UDP 转发；固定源端口 |

> 2026-09-11 文档更正：**官方 macOS 版通过 Homebrew 安装**（homebrew-core，`brew install tailcat`，实测 stable 0.6.0 bottled）；
> GitHub Release 只有 linux/windows。brew 那份不含本 fork 的出口侧增强。
