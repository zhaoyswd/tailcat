//go:build !cshared

// endpointhint_cli.go — 出口侧「端点提示」：分档采集、判定、两段式地址打印（CLI / 上游向）。
//
// 背景（openspec change `direct-first-endpoint-hint`）：把出口的稳定公网端点作为
// 提示烤进地址，客户端从建连第一刻起就有直连候选。出口侧要做三件事：
//  1. 采集自身网络观测（STUN 映射与观测次数、是否随目标变化、本机接口公网 IP、
//     UPnP 映射端口、外部端口与监听端口是否一致）；
//  2. 按三档判定：① 可信（本机即公网 / 有路由器映射 / 显式声明外部端口）→ 写入；
//     ② 尽力而为（锥形 NAT 的 STUN 临时映射 / 全局 IPv6）→ 写入并标注；
//     ③ 不可信（对称 NAT、源端口被中间层改写）→ 不写入；
//  3. 单次地址打印（2026-09-15 起替代两段式）：分档验证完成前不发任何地址，
//     然后 announce 一次最终地址——有提示打提示版，没有就打原版形态；stderr 行、
//     --json 与 TAILCAT_ADDR_FILE 都由共享侧的 announce 闭包统一负责。
//
// 诚实边界：本地只能判「映射是否可信」，判不了「入站过滤是否开放」——最终裁决
// 是客户端的有界探测（探测与会合并发，全错时代价只是几个无效探测包）。
package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/tsaddr"
)

// endpointHintPollInterval / endpointHintDeadline 控制第二阶段等多久：
// netcheck 与 UPnP 都在 Start 之后异步进行，全量给 12s；STUN 结果一到、且
// （拿到映射 或 又等了 6s）就提前收——UPnP 建立映射通常在启动后几秒内。
const (
	endpointHintPollInterval = 500 * time.Millisecond
	endpointHintDeadline     = 12 * time.Second
	endpointHintUPnPGrace    = 6 * time.Second
)

// publishEndpointHints 由 serve 的共享路径调用（App 构建为空实现）：
// 等待观测就绪 → 分档判定 → 打档位日志行 → announce 一次最终地址（带提示或原版形态）。
// ci 是本次 serve 用来生成首屏地址的同一个 ConnInfo（只读借用，本协程内追加提示）；
// plainAddr 是不含提示的地址（③档全剔除/无观测/--endpoint-hint=false 时 announce 它）。
func publishEndpointHints(s *tailcat.Server, ci *tailcat.ConnInfo, plainAddr tailcat.Addr, logf func(string, ...any), announce func(tailcat.Addr)) {
	if !endpointHintEnabled() {
		logf("endpoint-hint: 已按 --endpoint-hint=false 禁用，地址不带端点提示")
		announce(plainAddr)
		return
	}
	go func() {
		obs := waitForEndpointHintObservation(s, logf)
		manual := parseManualEndpoints(logf)
		hints, basis := endpointClassify(obs, localPublicAddrs(), localLANAddrs(), manual, time.Now())
		logf("endpoint-hint: %s", basis)
		if len(hints) == 0 {
			announce(plainAddr)
			return
		}
		ci.EndpointHints = hints
		announce(ci.Addr())
	}()
}

// waitForEndpointHintObservation 轮询 Server 的自身网络观测直到「够用」：
// netcheck 报告出现，且（拿到 UPnP 映射 或 已过 UPnP 宽限期）。全程有界。
func waitForEndpointHintObservation(s *tailcat.Server, logf func(string, ...any)) tailcat.EndpointHintObservation {
	start := time.Now()
	deadline := start.Add(endpointHintDeadline)
	var last tailcat.EndpointHintObservation
	for time.Now().Before(deadline) {
		last = s.EndpointHintObservation()
		if last.Report != nil && (last.Report.IPv4 || last.Report.IPv6) {
			if last.MappedPort != 0 || time.Since(start) > endpointHintUPnPGrace {
				return last
			}
		}
		time.Sleep(endpointHintPollInterval)
	}
	if last.Report == nil {
		logf("endpoint-hint: %.0fs 内没有 netcheck 结果，跳过提示采集", endpointHintDeadline.Seconds())
	}
	return last
}

// localPublicAddrs 返回本机接口上的公网 IPv4 集合（用于判「本机地址即公网」）。
func localPublicAddrs() (pub []netip.Addr) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !addr.Is4() || !isPublicV4(addr) {
				continue
			}
			pub = append(pub, addr)
		}
	}
	return pub
}

// localLANAddrs 返回本机**物理**网卡上的 RFC1918 IPv4 地址（④LAN 候选，
// openspec direct-handshake-connect）。虚拟网卡（docker0/bridge/veth 等容器与
// 虚拟网段）被排除——它们的「LAN」对任何客户端都不可达。CGNAT 段（100.64/10）
// 不是家庭 LAN，同样排除。
func localLANAddrs() []netip.Addr {
	sysIfs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	ifaces := make([]lanIfAddrs, 0, len(sysIfs))
	for _, ifc := range sysIfs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		ifaces = append(ifaces, lanIfAddrs{name: ifc.Name, flags: ifc.Flags, addrs: addrs})
	}
	return lanAddrsFromIfaces(ifaces)
}

// lanIfAddrs 是 lanAddrsFromIfaces 的输入单元：接口名/标志/已解析地址
// （net.Interface 的 Addrs 是系统调用、不可注入，纯函数收三元组以便单测）。
type lanIfAddrs struct {
	name  string
	flags net.Flags
	addrs []net.Addr
}

// lanAddrsFromIfaces 是 localLANAddrs 的纯函数形态（单测覆盖）。
func lanAddrsFromIfaces(ifaces []lanIfAddrs) (lan []netip.Addr) {
	for _, ifc := range ifaces {
		if tailcat.IsVirtualInterface(ifc.name) {
			continue
		}
		if ifc.flags&net.FlagUp == 0 || ifc.flags&net.FlagLoopback != 0 {
			continue
		}
		for _, a := range ifc.addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap() // net.ParseIP/接口地址可能是 4-in-6 表示
			if !addr.Is4() {
				continue
			}
			if !addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || tsaddr.CGNATRange().Contains(addr) {
				continue
			}
			lan = append(lan, addr)
		}
	}
	return lan
}

// isPublicV4：可作直连候选的 v4 —— 非私网、非 CGNAT（tsaddr 判，IsPrivate 不含
// 100.64/10）、非回环/链路本地。
func isPublicV4(a netip.Addr) bool {
	return a.IsValid() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !tsaddr.CGNATRange().Contains(a)
}

// parseManualEndpoints 解析 --endpoint（逗号分隔的 ip:port 列表）。
func parseManualEndpoints(logf func(string, ...any)) (out []netip.AddrPort) {
	if flagEndpoint == nil || *flagEndpoint == "" {
		return nil
	}
	for _, s := range strings.Split(*flagEndpoint, ",") {
		ap, err := netip.ParseAddrPort(strings.TrimSpace(s))
		if err != nil {
			logf("endpoint-hint: --endpoint %q 无效，忽略: %v", s, err)
			continue
		}
		out = append(out, ap)
	}
	return out
}

// endpointClassify 把出口自身观测分档成提示候选（纯函数，单测覆盖）。
// 返回候选列表与一行判定依据（启动日志用，可 grep）。
//
// 判定顺序（v4）：
//   - 无 netcheck / 无 UDP ⇒ 无 v4 候选；
//   - 对称 NAT（MappingVariesByDestIP=true）⇒ ③ 剔除；
//   - 钉了监听端口而 STUN 端口对不上 ⇒ 源端口被代理/中间层改写（坑 29）⇒ ③ 剔除；
//     此时 STUN 的 IP 也可能是代理出口 IP（本地实测：Surge 无 DIRECT 规则的端口上
//     STUN 报代理 IP + 临时端口），「UPnP 端口 + STUN IP」会拼出不可达的假候选，
//     所以该剔除**优先于**一切①档证据；
//   - 有显式外部端口 / UPnP 映射 ⇒ ① 可信（端口取声明值）；
//   - 本机接口即公网 ⇒ ① 可信（无 NAT，STUN 端口即监听端口）；
//   - 其余（锥形 NAT 临时映射）⇒ ② 尽力而为。
//
// v6 一律 ②（家用路由器 v6 入站防火墙多为默认拒绝，本机判不了），
// 端口自洽检查同样适用。--endpoint 的手动项以 ③手动 档追加在最后。
func endpointClassify(obs tailcat.EndpointHintObservation, localPublic []netip.Addr, lan []netip.Addr, manual []netip.AddrPort, now time.Time) (hints []tailcat.EndpointHint, basis string) {
	var parts []string
	r := obs.Report
	if r == nil {
		parts = append(parts, "无netcheck")
	} else {
		varies := variesByDest(r)
		gv4, gv4ok := globalV4(r)
		switch {
		case !gv4ok:
			parts = append(parts, "v4=无STUN映射")
		case varies:
			parts = append(parts, fmt.Sprintf("v4a=%v 档=③剔除(对称NAT)", gv4))
		case obs.ListenPort != 0 && gv4.Port() != obs.ListenPort:
			// 坑 29 的剔除优先于①档证据，理由见函数头注释。
			parts = append(parts, fmt.Sprintf("v4a=%v 档=③剔除(源端口被改写: STUN=%d 监听=%d)", gv4, gv4.Port(), obs.ListenPort))
		default:
			// 端口自洽通过后按证据强度定档；候选端口取声明值（路由器把外部端口
			// 转发到监听端口，外部端口不必等于监听端口）。
			var (
				ap   netip.AddrPort
				tier int
				why  string
			)
			switch {
			case obs.AdvertisePort != 0:
				ap, tier, why = netip.AddrPortFrom(gv4.Addr(), obs.AdvertisePort), tailcat.EndpointHintTrusted, "显式外部端口"
			case obs.MappedPort != 0:
				ap, tier, why = netip.AddrPortFrom(gv4.Addr(), obs.MappedPort), tailcat.EndpointHintTrusted, "UPnP映射"
			case containsAddr(localPublic, gv4.Addr()):
				ap, tier, why = gv4, tailcat.EndpointHintTrusted, "本机接口即公网"
			default:
				ap, tier, why = gv4, tailcat.EndpointHintBestEffort, "锥形NAT临时映射"
			}
			hints = append(hints, tailcat.EndpointHint{AddrPort: ap, Tier: tier, Generated: now.Unix()})
			parts = append(parts, fmt.Sprintf("v4a=%v 档=%s(%s) 端口自洽=%t mappedPort=%d 观测次数=%d",
				ap, tailcat.EndpointHintTierName(tier), why,
				obs.ListenPort == 0 || ap.Port() == obs.ListenPort || tier != tailcat.EndpointHintBestEffort,
				obs.MappedPort, r.GlobalV4Counters[gv4]))
		}
		parts = append(parts, "mapvarydest="+variesByDestStr(r))
		if gv6 := r.GlobalV6; gv6.IsValid() && isPublicV6(gv6.Addr()) {
			if obs.ListenPort == 0 || gv6.Port() == obs.ListenPort {
				hints = append(hints, tailcat.EndpointHint{AddrPort: gv6, Tier: tailcat.EndpointHintBestEffort, Generated: now.Unix()})
				parts = append(parts, fmt.Sprintf("v6a=%v 档=%s(入站过滤未知)", gv6, tailcat.EndpointHintTierName(tailcat.EndpointHintBestEffort)))
			} else {
				parts = append(parts, fmt.Sprintf("v6a=%v 档=③剔除(源端口被改写)", gv6))
			}
		} else {
			parts = append(parts, "v6=无")
		}
	}
	// ④LAN：本机物理网卡的 RFC1918 地址，端口取监听端口。不经 NAT、不受
	// netcheck/对称 NAT 判定影响（无 netcheck 结果时也成立）。ListenPort=0
	// （随机端口）时无稳定端口语义，跳过。仅同网段的客户端可达——取舍交给
	// 客户端的网络感知调度（蜂窝丢弃、Wi-Fi 同网段最优先）。
	if obs.ListenPort != 0 {
		var lanParts []string
		for _, a := range lan {
			ap := netip.AddrPortFrom(a, obs.ListenPort)
			hints = append(hints, tailcat.EndpointHint{AddrPort: ap, Tier: tailcat.EndpointHintLAN, Generated: now.Unix()})
			lanParts = append(lanParts, ap.String())
		}
		if len(lanParts) > 0 {
			parts = append(parts, fmt.Sprintf("LAN=%s 档=%s(仅同网段客户端可达)", strings.Join(lanParts, ","), tailcat.EndpointHintTierName(tailcat.EndpointHintLAN)))
		}
	} else if len(lan) > 0 {
		parts = append(parts, "LAN=有私网地址但监听端口未钉死，跳过④档")
	}
	for _, ap := range manual {
		hints = append(hints, tailcat.EndpointHint{AddrPort: ap, Tier: tailcat.EndpointHintManual, Generated: now.Unix()})
		parts = append(parts, fmt.Sprintf("手动=%v 档=%s", ap, tailcat.EndpointHintTierName(tailcat.EndpointHintManual)))
	}
	// 生成端封顶：候选序为 公网(v4/v6) → ④LAN → ③手动，超 MaxEndpointHints
	// 从尾部截（优先截手动项；客户端 ParseAddr 对候选数有硬校验，生成端
	// 不封顶会造出自家客户端拒解析的地址）。
	if n := len(hints); n > tailcat.MaxEndpointHints {
		cut := hints[tailcat.MaxEndpointHints:]
		hints = hints[:tailcat.MaxEndpointHints]
		var cutDesc []string
		for _, h := range cut {
			cutDesc = append(cutDesc, h.AddrPort.String())
		}
		parts = append(parts, fmt.Sprintf("候选超上限：截掉 %d 条(%s)", len(cut), strings.Join(cutDesc, ",")))
	}
	if len(hints) == 0 && len(parts) > 0 {
		parts = append(parts, "⇒ 地址不带端点提示")
	}
	return hints, strings.Join(parts, " ")
}

func variesByDest(r *netcheck.Report) bool {
	return r.MappingVariesByDestIP.EqualBool(true)
}

func variesByDestStr(r *netcheck.Report) string {
	if v, ok := r.MappingVariesByDestIP.Get(); ok {
		return strconv.FormatBool(v)
	}
	return "未知"
}

// globalV4 取 STUN 学到的主 v4 公网映射（公网性校验，剔除「STUN 返回私网/CGNAT」的异常）。
func globalV4(r *netcheck.Report) (netip.AddrPort, bool) {
	g := r.GlobalV4
	if !g.IsValid() || !g.Addr().Is4() || !isPublicV4(g.Addr()) {
		return netip.AddrPort{}, false
	}
	return g, true
}

func isPublicV6(a netip.Addr) bool {
	return a.IsValid() && a.Is6() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsPrivate()
}

func containsAddr(addrs []netip.Addr, a netip.Addr) bool {
	for _, x := range addrs {
		if x == a {
			return true
		}
	}
	return false
}

// endpointHintEnabled / flagEndpoint 在 flags_cli.go 注册；这里只做防御性读取
// （测试环境可能未注册 flag）。
func endpointHintEnabled() bool {
	if flagEndpointHint == nil {
		return true
	}
	return *flagEndpointHint
}
