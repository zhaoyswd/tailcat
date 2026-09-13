//go:build !cshared

// proxyudp.go — 「被转发的 UDP 也走代理」：能力探测、结论缓存与拨号接线（CLI/上游向）。
//
// 为什么需要：出口原先只有 TCP 能经 --forward-via-proxy（proxyforward.go），UDP 那句
// net.DialUDP 是直连写死的 ⇒ 境外 QUIC / 纯 UDP 服务在出口侧没有代理可走。
// 而「代理到底支不支持 UDP」是**可探测的**：SOCKS5 的 UDP ASSOCIATE 里 REP=0x07/0x02
// 是确定性否定；REP=0 只代表「声称支持」，必须再发一个可自校验的数据报确认。
//
// 探测的三个坑（都实测踩过，别改回去）：
//  1. 探针目标不能用域名：规则型代理会把 stun.l.google.com 解析成 198.18.x.x（fake-IP），
//     回来的根本不是 STUN 应答 ⇒ 只用**字面 IP**。
//  2. 中继回复的 SOCKS5 UDP 头不一定是 ATYP=1 ⇒ 必须按 RFC1928 解析（socksudp.go）。
//  3. 别拿 :53 当探针：DNS 会被劫持/伪造 ⇒ 用 STUN（固定格式，magic cookie + 事务 ID
//     都可校验），并校验事务 ID，而不是「收到包就算通」。
//
// 结论按代理端点缓存在进程内（连续失败若干次后重探）；默认不阻塞：auto 模式下第一次
// 需要转发 UDP 时才探测，探测本身另有 5 秒上限。
package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// forwardUDPMode 是 --forward-udp 的取值。
type forwardUDPMode string

const (
	forwardUDPAuto forwardUDPMode = "auto" // 默认：探测后决定
	forwardUDPOn   forwardUDPMode = "on"   // 必须支持，否则明确失败
	forwardUDPOff  forwardUDPMode = "off"  // 不做 UDP 代理
)

// forwardUDPModeValue 由 setupForwarding 按 --forward-udp 设置（默认 auto）。
var forwardUDPModeValue = forwardUDPAuto

// udpProbeTimeout 是单次能力探测的时间上限（含 STUN 往返）。
const udpProbeTimeout = 5 * time.Second

// udpProbeTargets 是能力探测用的 STUN 目标（字面 IP:port）。由 serve 在拿到 DERP 区域后
// 填入（DERP 节点本身就提供 STUN）；为空时用内置的字面 IP 兜底。
var (
	udpProbeMu      sync.Mutex
	udpProbeTargets []netip.AddrPort
)

// fallbackUDPProbeTargets 是拿不到 DERP 区域时的兜底 STUN（字面 IP，不能用域名）。
var fallbackUDPProbeTargets = []netip.AddrPort{
	netip.MustParseAddrPort("162.159.207.1:3478"), // Cloudflare
}

func setUDPProbeTargets(ts []netip.AddrPort) {
	udpProbeMu.Lock()
	defer udpProbeMu.Unlock()
	udpProbeTargets = ts
}

func getUDPProbeTargets() []netip.AddrPort {
	udpProbeMu.Lock()
	defer udpProbeMu.Unlock()
	if len(udpProbeTargets) == 0 {
		return fallbackUDPProbeTargets
	}
	return udpProbeTargets
}

// derpSTUNTargets 从 DERP 区域里取「字面 IPv4 + STUN 端口」作为探测目标
// （DERP 节点自己就提供 STUN，端口缺省 3478）。
func derpSTUNTargets(reg *tailcfg.DERPRegion) []netip.AddrPort {
	if reg == nil {
		return nil
	}
	var out []netip.AddrPort
	for _, n := range reg.Nodes {
		if n == nil || n.IPv4 == "" {
			continue
		}
		addr, err := netip.ParseAddr(n.IPv4)
		if err != nil {
			continue
		}
		port := n.STUNPort
		if port <= 0 || port > 65535 {
			port = 3478
		}
		out = append(out, netip.AddrPortFrom(addr.Unmap(), uint16(port)))
	}
	return out
}

// udpProxyState 是探测结论。
type udpProxyState int

const (
	udpProxyUnknown     udpProxyState = iota // 还没探过
	udpProxySupported                        // 确认可用：REP=0 且探针收到可校验应答
	udpProxyUnsupported                      // 明确否定：REP=0x07/0x02
	udpProxyUnavailable                      // 声称支持但数据不通（REP=0 但探针无有效应答）
	udpProxyNoProxy                          // 没有配置代理 / 代理不是 socks5
)

func (s udpProxyState) String() string {
	switch s {
	case udpProxySupported:
		return "支持 UDP"
	case udpProxyUnsupported:
		return "不支持 UDP"
	case udpProxyUnavailable:
		return "声称支持但数据不通"
	case udpProxyNoProxy:
		return "没有可承载 UDP 的代理"
	default:
		return "未知"
	}
}

type udpProxyStatus struct {
	state  udpProxyState
	detail string // 人话说明（进日志）
	at     time.Time
	fails  int // 连续转发失败次数：到阈值就把结论置回 unknown 重探
}

// udpReProbeAfterFailures 是「连续多少次转发失败后重新探测」。
const udpReProbeAfterFailures = 3

var udpProxyCache struct {
	mu       sync.Mutex
	status   udpProxyStatus
	inflight chan struct{}
}

// udpProxyStatusNow 返回当前结论；未知时同步探测一次。
// 并发调用共享同一次探测（避免每个 UDP 流各探一次）。
func udpProxyStatusNow(ctx context.Context) udpProxyStatus {
	for {
		udpProxyCache.mu.Lock()
		if st := udpProxyCache.status; st.state != udpProxyUnknown {
			udpProxyCache.mu.Unlock()
			return st
		}
		wait := udpProxyCache.inflight
		if wait != nil {
			udpProxyCache.mu.Unlock()
			select {
			case <-wait:
				continue // 探测已完成，回到循环读结论
			case <-ctx.Done():
				return udpProxyStatus{state: udpProxyUnknown, detail: "等待代理探测结果超时"}
			}
		}
		done := make(chan struct{})
		udpProxyCache.inflight = done
		udpProxyCache.mu.Unlock()

		st := probeUDPProxy(ctx)

		udpProxyCache.mu.Lock()
		udpProxyCache.status = st
		udpProxyCache.inflight = nil
		udpProxyCache.mu.Unlock()
		close(done)
		return st
	}
}

// noteUDPForwardFailure 记一次「按结论该走代理、但拨号失败」。
// 连续失败到阈值就把结论置回未知，下次重新探测（代理重启/换后端都能自愈）。
func noteUDPForwardFailure() {
	udpProxyCache.mu.Lock()
	defer udpProxyCache.mu.Unlock()
	udpProxyCache.status.fails++
	if udpProxyCache.status.fails >= udpReProbeAfterFailures {
		forwardLogf()("forward-udp: 连续 %d 次经代理转发 UDP 失败，丢弃探测结论，下次重新探测", udpProxyCache.status.fails)
		udpProxyCache.status = udpProxyStatus{}
	}
}

// forwardLogf 是 CLI 的日志出口（getLogf 的包级封装：未初始化 flag 时退化为丢弃，便于单测）。
func forwardLogf() logger.Logf {
	if flagVerbose == nil {
		return logger.Discard
	}
	return getLogf()
}

// probeUDPProxy 探测 forwardProxy 能否承载 UDP，并把结论打成一行日志。
func probeUDPProxy(ctx context.Context) udpProxyStatus {
	var st udpProxyStatus
	if forwardProxy == nil {
		st = udpProxyStatus{state: udpProxyNoProxy, detail: "没有配置 --forward-via-proxy"}
	} else if s := forwardProxy.Scheme; s != "socks5" && s != "socks5h" {
		st = udpProxyStatus{state: udpProxyNoProxy, detail: fmt.Sprintf("代理是 %s://，HTTP 代理不能承载 UDP", s)}
	} else {
		pctx, cancel := context.WithTimeout(ctx, udpProbeTimeout)
		defer cancel()
		st = probeUDPOverSOCKS5(pctx, forwardProxy, getUDPProbeTargets())
	}
	st.at = time.Now()
	logUDPProxyVerdict(forwardLogf(), st)
	return st
}

// probeUDPOverSOCKS5 做真正的探测：协商 + UDP ASSOCIATE（看 REP），成功后再用 STUN 探针
// 确认数据确实被中继（按字面 IP、校验事务 ID）。
func probeUDPOverSOCKS5(ctx context.Context, p *url.URL, targets []netip.AddrPort) udpProxyStatus {
	if len(targets) == 0 {
		return udpProxyStatus{state: udpProxyUnknown, detail: "没有可用的字面 IP 探针目标"}
	}
	ctrl, relay, rep, err := socks5UDPAssociate(ctx, p, netip.AddrPort{})
	if err != nil {
		return udpProxyStatus{state: udpProxyUnknown, detail: err.Error()}
	}
	defer ctrl.Close()
	if rep != socks5RepSuccess {
		if rep == socks5RepCommandNotSupprt || rep == socks5RepNotAllowed {
			return udpProxyStatus{state: udpProxyUnsupported, detail: "UDP ASSOCIATE 被拒：" + socks5RepString(rep)}
		}
		return udpProxyStatus{state: udpProxyUnavailable, detail: "UDP ASSOCIATE 被拒：" + socks5RepString(rep)}
	}
	relayConn, err := dialRelayUDP(ctx, relay)
	if err != nil {
		return udpProxyStatus{state: udpProxyUnavailable, detail: err.Error()}
	}
	conn := newSocksUDPConn(ctrl, relayConn, targets[0])
	defer conn.Close()
	var lastErr error
	for _, target := range targets {
		mapped, err := stunProbeViaSOCKS(ctx, conn, target)
		if err == nil {
			return udpProxyStatus{
				state:  udpProxySupported,
				detail: fmt.Sprintf("探针 %v 收到可校验应答（映射 %v，中继 %v）", target, mapped, relay),
			}
		}
		lastErr = err
	}
	return udpProxyStatus{
		state:  udpProxyUnavailable,
		detail: fmt.Sprintf("中继已建立但探针没有有效应答（最后一个目标 %v：%v）", targets[len(targets)-1], lastErr),
	}
}

// stunProbeViaSOCKS 经一条 SOCKS5 UDP 关联向 target 发一个 STUN Binding 请求并校验应答。
// 用 tailscale 的 stun 客户端而不是手搓报文：它带 SOFTWARE/FINGERPRINT 属性，
// DERP 的 STUN 服务端只认这种（实测手搓的 20 字节裸请求收不到应答）。
func stunProbeViaSOCKS(ctx context.Context, conn *socksUDPConn, target netip.AddrPort) (netip.AddrPort, error) {
	if !target.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("探针目标无效：%v", target)
	}
	txID := stun.NewTxID()
	if _, err := conn.writeTo(target, stun.Request(txID)); err != nil {
		return netip.AddrPort{}, err
	}
	deadline := time.Now().Add(3 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return netip.AddrPort{}, err
		}
		gotTx, mapped, err := stun.ParseResponse(buf[:n])
		if err != nil {
			continue // 不是 STUN 应答（可能是并发流的数据）⇒ 继续等
		}
		if gotTx != txID {
			continue // 事务 ID 对不上 ⇒ 不是我们这个请求的应答
		}
		return mapped, nil
	}
}

// logUDPProxyVerdict 打一行「代理地址 + 探测结论 + 被转发 UDP 的出口路径」。
func logUDPProxyVerdict(l logger.Logf, st udpProxyStatus) {
	if l == nil || forwardProxy == nil {
		return
	}
	path := "直出"
	if st.state == udpProxySupported {
		path = "经代理"
	}
	l("forward-udp: 代理 %v %s（%s）—— 被转发的 UDP 走 %s", forwardProxy.Host, st.state, st.detail, path)
}

// dialForwardUDP 拨一条到 dst 的 UDP 通道。via 用于日志（"direct" / "socks5://host"），
// 让每条转发日志自己说明走了哪条路（"udp forward -> 1.1.1.1:443 (via direct)"）。
//
// 语义（对应 --forward-udp）：
//   - off / 没配代理：直连（与改动前完全一致）。
//   - auto：探测后决定；代理能承载就经代理，不能就**回落直出并在日志里说明原因**。
//   - on：必须经代理，探测不通过就明确失败（不静默直出）。
func dialForwardUDP(ctx context.Context, dst netip.AddrPort) (tailcat.ConnPacketConn, string, error) {
	if forwardProxy == nil || forwardUDPModeValue == forwardUDPOff {
		up, err := dialDirectUDP(dst)
		return up, "direct", err
	}
	if s := forwardProxy.Scheme; s != "socks5" && s != "socks5h" {
		if forwardUDPModeValue == forwardUDPOn {
			return nil, "", fmt.Errorf("--forward-udp=on 但代理是 %s://：HTTP 代理不能承载 UDP", s)
		}
		up, err := dialDirectUDP(dst)
		return up, "direct(代理是 " + s + "://，不能承载 UDP)", err
	}
	st := udpProxyStatusNow(ctx)
	if st.state == udpProxySupported {
		c, err := dialSOCKS5UDP(ctx, forwardProxy, dst)
		if err != nil {
			noteUDPForwardFailure()
			return nil, "", fmt.Errorf("经代理 %v 转发 UDP 失败: %w", forwardProxy.Host, err)
		}
		return c, "socks5://" + forwardProxy.Host, nil
	}
	if forwardUDPModeValue == forwardUDPOn {
		return nil, "", fmt.Errorf("--forward-udp=on 但代理 %v %s：%s", forwardProxy.Host, st.state, st.detail)
	}
	up, err := dialDirectUDP(dst)
	return up, "direct(代理" + st.state.String() + "：" + st.detail + ")", err
}

func dialDirectUDP(dst netip.AddrPort) (tailcat.ConnPacketConn, error) {
	up, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return nil, err
	}
	return up, nil
}

// parseForwardUDPMode 解析 --forward-udp 的取值（纯函数，便于单测）。
func parseForwardUDPMode(v string) (forwardUDPMode, error) {
	switch v {
	case "", string(forwardUDPAuto):
		return forwardUDPAuto, nil
	case string(forwardUDPOn):
		return forwardUDPOn, nil
	case string(forwardUDPOff):
		return forwardUDPOff, nil
	default:
		return "", fmt.Errorf("--forward-udp %q：只支持 auto、on、off", v)
	}
}
