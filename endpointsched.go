// endpointsched.go — 建连候选的网络感知过滤（openspec change
// direct-handshake-connect）。纯函数、无网络依赖、单测覆盖。
//
// 2026-09-17 按 review 大幅简化：只保留「蜂窝丢弃私网候选」（必然不可
// 达，向运营商内网发探测既浪费也留指纹；学习端点一起过同样的滤——旧
// 版把 learned 无条件放最前、绕过了私网过滤，在家学到 LAN 端点后切蜂窝
// 仍会去探，是自相矛盾）。排序整体删除：候选全部进入 netmap 的
// Endpoints 后 magicsock 是**并发探测**的，谁先 pong 谁赢，顺序不改变
// 探测并发度与结果；"Wi-Fi 同网段最优先/v6 优先"的收益无法兑现。
package tailcat

import (
	"net/netip"

	"tailscale.com/net/tsaddr"
)

// FilterHints 过滤建连候选：bearer 为 "cellular" 时丢弃私网候选
// （RFC1918/CGNAT/链路本地，含学习端点），其余情况原样保留（判据缺失
// 时保守不过滤）。返回保留列表与被丢弃列表（诊断日志用）。
func FilterHints(learned []netip.AddrPort, hints []EndpointHint, bearer string) (keep, dropped []netip.AddrPort) {
	dropLAN := bearer == "cellular"
	for _, ap := range learned {
		if !ap.IsValid() {
			continue
		}
		if dropLAN && isLanCandidate(ap) {
			dropped = append(dropped, ap)
			continue
		}
		keep = append(keep, ap)
	}
	for _, h := range hints {
		if !h.AddrPort.IsValid() {
			continue
		}
		if dropLAN && isLanCandidate(h.AddrPort) {
			dropped = append(dropped, h.AddrPort)
			continue
		}
		keep = append(keep, h.AddrPort)
	}
	return keep, dropped
}

// isLanCandidate reports whether ap is a private (same-LAN-only) candidate:
// RFC1918 or CGNAT space. Link-local is treated as private too (unusable
// off-link). 已知边界：host-network 容器/EIP-NAT 主机会把内网地址采成
// ④LAN 候选（对客户端不可达）——过滤只认地址类别不认「是不是真的同
// LAN」，残留候选的代价是多一次无效探测，无正确性影响。
func isLanCandidate(ap netip.AddrPort) bool {
	a := ap.Addr().Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast() || tsaddr.CGNATRange().Contains(a)
}
