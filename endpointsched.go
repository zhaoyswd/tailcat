// endpointsched.go — 建连候选的网络感知排序与过滤（openspec change
// direct-handshake-connect）。纯函数、无网络依赖、单测覆盖。
//
// 规则（判据缺失时保守：不过滤、不重排）：
//   - 蜂窝：丢弃私网候选（RFC1918/CGNAT/链路本地——必然不可达，向运营商
//     内网发探测既浪费也留指纹）；全局 IPv6 优先于公网 IPv4。
//   - Wi-Fi：与手机当前接口地址**同网段**的私网候选最高优先（回家场景：
//     手机与出口同 LAN，一跳直达）；其余私网殿后（不同网段的 Wi-Fi 上
//     不可达，但「握手成功即止」模型下只在前面的都失败后才被试到）；
//     公网候选保持原序。
//   - 学习端点（端点学习缓存）始终排在全部候选之前（最新、最可能命中）。
package tailcat

import (
	"net/netip"

	"tailscale.com/net/tsaddr"
)

// LocalNetInfo 是调用方（扩展 net observer）传入的手机网络上下文。
// Bearer 为 "cellular"/"wifi"（其它值=未知，保守处理）；Addrs 为手机
// 当前接口地址（含前缀长度，用于同网段判断）。
type LocalNetInfo struct {
	Bearer string
	Addrs  []netip.Prefix
}

// isLanCandidate reports whether ap is a private (same-LAN-only) candidate:
// RFC1918 or CGNAT space. Link-local is treated as private too (unusable
// off-link).
func isLanCandidate(ap netip.AddrPort) bool {
	a := ap.Addr().Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast() || tsaddr.CGNATRange().Contains(a)
}

// samePrefix reports whether addr falls inside one of the phone's current
// interface prefixes.
func samePrefix(addr netip.Addr, local []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range local {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// SortEndpoints orders and filters the connect candidates for the current
// phone network. learned (endpoint-learning cache, most recent first) always
// comes first; hints follow the rules above. filteredOut is returned for
// diagnostics (the scheduler logs what it dropped and why).
func SortEndpoints(learned []netip.AddrPort, hints []EndpointHint, net LocalNetInfo) (ordered, filteredOut []netip.AddrPort) {
	var v6, v4pub, lanSame, lanOther []netip.AddrPort

	for _, h := range hints {
		ap := h.AddrPort
		if !ap.IsValid() {
			continue
		}
		lan := isLanCandidate(ap)
		switch {
		case net.Bearer == "cellular" && lan:
			filteredOut = append(filteredOut, ap) // 蜂窝：私网必然不可达
		case lan && samePrefix(ap.Addr(), net.Addrs):
			lanSame = append(lanSame, ap) // Wi-Fi 同网段：一跳直达
		case lan:
			lanOther = append(lanOther, ap) // 其余私网殿后
		case ap.Addr().Is6():
			v6 = append(v6, ap)
		default:
			v4pub = append(v4pub, ap)
		}
	}

	var public []netip.AddrPort
	switch {
	case net.Bearer == "cellular":
		public = append(v6, v4pub...) // 蜂窝：v6 NAT-free 优先
	case net.Bearer == "wifi":
		public = append(v4pub, v6...) // Wi-Fi：保持生成端原序（v4 在前）
	default:
		public = append(v4pub, v6...) // 判据缺失：保守原序
	}

	ordered = append(ordered, learned...)
	ordered = append(ordered, lanSame...)
	ordered = append(ordered, public...)
	ordered = append(ordered, lanOther...)
	return ordered, filteredOut
}
