// endpointhint.go — 地址端点提示（直连候选）的公共类型与客户端消费逻辑。
//
// 背景：客户端 netmap 里出口节点不填端点，第一个直连机会只能等出口经 DERP
// 发来的 CallMeMaybe，而那条消息压在一串时序上（meow → 出口 STUN 完成 → 只对
// 未注册客户端发），丢一次整段会话就可能一直挂在中继上。把出口的稳定公网
// 端点作为**提示**烤进 tailcat 地址（见 wireConnInfo.EndpointHints），客户端
// 从建连第一刻起就有直连候选，探测与经 DERP 的注册并发，不再依赖那串时序。
//
// 注意边界（openspec change `direct-first-endpoint-hint`）：注册（meow）仍必须
// 经 DERP —— 服务端只经 DERP 的 meow 认识客户端（onMeow 唯一调用点是
// onDERPRecv；peerConfig 对未注册 key 返回 false，直连的 WireGuard 握手会被
// 丢弃）。提示只是让直连候选提前就位，不是「与中继零接触」。
package tailcat

import (
	"net/netip"
	"time"
)

// Endpoint hint tier values: the server's confidence in a candidate,
// as classified by its own local observations. The tier decides whether
// a candidate is written into the address at all and is echoed in
// client-side diagnostics; it never changes the client's connect order
// or adds waiting.
const (
	// EndpointHintTrusted (① 可信): the server's interface address is
	// its public address, or a router port mapping (UPnP/NAT-PMP/PCP)
	// or an explicitly advertised external port backs the candidate.
	EndpointHintTrusted = 1

	// EndpointHintBestEffort (② 尽力而为): a cone-NAT STUN mapping, or
	// a global IPv6 address the server can't prove inbound-reachable.
	EndpointHintBestEffort = 2

	// EndpointHintManual (③ 手动): user-specified via --endpoint.
	EndpointHintManual = 3

	// EndpointHintLAN (④ 局域网): an RFC1918 address on one of the
	// server's physical interfaces. Only meaningful to a client on the
	// same LAN (the phone-at-home case); the client's network-aware
	// scheduling decides whether to use it — cellular clients filter it
	// out entirely.
	EndpointHintLAN = 4
)

// MaxEndpointHints caps how many hints an address may carry, so a
// malformed or hostile address can't turn into an unbounded candidate
// list the client would probe.
const MaxEndpointHints = 8

// EndpointHintTTL is how long a client keeps using hint candidates
// after they were generated. Hints are a snapshot of the exit's network
// at generation time; old ones may point at reassigned IPs, and probing
// them costs packets and third-party exposure for no gain. Exits with
// stable endpoints refresh the hint on every restart, so users only
// need to re-paste the address after redeploying an exit.
const EndpointHintTTL = 7 * 24 * time.Hour

// EndpointHint is one direct-connect candidate for the server, as
// observed (or manually asserted) by the server. See wire.go for the
// CBOR form and endpointhint_server.go / endpointhint_cli.go for how
// the server side classifies and writes them.
type EndpointHint struct {
	// AddrPort is the candidate's public IP and port. IPv4 or IPv6.
	AddrPort netip.AddrPort `json:",omitempty"`

	// Tier is one of the EndpointHint* constants above.
	Tier int `json:",omitempty"`

	// Generated is when the server observed the candidate, as unix
	// seconds. Zero means unknown; FreshEndpointHints treats it as
	// fresh (it can only come from hand-crafted addresses).
	Generated int64 `json:",omitempty"`
}

// Fresh reports whether the hint is still within the client TTL of now.
func (h EndpointHint) Fresh(now time.Time) bool {
	if h.Generated <= 0 {
		return true
	}
	gen := time.Unix(h.Generated, 0)
	return now.Sub(gen) < EndpointHintTTL && gen.Before(now.Add(time.Hour))
}

// FreshEndpointHints splits hints into those still usable (nil if none)
// and how many were skipped as stale. Pure function; unit-tested.
func FreshEndpointHints(hints []EndpointHint, now time.Time) (fresh []EndpointHint, skipped int) {
	for _, h := range hints {
		if h.Fresh(now) {
			fresh = append(fresh, h)
		} else {
			skipped++
		}
	}
	return fresh, skipped
}

// EndpointHintTierName returns a short human-readable tier label for
// logs ("①可信" / "②尽力" / "③手动" / "未知").
func EndpointHintTierName(tier int) string {
	switch tier {
	case EndpointHintTrusted:
		return "①可信"
	case EndpointHintBestEffort:
		return "②尽力"
	case EndpointHintManual:
		return "③手动"
	case EndpointHintLAN:
		return "④LAN"
	}
	return "未知"
}

// EndpointHints returns the endpoint hints carried by the client's
// server address, as parsed. It returns nil for hint-less addresses;
// use FreshEndpointHints to apply the client TTL.
func (c *Client) EndpointHints() []EndpointHint {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	return c.ci.EndpointHints
}
