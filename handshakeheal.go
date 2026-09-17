// handshakeheal.go — 直连优先路径的「握手卡死」自愈（2026-09-17 真机复现后加）。
//
// 背景（真机实测）：直连路径上**首个握手响应可能丢**（同网段发到公网 IP 走发夹 NAT、
// 蜂窝映射刚建立等）。WireGuard 此时不会重新生成握手，而是每 5 秒**重发同一个
// initiation**；而响应方按防重放规则把它整条丢掉（出口日志
// `ConsumeMessageInitiation: handshake replay`）⇒ 双方僵住，直到客户端因为「有数据要发」
// 触发一次**全新**握手才恢复（实测卡了约 90 秒，期间隧道是黑洞）。
//
// 修法：给客户端一个「重新武装握手」的入口 —— wireguard-go 的
// ScheduleHandshakeOnUserSend 会让下一次出站消息发起**新**握手（新 ephemeral、带新
// 时间戳，响应方接受）。触发判据用 wireguard 自己的状态，不猜日志：
//   - HandshakeAttempts() > 0：正在重试却没成 —— 这就是「卡住」的定义；
//   - 或者最近一次完成握手太久（LastHandshake）——长时间没有可用会话。
// 两个判据都来自 wgint.Peer（tailscale 官方的 unsafe 访问器）。
package tailcat

import (
	"context"
	"time"
)

// KickStaleHandshake 在「握手看起来卡住」时重新武装一次握手，返回是否真的武装了。
//
// maxAge 是「最近一次成功握手」的容忍时长：超过它、或从未成功过，都算需要重新武装。
// 传 0 表示无条件重新武装（探针每次尝试都用得上：让每次尝试都是全新握手，而不是
// 重发同一个 initiation）。
//
// 幂等、廉价（只置一个标志位）；真正的发送仍受 WireGuard 的 5s RekeyTimeout 约束 ——
// 被这个窗口挡下的请求会留到下一次出站消息，不会丢。
func (c *Client) KickStaleHandshake(maxAge time.Duration) bool {
	if err := c.ensureStarted(context.Background()); err != nil {
		return false
	}
	lb := c.lb
	if lb == nil || lb.serverPub.IsZero() {
		return false
	}
	eng := lb.sys.Engine.Get()
	if eng == nil {
		return false
	}
	if maxAge > 0 {
		if peer, ok := eng.PeerByKey(lb.serverPub); ok && peer.IsValid() {
			if peer.HandshakeAttempts() == 0 {
				if last := peer.LastHandshake(); !last.IsZero() && time.Since(last) < maxAge {
					return false // 会话新鲜且没在重试：不需要动
				}
			}
		}
	}
	eng.MarkDevicePeerForHandshake(lb.serverPub)
	return true
}

// HandshakeStatus 报告与出口这条链路的 wireguard 握手状态（诊断/日志用）：
// last = 最近一次**完成**握手的时间（零值 = 从未完成），attempts = 当前连续重试计数。
func (c *Client) HandshakeStatus() (last time.Time, attempts uint32, ok bool) {
	if err := c.ensureStarted(context.Background()); err != nil {
		return time.Time{}, 0, false
	}
	lb := c.lb
	if lb == nil || lb.serverPub.IsZero() {
		return time.Time{}, 0, false
	}
	eng := lb.sys.Engine.Get()
	if eng == nil {
		return time.Time{}, 0, false
	}
	peer, found := eng.PeerByKey(lb.serverPub)
	if !found || !peer.IsValid() {
		return time.Time{}, 0, false
	}
	return peer.LastHandshake(), peer.HandshakeAttempts(), true
}
