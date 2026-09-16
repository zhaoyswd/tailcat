// directconnect.go — 客户端直连优先建连（openspec change
// direct-handshake-connect）。
//
// 机制（2026-09-16 实测定稿）：地址带未过期端点候选且 DirectConnect 开启时，
// 建连不再以 meowed 为同步门槛——meow 转后台异步补注册，dial 立即开始，
// WireGuard 握手由服务端懒注册（peerConfig 放行）承接（不依赖 meow 到达，
// 经 DERP 或既有路径完成），数据面先行。meow 完成后服务端拿到本机 disco key
// 注册，此时主动发一次 disco ping 把候选端点变成 bestAddr，数据面切直连。
// TSMP 探测作为就绪探针（WG 加密层，不依赖 disco）；多次未成则回落现状
// meow 同步会合（官方服务端上这是必然路径）。
//
// 已知边界：WireGuard-only peer 形态（握手与数据从第一个包起直发候选、零
// DERP 接触）在 magicsock/wireguard-go 深处存在未定位的握手静默失败
// （实验：直发 initiation 到达服务端 UDP 但握手不成，回落后一切正常），
// 暂不启用；本文件的结构（探测/回落/异步注册）为其保留了接入点。
package tailcat

import (
	"context"
	"errors"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// 直连就绪探测预算：单次尝试 1s（握手经 DERP 时 2×RTT + TSMP 1×RTT，
// 本机/直连 <100ms、中继 <2.5s——失败重试覆盖丢包）。
const (
	directProbeAttempt  = time.Second
	directProbeAttempts = 3
)

// meow 后台补注册的重试节奏（b2 形态：成功使出口获得本机 disco key 注册
// 与 CallMeMaybe 通告通道；失败不影响懒注册数据面）。
const (
	meowBgAttempts = 3
	meowBgInterval = time.Second
	meowBgBudget   = 15 * time.Second
)

// PingDirect 是直连优先模式的就绪探测：并发启动 meow 后台补注册，然后
// 以 TSMP ping 探测握手是否完成；成功即就绪。全部尝试失败则回落现状
// meow 同步会合并按其判据就绪（与未开启直连时一致）。
func (c *Client) PingDirect(ctx context.Context) error {
	if err := c.ensureStarted(ctx); err != nil {
		return err
	}
	go c.meowBackground()
	for range directProbeAttempts {
		if err := c.probeTSMP(ctx); err == nil {
			c.upDone.Store(true)
			return nil
		}
	}
	c.lb.logf("connect: hint-miss→derp（直连探测 %d×%v 未成，回落 meow 会合）", directProbeAttempts, directProbeAttempt)
	_, err := c.Ping(ctx)
	return err
}

// Ready 按当前模式执行就绪探测：直连优先模式走 PingDirect，否则走现状
// meow 会合（Client.Ping）。tunmode 暖机与状态机统一经此入口。
func (c *Client) Ready(ctx context.Context) error {
	if c.lb != nil && c.lb.directFirst.Load() {
		return c.PingDirect(ctx)
	}
	_, err := c.Ping(ctx)
	return err
}

// probeTSMP sends one TSMP ping through the tunnel to the server's tailcat
// address and waits for the reply within directProbeAttempt. The WireGuard
// handshake happens implicitly on the first outbound packet; server-side lazy
// registration admits it before (or without) the meow arriving.
func (c *Client) probeTSMP(parent context.Context) error {
	c.lb.mu.Lock()
	nm := c.lb.nm
	c.lb.mu.Unlock()
	if nm == nil || len(nm.Peers) == 0 || nm.Peers[0].Addresses().Len() == 0 {
		return errors.New("no server peer address")
	}
	ctx, cancel := context.WithTimeout(parent, directProbeAttempt)
	defer cancel()
	ch := make(chan *ipnstate.PingResult, 1)
	c.lb.sys.Engine.Get().Ping(nm.Peers[0].Addresses().At(0).Addr(), tailcfg.PingTSMP, 0, func(r *ipnstate.PingResult) {
		select {
		case ch <- r:
		default:
		}
	})
	select {
	case r := <-ch:
		if r.Err == "" {
			return nil
		}
		return errors.New(r.Err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// meowBackground performs the async meow registration (b2): a few bounded
// retries, result logged only. On success the server has our disco key in
// b.clients (its peerByIP fast path + CallMeMaybe announcements), and we
// immediately kick one disco ping so the hint candidates can become bestAddr
// and the data plane switches to the direct path without waiting for
// magicsock's own discovery cadence.
func (c *Client) meowBackground() {
	if c.meowedOnce.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), meowBgBudget)
	defer cancel()
	for range meowBgAttempts {
		if _, err := c.ping(ctx); err == nil {
			c.meowedOnce.Store(true)
			// meowed 到达即满足现状的就绪语义，置 upDone 让后续 up/DiscoPing
			// 直接放行，不再重跑探测（kickDisco 的 DiscoPing 也会经 up）。
			c.upDone.Store(true)
			c.lb.logf("connect: meow 注册完成（出口动态通告通道就绪，促直连切换）")
			c.lb.advertiseEndpoints()
			go c.kickDisco()
			return
		}
		select {
		case <-ctx.Done():
			c.lb.logf("connect: meow 异步注册未成（预算耗尽），懒注册数据面不受影响")
			return
		case <-time.After(meowBgInterval):
		}
	}
	c.lb.logf("connect: meow 异步注册未成（DERP 不可达或出口无响应），懒注册数据面不受影响")
}

// kickDisco sends one disco ping to the server (via the normal magicsock
// path) to promote hint candidates to bestAddr right after registration,
// instead of waiting for the next outbound packet to trigger discovery.
func (c *Client) kickDisco() {
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	if _, err := c.DiscoPing(dctx); err != nil {
		c.lb.logf("connect: meow 后促直连的 disco ping 未成（%v），交由常规节奏", err)
	}
}
