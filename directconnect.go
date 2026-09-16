// directconnect.go — 客户端直连优先建连（openspec change
// direct-handshake-connect）。
//
// 机制（2026-09-17 按 review 修订定稿）：地址带未过期候选（hint 或学习
// 端点）且 DirectConnect 开启时，就绪不再以 meowed 为串行门槛——TSMP
// 探针与后台 meow **赛跑**，谁先成功谁就算就绪：
//   - 服务端懒注册（peerConfig 放行）让 WireGuard 握手不依赖 meow 先行
//     到达，探针（握手隐含在首个出站包里 + TSMP 往返）可在 meow 之前完成；
//   - 官方（无懒注册的）服务端上探针握手被丢，meow 赢得赛跑——**不多付
//     任何等待**（旧实现顺序探测 3×1s 再回落，官方出口白等 3s，已修）；
//   - meow 完成后服务端拿到本机 disco key 注册，kickDisco 立刻促直连
//     切换（hint 候选经 disco pong 成为 bestAddr）。
//
// 已知边界（诚实声明）：非 WireGuard-only peer 的**首个握手包本身走 DERP**
// （magicsock addrForSendLocked 对无 bestAddr 的普通 peer 只给 derpAddr），
// 所以 DERP 完全不可达时握手与 meow 一起失败——「DERP 不可用即连不上」
// 没有被本 change 解决；实际收益是「就绪不再串行多等一个中继往返 +
// 注册后立刻促直连」。零中继首跳的 WireGuard-only 形态在 wireguard-go
// 深处存在未定位的握手静默失败，未启用（现象记录见 PATCHES §2.8）。
package tailcat

import (
	"context"
	"errors"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// 直连就绪探测预算。注意蜂窝中继路径 RTT 600–750ms，1s 的单次窗口对
// 「握手 2×RTT + TSMP 1×RTT」并不宽裕——首次尝试超时是预期内的情况，
// 靠重试兜底；赛跑的另一条腿（meow）通常在官方出口上更快到达。
const (
	directProbeAttempt  = time.Second
	directProbeAttempts = 3
)

// meow 后台补注册的节奏与预算（b2 形态）。
const (
	meowBgAttempts = 3
	meowBgInterval = time.Second
	meowBgBudget   = 15 * time.Second
)

// PingDirect 是直连优先模式的就绪探测：后台 meow 与 TSMP 探针赛跑，
// 谁先成功谁就算就绪。探针全败且 meow 在预算内也没到，则等 meow 到
// 调用方 ctx 到点为止（回落语义与旧路径「无条件等 meowed」一致）。
func (c *Client) PingDirect(ctx context.Context) error {
	if err := c.ensureStarted(ctx); err != nil {
		return err
	}
	by, err := c.raceReady(ctx)
	if err == nil {
		c.readyByVal.Store(by)
		c.upDone.Store(true)
	}
	return err
}

// Ready 按当前模式执行就绪探测：直连优先模式走 PingDirect，否则走现状
// meow 会合（Client.Ping）。返回就绪判据（"direct"/"meow"，供诊断）。
//
// ⚠️ 必须先 ensureStarted 再判模式（与 up() 同一条铁律）：首次调用时
// c.lb 还没建（initLocked 在 ensureStarted 里跑、directFirst 也是那时才
// 置位），先判断会永远走普通路径——本函数第一版犯过这个错并被 review
// 揪出（App 路径上新模式从未执行过）。
func (c *Client) Ready(ctx context.Context) (readyBy string, err error) {
	if err := c.ensureStarted(ctx); err != nil {
		return "", err
	}
	if c.lb.directFirst.Load() {
		if err := c.PingDirect(ctx); err != nil {
			return "", err
		}
		return c.readyBy(), nil
	}
	_, err = c.Ping(ctx)
	if err == nil {
		c.readyByVal.Store("meow")
	}
	return c.readyBy(), err
}

// readyBy returns the recorded readiness basis ("" before first success).
func (c *Client) readyBy() string {
	if v, ok := c.readyByVal.Load().(string); ok {
		return v
	}
	return ""
}

// raceReady runs the TSMP probe attempts against the background meow
// registration; first success wins. If the probe exhausts its attempts and
// meow hasn't landed either, it keeps waiting on meowWait until the parent
// context is done.
func (c *Client) raceReady(ctx context.Context) (string, error) {
	c.startMeowBackground()
	for range directProbeAttempts {
		select {
		case <-c.meowWait:
			return "meow", nil
		default:
		}
		if err := c.probeTSMP(ctx); err == nil {
			return "direct", nil
		}
		select {
		case <-c.meowWait:
			return "meow", nil
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(directProbeAttempt):
		}
	}
	c.lb.logf("connect: hint-miss→meow（直连探测 %d×%v 未成，等 meow 会合）", directProbeAttempts, directProbeAttempt)
	select {
	case <-c.meowWait:
		return "meow", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
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

// startMeowBackground launches the async meow registration with an in-flight
// latch: failures don't latch meowedOnce, but a Dial storm must not spawn
// parallel 15s-budget goroutines (one at a time).
func (c *Client) startMeowBackground() {
	if c.meowedOnce.Load() || !c.meowInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.meowInFlight.Store(false)
		c.meowBackground()
	}()
}

// meowBackground performs the async meow registration (b2): a few bounded
// retries, result logged only. Exits early when the client is closed (bgDone)
// so it never outlives its generation (AGENTS 坑 26/26b 的世代教训).
// On success it does NOT call advertiseEndpoints: the client's onMeowed
// callback (initLocked) already does — 旧版这里重复调过一次（review 指出）。
func (c *Client) meowBackground() {
	if c.meowedOnce.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), meowBgBudget)
	defer cancel()
	for range meowBgAttempts {
		select {
		case <-c.bgDone:
			return
		default:
		}
		if _, err := c.ping(ctx); err == nil {
			c.meowedOnce.Store(true)
			// meowed 到达即满足旧路径的就绪语义（赛跑的另一条腿在等它）。
			c.upDone.Store(true)
			c.lb.logf("connect: meow 注册完成（出口动态通告通道就绪）")
			go c.kickDisco()
			return
		}
		select {
		case <-c.bgDone:
			return
		case <-ctx.Done():
			c.lb.logf("connect: meow 异步注册未成（预算耗尽），懒注册数据面不受影响")
			return
		case <-time.After(meowBgInterval):
		}
	}
	c.lb.logf("connect: meow 异步注册未成（DERP 不可达或出口无响应），懒注册数据面不受影响")
}

// kickDisco sends one disco ping to the server so hint candidates can become
// bestAddr right after registration, without waiting for magicsock's own
// discovery cadence. Bounded and generation-safe.
func (c *Client) kickDisco() {
	select {
	case <-c.bgDone:
		return
	default:
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	if _, err := c.DiscoPing(dctx); err != nil {
		select {
		case <-c.bgDone:
		default:
			c.lb.logf("connect: meow 后促直连的 disco ping 未成（%v），交由常规节奏", err)
		}
	}
}
