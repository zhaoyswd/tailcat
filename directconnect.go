// directconnect.go — 客户端直连优先建连（openspec change
// direct-handshake-connect）。
//
// 机制（2026-09-17 二轮 review 修订定稿）：地址带未过期候选（hint 或学习
// 端点）且 DirectConnect 开启时，就绪不再以 meowed 为**串行**门槛——TSMP
// 探针与后台 meow 真并发赛跑（多路 select 同权等待，谁先成谁算就绪）：
//   - 服务端懒注册（peerConfig 放行）让 WireGuard 握手不必等 meow 先到；
//   - 官方（无懒注册的）服务端上探针握手被丢，meow 赢得赛跑——不多付任何
//     探测等待（旧实现顺序探测 3×1s 再回落，官方出口白等 3s，已修）；
//   - meow 完成后服务端拿到本机 disco key 注册，kickDisco 立刻促直连
//     切换（hint 候选经 disco pong 成为 bestAddr）。
//
// ⚠️ 收益口径（按真机实测校准，别照 proposal 的旧话术引用）：健康路径上
// 就绪判据**通常仍是 meow**——meow 是 1 个中继 RTT、探针要 2 个（握手 1 +
// TSMP 1）且 meow 先发。所以本机制实际省下的是「首个数据流不再单独付一次
// 握手 RTT」（握手已与 meow 并行完成），外加「meow 首包丢失时不至于卡死
// 就绪」。**不是**「就绪不再含一个中继往返」，也**不是**「首个包不经 DERP」。
//
// 已知边界（诚实声明）：非 WireGuard-only peer 的**首个握手包本身走 DERP**
// （magicsock addrForSendLocked 对无 bestAddr 的普通 peer 只给 derpAddr），
// 所以 DERP 完全不可达时握手与 meow 一起失败——「DERP 不可用即连不上」
// 没有被本 change 解决。零中继首跳的 WireGuard-only 形态在 wireguard-go
// 深处存在未定位的握手静默失败，未启用（现象记录见 PATCHES §2.8）。
package tailcat

import (
	"context"
	"errors"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// 直连就绪探测预算：单次尝试 1s（内部自带超时），两次尝试之间再歇 1s，
// 共 attempts 次。⚠️ 蜂窝中继路径 RTT 600–750ms，而探针要「握手 + TSMP」
// 两个往返，单次 1s 的窗口并不宽裕——首次超时属预期内，靠重试兜底；
// 赛跑改写后这些参数只影响探针腿，meow 腿任何时刻成即刻就绪。
const (
	directProbeAttempt  = time.Second
	directProbeAttempts = 3
)

// meow 后台补注册的节奏与预算（b2 形态）：budget 内 ping() 自带每秒重发，
// 仍不成则转慢节奏低频重试（meowBgSlowInterval），而不是就此放弃。
//
// 慢节奏的理由：meow 是**直连路径的唯一前提**——服务端要靠它拿到本机
// disco key 才会回应 disco ping。若快节奏全败而探针已就绪，本世代会停在
// 「数据面可用但从未注册」：拿不到直连，且换网时就地重绑的判据
// （Client.DiscoPing）永远失败 ⇒ 每次网络变化都落回整套重建。低频重试让
// 这种状态在 30s 内自愈；持续 DERP 故障下它也只是每 30s 一个包。
// 成功或 Client.Close（bgDone）即退出，不跨世代存活。
const (
	meowBgBudget       = 15 * time.Second
	meowBgSlowInterval = 30 * time.Second
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

// raceReady 启动后台 meow 注册并跑赛跑核心（raceFirst）。
func (c *Client) raceReady(ctx context.Context) (string, error) {
	c.startMeowBackground()
	by, err := raceFirst(ctx, c.meowWait, c.probeTSMP, directProbeAttempts, directProbeAttempt, func() {
		c.lb.logf("connect: 探针 %d×%v 未成→meow（直连腿出局，等会合）", directProbeAttempts, directProbeAttempt)
	})
	if by == "direct" {
		c.lb.logf("connect: 直连探针先成就绪（meow 仍在后台补注册）")
	}
	return by, err
}

// raceFirst 是赛跑核心（与具体的探测手段解耦，便于单测）：meow 到达与 probe
// 成功被**同权**等待——探针在飞期间 meow 到达也立刻就绪。
// ⚠️ 第一版把 probe 同步写在循环体里，meow 只能在探针窗口的边界被观察到，
// 最坏白等一个窗口（1s）；本函数就是那次 review 的修法。
//
// 结果：meow 先成 → "meow"；probe 先成 → "direct"；probe 用尽 attempts 次仍
// 不成 → 探针腿出局（回调 onProbeExhausted，可 nil），只剩 meow 一条腿，
// 等到 ctx 到点（= 旧路径「无条件等 meowed」的语义）。
func raceFirst(ctx context.Context, meow <-chan struct{}, probe func(context.Context) error, attempts int, window time.Duration, onProbeExhausted func()) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // 返回即掐掉还可能发着探针的 goroutine

	probeOK := make(chan struct{}, 1)
	probeOut := make(chan struct{})
	go func() {
		for range attempts {
			if ctx.Err() != nil {
				return
			}
			if err := probe(ctx); err == nil {
				probeOK <- struct{}{} // 缓冲 1：调用方已返回也不会阻塞
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(window):
			}
		}
		close(probeOut)
	}()

	for {
		select {
		case <-meow:
			return "meow", nil
		case <-probeOK:
			return "direct", nil
		case <-probeOut:
			if onProbeExhausted != nil {
				onProbeExhausted()
			}
			select {
			case <-meow:
				return "meow", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// probeTSMP sends one TSMP ping through the tunnel to the server's tailcat
// address and waits for the reply within directProbeAttempt. The WireGuard
// handshake happens implicitly on the first outbound packet; server-side lazy
// registration admits it before (or without) the meow arriving.
func (c *Client) probeTSMP(parent context.Context) error {
	// 每次探针尝试都重新武装一次握手：尝试之间因此不是「重发同一个 initiation」，
	// 而是一次全新的握手（新 ephemeral/时间戳）。理由见 handshakeheal.go —— 重发同一
	// 个 initiation 会被响应方按防重放丢弃，首包丢了就白等整个重试周期。
	c.KickStaleHandshake(0)
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
// parallel registration goroutines (one at a time).
func (c *Client) startMeowBackground() {
	if c.meowedOnce.Load() || !c.meowInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.meowInFlight.Store(false)
		c.meowBackground()
	}()
}

// meowBackground 是后台补注册：快节奏一段（预算内 Client.ping 自带重发），
// 不成则转慢节奏低频重试，直到成功或 client 收工（bgDone）。不「首段失败即
// 放弃」的理由见 meowBgSlowInterval 的说明。
// 成功后不再调 advertiseEndpoints：客户端 onMeowed 回调（initLocked）已经
// 调过——旧版这里重复调过一次（review 指出）。
func (c *Client) meowBackground() {
	if c.meowedOnce.Load() {
		return
	}
	if err := c.meowAttempt(meowBgBudget); err == nil {
		c.meowRegistered()
		return
	}
	select {
	case <-c.bgDone:
		return
	default:
	}
	c.lb.logf("connect: meow 快节奏注册未成（%v 预算耗尽），转慢节奏重试（每 %v）——直连路径依赖注册",
		meowBgBudget, meowBgSlowInterval)
	for {
		select {
		case <-c.bgDone:
			return
		case <-time.After(meowBgSlowInterval):
		}
		if err := c.meowAttempt(meowBgBudget); err == nil {
			c.meowRegistered()
			return
		}
	}
}

// meowAttempt 做一段注册尝试（Client.ping 内部每秒重发），预算 timeout；
// 期间 client 收工（bgDone）会被立刻打断，不必等预算耗尽。
func (c *Client) meowAttempt(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		select {
		case <-c.bgDone:
			cancel()
		case <-ctx.Done():
		}
	}()
	_, err := c.ping(ctx)
	return err
}

// meowRegistered 是注册成功的收尾：闩住、满足旧路径的就绪语义（赛跑的另一
// 条腿还在等 meowWait）、促一次直连切换。
func (c *Client) meowRegistered() {
	c.meowedOnce.Store(true)
	c.upDone.Store(true)
	c.lb.logf("connect: meow 注册完成（出口拿到本机 disco key，促直连切换）")
	go c.kickDisco()
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
