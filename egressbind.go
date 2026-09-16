//go:build !cshared

// egressbind.go — 出口的「物理上行绑定」（openspec change `bind-interface-probe`，CLI/上游向）。
//
// 问题（坑 29）：TUN 型代理（Surge 增强模式等）把 utun 设为全局默认路由后，未绑定 socket 的
// UDP 会被代理用自己的 socket 重发——源端口与 IP 都不是 tailcat 的 ⇒ STUN 学到代理的映射、
// 对端 disco ping 回不来 ⇒ 直连永远建不起来。共享文件 tailcat.go 的 createEngine 历史上把
// netns 进程级关闭（客户端无 TUN 可避 + 回退坑 loopback netcheck），出口因此从未被绑定。
//
// 机制（2026-09-15 勘察定稿，零上游补丁）：出口在绑定生效时**保持 netns 启用**——magicsock
// 的 UDP 与 derphttp 的 TCP 本来就都走 netns.Control，启用后自然同进同退；darwin 上再用
// netmon.UpdateLastKnownDefaultRouteInterface 把 netns 的接口解析**钉到探针赢家**（该值正是
// OSDefaultRoute 的优选来源）。本机实测：绑 en0 的 socket STUN 外显 114.242.60.128（真实
// 公网），未绑定外显 203.175.12.168（代理）。
//
// 判定以数据可通为准：候选网卡逐个「绑定后发 DNS 探针」验证（anycast 字面 IP、随机 TXID、
// 应答源必须等于所查 resolver——路由器劫持代答不算）；全不通 = 保持 netns 关闭（= 现状），
// 绝不 fatal。Linux 无 Update 旋钮：绑定目标只能是 netmon 的默认路由解析，探针只做验证门控。
package tailcat

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
)

// 探针参数：三个公共 anycast DNS（国内国外都通）、并发、总时限。
// TAILCAT_BIND_PROBE_DNS 可覆盖（逗号分隔的 ip[:port] 列表）。
var defaultProbeDNS = []string{"223.5.5.5", "119.29.29.29", "1.1.1.1"}

const (
	probeTimeout     = 1 * time.Second
	switchDwellTime  = 30 * time.Second // 迟滞粘性窗口：切换后这么久内不再换
	failsBeforeReval = 2                // 当前绑定连续几轮复核失败才触发重评估
)

// virtualIfPrefixes 是候选黑名单——只是省时降噪，终审权在探针（漏网的多余网卡探不通自然出局）。
var virtualIfPrefixes = []string{
	"lo", "utun", "tun", "tap", "wg", "tailscale", "awdl", "llw", "anpi",
	"bridge", "vmenet", "docker", "virbr", "veth", "br-", "ap",
}

// IsVirtualInterface reports whether name looks like a virtual interface
// (loopback/tun/bridge/docker/…), per the egressbind candidate blacklist.
// Exported for the endpoint-hint LAN collector, which must skip virtual
// interfaces so container bridges don't leak into addresses as LAN hints.
func IsVirtualInterface(name string) bool { return isVirtualInterface(name) }

func isVirtualInterface(name string) bool {
	for _, p := range virtualIfPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// enumerateCandidates 返回候选物理网卡名（up + 有 IPv4 地址 + 不在黑名单）。纯函数，单测覆盖。
func enumerateCandidates(ifaces []net.Interface) []string {
	var out []string
	for _, ifc := range ifaces {
		if isVirtualInterface(ifc.Name) {
			continue
		}
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		hasV4 := false
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				hasV4 = true
				break
			}
		}
		if hasV4 {
			out = append(out, ifc.Name)
		}
	}
	return out
}

// probeDNSPacket 构造一个最小 DNS 查询（随机 TXID、查询随机子域的 A 记录）。
// 应答内容无关紧要（NOERROR/NXDOMAIN 都算通）——能收到 TXID 匹配、来源正确的应答即证明
// 该路径能承载我们自己的 UDP 往返。
func probeDNSPacket(txid uint16, qname string) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, txid)
	b = binary.BigEndian.AppendUint16(b, 0x0100) // RD=1
	b = binary.BigEndian.AppendUint16(b, 1)      // QDCOUNT=1
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	for _, label := range strings.Split(qname, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1) // A
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	return b
}

// dnsProbeViaConn 从给定（已绑定的）UDP socket 向 targets 并发发探针，任一应答即胜。
// 校验：应答 TXID 匹配 且 应答源地址 == 所查 resolver（挡路由器劫持代答）。
// 返回胜出目标与往返延迟；全超时返回 ok=false。
func dnsProbeViaConn(conn *net.UDPConn, targets []netip.AddrPort, timeout time.Duration) (win netip.AddrPort, rtt time.Duration, ok bool) {
	if len(targets) == 0 {
		return netip.AddrPort{}, 0, false
	}
	txid := uint16(rand.Int31n(1 << 16))
	qname := fmt.Sprintf("%08x.probe.invalid", rand.Int31())
	pkt := probeDNSPacket(txid, qname)
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	start := time.Now()
	for _, t := range targets {
		_, _ = conn.WriteToUDPAddrPort(pkt, t)
	}
	buf := make([]byte, 512)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return netip.AddrPort{}, 0, false // 超时/错误
		}
		if n < 12 {
			continue
		}
		if binary.BigEndian.Uint16(buf) != txid {
			continue
		}
		if !containsTarget(targets, from) {
			continue // 源不符（劫持代答等）：不算证据，继续等
		}
		return from, time.Since(start), true
	}
}

func containsTarget(ts []netip.AddrPort, a netip.AddrPort) bool {
	for _, t := range ts {
		if t == a {
			return true
		}
	}
	return false
}

// probeTargets 解析配置（env 覆盖）为端口 53 的 AddrPort 列表。
func probeTargets() []netip.AddrPort {
	strs := defaultProbeDNS
	if v := os.Getenv("TAILCAT_BIND_PROBE_DNS"); v != "" {
		strs = strings.Split(v, ",")
	}
	var out []netip.AddrPort
	for _, s := range strs {
		s = strings.TrimSpace(s)
		if !strings.Contains(s, ":") {
			s += ":53"
		}
		if ap, err := netip.ParseAddrPort(s); err == nil && ap.IsValid() {
			out = append(out, ap)
		}
	}
	return out
}

// bindFDtoInterface 把 fd 绑定到指定接口。darwin 实现见本文件（IP_BOUND_IF/IPV6_BOUND_IF），
// Linux（SO_BINDTODEVICE）见 egressbind_linux.go，其余平台见 egressbind_other.go。
func bindFDtoInterface(fd int, network, ifName string) error {
	return bindFDtoInterfaceImpl(fd, network, ifName)
}

// probeCandidate 对单个候选建 UDP socket、绑定后发探针。返回 RTT 与结论。
// 绑定失败（接口消失等）按探不通处理。
func probeCandidate(ifName string, targets []netip.AddrPort, timeout time.Duration) (rtt time.Duration, ok bool, err error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		cerr := c.Control(func(fd uintptr) {
			serr = bindFDtoInterface(int(fd), network, ifName)
		})
		if cerr != nil {
			return cerr
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		return 0, false, err
	}
	defer pc.Close()
	conn := pc.(*net.UDPConn)
	_, rtt, ok = dnsProbeViaConn(conn, targets, timeout)
	return rtt, ok, nil
}

// bindState 是出口绑定的当前状态。
type bindState struct {
	mu      sync.Mutex
	ifName  string // 当前绑定（"" = 未绑）
	since   time.Time
	failStk int
}

var egressBindSt = &bindState{}

// egressBindActive 供共享的 createEngine 查询：绑定生效时跳过 netns.SetEnabled(false)。
func egressBindActive() bool {
	egressBindSt.mu.Lock()
	defer egressBindSt.mu.Unlock()
	return egressBindSt.ifName != ""
}

func egressBindInterface() string {
	egressBindSt.mu.Lock()
	defer egressBindSt.mu.Unlock()
	return egressBindSt.ifName
}

func setEgressBind(name string) {
	egressBindSt.mu.Lock()
	defer egressBindSt.mu.Unlock()
	egressBindSt.ifName = name
	egressBindSt.since = time.Now()
	egressBindSt.failStk = 0
}

func bindSince() time.Time {
	egressBindSt.mu.Lock()
	defer egressBindSt.mu.Unlock()
	return egressBindSt.since
}

func bindFailStk() int {
	egressBindSt.mu.Lock()
	defer egressBindSt.mu.Unlock()
	return egressBindSt.failStk
}

func bindIncrFail() int {
	egressBindSt.mu.Lock()
	defer egressBindSt.mu.Unlock()
	egressBindSt.failStk++
	return egressBindSt.failStk
}

// startEgressBind 由 createLocoServer 在 createEngine **之前**调用（App 构建为空实现，
// 见 egressbind_stub.go）。mode: "off"（默认）| "physical" | "<接口名>"。
// 初始评估同步完成（决定 netns 开关与解析，有界 ~1s）；之后转入事件驱动 + 周期复核的监控循环。
func startEgressBind(lb *locoBackend, mode string) {
	if mode == "" || mode == "off" {
		return
	}
	targets := probeTargets()
	pinned := mode != "physical"
	// 初始评估（并发探针，有界）：必须在 createEngine 前落地，netns 的开关/解析才对得上。
	winner, basis := evaluateBind(mode, pinned, targets, lb)
	applyBindDecision(lb, winner, basis)
	go egressBindMonitor(lb, mode, pinned, targets)
}

// egressBindMonitor：复核当前绑定（探针），失败达阈值或收到网络变化事件时重评估。
func egressBindMonitor(lb *locoBackend, mode string, pinned bool, targets []netip.AddrPort) {
	kick := make(chan struct{}, 1)
	if m, ok := lb.sys.NetMon.GetOK(); ok {
		m.RegisterChangeCallback(func(*netmon.ChangeDelta) {
			select {
			case kick <- struct{}{}:
			default:
			}
		})
	}
	for {
		select {
		case <-kick:
		case <-time.After(monitorTick()):
		}
		cur := egressBindInterface()
		if cur != "" {
			if _, ok, _ := probeCandidate(cur, targets, probeTimeout); ok {
				if bindFailStk() > 0 {
					lb.logf("bind-interface: %s 复核恢复", cur)
					setEgressBind(cur) // 清零失败计数
				}
				continue
			}
			fails := bindIncrFail()
			if fails < failsBeforeReval || time.Since(bindSince()) < switchDwellTime {
				continue // 未达阈值 / 粘性窗口内：不动
			}
			lb.logf("bind-interface: %s 连续 %d 轮复核失败，重新评估", cur, fails)
		}
		winner, basis := evaluateBind(mode, pinned, targets, lb)
		applyBindDecision(lb, winner, basis)
	}
}

func monitorTick() time.Duration {
	if egressBindInterface() != "" {
		return 60 * time.Second // 绑定中：复核节拍与 netcheck 同量级
	}
	return 15 * time.Second // 未绑：等网络起来的重试节拍
}

// evaluateBind 枚举候选、**并发**逐个探针，返回赢家与判定依据行。
func evaluateBind(mode string, pinned bool, targets []netip.AddrPort, lb *locoBackend) (winner string, basis string) {
	if len(targets) == 0 {
		return "", "无有效探针目标（检查 TAILCAT_BIND_PROBE_DNS）"
	}
	var cands []string
	if pinned {
		cands = []string{mode}
	} else {
		ifaces, err := net.Interfaces()
		if err != nil {
			return "", fmt.Sprintf("枚举网卡失败: %v", err)
		}
		cands = enumerateCandidates(ifaces)
	}
	if len(cands) == 0 {
		return "", "无候选物理网卡"
	}
	// netmon 解析的默认接口作为优先级提示（darwin 的 delegated 解析在这套缓存里）。
	hint := ""
	if lb != nil {
		if m, ok := lb.sys.NetMon.GetOK(); ok {
			if st := m.InterfaceState(); st != nil && st.DefaultRouteInterface != "" {
				hint = st.DefaultRouteInterface
			}
		}
	}
	type result struct {
		name string
		rtt  time.Duration
		ok   bool
		err  error
	}
	results := make([]result, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Add(1)
		go func(i int, c string) {
			defer wg.Done()
			rtt, ok, err := probeCandidate(c, targets, probeTimeout)
			results[i] = result{c, rtt, ok, err}
		}(i, c)
	}
	wg.Wait()

	var lines []string
	var passed []result
	for _, r := range results {
		switch {
		case r.err != nil:
			lines = append(lines, fmt.Sprintf("%s:绑定失败(%v)", r.name, r.err))
		case r.ok:
			passed = append(passed, r)
			lines = append(lines, fmt.Sprintf("%s:%dms", r.name, r.rtt.Milliseconds()))
		default:
			lines = append(lines, fmt.Sprintf("%s:探针无应答", r.name))
		}
	}
	basis = fmt.Sprintf("目标=%s 候选[%s]", joinAddrs(targets), strings.Join(lines, " "))
	if len(passed) == 0 {
		return "", basis + " ⇒ 不绑（保持现状）"
	}
	// 排序：netmon 提示优先，其次 RTT。
	best := passed[0]
	for _, p := range passed[1:] {
		pHint, bHint := p.name == hint, best.name == hint
		if pHint && !bHint || pHint == bHint && p.rtt < best.rtt {
			best = p
		}
	}
	if hint != "" && best.name == hint {
		basis += " 解析=" + hint
	}
	return best.name, basis
}

func joinAddrs(ts []netip.AddrPort) string {
	var sb strings.Builder
	for i, t := range ts {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(t.String())
	}
	return sb.String()
}

// applyBindDecision 把赢家落地：darwin 钉 netns 解析 + 保持 netns 启用 + Rebind 生效；
// 赢家为空则解绑（netns 关闭 = 回到现状）。迟滞由调用方（监控循环的阈值判断）保证。
func applyBindDecision(lb *locoBackend, winner, basis string) {
	cur := egressBindInterface()
	if winner == "" {
		if cur != "" {
			lb.logf("bind-interface: 解除绑定 %s（%s）", cur, basis)
			setEgressBind("")
			netns.SetEnabled(false)
			rebindMagicsock(lb)
		} else if basis != "" {
			lb.logf("bind-interface: %s", basis)
		}
		return
	}
	if cur == winner {
		return // 无变化
	}
	// darwin：钉住 netns 的解析（OSDefaultRoute 优选读这个值；空串撤不掉，解绑走 SetEnabled(false)）。
	pinNetmonDefaultRoute(winner)
	forceBindToDevice()
	setEgressBind(winner)
	netns.SetEnabled(true)
	lb.logf("bind-interface: physical → %s（%s）", winner, basis)
	rebindMagicsock(lb)
}

// rebindMagicsock 重建 UDP socket（经 netns.Control 读新解析/新开关）并刷新选路。
func rebindMagicsock(lb *locoBackend) {
	if mc, ok := lb.sys.MagicSock.GetOK(); ok {
		mc.Rebind()
		mc.ReSTUN("egress-bind")
	}
	if lb.nm != nil {
		go lb.advertiseEndpoints()
	}
}
