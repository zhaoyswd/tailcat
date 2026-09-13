//go:build !cshared

// flags_cli.go — 出口侧的几个 CLI 开关（CLI / 上游向；App 构建不编译本文件）。
//
// 为什么要单独一个文件：这些 flag 只在 `serve`（尤其是 exit-node）里用得到，
// 而它们的**声明与注册**原先写在共享的 tailcat.go 里 —— 那样 App 核也会把
// flag 注册代码与帮助文本链接进去（实测 .so 里能 grep 到 `forward-via-proxy` 等字符串）。
// 现在共享文件只通过下面的取值函数访问：App 构建由 proxyforward_stub.go 提供同名实现，
// 于是「CLI 的东西不进 App」在编译期就成立（见 tools/tailcat/PATCHES.md §2.3）。
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/peterbourgon/ff/v4"
	"tailscale.com/tailcfg"
)

var (
	flagListenPort    *int
	flagAdvertisePort *int
	flagForwardProxy  *string
	flagForwardUDP    *string
)

// registerExitNodeFlags 由 newRootCommand 调用（App 构建里为空实现）。
func registerExitNodeFlags(rootFS *ff.FlagSet) {
	flagListenPort = rootFS.IntLong("listen-port", envInt("TAILCAT_LISTEN_PORT"), "pin the local UDP port the tunnel binds instead of choosing a random one. Pinning it lets a router, firewall, or local proxy match tailcat's own traffic by source port (e.g. send the punch socket direct while forwarded traffic keeps using a proxy) and keeps port mappings stable across restarts. The default can also be set with the TAILCAT_LISTEN_PORT environment variable")
	flagAdvertisePort = rootFS.IntLong("advertise-port", envInt("TAILCAT_ADVERTISE_PORT"), "external UDP port to advertise to peers as this node's endpoint, overriding the port discovered via UPnP/STUN. Set it when the router forwards a different external port to --listen-port. The default can also be set with the TAILCAT_ADVERTISE_PORT environment variable")
	flagForwardProxy = rootFS.StringLong("forward-via-proxy", os.Getenv("TAILCAT_FORWARD_PROXY"), "route the traffic this exit node relays through an upstream proxy, e.g. socks5://127.0.0.1:6153 or http://127.0.0.1:6152. Keeps tailcat's own punch socket direct, which matters when the proxy is a TUN-mode client. The default can also be set with the TAILCAT_FORWARD_PROXY environment variable")
	flagForwardUDP = rootFS.StringLong("forward-udp", os.Getenv("TAILCAT_FORWARD_UDP"), "how the UDP this exit node relays should use --forward-via-proxy: 'auto' (default) probes the proxy once (SOCKS5 UDP ASSOCIATE + a STUN probe) and uses it when it really relays datagrams; 'on' requires it and exits if it does not; 'off' never proxies UDP. Only socks5:// proxies can carry UDP, and the proxy server itself must support it (Surge does not; mihomo/sing-box/Xray do). The default can also be set with the TAILCAT_FORWARD_UDP environment variable")
}

// listenPortFlag / advertisePortFlag 供共享的 serve 路径取值（未注册时返回 0）。
func listenPortFlag() int {
	if flagListenPort == nil {
		return 0
	}
	return *flagListenPort
}

func advertisePortFlag() int {
	if flagAdvertisePort == nil {
		return 0
	}
	return *flagAdvertisePort
}

// setupForwarding 按 --forward-via-proxy / --forward-udp 建好转发用的代理配置，
// 并把「UDP 代理解析到哪一步」写进日志。
//
// reg 是本次使用的 DERP 区域 —— 它的节点自带 STUN，正好当能力探测的字面 IP 目标。
// --forward-udp=on 在这里同步探测：不接受静默降级，代理扛不了 UDP 就直接退出。
func setupForwarding(reg *tailcfg.DERPRegion) error {
	v := ""
	if flagForwardProxy != nil {
		v = *flagForwardProxy
	}
	if err := setupForwardingURL(v); err != nil {
		return err
	}
	modeStr := ""
	if flagForwardUDP != nil {
		modeStr = *flagForwardUDP
	}
	mode, err := parseForwardUDPMode(modeStr)
	if err != nil {
		return err
	}
	forwardUDPModeValue = mode
	setUDPProbeTargets(derpSTUNTargets(reg))
	if forwardProxy == nil || mode == forwardUDPOff {
		return nil
	}
	logf := forwardLogf()
	if forwardProxy.Scheme != "socks5" && forwardProxy.Scheme != "socks5h" {
		if mode == forwardUDPOn {
			return fmt.Errorf("--forward-udp=on 但 --forward-via-proxy=%v 不是 socks5：%s 代理不能承载 UDP", forwardProxy.Scheme, forwardProxy.Scheme)
		}
		logf("forward-udp: 代理 %v 是 %s://（HTTP 代理不能承载 UDP）—— auto 模式下被转发的 UDP 直出", forwardProxy.Host, forwardProxy.Scheme)
		return nil
	}
	if mode == forwardUDPAuto {
		logf("forward-udp: auto —— 第一次需要转发 UDP 时探测代理 %v 是否真的中继 UDP（探测目标：%v）", forwardProxy.Host, getUDPProbeTargets())
		return nil
	}
	// on：启动时同步探测，失败即明确退出（不静默降级）。
	st := udpProxyStatusNow(context.Background())
	if st.state != udpProxySupported {
		return fmt.Errorf("--forward-udp=on：代理 %v %s（%s）", forwardProxy.Host, st.state, st.detail)
	}
	return nil
}

// envInt 读一个整数环境变量（供 flag 默认值使用；无效或未设返回 0）。
func envInt(name string) int {
	v := os.Getenv(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n >= 65536 {
		return 0
	}
	return n
}
