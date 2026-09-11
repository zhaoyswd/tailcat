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
	"os"
	"strconv"

	"github.com/peterbourgon/ff/v4"
)

var (
	flagListenPort    *int
	flagAdvertisePort *int
	flagForwardProxy  *string
)

// registerExitNodeFlags 由 newRootCommand 调用（App 构建里为空实现）。
func registerExitNodeFlags(rootFS *ff.FlagSet) {
	flagListenPort = rootFS.IntLong("listen-port", envInt("TAILCAT_LISTEN_PORT"), "pin the local UDP port the tunnel binds instead of choosing a random one. Pinning it lets a router, firewall, or local proxy match tailcat's own traffic by source port (e.g. send the punch socket direct while forwarded traffic keeps using a proxy) and keeps port mappings stable across restarts. The default can also be set with the TAILCAT_LISTEN_PORT environment variable")
	flagAdvertisePort = rootFS.IntLong("advertise-port", envInt("TAILCAT_ADVERTISE_PORT"), "external UDP port to advertise to peers as this node's endpoint, overriding the port discovered via UPnP/STUN. Set it when the router forwards a different external port to --listen-port. The default can also be set with the TAILCAT_ADVERTISE_PORT environment variable")
	flagForwardProxy = rootFS.StringLong("forward-via-proxy", os.Getenv("TAILCAT_FORWARD_PROXY"), "route the traffic this exit node relays through an upstream proxy, e.g. socks5://127.0.0.1:6153 or http://127.0.0.1:6152. Keeps tailcat's own punch socket direct, which matters when the proxy is a TUN-mode client. The default can also be set with the TAILCAT_FORWARD_PROXY environment variable")
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

// setupForwarding 按 --forward-via-proxy 建好转发用的代理配置（实现见 proxyforward.go）。
func setupForwarding() error {
	v := ""
	if flagForwardProxy != nil {
		v = *flagForwardProxy
	}
	return setupForwardingURL(v)
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
