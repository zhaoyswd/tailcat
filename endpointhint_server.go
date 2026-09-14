//go:build !cshared

// endpointhint_server.go — 出口侧「端点提示」的自网络观测访问器（CLI / 上游向）。
//
// 分档判定（见 cmd/tailcat/endpointhint_cli.go）需要 magicsock 内部的观测值：
// 最近一次 netcheck 报告（STUN 映射、是否随目标变化、观测次数）与 UPnP 拿到的
// 外部端口。这些都在 locoBackend/magicsock 里，CLI 够不着，所以在这里开一个
// 只读访问器。App 构建（cshared）不编译本文件：客户端永远不需要它。
package tailcat

import (
	"context"

	"tailscale.com/net/netcheck"
)

// EndpointHintObservation 是出口对自身网络环境的一次快照，供分档判定用。
type EndpointHintObservation struct {
	// Report 是最近一次 netcheck 报告（nil = 还没跑过，刚启动）。
	Report *netcheck.Report

	// MappedPort 是 UPnP/NAT-PMP/PCP 为 magicsock 的 UDP 端口拿到的外部端口
	//（0 = 没拿到）。只给端口不给 IP：外部 IP 以 STUN（Report.GlobalV4）为准
	//（本机那台路由器 GetExternalIPAddress 返回空，实测见 portmapping.go）。
	MappedPort uint16

	// ListenPort 是配置钉死的本地 UDP 监听端口（0 = 随机）。
	ListenPort uint16

	// AdvertisePort 是显式声明的外部端口（--advertise-port / TAILCAT_ADVERTISE_PORT，0 = 未设）。
	AdvertisePort uint16
}

// EndpointHintObservation 返回出口当前的自身网络观测快照。
// 必须在 Start 之后调用；之前调用返回零值快照。
func (s *Server) EndpointHintObservation() EndpointHintObservation {
	if s == nil || s.lb == nil {
		return EndpointHintObservation{}
	}
	obs := EndpointHintObservation{
		ListenPort:    s.lb.listenPort,
		AdvertisePort: s.lb.advertisePort,
	}
	s.lb.mu.Lock()
	obs.MappedPort = s.lb.mappedPort
	s.lb.mu.Unlock()
	if mc, ok := s.lb.sys.MagicSock.GetOK(); ok {
		obs.Report = mc.GetLastNetcheckReport(context.Background())
	}
	return obs
}
