// localaddr.go — 本机地址采集时的「不可达地址」过滤（App 线 + CLI 线共用）。
//
// 背景（2026-09-18 真机事故）：magicsock 的 LocalAddrs 是「本机所有接口的地址」，
// onEngineStatus 把它们**全部**塞进 b.eps，再由 advertiseEndpoints 经 CallMeMaybe
// 通告给对端当直连候选。虚拟网卡上的地址（容器网桥、虚拟机网段、代理 TUN、以及
// **我们自己的隧道地址**）对端根本不可达，却会被当成候选反复探测：真机日志里出口
// 拿着 Mac 的 bridge101（192.168.215.0，还是个网段地址）、utun4（198.18.0.1，代理
// TUN）、手机自己的隧道地址 10.126.126.2 每 5s ping 一次，全是
// `sendto: no route to host`（8 分钟 320+ 行）。
//
// 三道判据（叠加，只影响「通告给对端」的集合，不影响本机发包选路）：
//
//	① 接口名黑名单：docker0 / bridge* / utun* / vpn-tun / ancowlan0 / hw_sate_vnet …
//	   —— 与出口的物理上行绑定（egressbind.go）共用同一份名单，判据单一真源。
//	② 网段地址：接口地址恰好是该网段的网络地址（192.168.215.0/24 这种）。配置错误
//	   （手工把 /24 网段里的 .0 配到网卡上）会让它出现在接口地址里，但它不是任何
//	   主机地址；对端 ARP 不到，只会得到 EHOSTUNREACH。
//	③ 自己的隧道地址（tailcat 地址空间里那个）：通告它等于让对端往隧道里套隧道。
package tailcat

import (
	"net"
	"net/netip"
	"slices"
	"strings"
)

// virtualIfPrefixes 是接口名前缀黑名单：命中即认为该接口是虚拟接口，其地址不
// 作为直连候选通告出去。只做降噪，不做安全边界（真判据是「对端能不能到」，
// 那要由客户端的探测与发送失败降权来裁决，见依赖补丁的 noteSendFailure）。
var virtualIfPrefixes = []string{
	// 回环与点对点隧道
	"lo", "utun", "tun", "tap", "wg", "tailscale", "ipsec", "ppp", "vpn", "ancowlan",
	// Apple 专属
	"awdl", "llw", "anpi",
	// 虚拟网桥 / 容器 / 虚拟机
	"bridge", "vmenet", "vmnet", "docker", "virbr", "veth", "br-",
	// 无线/网络共享的从接口
	"ap",
	// 鸿蒙系统接口（实测：hw_sate_vnet 卫星链路、ifb 流量镜像、dummy、tunl/vti/sit）
	"hw_sate_vnet", "ifb", "dummy", "tunl", "vti", "sit", "ip6tnl", "rmnet_",
}

// isVirtualInterface reports whether name looks like a virtual interface.
func isVirtualInterface(name string) bool {
	for _, p := range virtualIfPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// IsVirtualInterface reports whether name looks like a virtual interface
// (loopback/tun/bridge/docker/…). Exported for the egress-bind candidate
// blacklist and the endpoint-hint LAN collector.
func IsVirtualInterface(name string) bool { return isVirtualInterface(name) }

// ifaceAddrs 是 localAddrExclusions 的输入单元：接口名/标志/已解析地址
// （net.Interface 的 Addrs 是系统调用、不可注入，纯函数收三元组以便单测）。
type ifaceAddrs struct {
	name  string
	flags net.Flags
	addrs []net.Addr
}

// localAddrExclusions 返回「不该通告给对端」的地址集合，值为被排除的原因（日志用）。
// extra 是调用方额外的排除项（例如自己的隧道地址）。同一个地址可能命中多条判据
// （虚拟接口上的网段地址、隧道接口上的隧道地址），取**最具体**的那条：
// 自己的隧道地址 > 虚拟接口 > 网段地址。
func localAddrExclusions(ifaces []ifaceAddrs, extra []netip.Addr) map[netip.Addr]string {
	const (
		prioNetworkBase = 1
		prioVirtualIf   = 2
		prioSelfTunnel  = 3
	)
	out := map[netip.Addr]string{}
	prio := map[netip.Addr]int{}
	set := func(addr netip.Addr, p int, why string) {
		if cur, ok := prio[addr]; ok && cur >= p {
			return
		}
		prio[addr] = p
		out[addr] = why
	}
	for _, a := range extra {
		if a.IsValid() {
			set(a.Unmap(), prioSelfTunnel, "自己的隧道地址")
		}
	}
	for _, ifc := range ifaces {
		virtual := isVirtualInterface(ifc.name)
		for _, a := range ifc.addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if virtual {
				set(addr, prioVirtualIf, "虚拟接口 "+ifc.name)
				continue
			}
			// 网段地址（网络地址）不是主机地址：手工把 /24 里的 .0 配上就会这样。
			if isNetworkBase(addr, ipn.Mask) {
				set(addr, prioNetworkBase, "网段地址（网络地址）")
			}
		}
	}
	return out
}

// isNetworkBase reports whether addr is the network address of its own subnet, i.e.
// a misconfigured host address (e.g. 192.168.215.0 with a /24 netmask): the host
// bits are all zero. /31, /32 and their v6 equivalents are point-to-point/host
// assignments where every address is a legal host address, so they are skipped.
func isNetworkBase(addr netip.Addr, mask net.IPMask) bool {
	ones, bits := mask.Size()
	if ones <= 0 || ones >= bits-1 {
		return false
	}
	if addr.Is4() {
		if len(mask) != 4 {
			return false
		}
		b := addr.As4()
		for i := range b {
			if b[i]&^mask[i] != 0 {
				return false
			}
		}
		return true
	}
	if len(mask) != 16 {
		return false
	}
	b := addr.As16()
	for i := range b {
		if b[i]&^mask[i] != 0 {
			return false
		}
	}
	return true
}

// localAddrExclusionsNow 采集当前系统的排除集合；extra 见 localAddrExclusions。
func localAddrExclusionsNow(extra ...netip.Addr) map[netip.Addr]string {
	sysIfs, err := net.Interfaces()
	if err != nil {
		return localAddrExclusions(nil, extra)
	}
	ifaces := make([]ifaceAddrs, 0, len(sysIfs))
	for _, ifc := range sysIfs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		ifaces = append(ifaces, ifaceAddrs{name: ifc.Name, flags: ifc.Flags, addrs: addrs})
	}
	return localAddrExclusions(ifaces, extra)
}

// skippedAddrsSummary 把排除集合整理成一行稳定的诊断串（按地址排序）：调用方拿它
// 与上一次的快照比较，只在集合变化时打日志（onEngineStatus 每拍都跑）。
func skippedAddrsSummary(m map[netip.Addr]string) string {
	if len(m) == 0 {
		return ""
	}
	addrs := make([]netip.Addr, 0, len(m))
	for a := range m {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	var sb strings.Builder
	for i, a := range addrs {
		if i > 0 {
			sb.WriteString("、")
		}
		sb.WriteString(a.String())
		sb.WriteString("（")
		sb.WriteString(m[a])
		sb.WriteString("）")
	}
	return sb.String()
}

// upnpIPv4Candidates 从「接口名 → 地址」快照里挑出可能用于 UPnP 的内网 IPv4 候选。
// 判据与通告过滤同源（isVirtualInterface，见文件头）：bridge/docker/utun 上的地址
// 拨不到路由器，却会被 SSDP 逐个试 —— 白白吃掉 5s 超时，日志还会写成一串
// `sendto: no route to host`（真机 2026-09-18：Mac 出口的候选列表里混着
// bridge100/bridge101，其中就有那个 192.168.215.0）。输出按地址排序，日志稳定。
func upnpIPv4Candidates(interfaceIPs map[string][]netip.Prefix) []netip.Addr {
	out := make([]netip.Addr, 0, len(interfaceIPs))
	for name, ips := range interfaceIPs {
		if isVirtualInterface(name) {
			continue
		}
		for _, ip := range ips {
			a := ip.Addr().Unmap()
			if a.Is4() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsUnspecified() &&
				!a.IsMulticast() {
				out = append(out, a)
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}
