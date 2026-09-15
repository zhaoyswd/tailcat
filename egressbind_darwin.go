//go:build !cshared && darwin

// egressbind_darwin.go — darwin 的绑定实现（IP_BOUND_IF / IPV6_BOUND_IF，按接口索引）。
package tailcat

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"
)

func bindFDtoInterfaceImpl(fd int, network, ifName string) error {
	ifc, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifName, err)
	}
	if strings.Contains(network, "6") {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifc.Index)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, ifc.Index)
}

// pinNetmonDefaultRoute 把 netns 的接口解析钉到 ifName（darwin 专属旋钮，仅此平台有实现）。
func pinNetmonDefaultRoute(ifName string) {
	netmon.UpdateLastKnownDefaultRouteInterface(ifName)
}

// forceBindToDevice：仅 Linux 有实际动作（设 TS_FORCE_LINUX_BIND_TO_DEVICE=1）。
func forceBindToDevice() {}
