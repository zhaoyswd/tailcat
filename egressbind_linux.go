//go:build !cshared && linux

// egressbind_linux.go — Linux 的绑定实现（SO_BINDTODEVICE，需 CAP_NET_RAW）。
// 注意 tailscale netns 在非 root 下会静默吞掉 setsockopt 失败 ⇒ 绑定是否真生效以
// 行为判据为准（v4a 端口自洽，endpoint-hint 的③档检查天然承担这个观测位）。
package tailcat

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func bindFDtoInterfaceImpl(fd int, network, ifName string) error {
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifName); err != nil {
		return fmt.Errorf("SO_BINDTODEVICE %q: %w", ifName, err)
	}
	return nil
}

var _ = net.InterfaceByName // 保持 net 引用（与其它平台文件对齐）
