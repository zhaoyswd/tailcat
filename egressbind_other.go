//go:build !cshared && !darwin && !linux

// egressbind_other.go — 其余平台的绑定实现（不支持 ⇒ 返回错误 ⇒ 该候选探不通 ⇒ 不绑）。
package tailcat

import "fmt"

func bindFDtoInterfaceImpl(fd int, network, ifName string) error {
	return fmt.Errorf("egress bind: 平台不支持")
}

func pinNetmonDefaultRoute(ifName string) {}

// forceBindToDevice：仅 Linux 有实际动作（设 TS_FORCE_LINUX_BIND_TO_DEVICE=1）。
func forceBindToDevice() {}
