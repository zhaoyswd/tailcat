//go:build windows

// term_service_windows.go — Windows 桩：终端服务需要 unix 的 pty/信号/进程树语义，
// 本平台不提供（启动时打一行警告并继续提供 exit-node/files）。
package main

import (
	"net"

	"tailscale.com/types/logger"
)

func termDisabledByEnv() bool { return false }

// termService 在 Windows 上只有形状（serve seam 需要同名类型，编译期保证两边方法集一致）。
type termService struct{}

func newTermService(logf logger.Logf) *termService { return &termService{} }

func (s *termService) Port() uint16         { return 0 }
func (s *termService) ShellText() string    { return "" }
func (s *termService) HistoryText() string  { return "" }
func (s *termService) ServeConn(c net.Conn) { _ = c.Close() }
func (s *termService) Close()               {}
