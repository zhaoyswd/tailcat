//go:build windows

// term_agent_windows.go — Windows 上不做 agent 检测（终端服务本身也不支持，见 term_service_windows.go）。
package main

// termPlatformSupported 报告本平台是否支持终端服务（Windows = 否）。
func termPlatformSupported() bool { return false }
