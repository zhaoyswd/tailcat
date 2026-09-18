// buildcaps.go — 出口构建的能力标记（fork 专用，非上游代码）。
//
// 为什么需要：客户端（tier App）要能一眼分辨「这个地址来自增强版还是官方版」，
// 才能把只有增强版才有的功能（agent 会话、UDP 转发…）按实际情况展示，
// 而不是让用户点进去撞一堵墙。官方 tailcat 无法被改造，所以做法是**增强版
// 在地址里多写一个字段**：官方地址没有这个字段 ⇒ 客户端判成「官方/旧版」。
//
// 标记落在地址（token）里而不是运行时握手，因为：①官方出口根本没有可握手的
// 通道；②用户粘贴的地址是 App 唯一持有的、可离线判读的后端描述。
// 代价：同一个 key 在增强版下生成的地址串与官方版不同（能力位参与编码），
// 升级出口后要在 App 里重新粘贴一次地址才能让标记生效。
//
// 能力位是**构建级**声明，不是运行配置：出口编进了某项能力但运行时没启用时，
// 地址里照样有对应的位。需要按运行配置判断的（例如 files 服务开没开）由客户端
// 连上去试，见 App 侧的文件错误码。
package main

import (
	"strings"

	"github.com/tailscale/tailcat"
)

// buildTagMaxLen 印进地址的构建号长度上限（v0.6.0-udp.18 是 13 字符）。
// 超过就说明这不是发行版构建：go build 的版本是模块伪版本号
// （v0.6.1-0.20260917023950-067ae990d51f+dirty 这种），go install 的是
// 模块版本 —— 又长又没辨识度，白撑地址长度。
const (
	buildTagMaxLen = 20
	buildTagHead   = 8
	buildTagTail   = buildTagMaxLen - buildTagHead - 1 // 1 = 中间的 "~"
)

// forkBuildTag 印在地址里的构建号（诊断用），供客户端在日志/界面里显示
// 「出口是哪个构建」。发行版构建照抄 tag 原文（`v0.6.0-udp.18`），
// 便于与 Releases 页面对照。
func forkBuildTag() string {
	tag := strings.TrimSpace(versionString())
	if tag == "" {
		return "dev"
	}
	return truncateBuildTag(tag)
}

// truncateBuildTag 把超长版本串压成 `头8~尾11`。
// ⚠️ **不要**压成笼统的 "dev"：那会把「这是哪个构建」这条诊断信息整个抹掉 ——
// 真机上就表现成「手机里 Build=dev，查不出出口跑的是哪版，也看不出有没有重新部署」
//（2026-09-18 排查 #11 时踩到）。伪版本号/`-dirty` 这类长串的版本主体在头、
// 提交哈希与 dirty 标在尾，掐头留尾比一个 "dev" 有用得多。
func truncateBuildTag(tag string) string {
	if len(tag) <= buildTagMaxLen {
		return tag
	}
	return tag[:buildTagHead] + "~" + tag[len(tag)-buildTagTail:]
}

// forkCaps 本构建支持的可选能力。新增可选功能时在这里加一位
// （tailcat 库里的 Cap* 常量，App 侧同步解析）。
func forkCaps() tailcat.Caps {
	return tailcat.CapUDPForward | tailcat.CapFixedPort | tailcat.CapProxyForward
}
