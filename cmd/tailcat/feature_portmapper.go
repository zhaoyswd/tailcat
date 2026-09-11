// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_portmapper

package main

// 空导入把 feature/portmapper 的 init() 拉进来，它注册 UPnP / NAT-PMP / PCP 支持。
// 没有这个导入时 HookNewPortMapper 永远为空、magicsock 的 portMapper 为 nil ——
// 即使路由器的 UPnP 开着，隧道也从不申请端口映射（netcheck 报 portmap=?）。
// 用 build tag 隔离：App 侧核带着 ts_omit_portmapper（省体积、手机在蜂窝上也用不上），
// 出口 CLI 的 release 构建去掉该 tag 即自动获得 UPnP 能力。
//
// 注意：发现走 SSDP 组播，必须能从**物理接口**发出去；若出口主机前面还有一层
// TUN 型代理（Surge 等）抢了默认路由，SSDP 出不去，UPnP 仍然拿不到映射
// （实测：默认路由无响应、绑定 en0 0.11s 就拿到路由器响应）——那种环境请改用
// 路由器上的静态端口转发。
import _ "tailscale.com/feature/portmapper"
