//go:build !cshared

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/ipv4"

	"tailscale.com/types/logger"
)

// 出口节点（Server）的 UPnP 端口映射。
//
// 为什么不用 tailscale 的 net/portmapper：它给设备打分时会校验 GetStatusInfo /
// GetExternalIPAddress，并在若干「常见控制路径」上探测；家用路由器常有非标准实现
// （实测某路由器 GetExternalIPAddress 返回空值、控制路径是私有的 /ctrlu/<uuid>/...），
// 于是它直接放弃、也不报错，取外面看就是「路由器 UPnP 开着但没用」。
// 出口真正需要的只有两件事：SSDP 找到 IGD、AddPortMapping 把 magicsock 的 UDP 端口映射出去。
// 这段代码只做这两件事，并且在失败时**明确打日志**，让人知道该去路由器上手动转发。

const (
	ssdpAddr        = "239.255.255.250:1900"
	ssdpST          = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
	upnpMapDesc     = "tailcat-exit"
	upnpTimeout     = 5 * time.Second
	upnpRenewPeriod = 30 * time.Minute
)

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type upnpDeviceNode struct {
	Services []upnpService    `xml:"serviceList>service"`
	Devices  []upnpDeviceNode `xml:"deviceList>device"`
}

type upnpRoot struct {
	Device upnpDeviceNode `xml:"device"`
}

// igd 是一个可用的 WAN 连接服务（WANIPConnection / WANPPPConnection）。
type igd struct {
	controlURL  string
	serviceType string
}

// discoverIGD 用 SSDP 找到网关的 UPnP 描述，再解析出 WAN 连接服务的控制地址。
func discoverIGD(ctx context.Context, localIP netip.Addr, logf logger.Logf) (*igd, error) {
	loc, err := ssdpLocation(ctx, localIP)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("解析 LOCATION %q: %w", loc, err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", loc, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("取描述文件: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var root upnpRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("解析描述文件: %w", err)
	}
	if svc := findWANService(root.Device); svc != nil {
		u, err := base.Parse(svc.ControlURL)
		if err != nil {
			return nil, fmt.Errorf("解析 controlURL %q: %w", svc.ControlURL, err)
		}
		return &igd{controlURL: u.String(), serviceType: svc.ServiceType}, nil
	}
	return nil, fmt.Errorf("描述文件里没有 WANIPConnection/WANPPPConnection 服务")
}

func findWANService(d upnpDeviceNode) *upnpService {
	for i := range d.Services {
		st := d.Services[i].ServiceType
		if strings.Contains(st, "WANIPConnection") || strings.Contains(st, "WANPPPConnection") {
			return &d.Services[i]
		}
	}
	for i := range d.Devices {
		if svc := findWANService(d.Devices[i]); svc != nil {
			return svc
		}
	}
	return nil
}

// ssdpLocation 发一次 SSDP M-SEARCH，取第一个 IGD 的 LOCATION。
// localIP 非零时把 socket 绑在该地址上：组播发现必须从**物理接口**出去，
// 否则在有 TUN 型代理（Surge 等）抢了默认路由的机器上，发现报文永远出不去。
func ssdpLocation(ctx context.Context, localIP netip.Addr) (string, error) {
	var laddr *net.UDPAddr
	if localIP.IsValid() {
		laddr = &net.UDPAddr{IP: localIP.AsSlice()}
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return "", fmt.Errorf("SSDP socket: %w", err)
	}
	defer conn.Close()
	// 组播出口网卡必须显式指定：只 bind 源地址时，macOS 仍可能把报文交给默认路由
	// （有 TUN 型代理时就是那条隧道），实测这就是「python 能收到、Go 收不到」的差别。
	if localIP.IsValid() {
		if ifi := ifaceForIP(localIP); ifi != nil {
			pc := ipv4.NewPacketConn(conn)
			if err := pc.SetMulticastInterface(ifi); err != nil {
				return "", fmt.Errorf("指定组播出口 %v: %w", ifi.Name, err)
			}
			_ = pc.SetMulticastTTL(2)
		}
	}
	raddr, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return "", err
	}
	msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\nST: " + ssdpST + "\r\n\r\n"
	deadline := time.Now().Add(upnpTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.WriteToUDP([]byte(msg), raddr); err != nil {
		return "", fmt.Errorf("发送 M-SEARCH: %w", err)
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return "", fmt.Errorf("没有 IGD 响应（路由器未开 UPnP，或组播出不去）: %w", err)
		}
		if loc := headerValue(string(buf[:n]), "LOCATION"); loc != "" {
			return loc, nil
		}
	}
}

// ifaceForIP 找出拥有该地址的网卡（SSDP 的组播出口）。
func ifaceForIP(ip netip.Addr) *net.Interface {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifis {
		addrs, err := ifis[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if got, ok := netip.AddrFromSlice(ipn.IP); ok && got.Unmap() == ip.Unmap() {
				return &ifis[i]
			}
		}
	}
	return nil
}

func headerValue(resp, key string) string {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > len(key)+1 && strings.EqualFold(line[:len(key)], key) && line[len(key)] == ':' {
			return strings.TrimSpace(line[len(key)+1:])
		}
	}
	return ""
}

func (g *igd) soap(ctx context.Context, action string, args ...[2]string) (string, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"`)
	b.WriteString(` s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:`)
	b.WriteString(action)
	b.WriteString(` xmlns:u="`)
	b.WriteString(g.serviceType)
	b.WriteString(`">`)
	for _, kv := range args {
		b.WriteString("<" + kv[0] + ">" + kv[1] + "</" + kv[0] + ">")
	}
	b.WriteString("</u:" + action + "></s:Body></s:Envelope>")

	req, err := http.NewRequestWithContext(ctx, "POST", g.controlURL, strings.NewReader(b.String()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.serviceType+"#"+action+`"`)
	// 家用路由器的嵌入式 HTTP 服务很挑：Go 默认的 keep-alive/gzip 会让它直接关连接
	// （实测报 EOF，而同样请求用 urllib 发就正常）。显式 Connection: close + UA 即可。
	req.Close = true
	req.Header.Set("User-Agent", "tailcat/upnp")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return string(body), fmt.Errorf("%s: HTTP %d: %s", action, resp.StatusCode, firstLine(string(body)))
	}
	return string(body), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func (g *igd) addPortMapping(ctx context.Context, externalPort uint16, internalIP netip.Addr, internalPort uint16) error {
	// 先删同名映射，保证幂等（多数路由器重复添加会返回 718 ConflictInMappingEntry）
	_, _ = g.soap(ctx, "DeletePortMapping", [2]string{"NewRemoteHost", ""},
		[2]string{"NewExternalPort", fmt.Sprint(externalPort)}, [2]string{"NewProtocol", "UDP"})
	_, err := g.soap(ctx, "AddPortMapping",
		[2]string{"NewRemoteHost", ""},
		[2]string{"NewExternalPort", fmt.Sprint(externalPort)},
		[2]string{"NewProtocol", "UDP"},
		[2]string{"NewInternalPort", fmt.Sprint(internalPort)},
		[2]string{"NewInternalClient", internalIP.String()},
		[2]string{"NewEnabled", "1"},
		[2]string{"NewPortMappingDescription", upnpMapDesc},
		[2]string{"NewLeaseDuration", "0"}, // 0 = 不过期（不少家用路由器也只支持 0）
	)
	return err
}

// ensurePortMapping 为 internalPort 申请一个外部端口（优先同号），返回实际拿到的外部端口与所用内网地址。
// candidates 是本机的内网 IPv4 候选：逐个发 SSDP 试，谁能找到 IGD 就用谁 ——
// 一台机器上常有多张网卡（虚拟网卡、代理的 utun），只有与路由器同网段的那张能用。
func ensurePortMapping(ctx context.Context, candidates []netip.Addr, internalPort uint16, logf logger.Logf) (uint16, netip.Addr, error) {
	var g *igd
	var localIP netip.Addr
	var lastErr error
	for _, cand := range candidates {
		got, err := discoverIGD(ctx, cand, logf)
		if err != nil {
			lastErr = err
			continue
		}
		g, localIP = got, cand
		break
	}
	if g == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("没有可用的内网 IPv4 候选")
		}
		return 0, netip.Addr{}, lastErr
	}
	// 先试与内网同号（对端地址可预测），失败再退到别的端口。
	if err := g.addPortMapping(ctx, internalPort, localIP, internalPort); err == nil {
		return internalPort, localIP, nil
	} else {
		logf("UPnP: 外部端口 %d 申请失败（%v），改用其它端口", internalPort, err)
	}
	// 随机外部端口：直接请路由器分配（AddAnyPortMapping 在部分 IGD 上可用；
	// 不支持时用 AddPortMapping + 一个高位端口试一次）。
	if err := g.addPortMapping(ctx, internalPort+1, localIP, internalPort); err == nil {
		return internalPort + 1, localIP, nil
	}
	return 0, localIP, fmt.Errorf("AddPortMapping 失败（外部端口 %d/%d 都被拒）", internalPort, internalPort+1)
}

// startPortMapping 在出口（Server）启动后，为 magicsock 的 UDP 端口向路由器申请 UPnP 映射，
// 成功则记下外部端口供通告使用；每 30 分钟续期一次。失败会明确打日志——
// 家用路由器常有非标准 UPnP 实现（见 portmapping.go 顶部说明），让人知道该去手动转发。
func (lb *locoBackend) startPortMapping() {
	if os.Getenv("TAILCAT_NO_UPNP") != "" {
		lb.logf("UPnP: 已按 TAILCAT_NO_UPNP 禁用端口映射")
		return
	}
	go func() {
		for {
			mc := lb.sys.MagicSock.Get()
			if mc != nil {
				if port := mc.LocalPort(); port != 0 {
					cands := lb.localIPv4Candidates()
					if len(cands) == 0 {
						lb.logf("UPnP: 找不到可用的内网 IPv4，跳过端口映射")
					} else {
						ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
						ext, usedIP, err := ensurePortMapping(ctx, cands, port, lb.logf)
						cancel()
						if err == nil {
							lb.mu.Lock()
							lb.mappedPort = ext
							lb.mu.Unlock()
							lb.logf("UPnP: 已建立端口映射 外部 UDP %d → %v:%d（对端将拿到公网IP:%d）",
								ext, usedIP, port, ext)
						} else {
							lb.logf("UPnP: 未取得端口映射（%v）；出口在 NAT 后面时对端只能依赖打洞，"+
								"可在路由器上手动把 UDP %d 转发到本机（候选 %v）", err, port, cands)
						}
					}
				}
			}
			time.Sleep(upnpRenewPeriod)
		}
	}()
}

// localIPv4Candidates 列出本机可能用于 UPnP 的内网 IPv4 候选。
// 不能只看默认路由接口：代理类工具（Surge 等）的 utun 常占着默认路由；也不能只取第一个，
// 一台机器上常有多张虚拟网卡。过滤判据与直连候选通告同源（upnpIPv4Candidates →
// isVirtualInterface）：bridge/docker/utun 上的地址拨不到路由器，留着只会白吃 SSDP 超时。
// 真正的判据仍由调用方用 SSDP 自校验（谁能联系上路由器就用谁）。
func (lb *locoBackend) localIPv4Candidates() []netip.Addr {
	mon := lb.sys.NetMon.Get()
	if mon == nil {
		return nil
	}
	return upnpIPv4Candidates(mon.InterfaceState().InterfaceIPs)
}
