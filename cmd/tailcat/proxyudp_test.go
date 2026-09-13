// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/net/socks5"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
)

// resetUDPProxyCache 清掉进程内缓存的探测结论（每个用例自己造环境）。
func resetUDPProxyCache(t *testing.T) {
	t.Helper()
	udpProxyCache.mu.Lock()
	udpProxyCache.status = udpProxyStatus{}
	udpProxyCache.inflight = nil
	udpProxyCache.mu.Unlock()
	t.Cleanup(func() { resetUDPProxyCacheNoT() })
}

func resetUDPProxyCacheNoT() {
	udpProxyCache.mu.Lock()
	udpProxyCache.status = udpProxyStatus{}
	udpProxyCache.inflight = nil
	udpProxyCache.mu.Unlock()
}

// setForwardProxyForTest 临时设置包级的代理配置与被转发 UDP 的模式。
func setForwardProxyForTest(t *testing.T, rawURL string, mode forwardUDPMode) {
	t.Helper()
	oldProxy, oldMode := forwardProxy, forwardUDPModeValue
	t.Cleanup(func() {
		forwardProxy = oldProxy
		forwardUDPModeValue = oldMode
	})
	if rawURL == "" {
		forwardProxy = nil
	} else {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		forwardProxy = u
	}
	forwardUDPModeValue = mode
}

// startFakeSOCKS5UDP 起一个「只会对 UDP ASSOCIATE 回固定 REP」的假代理，返回 host:port。
// REP=0 时把中继地址指向一个从不回包的 UDP socket（用来造「声称支持、实际不中继」）。
func startFakeSOCKS5UDP(t *testing.T, rep byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	blackhole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blackhole.Close() })
	bhPort := blackhole.LocalAddr().(*net.UDPAddr).Port

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var greet [2]byte
				if _, err := io.ReadFull(c, greet[:]); err != nil {
					return
				}
				methods := make([]byte, int(greet[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				var req [10]byte // VER CMD RSV ATYP(1) ADDR(4) PORT(2)
				if _, err := io.ReadFull(c, req[:]); err != nil {
					return
				}
				reply := []byte{5, rep, 0, 1, 127, 0, 0, 1, byte(bhPort >> 8), byte(bhPort)}
				c.Write(reply)
				io.Copy(io.Discard, c) // 保持控制连接
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestProbeUDPOverSOCKS5Rejected(t *testing.T) {
	resetUDPProxyCache(t)
	for _, rep := range []byte{socks5RepCommandNotSupprt, socks5RepNotAllowed} {
		addr := startFakeSOCKS5UDP(t, rep)
		u, _ := url.Parse("socks5://" + addr)
		st := probeUDPOverSOCKS5(context.Background(), u, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478")})
		if st.state != udpProxyUnsupported {
			t.Errorf("REP=0x%02x：state = %v（%s），want %v", rep, st.state, st.detail, udpProxyUnsupported)
		}
	}
}

func TestProbeUDPOverSOCKS5NotRelaying(t *testing.T) {
	resetUDPProxyCache(t)
	addr := startFakeSOCKS5UDP(t, socks5RepSuccess)
	u, _ := url.Parse("socks5://" + addr)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	st := probeUDPOverSOCKS5(ctx, u, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478")})
	if st.state != udpProxyUnavailable {
		t.Errorf("REP=0 但无中继：state = %v（%s），want %v", st.state, st.detail, udpProxyUnavailable)
	}
}

func TestProbeUDPOverSOCKS5ConnectFailure(t *testing.T) {
	resetUDPProxyCache(t)
	// 没有任何东西在监听这个端口
	u, _ := url.Parse("socks5://127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st := probeUDPOverSOCKS5(ctx, u, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478")})
	if st.state != udpProxyUnknown {
		t.Errorf("连不上代理：state = %v（%s），want %v", st.state, st.detail, udpProxyUnknown)
	}
}

func TestDialForwardUDPWithoutProxyIsDirect(t *testing.T) {
	setForwardProxyForTest(t, "", forwardUDPAuto)
	echo := startUDPEchoAddrPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, via, err := dialForwardUDP(ctx, echo)
	if err != nil {
		t.Fatalf("dialForwardUDP: %v", err)
	}
	defer conn.Close()
	if via != "direct" {
		t.Errorf("via = %q，want direct", via)
	}
	roundTripUDP(t, conn, "direct-no-proxy")
}

func TestDialForwardUDPOffWithProxyIsDirect(t *testing.T) {
	// 有代理但 --forward-udp=off：行为必须与不配代理完全一致（直出）。
	setForwardProxyForTest(t, "socks5://127.0.0.1:1", forwardUDPOff)
	echo := startUDPEchoAddrPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, via, err := dialForwardUDP(ctx, echo)
	if err != nil {
		t.Fatalf("dialForwardUDP: %v", err)
	}
	defer conn.Close()
	if via != "direct" {
		t.Errorf("via = %q，want direct", via)
	}
	roundTripUDP(t, conn, "off-with-proxy")
}

func TestDialForwardUDPAutoFallsBackToDirect(t *testing.T) {
	// auto + 代理明确不支持 UDP ⇒ 回落直出，且 via 里写明原因。
	resetUDPProxyCache(t)
	proxyAddr := startFakeSOCKS5UDP(t, socks5RepCommandNotSupprt)
	setForwardProxyForTest(t, "socks5://"+proxyAddr, forwardUDPAuto)
	echo := startUDPEchoAddrPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, via, err := dialForwardUDP(ctx, echo)
	if err != nil {
		t.Fatalf("dialForwardUDP: %v", err)
	}
	defer conn.Close()
	if via == "direct" || len(via) < len("direct(") {
		t.Errorf("via = %q，want 带原因的 direct(...)", via)
	}
	roundTripUDP(t, conn, "auto-fallback")
}

func TestDialForwardUDPOnFailsWhenUnsupported(t *testing.T) {
	// on + 代理不支持 ⇒ 明确失败（不静默直出）。
	resetUDPProxyCache(t)
	proxyAddr := startFakeSOCKS5UDP(t, socks5RepCommandNotSupprt)
	setForwardProxyForTest(t, "socks5://"+proxyAddr, forwardUDPOn)
	echo := startUDPEchoAddrPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := dialForwardUDP(ctx, echo); err == nil {
		t.Fatal("--forward-udp=on 且代理不支持 UDP 时应当报错")
	}
}

func TestDialForwardUDPOnFailsForHTTPProxy(t *testing.T) {
	setForwardProxyForTest(t, "http://127.0.0.1:1", forwardUDPOn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := dialForwardUDP(ctx, netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("HTTP 代理 + on 应当报错（HTTP 不能承载 UDP）")
	}
}

// derpRegionForTest 造一个只含一个节点的 DERP 区域。
func derpRegionForTest(t *testing.T, ipv4 string, stunPort int) *tailcfg.DERPRegion {
	t.Helper()
	return &tailcfg.DERPRegion{
		RegionID:   999,
		RegionName: "test",
		Nodes: []*tailcfg.DERPNode{{
			Name:     "test",
			HostName: "test.example",
			IPv4:     ipv4,
			STUNPort: stunPort,
		}},
	}
}

// startUDPEchoAddrPort 起一个本地 UDP 回声服务，返回它的地址。
// （名字刻意区别于上游 serve_test.go 里的 startUDPEcho —— 它返回的是端口号，fork 树里两个文件会共存。）
func startUDPEchoAddrPort(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], addr)
		}
	}()
	ap, ok := netip.AddrFromSlice(pc.LocalAddr().(*net.UDPAddr).IP)
	if !ok {
		t.Fatal("echo addr")
	}
	return netip.AddrPortFrom(ap, uint16(pc.LocalAddr().(*net.UDPAddr).Port))
}

func roundTripUDP(t *testing.T, conn tailcat.ConnPacketConn, payload string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != payload {
		t.Fatalf("回声 = %q，want %q", got, payload)
	}
}

// TestSOCKSUDPClientEndToEnd 是「客户端真的能经 SOCKS5 发 UDP」的端到端验证：
// 代理用 tailscale 自带的 socks5.Server（就是 `tailcat socks` 用的那个，已知支持 UDP），
// 出口侧走真实的 tailcat 隧道 + OnUDPForward（exit-node 语义），目标是一个本地 UDP 回声。
func TestSOCKSUDPClientEndToEnd(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, testLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}
	echo := startUDPEchoAddrPort(t)

	s := &tailcat.Server{Logf: testLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	s.OnUDPForward = func(dst netip.AddrPort) func(tailcat.ConnPacketConn) {
		return func(c tailcat.ConnPacketConn) {
			up, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
			if err != nil {
				c.Close()
				return
			}
			tailcat.ProxyPacketConns(c, up)
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	cl := &tailcat.Client{Server: s.TailcatAddr(), Logf: testLogger(t, "client")}
	t.Cleanup(func() { cl.Close() })
	pingUntilDirect(t, cl)
	clientForAddr := func(tailcat.Addr) *tailcat.Client { return cl }

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socksLn.Close() })
	ss := &socks5.Server{
		Logf: testLogger(t, "socks5"),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dst, err := classifySOCKSAddr(ctx, lookupNetIP, addr)
			if err != nil {
				return nil, err
			}
			return dialSOCKSTarget(ctx, network, dst, cl, clientForAddr)
		},
	}
	go func() { _ = ss.Serve(socksLn) }()

	proxyURL := &url.URL{Scheme: "socks5", Host: socksLn.Addr().String()}

	// ① 探测：本机 STUN（loopback）经代理可达 ⇒ 判定支持。
	targets := derpSTUNTargets(reg)
	if len(targets) == 0 {
		t.Fatal("derpSTUNTargets 为空")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := probeUDPOverSOCKS5(ctx, proxyURL, targets)
	if st.state != udpProxySupported {
		t.Fatalf("探测结论 = %v（%s），want %v", st.state, st.detail, udpProxySupported)
	}

	// ② 转发：经代理向回声服务发一包，要求原样回来。
	conn, err := dialSOCKS5UDP(ctx, proxyURL, echo)
	if err != nil {
		t.Fatalf("dialSOCKS5UDP: %v", err)
	}
	defer conn.Close()
	roundTripUDP(t, conn, "via-socks5")
}

// TestDerpSTUNTargetsParsing 只验证「从 DERP 区域取字面 IP STUN 目标」的纯逻辑。
func TestDerpSTUNTargetsParsing(t *testing.T) {
	reg := derpRegionForTest(t, "203.0.113.9", 0)
	got := derpSTUNTargets(reg)
	want := netip.MustParseAddrPort("203.0.113.9:3478")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("derpSTUNTargets = %v，want [%v]", got, want)
	}
	reg = derpRegionForTest(t, "203.0.113.9", 1234)
	if got := derpSTUNTargets(reg); len(got) != 1 || got[0].Port() != 1234 {
		t.Fatalf("derpSTUNTargets（指定端口）= %v", got)
	}
	// 没有 IPv4 的节点（只有域名）不产生目标
	if got := derpSTUNTargets(derpRegionForTest(t, "", 0)); len(got) != 0 {
		t.Fatalf("derpSTUNTargets（无 IPv4）= %v，want 空", got)
	}
	if got := derpSTUNTargets(nil); got != nil {
		t.Fatalf("derpSTUNTargets(nil) = %v，want nil", got)
	}
}
