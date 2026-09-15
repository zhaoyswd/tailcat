// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !cshared

package tailcat

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestIsVirtualInterface(t *testing.T) {
	for _, name := range []string{"lo0", "utun4", "tun0", "tap1", "wg0", "tailscale0", "awdl0", "llw0", "anpi0", "bridge0", "bridge100", "vmenet0", "docker0", "virbr0", "vethabc", "br-1234", "ap1"} {
		if !isVirtualInterface(name) {
			t.Errorf("%q 应命中黑名单", name)
		}
	}
	for _, name := range []string{"en0", "en5", "eth0", "kvmbr1", "wlan0", "ens192"} {
		if isVirtualInterface(name) {
			t.Errorf("%q 不应命中黑名单", name)
		}
	}
}

// enumerateCandidates 会调 ifc.Addrs()（真实系统调用），所以只测「黑名单 + 状态过滤」
// 这几条纯逻辑分支：合成接口没有地址 ⇒ 命中「无 IPv4」被过滤，同样验证了该分支。
func TestEnumerateCandidates(t *testing.T) {
	utun := net.Interface{Index: 99, Name: "utun9", Flags: net.FlagUp | net.FlagBroadcast}
	if got := enumerateCandidates([]net.Interface{utun}); len(got) != 0 {
		t.Errorf("utun9 应被黑名单过滤，got %v", got)
	}
	down := net.Interface{Index: 98, Name: "en7", Flags: net.FlagBroadcast}
	if got := enumerateCandidates([]net.Interface{down}); len(got) != 0 {
		t.Errorf("down 的接口应被过滤，got %v", got)
	}
	lo := net.Interface{Index: 97, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}
	if got := enumerateCandidates([]net.Interface{lo}); len(got) != 0 {
		t.Errorf("loopback 应被过滤，got %v", got)
	}
}

func TestProbeDNSPacket(t *testing.T) {
	pkt := probeDNSPacket(0xABCD, "x.probe.invalid")
	if got := binary.BigEndian.Uint16(pkt); got != 0xABCD {
		t.Errorf("TXID = %x", got)
	}
	if !bytes.Equal(pkt[len(pkt)-4:], []byte{0, 1, 0, 1}) {
		t.Errorf("QTYPE/QCLASS 尾部错误: %v", pkt[len(pkt)-4:])
	}
	qname := pkt[12 : len(pkt)-4]
	if qname[len(qname)-1] != 0 {
		t.Errorf("QNAME 未以 0 终止: %v", qname)
	}
}

// probeServer 起一个本地 UDP 服务器；serve 收到查询时自行决定怎么回（可用 reply 从
// 服务器自己的地址回，也可从别的端口回——后者模拟路由器劫持代答）。返回服务器地址。
func probeServer(t *testing.T, serve func(txid uint16, from *net.UDPAddr, reply func(pkt []byte))) *net.UDPAddr {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			_, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			txid := binary.BigEndian.Uint16(buf)
			reply := func(pkt []byte) { pc.WriteToUDP(pkt, from) }
			serve(txid, from, reply)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr)
}

func probeDial(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func validResp(txid uint16) []byte {
	resp := probeDNSPacket(txid, "x.probe.invalid")
	resp[2] = 0x80 // QR=1
	return resp
}

// TestDNSProbeViaConn 校验逻辑四分支：有效应答 ✓、TXID 不符 ✗、源不符（劫持代答）✗、全超时 ✗。
func TestDNSProbeViaConn(t *testing.T) {
	t.Run("有效应答", func(t *testing.T) {
		addr := probeServer(t, func(txid uint16, from *net.UDPAddr, reply func([]byte)) {
			reply(validResp(txid))
		})
		target := netip.MustParseAddrPort(addr.String())
		win, _, ok := dnsProbeViaConn(probeDial(t), []netip.AddrPort{target}, time.Second)
		if !ok || win != target {
			t.Errorf("ok=%v win=%v; want ok, %v", ok, win, target)
		}
	})
	t.Run("TXID 不符不算", func(t *testing.T) {
		addr := probeServer(t, func(txid uint16, from *net.UDPAddr, reply func([]byte)) {
			reply(validResp(txid + 1))
		})
		target := netip.MustParseAddrPort(addr.String())
		if _, _, ok := dnsProbeViaConn(probeDial(t), []netip.AddrPort{target}, 300*time.Millisecond); ok {
			t.Error("TXID 不符的应答不应判通")
		}
	})
	t.Run("源不符（劫持代答）不算", func(t *testing.T) {
		// 收到查询但从**另一个端口**回包（源 ≠ 所查目标）——模拟路由器劫持 :53 代答。
		addr := probeServer(t, func(txid uint16, from *net.UDPAddr, reply func([]byte)) {
			other, err := net.ListenUDP("udp4", nil)
			if err != nil {
				return
			}
			defer other.Close()
			other.WriteToUDP(validResp(txid), from)
		})
		target := netip.MustParseAddrPort(addr.String())
		if _, _, ok := dnsProbeViaConn(probeDial(t), []netip.AddrPort{target}, 300*time.Millisecond); ok {
			t.Error("源不符的应答不应判通（TXID 正确也不行）")
		}
	})
	t.Run("全超时", func(t *testing.T) {
		dead := netip.MustParseAddrPort("192.0.2.1:53") // TEST-NET，不可路由
		if _, _, ok := dnsProbeViaConn(probeDial(t), []netip.AddrPort{dead}, 200*time.Millisecond); ok {
			t.Error("无应答应判不通")
		}
	})
}

func TestProbeTargets(t *testing.T) {
	t.Setenv("TAILCAT_BIND_PROBE_DNS", "10.0.0.1, 10.0.0.2:5353")
	got := probeTargets()
	want := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:53"),
		netip.MustParseAddrPort("10.0.0.2:5353"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%v want %v", i, got[i], want[i])
		}
	}
}

// TestEvaluateBindPinnedUnavailable：显式接口名探不通 ⇒ 赢家为空（不绑）且依据行说明原因。
func TestEvaluateBindPinnedUnavailable(t *testing.T) {
	winner, basis := evaluateBind("en99", true, probeTargets(), nil)
	if winner != "" {
		t.Errorf("不可用接口不应给出赢家: %q", winner)
	}
	if basis == "" {
		t.Error("应给出判定依据行")
	}
}
