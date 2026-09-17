// direct_replace_test.go — 出口侧「provisional endpoint 被网络图就地收养」的回归用例
// （2026-09-18 真机症状：VPN 显示已连接，但文件管理/终端会话等一切自拨出口的连接全失败）。
//
// 链路：客户端直连握手（出口合成 provisional endpoint，并把它交给 WireGuard 设备当
// 发送 endpoint）→ 客户端 meow，出口把它提升为网络图 peer → 客户端**同身份重建会话**
// （新源端口，模拟换网/重连）。
//
// 修复前的做法是 delete + 新建：设备仍按旧对象发包，而旧对象已被摘出 peerMap、
// 再也收不到包（没有控制面时收到的包是路径信息的唯一来源）⇒ 出口发不出握手响应，
// 客户端在重试窗口里永远等不到 → 隧道"通了但什么都没通"。
package tailcat

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
)

func TestDirectHandshakeSurvivesSessionReplace(t *testing.T) {
	t.Parallel()
	dm := integration.RunDERPAndSTUN(t, log.Printf, "127.0.0.1")
	slog := log.New(os.Stderr, "SRV ", log.LstdFlags)
	clog := log.New(os.Stderr, "CLI ", log.LstdFlags)

	const payload = "replace-echo"
	s := &Server{Logf: slog.Printf, Region: dm.Regions[1], ListenPort: 41637}
	s.OnTCP = func(port uint16) func(net.Conn) {
		return func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
		}
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	ci, err := ParseAddr(s.TailcatAddr())
	if err != nil {
		t.Fatal(err)
	}
	ci.EndpointHints = []EndpointHint{{
		AddrPort:  netipMustAddrPort("127.0.0.1:41637"),
		Tier:      EndpointHintManual,
		Generated: time.Now().Unix(),
	}}

	// 两代客户端共用同一份身份：真机上这就是同一个 App（重新连接/换网后同 key 新会话）。
	ident := key.NewNode()
	newClient := func() *Client {
		c := &Client{Server: ci.Addr(), Logf: clog.Printf, DirectConnect: true, Key: ident}
		t.Cleanup(func() { c.Close() })
		return c
	}

	// 第一代：直连握手建连（出口此处的 peer 只能是 provisional 的——它还没有 meow）。
	c1 := newClient()
	rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
	by, rerr := c1.Ready(rctx)
	rcancel()
	if rerr != nil {
		t.Fatalf("gen1 Ready: %v", rerr)
	}
	if by != "direct" {
		t.Fatalf("gen1 readyBy=%q; 需要 direct（本用例的前提：出口先合成 provisional peer，再由 meow 提升）", by)
	}

	// 等出口把它提升为网络图 peer（meow 到达即 SetNetworkMap；修复前这一步会把设备
	// 仍持有的 endpoint 对象删掉）。
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.lb.mu.Lock()
		_, seen := s.lb.clients[ident.Public()]
		s.lb.mu.Unlock()
		if seen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("出口始终没收到 meow（网络图提升没发生），用例前提不成立")
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // 让 SetNetworkMap 落进 magicsock

	// 第二代：同身份、新 UDP 源端口（第一代的 socket 已关，旧候选地址成了死地址）。
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	c2 := newClient()
	dctx, dcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer dcancel()
	if _, err := c2.Ready(dctx); err != nil {
		t.Fatalf("gen2 Ready（出口答不出握手响应 ⇒ 真机症状「VPN 已连接但什么都连不上」）: %v", err)
	}

	// 数据面必须真的走得通。
	conn, err := c2.DialTCPPort(dctx, 80)
	if err != nil {
		t.Fatalf("gen2 dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("gen2 read: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("got %q; want %q", buf, payload)
	}
}
