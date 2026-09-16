package tailcat

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
)

// TestDirectMinimal — 直连优先建连的最小闭环：Server 带 ListenPort 钉死、
// 客户端用手动 hint 候选（loopback，无开发机环境依赖）走 Ready()（App
// 的真实入口）。断言 readyBy 有值 = 赛跑就绪路径真的执行过（Ready 的
// 第一版判据在 ensureStarted 之前、App 路径永远走不到直连分支，被
// review 揪出——本测试的 readyBy 断言就是防它回归）。
func TestDirectMinimal(t *testing.T) {
	t.Parallel()
	dm := integration.RunDERPAndSTUN(t, log.Printf, "127.0.0.1")
	slog := log.New(os.Stderr, "SRV ", log.LstdFlags)
	clog := log.New(os.Stderr, "CLI ", log.LstdFlags)

	s := &Server{Logf: slog.Printf, Region: dm.Regions[1], ListenPort: 41633}
	s.OnTCP = func(port uint16) func(net.Conn) {
		return func(c net.Conn) { io.Copy(c, c); c.Close() }
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
		AddrPort:  netipMustAddrPort("127.0.0.1:41633"),
		Tier:      EndpointHintManual,
		Generated: time.Now().Unix(),
	}}

	c := &Client{Server: ci.Addr(), Logf: clog.Printf, DirectConnect: true}
	t.Cleanup(func() { c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
	by, rerr := c.Ready(rctx) // App 的真实就绪入口
	rcancel()
	if rerr != nil {
		t.Fatalf("Ready: %v", rerr)
	}
	if by != "direct" && by != "meow" {
		t.Fatalf("readyBy = %q; want direct|meow（空 = Ready 没走赛跑路径，回归！）", by)
	}
	t.Logf("readyBy=%s", by)
	const payload = "direct-min-echo"
	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("got %q", buf)
	}
}

func netipMustAddrPort(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ap
}
