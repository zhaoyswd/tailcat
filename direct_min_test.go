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

// TestDirectMinimal — 直连握手先行的最小闭环：Server 带 ListenPort 钉死、
// 客户端只靠手动 hint 候选（无 meow 预注册）以 WireGuard-only 形态直发
// 握手 + TSMP 就绪探测。成功即证明懒注册 + wgonly + 回程索引全链工作。
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
		AddrPort:  netipMustAddrPort("192.168.3.12:41633"),
		Tier:      EndpointHintManual,
		Generated: time.Now().Unix(),
	}}

	c := &Client{Server: ci.Addr(), Logf: clog.Printf, DirectConnect: true}
	t.Cleanup(func() { c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
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
