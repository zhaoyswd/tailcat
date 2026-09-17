//go:build !windows

// term_e2e_test.go — 端到端判据：**真起的出口二进制** + **真隧道客户端**拨虚拟端口 7724。
// 覆盖 serve 侧的三处接线（handler 构造 / OnTCP 优先级 / 就绪日志），以及一次完整会话回合。
package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
)

func waitLogLine(t *testing.T, buf *lockedBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if strings.Contains(buf.String(), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等日志行 %q 超时；实际输出：\n%s", want, buf.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestTermServiceOverTunnel(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.env = append(e.env, "TAILCAT_TERM_SHELL=cat", "TAILCAT_TERM_DETECT=off")

	_, addr, stderr := e.startServer("serve", "exit-node")

	// ① 就绪日志（serve 钩子生效的对外判据）
	waitLogLine(t, stderr, "# Serving terminal sessions on port 7724")

	cl := &tailcat.Client{Server: tailcat.Addr(addr), DERPMapURL: e.derpMapURL, Logf: testLogger(t, "client")}
	t.Cleanup(func() { cl.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ② 经隧道拨「虚拟端口 7724」——验证 OnTCP 的终端分支优先于 exit-node 回落
	conn, err := cl.DialTCPPort(ctx, 7724)
	if err != nil {
		t.Fatalf("DialTCPPort(7724): %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	// ③ 帧协议一次完整回合：GREETING → HELLO(create) → ATTACHED → 回放/REPLAY-DONE
	if f := readTermFrameT(t, conn); f.op != opGreeting {
		t.Fatalf("首帧应为 GREETING，收到 0x%02x", f.op)
	}
	writeTermFrame(t, conn, opHello, encHello(90, 28, true, "e2e-tunnel"))
	if f := readTermFrameT(t, conn); f.op != opAttached {
		t.Fatalf("期望 ATTACHED，收到 0x%02x（payload %q）", f.op, f.payload)
	}
	if _, done := collectUntil(t, conn, opReplayDone); len(done.payload) < 5 {
		t.Fatalf("REPLAY-DONE 载荷过短：%v", done.payload)
	}

	// ④ 输入经隧道送到出口 PTY 并回显回来
	writeTermFrame(t, conn, opData, []byte("over-tunnel\n"))
	if got := readDataContains(t, conn, "over-tunnel"); !strings.Contains(got, "over-tunnel") {
		t.Fatalf("隧道上的回显缺失：%q", got)
	}

	// ⑤ KILL 收尾：OK + ENDED(killed)
	writeTermFrame(t, conn, opKill, encName("e2e-tunnel"))
	f := readTermFrameT(t, conn)
	for f.op == opData || f.op == opState {
		f = readTermFrameT(t, conn)
	}
	if f.op != opOK {
		t.Fatalf("KILL 应回 OK，收到 0x%02x（payload %q）", f.op, f.payload)
	}
}
