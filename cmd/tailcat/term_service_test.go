//go:build !windows

// term_service_test.go — 终端服务的端到端判据（真起 PTY 会话、真跑帧协议）：
//
//	新建 → 数据双向 → resize → 断开（会话保留、断线期间继续产历史）→ LIST 可见
//	→ 重进（回放含断线期间输出）→ KILL（OK + ENDED(killed)）→ 列表消失 → 出口无残留进程。
package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// 会话里跑「后台 ticker + 前台 cat」：既能验证输入回显，也能在断开期间继续产输出。
const testTermShell = "while :; do echo tick; sleep 0.2; done & cat"

func startTestTermService(t *testing.T) (*termService, net.Listener) {
	t.Helper()
	t.Setenv("TAILCAT_TERM_SHELL", testTermShell)
	t.Setenv("TAILCAT_TERM_HISTORY", "65536")
	t.Setenv("TAILCAT_TERM_REPLAY", "32768")
	t.Setenv("TAILCAT_TERM_DETECT", "off")
	svc := newTermService(nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go svc.ServeConn(c)
		}
	}()
	return svc, ln
}

func dialTerm(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	return c
}

func writeTermFrame(t *testing.T, c net.Conn, op byte, payload []byte) {
	t.Helper()
	if _, err := c.Write(encodeTermFrame(op, payload)); err != nil {
		t.Fatalf("write op 0x%02x: %v", op, err)
	}
}

func readTermFrameT(t *testing.T, c net.Conn) termFrame {
	t.Helper()
	f, err := readTermFrame(c)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return f
}

// collectUntil 收 DATA 直到目标 op（返回累计 DATA 与那一帧）。其它 op 直接失败。
func collectUntil(t *testing.T, c net.Conn, want byte) ([]byte, termFrame) {
	t.Helper()
	var data []byte
	for i := 0; i < 2048; i++ {
		f := readTermFrameT(t, c)
		switch f.op {
		case opData:
			data = append(data, f.payload...)
		case want:
			return data, f
		default:
			t.Fatalf("期望 op 0x%02x，收到 0x%02x（payload %q）", want, f.op, f.payload)
		}
	}
	t.Fatalf("等 op 0x%02x 超时", want)
	return nil, termFrame{}
}

// readDataContains 读帧直到累计 DATA 里出现 want（途中忽略 STATE）。
func readDataContains(t *testing.T, c net.Conn, want string) string {
	t.Helper()
	var data []byte
	for i := 0; i < 2048; i++ {
		f := readTermFrameT(t, c)
		switch f.op {
		case opData:
			data = append(data, f.payload...)
			if strings.Contains(string(data), want) {
				return string(data)
			}
		case opState, opOK:
			// 忽略
		default:
			t.Fatalf("等 %q 时收到 op 0x%02x（payload %q）", want, f.op, f.payload)
		}
	}
	t.Fatalf("等数据 %q 超时（累计 %q）", want, data)
	return ""
}

// attachTerm 建一条连接并完成一次 attach，返回连接、ATTACHED 载荷、回放的 DATA。
// attachTerm 返回：连接、ATTACHED 载荷、回放的 DATA、REPLAY-DONE 的 flags。
func attachTerm(t *testing.T, ln net.Listener, name string, create bool, cols, rows uint16) (net.Conn, []byte, []byte, byte) {
	t.Helper()
	c := dialTerm(t, ln)
	if f := readTermFrameT(t, c); f.op != opGreeting {
		t.Fatalf("首帧应为 GREETING，收到 0x%02x", f.op)
	}
	writeTermFrame(t, c, opHello, encHello(cols, rows, create, name))
	f := readTermFrameT(t, c)
	if f.op != opAttached {
		t.Fatalf("期望 ATTACHED，收到 0x%02x（payload %q）", f.op, f.payload)
	}
	replay, done := collectUntil(t, c, opReplayDone)
	if len(done.payload) < 5 {
		t.Fatalf("REPLAY-DONE 载荷过短：%v", done.payload)
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	return c, f.payload, replay, done.payload[4]
}

func listTerm(t *testing.T, ln net.Listener) map[string]any {
	t.Helper()
	c := dialTerm(t, ln)
	defer c.Close()
	if f := readTermFrameT(t, c); f.op != opGreeting {
		t.Fatalf("首帧应为 GREETING")
	}
	writeTermFrame(t, c, opList, nil)
	f := readTermFrameT(t, c)
	if f.op != opList {
		t.Fatalf("期望 LIST-REPLY，收到 0x%02x（payload %q）", f.op, f.payload)
	}
	var out map[string]any
	if err := json.Unmarshal(f.payload, &out); err != nil {
		t.Fatalf("LIST-REPLY 不是合法 JSON：%v（%q）", err, f.payload)
	}
	return out
}

func listSession(list map[string]any, name string) (map[string]any, bool) {
	arr, _ := list["sessions"].([]any)
	for _, it := range arr {
		m, _ := it.(map[string]any)
		if m != nil && m["name"] == name {
			return m, true
		}
	}
	return nil, false
}

func TestTermServiceLifecycle(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer ln.Close()
	defer svc.Close()

	// 1) 新建会话：历史为空 ⇒ 回放为空；ATTACHED 里带真实尺寸。
	c1, attached, replay1, _ := attachTerm(t, ln, "t-e2e", true, 100, 30)
	// 回放**总是**以换屏前序开头（客户端 vt 是新建的，起点要确定）；
	// 新建会话时前序之后不该有历史内容。
	const clearSeq = "\x1b[3J\x1b[2J\x1b[H"
	if !strings.HasPrefix(string(replay1), clearSeq) {
		t.Errorf("回放应以换屏前序开头，实际 %q", replay1)
	}
	if body := strings.TrimPrefix(string(replay1), clearSeq); strings.Contains(body, "hello-term") {
		t.Errorf("新会话不该有历史内容：%q", body)
	}
	if len(attached) < 10 {
		t.Fatalf("ATTACHED 载荷过短：%v", attached)
	}
	if cols := binary.LittleEndian.Uint16(attached[0:2]); cols != 100 {
		t.Errorf("ATTACHED cols = %d，期望 100", cols)
	}

	// 2) 数据双向：输入经 PTY 回显回来。
	//    先让 ticker 产几行，使回放窗口的起点早于后面的尺寸变化（否则 epoch 恰好等于起点，
	//    按语义那属于「窗口内全是新尺寸内容」，不该报跨尺寸）。
	time.Sleep(600 * time.Millisecond)
	writeTermFrame(t, c1, opData, []byte("hello-term\n"))
	if got := readDataContains(t, c1, "hello-term"); !strings.Contains(got, "hello-term") {
		t.Fatalf("未看到回显：%q", got)
	}

	// 3) resize 生效（LIST 里能看到新尺寸）。
	writeTermFrame(t, c1, opResize, encResize(80, 24))
	deadline := time.Now().Add(3 * time.Second)
	for {
		entry, ok := listSession(listTerm(t, ln), "t-e2e")
		if ok && int(entry["cols"].(float64)) == 80 && int(entry["rows"].(float64)) == 24 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resize 未生效：%v", entry)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 4) 断开：会话必须继续活着（client 断开只摘泵），且断线期间继续产历史。
	//    先等 ticker 在「改尺寸之后」再产几行 —— 否则尺寸 epoch 恰好落在回放窗口起点，
	//    那属于「窗口内全是新尺寸内容」，按语义不该报跨尺寸（bit1 只在窗口**内部**跨尺寸时置位）。
	time.Sleep(700 * time.Millisecond)
	_ = c1.Close()
	time.Sleep(1200 * time.Millisecond)
	entry, ok := listSession(listTerm(t, ln), "t-e2e")
	if !ok {
		t.Fatal("断开后会话应当仍在列表里")
	}
	if entry["attached"].(bool) {
		t.Error("断开后 attached 应当为 false")
	}
	pid := int(entry["pid"].(float64))

	// 5) 重进：回放里应当同时含断开前的输入回显与断开期间的 ticker 输出。
	c2, _, replay2, flags2 := attachTerm(t, ln, "t-e2e", false, 80, 24)
	text := string(replay2)
	if !strings.Contains(text, "hello-term") {
		t.Errorf("重进回放缺少断开前内容：%q", text)
	}
	if !strings.Contains(text, "tick") {
		t.Errorf("重进回放缺少断线期间输出：%q", text)
	}
	// resize 之后重进：REPLAY-DONE 的 bit1（跨尺寸变化）应当置位，供客户端提示历史排版。
	if flags2&replayFlagSizeChange == 0 {
		t.Errorf("REPLAY-DONE flags = 0x%x，期望含 bit1（跨尺寸变化）", flags2)
	}

	// 6) KILL：发起端收 OK，已 attach 的客户端收 ENDED(killed)。
	ck := dialTerm(t, ln)
	if f := readTermFrameT(t, ck); f.op != opGreeting {
		t.Fatal("首帧应为 GREETING")
	}
	writeTermFrame(t, ck, opKill, encName("t-e2e"))
	if f := readTermFrameT(t, ck); f.op != opOK {
		t.Fatalf("KILL 应回 OK，收到 0x%02x（payload %q）", f.op, f.payload)
	}
	_ = ck.Close()
	f := readTermFrameT(t, c2)
	for f.op == opData || f.op == opState {
		f = readTermFrameT(t, c2)
	}
	if f.op != opEnded {
		t.Fatalf("期望 ENDED，收到 0x%02x", f.op)
	}
	if code := int32(binary.LittleEndian.Uint32(f.payload[0:4])); code != termEndKilled {
		t.Errorf("ENDED code = %d，期望 %d（killed）", code, termEndKilled)
	}
	_ = c2.Close()

	// 7) 列表里消失 + 出口无残留进程（回收四步的对外判据）。
	if _, ok := listSession(listTerm(t, ln), "t-e2e"); ok {
		t.Error("kill 后会话不应再出现在列表里")
	}
	termWaitPidGone(t, pid)
}

func termWaitPidGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := unix.Kill(pid, 0)
		if err != nil {
			return // ESRCH：进程没了
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d 仍存活（会话回收不干净）", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// 会话名非法 / 不存在 / 创建语义 的失败路径。
func TestTermServiceErrors(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer ln.Close()
	defer svc.Close()

	// 非法名字
	c := dialTerm(t, ln)
	defer c.Close()
	readTermFrameT(t, c)
	writeTermFrame(t, c, opHello, encHello(80, 24, true, "bad name!"))
	if f := readTermFrameT(t, c); f.op != opError {
		t.Fatalf("非法名应回 ERROR，收到 0x%02x", f.op)
	}

	// attach 不存在的会话（create=false）
	c2 := dialTerm(t, ln)
	defer c2.Close()
	readTermFrameT(t, c2)
	writeTermFrame(t, c2, opHello, encHello(80, 24, false, "nope"))
	f := readTermFrameT(t, c2)
	if f.op != opError {
		t.Fatalf("不存在的会话应回 ERROR，收到 0x%02x", f.op)
	}

	// KILL 不存在的会话
	c3 := dialTerm(t, ln)
	defer c3.Close()
	readTermFrameT(t, c3)
	writeTermFrame(t, c3, opKill, encName("nope"))
	if f := readTermFrameT(t, c3); f.op != opError {
		t.Fatalf("kill 不存在的会话应回 ERROR，收到 0x%02x", f.op)
	}
}
