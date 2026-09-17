//go:build !windows

package main

import (
	"bytes"
	"testing"
)

// 帧编解码往返 + 边界（openspec exit-terminal 设计 D4 的表驱动判据）。
func TestTermFrameRoundTrip(t *testing.T) {
	name := "dev-abc123"
	cases := []struct {
		op      byte
		payload []byte
	}{
		{opGreeting, encGreeting()},
		{opHello, encHello(120, 40, true, name)},
		{opResize, encResize(100, 30)},
		{opData, []byte("hello \x1b[31m世界\x1b[0m")},
		{opReplayDone, encReplayDone(12345, replayFlagTruncated|replayFlagSizeChange)},
		{opEnded, encEnded(termEndKilled, "killed")},
		{opState, encState(agentCodex, stateRunning, "codex · 工作中")},
		{opError, encError("no_session", "会话不存在")},
		{opOK, nil},
		{opKill, encName(name)},
	}
	for _, c := range cases {
		raw := encodeTermFrame(c.op, c.payload)
		got, err := readTermFrame(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("op 0x%02x: readTermFrame: %v", c.op, err)
		}
		if got.op != c.op || !bytes.Equal(got.payload, c.payload) {
			t.Fatalf("op 0x%02x: 往返不一致 got op=0x%02x payload=%q", c.op, got.op, got.payload)
		}
	}
}

func TestTermFrameShortAndTruncated(t *testing.T) {
	// 头都没读全
	if _, err := readTermFrame(bytes.NewReader([]byte{opData})); err == nil {
		t.Error("短头应当报错")
	}
	// 声明长度大于实际载荷（截断的包）必须报错，不能静默返回半截数据
	raw := append([]byte{opData, 0x10, 0x00}, []byte("only-a-few")...)
	if _, err := readTermFrame(bytes.NewReader(raw)); err == nil {
		t.Error("截断的帧应当报错")
	}
}

func TestTermHelloRoundTrip(t *testing.T) {
	cols, rows, create, name, err := decHello(encHello(80, 24, false, "s1"))
	if err != nil {
		t.Fatal(err)
	}
	if cols != 80 || rows != 24 || create || name != "s1" {
		t.Fatalf("hello 往返不一致：%d %d %v %q", cols, rows, create, name)
	}
	if _, _, _, _, err := decHello([]byte{1, 2, 3}); err == nil {
		t.Error("过短的 HELLO 应当报错")
	}
}

func TestTermGreeting(t *testing.T) {
	ver, features, err := decGreeting(encGreeting())
	if err != nil {
		t.Fatal(err)
	}
	if ver != termProtoVer {
		t.Errorf("协议版本 = %d，期望 %d", ver, termProtoVer)
	}
	if features&featReplay == 0 || features&featAgent == 0 {
		t.Errorf("features 缺少必需位：0x%x", features)
	}
}
