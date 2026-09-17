//go:build !windows

// term_frames.go — 终端服务的帧协议编解码（纯函数，有单测）。
//
// 帧 = [op:1][len:2 LE][payload]，len ≤ 65535；DATA 由发送方按 ≤16KiB 分片。
// 这套字节布局是**两端契约**：App 侧 terminal 模块的 cpp/stream/term_frames.h
// 必须逐字段一致（见 openspec exit-terminal 设计 D4）。
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	termProtoVer     = 1
	termMaxPayload   = 65535
	termDataChunk    = 16 << 10
	termMaxNameLen   = 64
	termMaxReasonLen = 200
)

// op：帧类型。两个方向共用一个字节空间，靠连接方向区分（DATA 双向同 op）。
const (
	opHello      byte = 0x00
	opData       byte = 0x01
	opResize     byte = 0x02
	opEnded      byte = 0x03
	opList       byte = 0x04 // C→S 请求；S→C 为 LIST-REPLY（payload 是 JSON）
	opKill       byte = 0x05
	opError      byte = 0x06
	opState      byte = 0x07
	opReserved08 byte = 0x08 // 保留（旧提案里曾是 LIST-REPLY；不得复用，避免老客户端误读）
	opAttached   byte = 0x09
	opReplayDone byte = 0x0A
	opOK         byte = 0x0B
	opGreeting   byte = 0x0C
)

// GREETING 的 features 位（客户端不认识的位忽略）。
const (
	featList   = 1 << 0
	featReplay = 1 << 1
	featModes  = 1 << 2
	featAgent  = 1 << 3
	featTitle  = 1 << 4

	termFeatures = featList | featReplay | featModes | featAgent | featTitle
)

// agent / state 枚举（与 App 侧一一对应）。
const (
	agentShell    byte = 0
	agentCodex    byte = 1
	agentClaude   byte = 2
	agentOpencode byte = 3
	agentOpenclaw byte = 4
	agentOther    byte = 5
	agentUnknown  byte = 255

	stateUnknown byte = 0
	stateRunning byte = 1
	stateWaiting byte = 2
	stateIdle    byte = 3
	stateEnded   byte = 4
)

// ended 的 code：≥0 是子进程退出码；负数表示由服务侧给出的原因（见 reason）。
const (
	termEndReplaced       = -1 // 同一会话被新的 attach 顶掉
	termEndKilled         = -2 // App 主动 kill
	termEndServiceStopped = -3 // 出口服务退出
)

// agentName 把枚举渲染成可检索的短名（日志/JSON 用）。
func agentName(a byte) string {
	switch a {
	case agentShell:
		return "shell"
	case agentCodex:
		return "codex"
	case agentClaude:
		return "claude"
	case agentOpencode:
		return "opencode"
	case agentOpenclaw:
		return "openclaw"
	case agentOther:
		return "other"
	}
	return "unknown"
}

// stateName 同上。
func stateName(s byte) string {
	switch s {
	case stateRunning:
		return "running"
	case stateWaiting:
		return "waiting"
	case stateIdle:
		return "idle"
	case stateEnded:
		return "ended"
	}
	return "unknown"
}

type termFrame struct {
	op      byte
	payload []byte
}

var errTermFrame = errors.New("term: bad frame")

// encodeTermFrame 组帧（len 由这里算，调用方只管 payload）。
func encodeTermFrame(op byte, payload []byte) []byte {
	if len(payload) > termMaxPayload {
		payload = payload[:termMaxPayload]
	}
	out := make([]byte, 3+len(payload))
	out[0] = op
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(payload)))
	copy(out[3:], payload)
	return out
}

// readTermFrame 读一帧；短读/超长/未知长度一律报错（连接由调用方关掉）。
func readTermFrame(r io.Reader) (termFrame, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return termFrame{}, err
	}
	n := int(binary.LittleEndian.Uint16(hdr[1:3]))
	f := termFrame{op: hdr[0]}
	if n > 0 {
		f.payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return termFrame{}, err
		}
	}
	return f, nil
}

// ---- payload 编解码 ----

func encGreeting() []byte {
	p := make([]byte, 5)
	p[0] = termProtoVer
	binary.LittleEndian.PutUint32(p[1:5], uint32(termFeatures))
	return p
}

func decGreeting(p []byte) (ver byte, features uint32, err error) {
	if len(p) < 5 {
		return 0, 0, fmt.Errorf("%w: greeting len %d", errTermFrame, len(p))
	}
	return p[0], binary.LittleEndian.Uint32(p[1:5]), nil
}

// encHello / decHello：cols/rows + flags(bit0=create) + nameLen + name。
func encHello(cols, rows uint16, create bool, name string) []byte {
	var flags byte
	if create {
		flags = 1
	}
	p := make([]byte, 6+len(name))
	binary.LittleEndian.PutUint16(p[0:2], cols)
	binary.LittleEndian.PutUint16(p[2:4], rows)
	p[4] = flags
	p[5] = byte(len(name))
	copy(p[6:], name)
	return p
}

func decHello(p []byte) (cols, rows uint16, create bool, name string, err error) {
	if len(p) < 6 {
		return 0, 0, false, "", fmt.Errorf("%w: hello len %d", errTermFrame, len(p))
	}
	cols = binary.LittleEndian.Uint16(p[0:2])
	rows = binary.LittleEndian.Uint16(p[2:4])
	create = p[4]&1 != 0
	// 布局：cols(2) rows(2) flags(1) nameLen(1) name
	n := int(p[5])
	if len(p) < 6+n {
		return 0, 0, false, "", fmt.Errorf("%w: hello name len %d > %d", errTermFrame, n, len(p)-6)
	}
	name = string(p[6 : 6+n])
	return cols, rows, create, name, nil
}

func encResize(cols, rows uint16) []byte {
	p := make([]byte, 4)
	binary.LittleEndian.PutUint16(p[0:2], cols)
	binary.LittleEndian.PutUint16(p[2:4], rows)
	return p
}

func decResize(p []byte) (cols, rows uint16, err error) {
	if len(p) < 4 {
		return 0, 0, fmt.Errorf("%w: resize len %d", errTermFrame, len(p))
	}
	return binary.LittleEndian.Uint16(p[0:2]), binary.LittleEndian.Uint16(p[2:4]), nil
}

// encAttached：cols/rows + modes(4) + agent/state + name。
func encAttached(cols, rows uint16, modes uint32, agent, state byte, name string) []byte {
	p := make([]byte, 10+len(name))
	binary.LittleEndian.PutUint16(p[0:2], cols)
	binary.LittleEndian.PutUint16(p[2:4], rows)
	binary.LittleEndian.PutUint32(p[4:8], modes)
	p[8] = agent
	p[9] = state
	copy(p[10:], name)
	return p
}

// replayDoneFlags：bit0 = 头部被截断；bit1 = 回放窗口跨过尺寸变化。
const (
	replayFlagTruncated  = 1 << 0
	replayFlagSizeChange = 1 << 1
)

func encReplayDone(replayed uint32, flags byte) []byte {
	p := make([]byte, 5)
	binary.LittleEndian.PutUint32(p[0:4], replayed)
	p[4] = flags
	return p
}

func encEnded(code int32, reason string) []byte {
	if len(reason) > termMaxReasonLen {
		reason = reason[:termMaxReasonLen]
	}
	p := make([]byte, 5+len(reason))
	binary.LittleEndian.PutUint32(p[0:4], uint32(code))
	p[4] = byte(len(reason))
	copy(p[5:], reason)
	return p
}

func encState(agent, state byte, title string) []byte {
	if len(title) > 512 {
		title = title[:512]
	}
	p := make([]byte, 4+len(title))
	p[0] = agent
	p[1] = state
	binary.LittleEndian.PutUint16(p[2:4], uint16(len(title)))
	copy(p[4:], title)
	return p
}

func encError(code, msg string) []byte {
	if len(code) > 255 {
		code = code[:255]
	}
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	p := make([]byte, 3+len(code)+len(msg))
	p[0] = byte(len(code))
	copy(p[1:], code)
	off := 1 + len(code)
	binary.LittleEndian.PutUint16(p[off:off+2], uint16(len(msg)))
	copy(p[off+2:], msg)
	return p
}

// encName / decName：统一的「nameLen + name」载荷（KILL 与 ATTACHED 之后的 name 都用它）。
func encName(name string) []byte {
	if len(name) > termMaxNameLen {
		name = name[:termMaxNameLen]
	}
	out := make([]byte, 1+len(name))
	out[0] = byte(len(name))
	copy(out[1:], name)
	return out
}

func decName(p []byte) (string, error) {
	if len(p) < 1 {
		return "", fmt.Errorf("%w: name len %d", errTermFrame, len(p))
	}
	n := int(p[0])
	if len(p) < 1+n {
		return "", fmt.Errorf("%w: name %d > %d", errTermFrame, n, len(p)-1)
	}
	return string(p[1 : 1+n]), nil
}
