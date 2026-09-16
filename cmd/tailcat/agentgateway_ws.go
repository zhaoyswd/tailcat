//go:build !cshared

// agentgateway_ws.go — 手写的最小 WebSocket 服务端（RFC 6455 子集）。
//
// 为什么不用 gorilla/websocket：port-source 的压平 modcache 里没有它，加新依赖
// 要重跑整套 modcache 压平 + go.sum 重生成；而本网关的 WS 用法极简——单端点、
// 纯文本帧、客户端只有自家 App——握手 + 帧编解码两百行内可控实现，零新依赖。
// 支持项：Upgrade 握手、text 帧、分片(continuation)、ping/pong、close、
// 7/16/64 位长度、客户端帧解掩码。不支持：压缩扩展、binary 帧（按协议错误处理）。
package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	agWSCont  = 0x0
	agWSText  = 0x1
	agWSBin   = 0x2
	agWSClose = 0x8
	agWSPing  = 0x9
	agWSPong  = 0xA
)

const agWSMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// 单条消息上限：session/read 的历史可能不小，8MB 足够且防滥用。
const agWSMaxMessage = 8 << 20

var errAgWSClosed = errors.New("agws: closed")

type agWSConn struct {
	c      net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	closed atomic.Bool
}

// agWSAccept 在裸连接上做服务端 Upgrade 握手；非 WS 请求回 400。
func agWSAccept(c net.Conn, br *bufio.Reader) (*agWSConn, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	if req.Method != http.MethodGet ||
		!headerContains(req.Header.Get("Upgrade"), "websocket") ||
		!headerContains(req.Header.Get("Connection"), "upgrade") ||
		req.Header.Get("Sec-WebSocket-Version") != "13" ||
		req.Header.Get("Sec-WebSocket-Key") == "" {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return nil, fmt.Errorf("非 WebSocket 请求: %s %s", req.Method, req.URL.Path)
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + agWSMagic))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"
	if _, err := io.WriteString(c, resp); err != nil {
		return nil, err
	}
	return &agWSConn{c: c, br: br}, nil
}

// headerContains：逗号分隔头的大小写不敏感包含（Upgrade: websocket, Upgrade）。
func headerContains(v, tok string) bool {
	for _, part := range splitComma(v) {
		if equalFoldASCII(part, tok) {
			return true
		}
	}
	return false
}

func splitComma(v string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(v); i++ {
		if i == len(v) || v[i] == ',' {
			// trim spaces
			s, e := start, i
			for s < e && v[s] == ' ' {
				s++
			}
			for e > s && v[e-1] == ' ' {
				e--
			}
			if e > s {
				out = append(out, v[s:e])
			}
			start = i + 1
		}
	}
	return out
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// ReadMessage 读到下一条完整 text 消息；控制帧就地处理（ping→pong）。
// 对端关闭返回 errAgWSClosed。
func (w *agWSConn) ReadMessage() ([]byte, error) {
	var msg []byte
	for {
		opcode, fin, payload, err := w.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case agWSPing:
			_ = w.writeFrame(agWSPong, payload)
		case agWSPong:
			// 忽略
		case agWSClose:
			_ = w.writeFrame(agWSClose, payload)
			w.markClosed()
			return nil, errAgWSClosed
		case agWSCont:
			msg = append(msg, payload...)
			if fin {
				return msg, nil
			}
		case agWSText:
			if fin && len(msg) == 0 {
				return payload, nil
			}
			msg = append(msg, payload...)
			if fin {
				return msg, nil
			}
		default:
			w.writeFrame(agWSClose, []byte{0x03, 0xf2}) // unsupported data? 用 protocol error
			w.markClosed()
			return nil, fmt.Errorf("agws: 不支持的 opcode %d", opcode)
		}
		if len(msg) > agWSMaxMessage {
			w.writeFrame(agWSClose, []byte{0x03, 0xf1}) // message too big
			w.markClosed()
			return nil, errors.New("agws: 消息超限")
		}
	}
}

// readFrame 读一个帧（含解掩码）。
func (w *agWSConn) readFrame() (opcode byte, fin bool, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(w.br, hdr[:]); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(w.br, ext[:]); err != nil {
			return
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(w.br, ext[:]); err != nil {
			return
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if opcode&0x8 != 0 && length > 125 { // 控制帧不得超 125 且不得分片
		err = errors.New("agws: 非法控制帧")
		return
	}
	if length > agWSMaxMessage {
		err = errors.New("agws: 帧超限")
		return
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(w.br, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(w.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}

// WriteMessage 发一条 text 帧（服务端不掩码）。超过 8MB 拒绝。
func (w *agWSConn) WriteMessage(p []byte) error {
	if len(p) > agWSMaxMessage {
		return errors.New("agws: 发送消息超限")
	}
	return w.writeFrame(agWSText, p)
}

func (w *agWSConn) writeFrame(opcode byte, payload []byte) error {
	if w.closed.Load() {
		return errAgWSClosed
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	var hdr []byte
	hdr = append(hdr, 0x80|opcode) // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(n))
		hdr = append(hdr, 127)
		hdr = append(hdr, ext...)
	}
	if _, err := w.c.Write(hdr); err != nil {
		w.markClosed()
		return err
	}
	if _, err := w.c.Write(payload); err != nil {
		w.markClosed()
		return err
	}
	return nil
}

// WritePing 服务端保活探测。
func (w *agWSConn) WritePing() error {
	return w.writeFrame(agWSPing, []byte("ka"))
}

func (w *agWSConn) markClosed() {
	if w.closed.CompareAndSwap(false, true) {
		w.c.Close()
	}
}

func (w *agWSConn) Close() {
	_ = w.writeFrame(agWSClose, []byte{0x03, 0xe8}) // normal closure
	w.markClosed()
}

// ---------- 测试/内部复用：帧写入（可掩码，客户端形态） ----------

// agWSWriteFrameMasked 写一个带掩码的帧（客户端→服务端方向；测试与内部客户端用）。
func agWSWriteFrameMasked(c net.Conn, opcode byte, payload []byte) error {
	hdr := []byte{0x80 | opcode}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(n))
		hdr = append(hdr, 0x80|127)
		hdr = append(hdr, ext...)
	}
	var mask [4]byte
	// 测试用固定掩码即可（RFC 允许任意值，生产客户端应随机）
	mask[0], mask[1], mask[2], mask[3] = 0x11, 0x22, 0x33, 0x44
	hdr = append(hdr, mask[:]...)
	mp := make([]byte, n)
	for i := range payload {
		mp[i] = payload[i] ^ mask[i%4]
	}
	_, err := c.Write(append(hdr, mp...))
	return err
}

// agWSClientHandshake 发起客户端握手（测试用）：返回读缓冲。
func agWSClientHandshake(c net.Conn, path string) (*bufio.Reader, error) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA}, 16))
	req := "GET " + path + " HTTP/1.1\r\nHost: ag\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	// 手工读原始响应头（http.ReadResponse 对无请求上下文的 101 语义有歧义，实测会卡）
	first, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(first, "101") {
		return nil, fmt.Errorf("握手失败: %s", strings.TrimSpace(first))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return br, nil
}
