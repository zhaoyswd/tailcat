//go:build !windows

// term_modes.go — 出口侧的**旁路扫描器**（只读，不消费字节）：从 PTY 输出流里维护
//
//	① 私有模式位掩码（光标键/鼠标上报/焦点/括号粘贴/备用屏）——attach 时下发给客户端，
//	   让「新建的本地 vt」立刻知道当前屏态（term 项目当年在客户端做 capture/回灌，
//	   踩过时机坑；这里改由出口持续维护，客户端零状态）。
//	② OSC 0/2 窗口标题（列表与页面副标题）。
//
// 关键约束：读缓冲边界不是协议边界 ⇒ 状态机必须能吃**跨 read 切断**的序列。
package main

// 模式位（与 App 侧 terminal 模块的 stream 层一一对应）。
const (
	termModeDECCKM    uint32 = 1 << 0 // ?1h/l   应用光标键
	termModeMouse1000 uint32 = 1 << 1 // ?1000h/l 鼠标：普通跟踪
	termModeMouse1002 uint32 = 1 << 2 // ?1002h/l 鼠标：按键跟踪
	termModeMouse1003 uint32 = 1 << 3 // ?1003h/l 鼠标：任意移动
	termModeMouse1006 uint32 = 1 << 4 // ?1006h/l 鼠标：SGR 格式
	termModeFocus     uint32 = 1 << 5 // ?1004h/l 焦点事件
	termModeBracketed uint32 = 1 << 6 // ?2004h/l 括号粘贴
	termModeAltScreen uint32 = 1 << 7 // ?1049h/l（含 ?47/?1047）备用屏
)

const (
	termScanNone = iota
	termScanEsc
	termScanCSI
	termScanOSC
	termScanOSCEsc
)

const (
	termScanMaxCSI = 64  // CSI 参数串上限（超长即放弃该序列，防内存放大）
	termScanMaxOSC = 512 // OSC 载荷上限
	termTitleMax   = 256 // 标题落库上限
)

// termScan 是每会话一个的扫描器（由会话锁保护，与 pump 同线程调用）。
type termScan struct {
	st      int
	buf     []byte
	tooLong bool

	modes uint32
	title string

	// changed 在「本批字节里模式位或标题有变化」时置位（调用方读后自行清零）。
	changed bool
}

func (s *termScan) write(p []byte) {
	for _, b := range p {
		s.byteIn(b)
	}
}

func (s *termScan) push(b byte, max int) {
	if len(s.buf) >= max {
		s.tooLong = true
		return
	}
	s.buf = append(s.buf, b)
}

func (s *termScan) byteIn(b byte) {
	switch s.st {
	case termScanNone:
		if b == 0x1b {
			s.st = termScanEsc
		}
	case termScanEsc:
		switch b {
		case '[':
			s.st, s.buf, s.tooLong = termScanCSI, s.buf[:0], false
		case ']':
			s.st, s.buf, s.tooLong = termScanOSC, s.buf[:0], false
		default:
			// 其它 ESC 序列（单字符或 DCS/OSC 之外的）不关心。
			s.st = termScanNone
		}
	case termScanCSI:
		if b >= 0x40 && b <= 0x7e { // final byte
			if !s.tooLong {
				s.finishCSI(b)
			}
			s.st = termScanNone
			return
		}
		s.push(b, termScanMaxCSI)
	case termScanOSC:
		switch b {
		case 0x07: // BEL
			if !s.tooLong {
				s.finishOSC()
			}
			s.st = termScanNone
		case 0x1b:
			s.st = termScanOSCEsc
		default:
			s.push(b, termScanMaxOSC)
		}
	case termScanOSCEsc:
		// ESC \ = ST；其它则把 ESC 当作序列结束（保守处理）。
		if b == '\\' && !s.tooLong {
			s.finishOSC()
		}
		s.st = termScanNone
	}
}

// finishCSI 处理 `CSI ? Pm h/l`（私有模式设置/复位）；其它 CSI 一律忽略。
func (s *termScan) finishCSI(final byte) {
	if final != 'h' && final != 'l' {
		return
	}
	params := string(s.buf)
	if len(params) == 0 || params[0] != '?' {
		return
	}
	set := final == 'h'
	var changed bool
	for _, part := range splitSemi(params[1:]) {
		n, ok := parseSmallInt(part)
		if !ok {
			continue
		}
		var bit uint32
		switch n {
		case 1:
			bit = termModeDECCKM
		case 47, 1047, 1049:
			bit = termModeAltScreen
		case 1000:
			bit = termModeMouse1000
		case 1002:
			bit = termModeMouse1002
		case 1003:
			bit = termModeMouse1003
		case 1004:
			bit = termModeFocus
		case 1006:
			bit = termModeMouse1006
		case 2004:
			bit = termModeBracketed
		default:
			continue
		}
		before := s.modes
		if set {
			s.modes |= bit
		} else {
			s.modes &^= bit
		}
		changed = changed || before != s.modes
	}
	s.changed = s.changed || changed
}

// finishOSC 处理 OSC 0/1/2（窗口标题）。
func (s *termScan) finishOSC() {
	payload := string(s.buf)
	if payload == "" {
		return
	}
	semi := -1
	for i := 0; i < len(payload); i++ {
		if payload[i] == ';' {
			semi = i
			break
		}
	}
	if semi < 0 {
		return
	}
	code := payload[:semi]
	if code != "0" && code != "1" && code != "2" {
		return
	}
	title := sanitizeTitle(payload[semi+1:])
	if title == s.title {
		return
	}
	s.title = title
	s.changed = true
}

// sanitizeTitle 去掉控制字符并按上限截断（远端可以随便发标题，别让它撑爆元数据）。
func sanitizeTitle(t string) string {
	out := make([]byte, 0, len(t))
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
		if len(out) >= termTitleMax {
			break
		}
	}
	return string(out)
}

func splitSemi(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// parseSmallInt 只接受 0..9999 的十进制（CSI 参数），其余视为无效。
func parseSmallInt(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
