//go:build !windows

package main

import "testing"

// 私有模式位扫描：跨 read 切断、多参数、复位、未知参数、OSC 标题。
func TestTermModeScan(t *testing.T) {
	cases := []struct {
		name     string
		chunks   []string
		want     uint32
		wantTitl string
	}{
		{
			name:   "基本设置",
			chunks: []string{"\x1b[?1000h\x1b[?1006h\x1b[?2004h"},
			want:   termModeMouse1000 | termModeMouse1006 | termModeBracketed,
		},
		{
			name:   "多参数一条序列",
			chunks: []string{"\x1b[?1002;1003;1004h"},
			want:   termModeMouse1002 | termModeMouse1003 | termModeFocus,
		},
		{
			name:   "复位",
			chunks: []string{"\x1b[?1000h\x1b[?1000l"},
			want:   0,
		},
		{
			name:   "备用屏",
			chunks: []string{"\x1b[?1049h"},
			want:   termModeAltScreen,
		},
		{
			name:   "跨 read 切断（逐字节喂）",
			chunks: []string{"\x1b", "[", "?", "1", "0", "0", "2", "h"},
			want:   termModeMouse1002,
		},
		{
			name:   "未知参数忽略、已知参数生效",
			chunks: []string{"\x1b[?9999;2004h"},
			want:   termModeBracketed,
		},
		{
			name:   "非私有 CSI 不影响位",
			chunks: []string{"\x1b[1;31mred\x1b[0m"},
			want:   0,
		},
		{
			name:     "OSC 标题（BEL 结尾）",
			chunks:   []string{"\x1b]0;codex · 跑测试\x07"},
			want:     0,
			wantTitl: "codex · 跑测试",
		},
		{
			name:     "OSC 标题（ST 结尾 + 切断）",
			chunks:   []string{"\x1b]2;zsh: /tmp\x1b", "\\"},
			want:     0,
			wantTitl: "zsh: /tmp",
		},
		{
			name:     "OSC 非标题（52 剪贴板）忽略",
			chunks:   []string{"\x1b]52;c;aGVsbG8=\x07"},
			want:     0,
			wantTitl: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s termScan
			for _, chunk := range c.chunks {
				s.write([]byte(chunk))
			}
			if s.modes != c.want {
				t.Errorf("modes = 0x%x，期望 0x%x", s.modes, c.want)
			}
			if s.title != c.wantTitl {
				t.Errorf("title = %q，期望 %q", s.title, c.wantTitl)
			}
		})
	}
}

// 超长序列必须被丢弃且不把内存撑大（远端可以随便发）。
func TestTermModeScanOverlong(t *testing.T) {
	var s termScan
	long := make([]byte, 0, 4096)
	long = append(long, "\x1b[?"...)
	for i := 0; i < 4000; i++ {
		long = append(long, '1')
	}
	long = append(long, 'h')
	s.write(long)
	if s.modes != 0 {
		t.Errorf("超长 CSI 不应生效：0x%x", s.modes)
	}
	if len(s.buf) > termScanMaxCSI {
		t.Errorf("缓冲区失控：%d", len(s.buf))
	}
}
