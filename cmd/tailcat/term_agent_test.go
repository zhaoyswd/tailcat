//go:build !windows

package main

import (
	"testing"
	"time"
)

// 夹具进程树：登录 shell（pid 100, pgid 100）+ 前台子进程（codex / npx 包装 / 无）。
func fixture(children ...procInfo) []procInfo {
	base := []procInfo{{pid: 100, ppid: 1, pgid: 100, cpu: 10, args: "/bin/zsh -l"}}
	return append(base, children...)
}

func TestClassifyAgent(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name      string
		procs     []procInfo
		prevCPU   int64
		outBytes  int64
		prevState byte
		prevQuiet int
		want      byte
		wantSt    byte
		fg        int
	}{
		{
			name:    "shell 空闲（zsh 唤醒烧 3 刻度 < 阈值）",
			procs:   fixture(),
			prevCPU: 10, outBytes: 0,
			want: agentShell, wantSt: stateIdle, fg: 100,
		},
		{
			name:    "shell 有输出（输出腿）",
			procs:   fixture(),
			prevCPU: 10, outBytes: 500,
			want: agentShell, wantSt: stateRunning, fg: 100,
		},
		{
			name: "shell 跑安静命令（CPU ≥100ms/s，CPU 腿对 shell 生效）",
			procs: fixture(procInfo{pid: 500, ppid: 100, pgid: 500, cpu: 1100,
				args: "make -j8"}),
			prevCPU: 1000, outBytes: 0,
			want: agentOther, wantSt: stateRunning,
		},
		{
			name: "agent 任务期（输出 ≥300B → running，CPU 零增量也成立）",
			procs: fixture(procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 5000,
				args: "/usr/local/bin/codex --model gpt-5"}),
			prevCPU: 5000, outBytes: 2500,
			want: agentCodex, wantSt: stateRunning,
		},
		{
			name: "codex 空闲（输出 0，CPU 不涨）→ waiting",
			procs: fixture(procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 5000,
				args: "/usr/local/bin/codex"}),
			prevCPU: 5000, outBytes: 0,
			want: agentCodex, wantSt: stateWaiting,
		},
		{
			// 2026-09-18 实测：用户 opencode 会话卡永久 running 的根因——MCP
			// server（uvx/python 子进程）保活烧 20~70ms/s。agent 判定不看 CPU。
			name: "agent 空闲但 MCP 保活烧 CPU（CPU 腿对 agent 失效）→ waiting",
			procs: fixture(
				procInfo{pid: 300, ppid: 100, pgid: 300, cpu: 5020, args: "/opt/homebrew/bin/opencode"},
				procInfo{pid: 301, ppid: 300, pgid: 300, cpu: 7040, args: "uv tool uvx mcp-server-foo"},
			),
			prevCPU: 12000, outBytes: 0,
			want: agentOpencode, wantSt: stateWaiting,
		},
		{
			// 闪烁级重绘（几十字节/次）不触发输出腿。
			name: "agent 闪烁级小重绘（50B < 阈值）→ waiting",
			procs: fixture(procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 5000,
				args: "/usr/local/bin/codex"}),
			prevCPU: 5000, outBytes: 50,
			want: agentCodex, wantSt: stateWaiting,
		},
		{
			// 磁滞：任务刚停（窗口已排空），本拍是第 1 拍安静（quiet=1 ≤ 阈值）→ 维持。
			name: "磁滞：running 后安静第 1 拍仍 running",
			procs: fixture(procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 5000,
				args: "/usr/local/bin/codex"}),
			prevCPU: 5000, outBytes: 0, prevState: stateRunning, prevQuiet: 0,
			want: agentCodex, wantSt: stateRunning,
		},
		{
			name: "磁滞：安静第 2 拍仍 running（agentQuietDegrade=2）",
			procs: fixture(procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 5000,
				args: "/usr/local/bin/codex"}),
			prevCPU: 5000, outBytes: 0, prevState: stateRunning, prevQuiet: 1,
			want: agentCodex, wantSt: stateRunning,
		},
		{
			name: "磁滞：安静第 3 拍降级 waiting",
			procs: fixture(procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 5000,
				args: "/usr/local/bin/codex"}),
			prevCPU: 5000, outBytes: 0, prevState: stateRunning, prevQuiet: 2,
			want: agentCodex, wantSt: stateWaiting,
		},
		{
			name: "npx 包装（node 跑 codex.js）",
			procs: fixture(
				procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 100, args: "npm exec codex"},
				procInfo{pid: 201, ppid: 200, pgid: 200, cpu: 900,
					args: "node /Users/u/.npm/_npx/1/node_modules/@openai/codex/bin/codex.js"},
			),
			prevCPU: 900, outBytes: 800,
			want: agentCodex, wantSt: stateRunning,
		},
		{
			name: "openclaw 有输出 → running",
			procs: fixture(procInfo{pid: 400, ppid: 100, pgid: 400, cpu: 50,
				args: "openclaw chat"}),
			prevCPU: 0, outBytes: 1000,
			want: agentOpenclaw, wantSt: stateRunning,
		},
		{
			// 旧语义里这条是 running（CPU 从 0→50）；新语义 agent 不看 CPU。
			name: "openclaw 纯 CPU 增量不算 running",
			procs: fixture(procInfo{pid: 400, ppid: 100, pgid: 400, cpu: 50,
				args: "openclaw chat"}),
			prevCPU: 0, outBytes: 0,
			want: agentOpenclaw, wantSt: stateWaiting,
		},
		{
			name:    "前台是别的程序且安静 → other/idle",
			procs:   fixture(procInfo{pid: 500, ppid: 100, pgid: 500, cpu: 5, args: "vim notes.md"}),
			prevCPU: 5, outBytes: 0,
			want: agentOther, wantSt: stateIdle,
		},
		{
			name:    "拿不到前台进程组 → unknown",
			procs:   fixture(),
			prevCPU: 10, outBytes: 0,
			want: agentUnknown, wantSt: stateUnknown, fg: -1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fg := c.fg
			if fg == 0 {
				fg = c.procs[len(c.procs)-1].pgid
			}
			if fg == -1 {
				fg = 0
			}
			v := classifyAgent(agentProbe{
				procs:     c.procs,
				fgPgid:    fg,
				prevCPU:   c.prevCPU,
				outBytes:  c.outBytes,
				prevState: c.prevState,
				prevQuiet: c.prevQuiet,
				shellPID:  100,
				now:       now,
			})
			if v.agent != c.want || v.state != c.wantSt {
				t.Errorf("agent=%s state=%s；期望 agent=%s state=%s",
					agentName(v.agent), stateName(v.state), agentName(c.want), stateName(c.wantSt))
			}
		})
	}
}

func TestAgentOfCommand(t *testing.T) {
	yes := []string{
		"codex",
		"/usr/local/bin/codex --yolo",
		"node /x/codex.js",
		"npx claude",
		"/opt/homebrew/bin/opencode",
		"openclaw",
	}
	for _, cmd := range yes {
		if _, ok := agentOfCommand(cmd); !ok {
			t.Errorf("%q 应当识别为 agent", cmd)
		}
	}
	no := []string{
		"/bin/zsh -l",
		"vim codex.md",
		"grep codex /var/log/x",
		"",
	}
	for _, cmd := range no {
		if a, ok := agentOfCommand(cmd); ok {
			t.Errorf("%q 不应识别成 agent（得到 %s）", cmd, agentName(a))
		}
	}
}

// TestOutBuckets 秒桶的窗口语义：跨秒空洞只按 sec 求和、覆盖旧桶。
func TestOutBuckets(t *testing.T) {
	s := &termSession{}
	now := time.Now()
	s.countOutLocked(100, now)
	s.countOutLocked(50, now) // 同秒累加
	if got := s.outBytesLocked(now); got != 150 {
		t.Fatalf("当前秒窗口和 = %d，期望 150", got)
	}
	// 3 秒窗口（含当前秒）：now-2 仍在、now-3 排除
	s2 := &termSession{}
	s2.countOutLocked(300, now.Add(-3*time.Second))
	s2.countOutLocked(10, now.Add(-2*time.Second))
	s2.countOutLocked(20, now)
	if got := s2.outBytesLocked(now); got != 30 {
		t.Fatalf("窗口和 = %d，期望 30（now-3 的 300 应排除）", got)
	}
	// 定长 4 桶：写第 5 个不同秒时抢最旧（now-4s 的桶没了，窗口只剩最近 3 秒）
	s3 := &termSession{}
	for i := 0; i < 5; i++ {
		s3.countOutLocked(i+1, now.Add(time.Duration(i-4)*time.Second))
	}
	for _, b := range s3.outBuckets {
		if b.sec == now.Add(-4*time.Second).Unix() && b.n != 0 {
			t.Fatalf("最旧桶（now-4s）应被抢占，仍持有 %d 字节", b.n)
		}
	}
	if got := s3.outBytesLocked(now); got != 12 { // now-2:3 + now-1:4 + now:5
		t.Fatalf("抢占后窗口和 = %d，期望 12", got)
	}
}
