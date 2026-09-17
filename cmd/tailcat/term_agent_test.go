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
	recent := now.Add(-500 * time.Millisecond)
	old := now.Add(-30 * time.Second)

	cases := []struct {
		name    string
		procs   []procInfo
		prevCPU int64
		lastOut time.Time
		want    byte
		wantSt  byte
	}{
		{
			name:    "shell 空闲",
			procs:   fixture(),
			prevCPU: 10,
			lastOut: old,
			want:    agentShell,
			wantSt:  stateIdle,
		},
		{
			name:    "shell 正在跑命令（有输出）",
			procs:   fixture(),
			prevCPU: 10,
			lastOut: recent,
			want:    agentShell,
			wantSt:  stateRunning,
		},
		{
			name: "直接跑 codex 且 CPU 在涨 → running",
			procs: fixture(procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 5000,
				args: "/usr/local/bin/codex --model gpt-5"}),
			prevCPU: 4000,
			lastOut: old,
			want:    agentCodex,
			wantSt:  stateRunning,
		},
		{
			name: "codex 静默且 CPU 不涨 → waiting",
			procs: fixture(procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 5000,
				args: "/usr/local/bin/codex"}),
			prevCPU: 5000,
			lastOut: old,
			want:    agentCodex,
			wantSt:  stateWaiting,
		},
		{
			name: "npx 包装（node 跑 codex.js）",
			procs: fixture(
				procInfo{pid: 200, ppid: 100, pgid: 200, cpu: 100, args: "npm exec codex"},
				procInfo{pid: 201, ppid: 200, pgid: 200, cpu: 900,
					args: "node /Users/u/.npm/_npx/1/node_modules/@openai/codex/bin/codex.js"},
			),
			prevCPU: 900,
			lastOut: recent,
			want:    agentCodex,
			wantSt:  stateRunning,
		},
		{
			name: "opencode 备用屏（有输出）",
			procs: fixture(procInfo{pid: 300, ppid: 100, pgid: 300, cpu: 20,
				args: "/opt/homebrew/bin/opencode"}),
			prevCPU: 20,
			lastOut: recent,
			want:    agentOpencode,
			wantSt:  stateRunning,
		},
		{
			name: "openclaw",
			procs: fixture(procInfo{pid: 400, ppid: 100, pgid: 400, cpu: 50,
				args: "openclaw chat"}),
			prevCPU: 0,
			lastOut: old,
			want:    agentOpenclaw,
			wantSt:  stateRunning, // CPU 从 0 → 50，说明在算
		},
		{
			name:    "前台是别的程序 → other",
			procs:   fixture(procInfo{pid: 500, ppid: 100, pgid: 500, cpu: 5, args: "vim notes.md"}),
			prevCPU: 5,
			lastOut: old,
			want:    agentOther,
			wantSt:  stateIdle,
		},
		{
			name:    "拿不到前台进程组 → unknown",
			procs:   fixture(),
			prevCPU: 10,
			lastOut: old,
			want:    agentUnknown,
			wantSt:  stateUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fg := 0
			if c.want != agentUnknown {
				fg = c.procs[len(c.procs)-1].pgid
				if c.name == "shell 空闲" || c.name == "shell 正在跑命令（有输出）" {
					fg = 100
				}
			}
			v := classifyAgent(agentProbe{
				procs:    c.procs,
				fgPgid:   fg,
				prevCPU:  c.prevCPU,
				lastOut:  c.lastOut,
				shellPID: 100,
				now:      now,
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
