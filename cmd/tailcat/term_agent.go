//go:build !windows

// term_agent.go — 会话里「现在在跑哪个 agent CLI」与「任务在干什么」的判定。
//
// 数据来源：① 会话前台进程组（终端语义：用户此刻在跟谁交互）② 从前台进程组向下的进程树
// ③ CPU 时间增量（agent 真在算）④ 最近的 PTY 输出（在说话/在刷屏）。
//
// 判定是**纯函数**（喂进程表 + 上轮采样 + 当前时间，出 agent/state），因此可以用夹具单测，
// 不依赖真跑起某个 CLI。平台差异只在「怎么拿到进程表」那一层（term_agent_unix.go）。
package main

import (
	"path"
	"strings"
	"time"
)

// procInfo 一条进程记录（平台的进程表拍平成这个样子）。
type procInfo struct {
	pid  int
	ppid int
	pgid int
	// cpu 是累计 CPU 时间的**单调刻度**（linux: jiffies；darwin: ps 的 time * 100）。
	// 只用来做两次采样之间的差值，单位本身不重要，但必须自洽。
	cpu int64
	// args 是命令行（argv 拼起来；darwin 用 ps 的 command= 列）。
	args string
}

// agentProbe：一轮采样需要的输入。
type agentProbe struct {
	procs     []procInfo
	fgPgid    int   // 会话前台进程组（0 = 拿不到）
	prevCPU   int64 // 上一轮同一进程组的 CPU 累计刻度（-1 = 没有上轮）
	prevProcs []procInfo
	lastOut   time.Time // 会话最近一次 PTY 输出的时间
	shellPID  int       // 会话 shell 的 pid（用于判定「前台就是 shell 本身」）
	now       time.Time
}

// agentVerdict：判定结果。
type agentVerdict struct {
	agent byte
	state byte
	cpu   int64 // 本轮采到的 CPU 刻度（下次采样当 prevCPU 用）
}

// agentQuietWindow：多久没有输出就算「没在说话」（配合 CPU 增量判 waiting）。
const agentQuietWindow = 3 * time.Second

// agentNames 已知 agent 的可执行名（不含扩展名）。新增一种 CLI 只加这里一行。
var agentNames = []struct {
	name  string
	agent byte
}{
	{"codex", agentCodex},
	{"claude", agentClaude},
	{"opencode", agentOpencode},
	{"openclaw", agentOpenclaw},
}

// classifyAgent 从进程表里判断前台进程组「正在跑什么」。
func classifyAgent(p agentProbe) agentVerdict {
	v := agentVerdict{agent: agentShell, state: stateIdle, cpu: -1}
	if len(p.procs) == 0 || p.fgPgid == 0 {
		v.agent = agentUnknown
		v.state = stateUnknown
		return v
	}

	// 前台进程组里的成员（终端把前台任务放在同一个 pgid 下）。
	fg := make([]procInfo, 0, 4)
	for _, pr := range p.procs {
		if pr.pgid == p.fgPgid {
			fg = append(fg, pr)
		}
	}
	if len(fg) == 0 {
		v.agent = agentUnknown
		v.state = stateUnknown
		return v
	}

	// 谁在跑 agent：取命中名字的进程里 **最深** 的那个（包一层 npx/node 也认）。
	matched := byte(agentOther)
	var matchedProc *procInfo
	for i := range fg {
		pr := &fg[i]
		a, ok := agentOfCommand(pr.args)
		if !ok {
			continue
		}
		if matchedProc == nil || isDescendantOf(pr.pid, matchedProc.pid, p.procs) {
			matched, matchedProc = a, pr
		}
	}
	if matchedProc != nil {
		v.agent = matched
	} else if anyShellInGroup(fg, p.shellPID) {
		v.agent = agentShell
	} else {
		v.agent = agentOther
	}

	// CPU 累计：前台进程组所有成员之和（含被 exec 换掉的子进程）。
	var cpu int64
	for _, pr := range fg {
		if pr.cpu > 0 {
			cpu += pr.cpu
		}
	}
	v.cpu = cpu

	active := p.now.Sub(p.lastOut) < agentQuietWindow
	working := active
	if p.prevCPU >= 0 && cpu > p.prevCPU {
		working = true
	}
	switch {
	case working:
		v.state = stateRunning
	case v.agent == agentShell || v.agent == agentOther:
		v.state = stateIdle
	default:
		v.state = stateWaiting
	}
	return v
}

// agentOfCommand 判断一条命令行是不是已知 agent。识别规则刻意保守（宁可不认，不要乱认：
// 认错会让界面显示错误的图标/状态）：
//   - argv[0] 的可执行名命中 → 命中（`codex`、`/usr/local/bin/codex`）
//   - 带路径的 token 命中 basename → 命中（`node .../@openai/codex/bin/codex.js`）
//   - 裸名字只在前面是 **runner** 时命中（`npx codex`、`npm exec codex`、`bunx claude`）
//
// ⇒ `grep codex /var/log/x` 这类「把名字当参数用」的命令不会误判。
func agentOfCommand(cmdline string) (byte, bool) {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return 0, false
	}
	if a, ok := agentNameOfToken(fields[0]); ok {
		return a, true
	}
	for i := 1; i < len(fields); i++ {
		tok := fields[i]
		if strings.HasPrefix(tok, "-") {
			continue
		}
		a, ok := agentNameOfToken(tok)
		if !ok {
			continue
		}
		if strings.Contains(tok, "/") || isRunnerToken(fields[i-1]) {
			return a, true
		}
	}
	return 0, false
}

// agentNameOfToken 把单个 token 的可执行名（去扩展名）映射到 agent 枚举。
func agentNameOfToken(tok string) (byte, bool) {
	base := path.Base(tok)
	for _, ext := range []string{".js", ".mjs", ".cjs", ".exe"} {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" {
		return 0, false
	}
	for _, known := range agentNames {
		if base == known.name {
			return known.agent, true
		}
	}
	return 0, false
}

// isRunnerToken：包一层跑 agent 的常见 runner（npx/bunx/yarn dlx/pnpm dlx/npm exec）。
func isRunnerToken(tok string) bool {
	switch path.Base(tok) {
	case "npx", "bunx", "dlx", "exec":
		return true
	}
	return false
}

// anyShellInGroup 判断前台进程组里是不是「就是那个登录 shell」（没有别的前台程序）。
func anyShellInGroup(fg []procInfo, shellPID int) bool {
	for _, pr := range fg {
		if shellPID != 0 && pr.pid == shellPID {
			return true
		}
	}
	// shellPID 拿不到时退化为「命令行首 token 是常见 shell 名」。
	fields := strings.Fields(fg[0].args)
	if len(fields) == 0 {
		return false
	}
	switch path.Base(fields[0]) {
	case "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh":
		return true
	}
	return false
}

// isDescendantOf 判断 pid 是不是 anc 的后代（用于在多个命中里取「最深」的那个）。
func isDescendantOf(pid, anc int, procs []procInfo) bool {
	if anc == 0 {
		return false
	}
	ppid := map[int]int{}
	for _, pr := range procs {
		ppid[pr.pid] = pr.ppid
	}
	for cur, hops := pid, 0; hops < 16; hops++ {
		p, ok := ppid[cur]
		if !ok || p <= 1 {
			return false
		}
		if p == anc {
			return true
		}
		cur = p
	}
	return false
}
