//go:build !windows

// term_agent.go — 会话里「现在在跑哪个 agent CLI」与「任务在干什么」的判定。
//
// 数据来源：① 会话前台进程组（终端语义：用户此刻在跟谁交互）② 从前台进程组向下的进程树
// ③ 近几秒的 PTY 输出**字节数**（输出腿：TUI 只要有进展就必须重绘——spinner/流式/工具输出，
// 实测任务期 2~5KB/s、空闲 0 B/s）④ CPU 时间增量（**只对 shell/other 生效**：agent 的 CPU
// 信号全是噪声——MCP server 保活 20~70ms/s 假阳性、codex 任务期 0 增量假阴性，见阈值注释）。
//
// 判定是**纯函数**（喂进程表 + 上轮采样 + 当前时间，出 agent/state/quiet），因此可以用夹具单测，
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
	procs  []procInfo
	fgPgid int   // 会话前台进程组（0 = 拿不到）
	// prevCPU 上一轮同一进程组的 CPU 累计刻度（-1 = 没有上轮）。
	// 只对 shell/other 生效：agent 判定完全不看 CPU（见 agentCPUIgnored）。
	prevCPU   int64
	prevProcs []procInfo
	// outBytes 近 agentOutWindowSec 秒的 PTY 输出字节数（输出腿的输入，
	// 由 termSession 的秒桶累计、sample 求和后喂进来）。
	outBytes int64
	// prevState / prevQuiet 磁滞输入：上一拍状态与截至上一拍的连续安静拍数。
	prevState byte
	prevQuiet int
	shellPID  int       // 会话 shell 的 pid（用于判定「前台就是 shell 本身」）
	now       time.Time
}

// agentVerdict：判定结果。
type agentVerdict struct {
	agent byte
	state byte
	cpu   int64 // 本轮采到的 CPU 刻度（下次采样当 prevCPU 用）
	// quiet 截至本轮的连续安静拍数（working 时清零；调用方存下来当 prevQuiet）。
	quiet int
}

// 判定阈值（2026-09-18 实测标定，Mac mini / codex 1.x / opencode 1.18）：
//   - codex、opencode 空闲时 PTY 输出 0 B/s（连光标都不闪）、任务期 2~5KB/s 持续；
//   - MCP server 子进程（uvx/python）保活烧 20~70ms/s CPU——「任何 CPU 增量就算
//     running」会让挂着的 opencode 永久显示运行中；
//   - codex 的 Rust 实现任务期 CPU 增量也常为 0（<10ms/s）——CPU 腿对 agent 既假阳
//     又假阴，因此 agent 判定**只用输出量**；
//   - zsh 空闲唤醒 <10ms/s、真跑安静命令（编译/压缩）≥100ms/s——shell/other 保留
//     CPU 腿但设阈值。cpu 刻度 1 = 10ms（darwin ps time*100 / linux jiffies）。
const (
	// agentOutWindowSec 输出量统计窗口（秒）。
	agentOutWindowSec = 3
	// agentOutThreshold 窗口内 ≥ 此字节数 = 在说话。闪烁级重绘（几十字节/次）
	// 与 spinner/流式（≥500B/s）之间取的分界。
	agentOutThreshold = 300
	// shellCPUBusyDelta shell/other 一拍 CPU 增量 ≥ 此刻度数（100ms）= 真在算。
	shellCPUBusyDelta = 10
	// agentQuietDegrade running 降级需要窗口排空后再连续安静的拍数（磁滞：
	// 升级即时，降级要 quiet > 此值）。
	agentQuietDegrade = 2
)

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
	// 已知 agent 在前台（codex/claude/opencode/openclaw…）——判定完全走输出腿，
	// CPU 腿只留给 shell/other（agentCPUIgnored 处的阈值注释有实测依据）。
	isAgent := matchedProc != nil

	// CPU 累计：前台进程组所有成员之和（含被 exec 换掉的子进程）。无论判定用不用，
	// 都要采出来返回给下一拍当 prevCPU（shell/other 的腿要用）。
	var cpu int64
	for _, pr := range fg {
		if pr.cpu > 0 {
			cpu += pr.cpu
		}
	}
	v.cpu = cpu

	// 输出腿：窗口内输出量 ≥ 阈值 = 在说话（闪烁级重绘被滤掉）。
	outTalking := p.outBytes >= agentOutThreshold
	// CPU 腿（仅 shell/other）：一拍增量 ≥ 100ms = 真在算（zsh 空闲唤醒被滤掉）。
	var cpuDelta int64
	if p.prevCPU >= 0 && cpu > p.prevCPU {
		cpuDelta = cpu - p.prevCPU
	}
	working := outTalking || (!isAgent && cpuDelta >= shellCPUBusyDelta)

	// 磁滞：安静拍计数（working 清零；否则累加，供降级判断与下一拍）。
	quiet := 0
	if !working {
		quiet = p.prevQuiet + 1
		if quiet > 99 {
			quiet = 99
		}
		// 降级保护：上一拍 running 且安静拍数未超限 → 维持 running（升级即时、
		// 降级要窗口排空后连续安静 agentQuietDegrade+1 拍）。
		if p.prevState == stateRunning && quiet <= agentQuietDegrade {
			working = true
		}
	}
	v.quiet = quiet

	switch {
	case working:
		v.state = stateRunning
	case isAgent:
		v.state = stateWaiting
	default:
		v.state = stateIdle
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
