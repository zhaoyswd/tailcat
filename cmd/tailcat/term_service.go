//go:build !windows

// term_service.go — 出口侧的终端服务：会话注册表 + PTY + 帧协议。
//
// 设计要点（见 openspec exit-terminal 设计 D3–D8）：
//   - **会话由出口持有**：客户端断开只摘泵、不杀进程；重进 attach 先回放有界历史。
//   - 默认开启（只要服务里有 exit-node）、零 CLI 旗标；调参走 TAILCAT_TERM_* 环境变量。
//   - 历史是**输出字节环**（不存输入）⇒ 回放不会重复用户敲过的命令；
//     回放窗口 = 尾部优先 + 时间预算，起点对齐行边界/ESC，attach 完成后用**尺寸哨兵**逼 TUI 重绘。
//   - 私有模式位与 OSC 标题由旁路扫描器维护（term_modes.go），随 ATTACHED/STATE 下发。
//   - 资源回收四步硬规则：Wait → 关 master → 删注册表 → 释放历史（缺一会漏 fd/僵尸）。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"tailscale.com/types/logger"
)

// termPlatformSupported 报告本平台是否支持终端服务（unix = 是；windows 见 *_windows.go）。
func termPlatformSupported() bool { return true }

const (
	termDefaultPort        = 7724
	termDefaultHistory     = 1 << 20   // 每会话保留的输出字节
	termDefaultReplay      = 256 << 10 // attach 时回放窗口上限
	termDefaultMaxSessions = 16

	termReplayBudget = 2 * time.Second
	termWriteTimeout = 10 * time.Second
	termHelloTimeout = 15 * time.Second
	termKillGrace    = 500 * time.Millisecond
	termSamplePeriod = time.Second
	termReplayTrim   = 4096 // 起点对齐时最多前看这么多字节
)

var termNameRx = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// termConfig 服务配置（全部来自环境变量，默认值即可用）。
type termConfig struct {
	port        uint16
	shell       string // 空 = 用户登录 shell
	history     int
	replay      int
	replayEpoch string // all | last
	maxSessions int
	detect      bool
}

// termDisabledByEnv：TAILCAT_TERM=off 是唯一的关闭方式（刻意不做 CLI 旗标）。
func termDisabledByEnv() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("TAILCAT_TERM")), "off")
}

func termEnvInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func termConfigFromEnv() termConfig {
	cfg := termConfig{
		port:        uint16(termEnvInt("TAILCAT_TERM_PORT", termDefaultPort)),
		shell:       strings.TrimSpace(os.Getenv("TAILCAT_TERM_SHELL")),
		history:     termEnvInt("TAILCAT_TERM_HISTORY", termDefaultHistory),
		replay:      termEnvInt("TAILCAT_TERM_REPLAY", termDefaultReplay),
		replayEpoch: strings.ToLower(strings.TrimSpace(os.Getenv("TAILCAT_TERM_REPLAY_EPOCH"))),
		maxSessions: termEnvInt("TAILCAT_TERM_MAX_SESSIONS", termDefaultMaxSessions),
		detect:      !strings.EqualFold(strings.TrimSpace(os.Getenv("TAILCAT_TERM_DETECT")), "off"),
	}
	if cfg.replayEpoch != "last" {
		cfg.replayEpoch = "all"
	}
	if cfg.replay > cfg.history {
		cfg.replay = cfg.history
	}
	return cfg
}

// ---- 登录 shell 与登录环境：与「用户自己开一个终端」对齐 ----
//
// 出口进程常由 launchd / systemd / docker 拉起，继承的是**服务环境**：里面有
// XPC_SERVICE_NAME、OSLogRateLimit 这类只在服务上下文里成立的变量，$SHELL 也可能缺失
//（真机实测：LaunchAgent 拉起的出口，会话里带 XPC_SERVICE_NAME=me.zhaozhe.tailcat-exit、
// 没有 TERM_PROGRAM，而 SHELL 一旦缺失就会掉到 /bin/sh）。原样交给 PTY 里的 shell，
// 用户拿到的就是一个「像服务、不像终端」的环境。所以这里对齐三件事：
//
//  1. 选**账号数据库里的登录 shell**（macOS dscl / 其它 unix /etc/passwd），
//     逐级回退 $SHELL → 平台默认；候选项都要求可执行。
//  2. 只把「用户身份 + 临时目录 + 语言 + agent socket」白名单变量交给子进程，
//     服务变量一律不带（XPC_*/OSLogRateLimit/__CF*…）。
//  3. 终端标记（TERM/COLORTERM/TERM_PROGRAM[/_VERSION]/TERM_SESSION_ID）由我们写，
//     让会话里跑的工具知道自己在一个名为 Tailcat 的终端里（TERM_PROGRAM 是 Terminal/iTerm/vscode 的惯例）。
//
// 之后一律以**登录 shell** 起（默认 `shell -l`；命令模式 `shell -lc '<命令>'`）：
// PATH、brew、pnpm 等由用户自己的 /etc/zprofile → ~/.zprofile → ~/.zshrc 决定 ——
// 和用户直接开终端走同一条路径，用户改 rc 之后下一个会话即生效。

// termPlatformShells 平台默认 shell 候选（账号数据库与 $SHELL 都拿不到时的最后回退）。
func termPlatformShells() []string {
	if runtime.GOOS == "darwin" {
		return []string{"/bin/zsh", "/bin/bash", "/bin/sh"}
	}
	return []string{"/bin/bash", "/bin/sh"}
}

// termAccountShell 从账号数据库取该用户的登录 shell（取不到返回空串）。
func termAccountShell() string {
	name := strings.TrimSpace(os.Getenv("USER"))
	if name == "" {
		name = strings.TrimSpace(os.Getenv("LOGNAME"))
	}
	if name == "" {
		if u, err := user.Current(); err == nil {
			name = u.Username
		}
	}
	if name == "" {
		return ""
	}
	if runtime.GOOS == "darwin" {
		// macOS 本地账号在 Open Directory 里，/etc/passwd 通常查不到（本机实测：
		// `grep zhaozhe /etc/passwd` 无输出，必须问 dscl）。
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+name, "UserShell").Output()
		if err != nil {
			return ""
		}
		s := strings.TrimSpace(string(out))
		if i := strings.LastIndex(s, ":"); i >= 0 {
			s = strings.TrimSpace(s[i+1:])
		}
		return s
	}
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[0] == name {
			return strings.TrimSpace(f[6])
		}
	}
	return ""
}

// termExecutable 判定候选 shell 是否真的可执行（不存在/目录/无 x 位都不行）。
func termExecutable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// pickShell 取第一个可执行的候选；全不可执行时返回首个非空候选
// （宁可让 spawn 明确失败，也不静默换一个用户没选的 shell）。
func pickShell(cands ...string) string {
	first := ""
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if first == "" {
			first = c
		}
		if termExecutable(c) {
			return c
		}
	}
	if first != "" {
		return first
	}
	return "/bin/sh"
}

// loginShell 解析顺序：账号数据库 > $SHELL（服务环境）> 平台默认。
func loginShell() string {
	return pickShell(append([]string{termAccountShell(), strings.TrimSpace(os.Getenv("SHELL"))},
		termPlatformShells()...)...)
}

// termEnvKeep 从服务环境里**白名单**保留的变量：身份、家目录、临时目录、语言、PATH。
// SSH_AUTH_SOCK 保留是有意的：macOS 的 Terminal 会话同样带一个 launchd 的 per-user
// listener socket，留着 ssh-agent 转发才继续可用。
var termEnvKeep = []string{
	"HOME", "USER", "LOGNAME", "TMPDIR", "SSH_AUTH_SOCK", "PATH",
	"LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
}

func termEnvKept(k string) bool {
	for _, want := range termEnvKeep {
		if k == want {
			return true
		}
	}
	return false
}

// termDefaultPATH 服务环境里没有 PATH 时的平台默认值。
func termDefaultPATH() string {
	if runtime.GOOS == "darwin" {
		return "/usr/bin:/bin:/usr/sbin:/sbin"
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

// termEnvLookup 在 []string 形态的环境里取值（取不到返回空串）。
func termEnvLookup(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// termLoginEnv 构造 PTY 子进程环境：白名单 + 强制终端标记（详见本节开头）。
func termLoginEnv(shell, sessionID string) []string {
	env := make([]string, 0, len(termEnvKeep)+8)
	havePATH, haveHOME := false, false
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" || !termEnvKept(k) {
			continue
		}
		switch k {
		case "PATH":
			havePATH = true
		case "HOME":
			haveHOME = true
		}
		env = append(env, kv)
	}
	if !haveHOME {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			env = append(env, "HOME="+u.HomeDir)
		}
	}
	if !havePATH {
		env = append(env, "PATH="+termDefaultPATH())
	}
	env = append(env,
		"SHELL="+shell, // 解析出的登录 shell，覆盖服务环境里的值
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"TERM_PROGRAM=Tailcat",
		"TERM_PROGRAM_VERSION="+forkBuildTag(),
		"TERM_SESSION_ID="+sessionID,
	)
	return env
}

type termService struct {
	cfg       termConfig
	logf      logger.Logf
	stopCh    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	sessions map[string]*termSession
}

func newTermService(logf logger.Logf) *termService {
	s := &termService{
		cfg:      termConfigFromEnv(),
		logf:     logf,
		stopCh:   make(chan struct{}),
		sessions: map[string]*termSession{},
	}
	go s.sampleLoop()
	return s
}

func (s *termService) Port() uint16      { return s.cfg.port }
func (s *termService) ShellText() string { return loginShell() }

func (s *termService) HistoryText() string {
	return fmt.Sprintf("%dKiB", s.cfg.history>>10)
}

// Close 关停服务：全部会话走同一回收路径（不影响其它服务）。
func (s *termService) Close() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
		s.mu.Lock()
		list := make([]*termSession, 0, len(s.sessions))
		for _, ss := range s.sessions {
			list = append(list, ss)
		}
		s.mu.Unlock()
		for _, ss := range list {
			ss.finish(termEndServiceStopped, "service_stopped")
		}
	})
}

// ---- 会话 ----

type termEpoch struct {
	off        int64
	cols, rows uint16
}

type termSession struct {
	svc     *termService
	name    string
	created time.Time
	pid     int

	mu         sync.Mutex
	ptmx       *os.File
	cmd        *exec.Cmd
	ring       []byte
	start      int64 // ring[0] 对应的绝对偏移
	written    int64 // 累计输出字节数（ring 末端）
	epochs     []termEpoch
	scan       termScan
	agent      byte
	state      byte
	prevCPU    int64
	prevQuiet  int // 截至上一采样的连续安静拍数（classifyAgent 磁滞输入）
	// outBuckets：按绝对秒键的输出字节桶（定长环形，countOutLocked 写、
	// outBytesLocked 求窗口和）——输出腿的数据源，见 term_agent.go 阈值注释。
	outBuckets [4]outBucket
	lastOut    time.Time
	lastActive time.Time
	cols, rows uint16
	attached   *termClient
	done       bool
	killed     bool // App 主动 KILL（ENDED 的 code 用 termEndKilled 而不是信号退出码）
	exitCode   int32
	waitOnce   sync.Once
}

// outBucket 一秒的输出字节数（sec 是 Unix 秒）。
type outBucket struct {
	sec int64
	n   int64
}

// countOutLocked 把一批 PTY 输出记进当前秒的桶（没有就抢占最旧的）。必须持 mu。
func (s *termSession) countOutLocked(n int, now time.Time) {
	sec := now.Unix()
	for i := range s.outBuckets {
		if s.outBuckets[i].sec == sec {
			s.outBuckets[i].n += int64(n)
			return
		}
	}
	oldest := 0
	for i := range s.outBuckets {
		if s.outBuckets[i].sec < s.outBuckets[oldest].sec {
			oldest = i
		}
	}
	s.outBuckets[oldest] = outBucket{sec: sec, n: int64(n)}
}

// outBytesLocked 近 agentOutWindowSec 秒的输出字节总和（含当前秒）。必须持 mu。
// 空闲秒没有桶（值为 0），跨秒空洞天然正确——只按 sec 比较即可。
func (s *termSession) outBytesLocked(now time.Time) int64 {
	floor := now.Unix() - int64(agentOutWindowSec) + 1
	var sum int64
	for i := range s.outBuckets {
		if s.outBuckets[i].sec >= floor {
			sum += s.outBuckets[i].n
		}
	}
	return sum
}

// termClient 一条已 attach 的连接。off/live 由 session.mu 保护；wmu 串行化写。
type termClient struct {
	conn net.Conn
	wmu  sync.Mutex
	off  int64
	live bool
}

func (c *termClient) frame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(termWriteTimeout))
	_, err := c.conn.Write(encodeTermFrame(op, payload))
	return err
}

func (c *termClient) close() { _ = c.conn.Close() }

// ---- 历史环 ----

// appendLocked 把输出写进**定长环**：ring 长度即历史上限，written 是累计字节数（绝对偏移），
// start = written - min(written, len(ring)) 是最旧可用字节的绝对偏移。
func (s *termSession) appendLocked(p []byte) {
	capBytes := len(s.ring)
	if capBytes == 0 {
		return
	}
	for len(p) > 0 {
		pos := int(s.written % int64(capBytes))
		n := copy(s.ring[pos:], p)
		s.written += int64(n)
		p = p[n:]
	}
	if start := s.written - int64(capBytes); start > s.start {
		s.start = start
	}
}

// readLocked 取 [off, off+max) 的输出字节（超出历史区间就从头开始）。
func (s *termSession) readLocked(off int64, max int) []byte {
	if off < s.start {
		off = s.start
	}
	if off >= s.written || max <= 0 {
		return nil
	}
	if int64(max) > s.written-off {
		max = int(s.written - off)
	}
	capBytes := len(s.ring)
	if capBytes == 0 {
		return nil
	}
	out := make([]byte, 0, max)
	for len(out) < max {
		pos := int(off % int64(capBytes))
		avail := capBytes - pos
		if avail > max-len(out) {
			avail = max - len(out)
		}
		out = append(out, s.ring[pos:pos+avail]...)
		off += int64(avail)
	}
	return out
}

// replayStartLocked 选回放起点：尾部优先（replay 上限）→ 行边界 → ESC 起点 → 原样。
func (s *termSession) replayStartLocked() (start int64, truncated bool) {
	start = s.start
	if s.svc.cfg.replayEpoch == "last" && len(s.epochs) > 0 {
		if off := s.epochs[len(s.epochs)-1].off; off > start {
			start = off
			truncated = true
		}
	}
	if s.svc.cfg.replay > 0 && s.written-start > int64(s.svc.cfg.replay) {
		start = s.written - int64(s.svc.cfg.replay)
		truncated = true
	}
	head := s.readLocked(start, termReplayTrim)
	if len(head) == 0 {
		return start, truncated
	}
	if i := indexByte(head, '\n'); i >= 0 {
		return start + int64(i) + 1, truncated
	}
	if i := indexByte(head, 0x1b); i > 0 {
		return start + int64(i), truncated
	}
	return start, truncated
}

func indexByte(p []byte, b byte) int {
	for i := range p {
		if p[i] == b {
			return i
		}
	}
	return -1
}

// epochsInRange 判断回放窗口内是否跨过尺寸变化（REPLAY-DONE flags bit1）。
func (s *termSession) epochsInRange(start, end int64) bool {
	for _, e := range s.epochs {
		if e.off > start && e.off < end {
			return true
		}
	}
	return false
}

// noteSizeLocked 记录一次尺寸变化（同时更新当前尺寸）。
func (s *termSession) noteSizeLocked(cols, rows uint16) {
	s.cols, s.rows = cols, rows
	s.epochs = append(s.epochs, termEpoch{off: s.written, cols: cols, rows: rows})
	if len(s.epochs) > 64 {
		s.epochs = s.epochs[len(s.epochs)-64:]
	}
}

// ---- 客户端投递 ----

func (s *termSession) deliverLocked() {
	c := s.attached
	if c == nil || !c.live {
		return
	}
	for {
		if c.off < s.start {
			c.off = s.start // 客户端太慢、历史被覆盖：跳到可用起点（宁可丢也不阻塞）
		}
		if c.off >= s.written {
			return
		}
		chunk := s.readLocked(c.off, termDataChunk)
		if len(chunk) == 0 {
			return
		}
		if err := c.frame(opData, chunk); err != nil {
			s.detachLocked(c)
			return
		}
		c.off += int64(len(chunk))
	}
}

func (s *termSession) detachLocked(c *termClient) {
	if s.attached == c {
		s.attached = nil
	}
	c.close()
	if s.svc.logf != nil {
		s.svc.logf("term: 会话 %s 客户端断开（会话继续运行）", s.name)
	}
}

func (s *termSession) pushStateLocked() {
	if c := s.attached; c != nil {
		if err := c.frame(opState, encState(s.agent, s.state, s.scan.title)); err != nil {
			s.detachLocked(c)
		}
	}
}

// attachLocked 把 c 接到会话上：顶掉旧客户端 → ATTACHED → 换屏前序 → 回放 → REPLAY-DONE → 实时。
func (s *termSession) attachLocked(c *termClient) error {
	if old := s.attached; old != nil && old != c {
		_ = old.frame(opEnded, encEnded(termEndReplaced, "replaced"))
		s.detachLocked(old)
	}
	s.attached = c
	c.live = false
	start, truncated := s.replayStartLocked()
	c.off = start

	if err := c.frame(opAttached, encAttached(s.cols, s.rows, s.scan.modes, s.agent, s.state, s.name)); err != nil {
		s.detachLocked(c)
		return err
	}
	// 换屏前序：客户端 vt 是新建的，这一步保证回放内容的起点是确定的。
	if err := c.frame(opData, []byte("\x1b[3J\x1b[2J\x1b[H")); err != nil {
		s.detachLocked(c)
		return err
	}
	deadline := time.Now().Add(termReplayBudget)
	end := s.written
	replayed := 0
	for c.off < end {
		chunk := s.readLocked(c.off, termDataChunk)
		if len(chunk) == 0 {
			break
		}
		if err := c.frame(opData, chunk); err != nil {
			s.detachLocked(c)
			return err
		}
		c.off += int64(len(chunk))
		replayed += len(chunk)
		if time.Now().After(deadline) && c.off < end {
			truncated = true // 时间预算用尽：丢头部保尾部（本循环本来就是从起点顺序发的）
			break
		}
	}
	sent := c.off
	flags := byte(0)
	if truncated {
		flags |= replayFlagTruncated
	}
	if s.epochsInRange(start, sent) {
		flags |= replayFlagSizeChange
	}
	if err := c.frame(opReplayDone, encReplayDone(uint32(replayed), flags)); err != nil {
		s.detachLocked(c)
		return err
	}
	if c.off < end {
		// 预算用尽（上面 break 的那一支）：剩余历史直接跳过，从「现在」接实时流。
		c.off = s.written
	}
	c.live = true
	// 回放期间新产生的字节 [c.off, s.written) 由这次 flush 补齐，然后交给 pump 持续投递。
	s.deliverLocked()
	return nil
}

// ---- 生命周期 ----

// finish 结束会话：回 ENDED → 关 master → 等子进程 → 从注册表删除。
// reason < 0 表示服务侧原因（killed/replaced/service_stopped）；0 表示子进程自己退出。
func (s *termSession) finish(reason int32, text string) {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	s.done = true
	code := s.exitCode
	if s.killed {
		code = termEndKilled
	}
	if reason < 0 {
		code = reason
	}
	if c := s.attached; c != nil {
		_ = c.frame(opEnded, encEnded(code, text))
		s.detachLocked(c)
	}
	ptmx := s.ptmx
	s.mu.Unlock()

	if ptmx != nil {
		_ = ptmx.Close()
	}
	s.waitOnce.Do(func() {
		if s.cmd != nil {
			_ = s.cmd.Wait()
		}
	})
	s.mu.Lock()
	if s.cmd != nil && s.cmd.ProcessState != nil {
		s.exitCode = int32(s.cmd.ProcessState.ExitCode())
	}
	s.ring = nil // 释放历史缓冲
	s.mu.Unlock()

	s.svc.remove(s.name, s)
}

func (s *termService) remove(name string, who *termSession) {
	s.mu.Lock()
	if cur, ok := s.sessions[name]; ok && cur == who {
		delete(s.sessions, name)
	}
	s.mu.Unlock()
}

// pump 常驻读 PTY：写历史、喂扫描器、投递给已 attach 的客户端（永远读，子进程才不会阻塞）。
func (s *termSession) pump() {
	buf := make([]byte, 32<<10)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.mu.Lock()
			now := time.Now()
			s.appendLocked(buf[:n])
			s.scan.write(buf[:n])
			s.countOutLocked(n, now)
			s.lastOut = now
			s.lastActive = now
			if s.scan.changed {
				s.scan.changed = false
				s.pushStateLocked()
			}
			s.deliverLocked()
			s.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	// 子进程退出 / PTY 关闭：收尸 → 统一收尾（ENDED + 回收四步）。
	s.waitOnce.Do(func() {
		if s.cmd != nil {
			_ = s.cmd.Wait()
		}
	})
	s.mu.Lock()
	code := int32(0)
	if s.cmd != nil && s.cmd.ProcessState != nil {
		code = int32(s.cmd.ProcessState.ExitCode())
	}
	s.exitCode = code
	s.mu.Unlock()
	s.finish(0, "")
}

// ---- 采样：agent / 任务状态 ----

func (s *termService) sampleLoop() {
	t := time.NewTicker(termSamplePeriod)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-t.C:
			s.sampleOnce(now)
		}
	}
}

func (s *termService) sampleOnce(now time.Time) {
	if !s.cfg.detect {
		return
	}
	procs := readProcs()
	s.mu.Lock()
	list := make([]*termSession, 0, len(s.sessions))
	for _, ss := range s.sessions {
		list = append(list, ss)
	}
	s.mu.Unlock()
	for _, ss := range list {
		ss.sample(now, procs)
	}
}

func (s *termSession) sample(now time.Time, procs []procInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.ptmx == nil {
		return
	}
	fg := foregroundPgid(s.ptmx.Fd())
	v := classifyAgent(agentProbe{
		procs:     procs,
		fgPgid:    fg,
		prevCPU:   s.prevCPU,
		outBytes:  s.outBytesLocked(now),
		prevState: s.state,
		prevQuiet: s.prevQuiet,
		shellPID:  s.pid,
		now:       now,
	})
	if v.cpu >= 0 {
		s.prevCPU = v.cpu
	}
	s.prevQuiet = v.quiet
	if v.agent != s.agent || v.state != s.state {
		s.agent, s.state = v.agent, v.state
		if s.svc.logf != nil {
			s.svc.logf("term: 会话 %s 状态 %s/%s（fg=%d procs=%d）",
				s.name, agentName(v.agent), stateName(v.state), fg, len(procs))
		}
		s.pushStateLocked()
	}
}

// ---- 连接处理 ----

// ServeConn 处理一条客户端连接（由 serve 的 OnTCP 在 term 端口上调用）。
func (s *termService) ServeConn(c net.Conn) {
	defer c.Close()
	client := &termClient{conn: c}
	if err := client.frame(opGreeting, encGreeting()); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(termHelloTimeout))
	f, err := readTermFrame(c)
	if err != nil {
		return
	}
	switch f.op {
	case opList:
		_ = client.frame(opList, []byte(s.listJSON()))
	case opKill:
		name, derr := decName(f.payload)
		if derr != nil {
			_ = client.frame(opError, encError("bad_name", derr.Error()))
			return
		}
		if err := s.kill(name); err != nil {
			_ = client.frame(opError, encError(err.code, err.msg))
			return
		}
		_ = client.frame(opOK, nil)
	case opHello:
		cols, rows, create, name, derr := decHello(f.payload)
		if derr != nil {
			_ = client.frame(opError, encError("bad_hello", derr.Error()))
			return
		}
		if !termNameRx.MatchString(name) {
			_ = client.frame(opError, encError("invalid_name", "会话名只能是 [A-Za-z0-9._-]{1,64}"))
			return
		}
		ss, cerr := s.attachOrCreate(name, cols, rows, create)
		if cerr != nil {
			_ = client.frame(opError, encError(cerr.code, cerr.msg))
			return
		}
		s.stream(ss, client, c)
	default:
		_ = client.frame(opError, encError("bad_op", fmt.Sprintf("首帧必须是 HELLO/LIST/KILL（收到 0x%02x）", f.op)))
	}
}

type termErr struct {
	code string
	msg  string
}

func (e *termErr) Error() string { return e.code + ": " + e.msg }

func termErrf(code, format string, args ...any) *termErr {
	return &termErr{code: code, msg: fmt.Sprintf(format, args...)}
}

func (s *termService) attachOrCreate(name string, cols, rows uint16, create bool) (*termSession, *termErr) {
	s.mu.Lock()
	ss := s.sessions[name]
	if ss == nil {
		if !create {
			s.mu.Unlock()
			return nil, termErrf("no_session", "会话 %s 不存在", name)
		}
		if len(s.sessions) >= s.cfg.maxSessions {
			s.mu.Unlock()
			return nil, termErrf("too_many", "会话数已达上限 %d，请先关闭一些会话", s.cfg.maxSessions)
		}
		var err error
		ss, err = s.spawnLocked(name, cols, rows)
		if err != nil {
			s.mu.Unlock()
			return nil, termErrf("spawn_failed", "%v", err)
		}
		s.sessions[name] = ss
	}
	s.mu.Unlock()

	// 先定尺寸（SIGWINCH 触发的重绘落在回放快照之后），再做历史。
	ss.resize(cols, rows)
	return ss, nil
}

// spawnLocked 起一个 PTY 会话（调用方持 s.mu）。
//
// 两种模式都走**登录 shell + 环境白名单**（见「登录 shell 与登录环境」一节）：
//   - 默认：`shell -l`（交互式登录 shell，rc 文件决定 PATH 等）
//   - TAILCAT_TERM_SHELL：`shell -lc '<命令>'`（例如 tmux；profile 里的 PATH 同样生效，
//     所以 homebrew 装的 tmux 在 macOS 上也找得到）
func (s *termService) spawnLocked(name string, cols, rows uint16) (*termSession, error) {
	shell := loginShell()
	var cmd *exec.Cmd
	if s.cfg.shell != "" {
		// TAILCAT_TERM_SHELL：一条命令（例如 tmux new -A -s tier / screen -dR）。
		// ⚠️ 不要退回硬编码的 /bin/sh：distroless 之类没有 /bin/sh 的镜像里那条逃生口会直接死。
		cmd = exec.Command(shell, "-lc", s.cfg.shell)
	} else {
		cmd = exec.Command(shell, "-l")
	}
	env := termLoginEnv(shell, "tailcat-"+name)
	cmd.Env = env
	if home := termEnvLookup(env, "HOME"); home != "" {
		cmd.Dir = home
	}
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	if err := pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		_ = ptmx.Close()
		return nil, err
	}
	now := time.Now()
	ss := &termSession{
		svc:        s,
		name:       name,
		created:    now,
		pid:        cmd.Process.Pid,
		ptmx:       ptmx,
		cmd:        cmd,
		ring:       make([]byte, s.cfg.history), // 定长环：长度即历史上限
		agent:      agentUnknown,
		state:      stateUnknown,
		lastOut:    now,
		lastActive: now,
		cols:       cols,
		rows:       rows,
	}
	ss.epochs = append(ss.epochs, termEpoch{off: 0, cols: cols, rows: rows})
	if s.logf != nil {
		s.logf("term: 新建会话 %s（pid=%d %dx%d shell=%s）", name, ss.pid, cols, rows, shell)
	}
	go ss.pump()
	return ss, nil
}

// resize 应用新尺寸（幂等）：PTY setsize + 记录 epoch。
func (s *termSession) resize(cols, rows uint16) {
	if cols == 0 || rows == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.ptmx == nil || (s.cols == cols && s.rows == rows) {
		return
	}
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows})
	s.noteSizeLocked(cols, rows)
}

// sentinelRepaint 尺寸哨兵：sentinel → 真实尺寸，两次 SIGWINCH 逼 TUI 重绘当前屏。
func (s *termSession) sentinelRepaint() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.ptmx == nil {
		return
	}
	cols, rows := s.cols, s.rows
	sentinel := cols
	if sentinel > 1 {
		sentinel--
	} else {
		sentinel = cols + 1
	}
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: sentinel, Rows: rows})
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows})
}

// stream：回放 + 实时循环（连接存续期间一直跑）。
func (s *termService) stream(ss *termSession, client *termClient, c net.Conn) {
	ss.mu.Lock()
	err := ss.attachLocked(client)
	ss.mu.Unlock()
	if err != nil {
		return
	}
	ss.sentinelRepaint()

	defer func() {
		ss.mu.Lock()
		if ss.attached == client {
			ss.attached = nil
		}
		ss.mu.Unlock()
	}()

	for {
		_ = c.SetReadDeadline(time.Time{})
		f, rerr := readTermFrame(c)
		if rerr != nil {
			return
		}
		switch f.op {
		case opData:
			ss.mu.Lock()
			ptmx := ss.ptmx
			ss.mu.Unlock()
			if ptmx != nil && len(f.payload) > 0 {
				if _, werr := ptmx.Write(f.payload); werr != nil {
					return
				}
			}
		case opResize:
			cols, rows, derr := decResize(f.payload)
			if derr != nil {
				_ = client.frame(opError, encError("bad_resize", derr.Error()))
				continue
			}
			ss.resize(cols, rows)
		case opKill:
			name, derr := decName(f.payload)
			if derr != nil {
				_ = client.frame(opError, encError("bad_name", derr.Error()))
				continue
			}
			if kerr := s.kill(name); kerr != nil {
				_ = client.frame(opError, encError(kerr.code, kerr.msg))
			} else {
				_ = client.frame(opOK, nil)
			}
		case opList:
			_ = client.frame(opList, []byte(s.listJSON()))
		default:
			_ = client.frame(opError, encError("bad_op", fmt.Sprintf("未知帧 0x%02x", f.op)))
		}
	}
}

// kill 主动结束会话（SIGHUP → 宽限 → SIGKILL）；由 pump 的收尾负责回 ENDED。
func (s *termService) kill(name string) *termErr {
	s.mu.Lock()
	ss := s.sessions[name]
	s.mu.Unlock()
	if ss == nil {
		return termErrf("no_session", "会话 %s 不存在", name)
	}
	ss.mu.Lock()
	pid := ss.pid
	done := ss.done
	ss.killed = true
	ss.mu.Unlock()
	if done {
		return termErrf("no_session", "会话 %s 已结束", name)
	}
	if err := signalPgid(pid, 1); err != nil { // 1 = SIGHUP
		// 组信号失败就退化为单进程终止。
		ss.mu.Lock()
		if ss.cmd != nil && ss.cmd.Process != nil {
			_ = ss.cmd.Process.Kill()
		}
		ss.mu.Unlock()
	}
	go func() {
		time.Sleep(termKillGrace)
		ss.mu.Lock()
		alive := !ss.done
		pid := ss.pid
		ss.mu.Unlock()
		if alive {
			_ = signalPgid(pid, 9) // SIGKILL
		}
	}()
	if s.logf != nil {
		s.logf("term: 关闭会话 %s（pid=%d）", name, pid)
	}
	return nil
}

// listJSON 回 LIST-REPLY 的 JSON（Go/ArkTS 消费；C++ 侧从不发 LIST）。
func (s *termService) listJSON() string {
	type entry struct {
		Name         string `json:"name"`
		CreatedMs    int64  `json:"createdMs"`
		LastActiveMs int64  `json:"lastActiveMs"`
		Attached     bool   `json:"attached"`
		Agent        string `json:"agent"`
		State        string `json:"state"`
		Title        string `json:"title"`
		Cols         uint16 `json:"cols"`
		Rows         uint16 `json:"rows"`
		Pid          int    `json:"pid"`
	}
	s.mu.Lock()
	out := make([]entry, 0, len(s.sessions))
	for _, ss := range s.sessions {
		ss.mu.Lock()
		done := ss.done
		if !done {
			out = append(out, entry{
				Name:         ss.name,
				CreatedMs:    ss.created.UnixMilli(),
				LastActiveMs: ss.lastActive.UnixMilli(),
				Attached:     ss.attached != nil,
				Agent:        agentName(ss.agent),
				State:        stateName(ss.state),
				Title:        ss.scan.title,
				Cols:         ss.cols,
				Rows:         ss.rows,
				Pid:          ss.pid,
			})
		}
		ss.mu.Unlock()
	}
	s.mu.Unlock()
	b, err := json.Marshal(map[string]any{"sessions": out})
	if err != nil {
		return `{"sessions":[]}`
	}
	return string(b)
}
