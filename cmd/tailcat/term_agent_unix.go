//go:build !windows

// term_agent_unix.go — 平台相关的「拿进程表」实现（darwin 走 ps，linux 走 /proc）。
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// readProcs 抓一份进程表快照。失败返回 nil（调用方降级成 unknown，不报错、不阻塞）。
func readProcs() []procInfo {
	if runtime.GOOS == "linux" {
		return readProcsLinux()
	}
	return readProcsPS()
}

// foregroundPgid 取终端前台进程组；0 = 拿不到（会话刚建、已结束等）。
func foregroundPgid(fd uintptr) int {
	if pgid, err := unix.IoctlGetInt(int(fd), unix.TIOCGPGRP); err == nil {
		return pgid
	}
	return 0
}

// signalPgid 给整个进程组发信号（KILL 路径用；SIGHUP 给会话 leader 的组）。
func signalPgid(pgid int, sig unix.Signal) error {
	if pgid <= 0 {
		return nil
	}
	return unix.Kill(-pgid, sig)
}

// readProcsLinux 读 /proc（不需要 fork 进程，成本最低）。
func readProcsLinux() []procInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := make([]procInfo, 0, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		statRaw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// comm 里可能有空格/括号，取最后一个 ')' 之后才是字段区。
		s := string(statRaw)
		i := strings.LastIndex(s, ")")
		if i < 0 || i+2 > len(s) {
			continue
		}
		f := strings.Fields(s[i+2:])
		if len(f) < 13 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		pgid, _ := strconv.Atoi(f[2])
		utime, _ := strconv.ParseInt(f[11], 10, 64)
		stime, _ := strconv.ParseInt(f[12], 10, 64)
		args := readCmdline(pid)
		out = append(out, procInfo{pid: pid, ppid: ppid, pgid: pgid, cpu: utime + stime, args: args})
	}
	return out
}

func readCmdline(pid int) string {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(raw) == 0 {
		return ""
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	return strings.Join(parts, " ")
}

// readProcsPS 走 ps（darwin；字段：pid ppid pgid time command）。
// time 的形态是 [[dd-]hh:]mm:ss[.ss] → 统一换算成「百分之一秒」当刻度。
func readProcsPS() []procInfo {
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,pgid=,time=,command=").Output()
	if err != nil {
		return nil
	}
	var procs []procInfo
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		pgid, err3 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		args := strings.Join(f[4:], " ")
		procs = append(procs, procInfo{pid: pid, ppid: ppid, pgid: pgid, cpu: parsePSTime(f[3]), args: args})
	}
	return procs
}

// parsePSTime 把 ps 的 TIME 列换算成百分之一秒。
func parsePSTime(s string) int64 {
	days := int64(0)
	if i := strings.IndexByte(s, '-'); i > 0 {
		if d, err := strconv.ParseInt(s[:i], 10, 64); err == nil {
			days = d
		}
		s = s[i+1:]
	}
	parts := strings.Split(s, ":")
	var hh, mm int64
	var ss float64
	switch len(parts) {
	case 3:
		hh, _ = strconv.ParseInt(parts[0], 10, 64)
		mm, _ = strconv.ParseInt(parts[1], 10, 64)
		ss, _ = strconv.ParseFloat(parts[2], 64)
	case 2:
		mm, _ = strconv.ParseInt(parts[0], 10, 64)
		ss, _ = strconv.ParseFloat(parts[1], 64)
	case 1:
		ss, _ = strconv.ParseFloat(parts[0], 64)
	default:
		return 0
	}
	total := float64(days*86400+hh*3600+mm*60) + ss
	return int64(total * 100)
}
