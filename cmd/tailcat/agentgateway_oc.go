//go:build !cshared

// agentgateway_oc.go — opencode 后端：HTTP 客户端 + SSE 事件消费 + 统一协议翻译
// + **按需拉起**（第一个请求到达时探测 4096，没人在跑就 spawn 子进程并守护）。
//
// 协议事实（2026-09-15 对 opencode 1.18.31 真机实测，SDK dev 分支类型有 5 处不符，
// 全部在此适配，勿按 SDK 改回）：
//   - Session.version 是字符串；/config/providers 返回 {providers:[], default:{}}
//     且 models 是按 id 键的对象；
//   - 流式增量在独立的 message.part.delta 事件（part.updated 的 delta 恒空）；
//   - 权限事件是 permission.asked / permission.replied{requestID, reply}；
//   - 事件天然有少量重复（session.status 与 session.idle 双发），归并幂等即可；
//   - 事件流按目录划分：消费 /global/event（老版本回退 /event），写操作按会话
//     所属目录带 ?directory= 路由（一个 serve 可跨目录访问全部会话）。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/logger"
)

// ---------- opencode 原始 JSON 形状 ----------

type ocpSession struct {
	ID        string `json:"id"`
	ProjectID string `json:"projectID"`
	Directory string `json:"directory"`
	ParentID  string `json:"parentID"`
	Title     string `json:"title"`
	Version   string `json:"version"` // 1.18 实测为字符串（如 "1.18.30"）
	Model     *struct {
		ID         string `json:"id"`
		ProviderID string `json:"providerID"`
		Variant    string `json:"variant"`
	} `json:"model"`
	Share     bool   `json:"share"`
	Time      struct {
		Created int64 `json:"created"`
		Updated int64 `json:"updated"`
	} `json:"time"`
}

type ocpMessage struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionID"`
	Role      string `json:"role"`
	Time      struct {
		Created   int64 `json:"created"`
		Completed int64 `json:"completed"`
	} `json:"time"`
	Agent      string `json:"agent"`
	ModelID    string `json:"modelID"`
	ProviderID string `json:"providerID"`
	Finish     string `json:"finish"`
	Cost       *float64 `json:"cost"`
	Tokens     *struct {
		Input     int64 `json:"input"`
		Output    int64 `json:"output"`
		Reasoning int64 `json:"reasoning"`
		Cache     *struct {
			Read int64 `json:"read"`
		} `json:"cache"`
	} `json:"tokens"`
	Error *struct {
		Name    string         `json:"name"`
		Data    map[string]any `json:"data"`
		Message string         `json:"message"`
	} `json:"error"`
}

type ocpPart struct {
	ID        string          `json:"id"`
	SessionID string          `json:"sessionID"`
	MessageID string          `json:"messageID"`
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	CallID    string          `json:"callID"`
	Tool      string          `json:"tool"`
	State     json.RawMessage `json:"state"`
	Hash      string          `json:"hash"`
	Files     json.RawMessage `json:"files"`
}

type ocpPermission struct {
	ID        string         `json:"id"`
	SessionID string         `json:"sessionID"`
	MessageID string         `json:"messageID"`
	CallID    string         `json:"callID"`
	Type      string         `json:"type"`
	Pattern   string         `json:"pattern"`
	Title     string         `json:"title"`
	Metadata  map[string]any `json:"metadata"`
	Time      struct {
		Created int64 `json:"created"`
	} `json:"time"`
}

type ocpProvidersResp struct {
	Providers []ocpProvider      `json:"providers"`
	Default   map[string]string  `json:"default"`
}

type ocpProvider struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Models map[string]struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Limit  *struct {
			Context int64 `json:"context"`
		} `json:"limit"`
	} `json:"models"`
}

// ---------- SSE 事件信封 ----------

type ocpSSEEvent struct {
	Type       string          `json:"type"`
	Properties json.RawMessage `json:"properties"`
}

// /global/event 的外层包裹：{payload: <Event>}（directory 字段 1.18 里未出现，忽略）
type ocpGlobalEvent struct {
	Payload ocpSSEEvent `json:"payload"`
}

// ---------- 后端 ----------

type agNtfOut struct {
	method string
	params any
}

type agOC struct {
	url  string // opencode base URL
	logf logger.Logf
	hc   *http.Client
	out  chan agNtfOut

	mu         sync.Mutex
	statuses   map[string]string       // sessionID -> idle|busy|retry
	dirs       map[string]string       // sessionID -> directory（写操作路由用）
	filesRoot  string                   // serve --files 的宿主目录；App 传 SFP 沙箱路径时换算
	approvals  map[string]ocpPermission // 权限ID -> 待答复（组 POST URL 要 sessionID）
	cmd        *exec.Cmd               // 按需拉起的子进程（nil = 外部实例/未拉起）
	lastSpawn  time.Time
	spawnErr   string
}

func newAGOC(logf logger.Logf) *agOC {
	u := os.Getenv("TAILCAT_OPENCODE_URL")
	if u == "" {
		u = "http://127.0.0.1:4096"
	}
	// hc 硬禁代理：即使出口环境有 HTTP_PROXY 等变量，到本机 opencode 的回环调用
	// 也绝不被代理走（默认 Transport 会读环境变量；codex/opencode 严格限定本机）。
	noProxyTransport := &http.Transport{Proxy: nil}
	return &agOC{
		url:       strings.TrimRight(u, "/"),
		logf:      logf,
		hc:        &http.Client{Timeout: 30 * time.Second, Transport: noProxyTransport},
		out:       make(chan agNtfOut, 256),
		statuses:  map[string]string{},
		dirs:      map[string]string{},
		approvals: map[string]ocpPermission{},
	}
}

func (b *agOC) caps() agCaps {
	return agCaps{Backend: "opencode", Approvals: true, Models: true, Usage: true}
}

func (b *agOC) notifications() <-chan agNtfOut { return b.out }

func (b *agOC) steer(ctx context.Context, sessionID, text string) error {
	return fmt.Errorf("opencode 后端不支持 turn/steer")
}

// ---------- 按需拉起 ----------

// ensureBackend 保证 opencode 可达：先探测（有人自己跑着 serve/TUI 连着的实例就直接用），
// 没有则 spawn 子进程并等就绪。所有请求方法先调它。
func (b *agOC) ensureBackend(ctx context.Context) error {
	if b.probe(ctx, 1500*time.Millisecond) == nil {
		return nil
	}
	if os.Getenv("TAILCAT_OPENCODE_SPAWN") == "off" {
		return errors.New("opencode 不可达（TAILCAT_OPENCODE_SPAWN=off 已禁用自动拉起）")
	}
	if err := b.spawnLocked(ctx); err != nil {
		return err
	}
	// 等就绪：opencode 冷启动 ~1-2s，给 15s
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := b.probe(ctx, 2000*time.Millisecond); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return errors.New("opencode 拉起后 15s 内未就绪")
}

func (b *agOC) probe(ctx context.Context, timeout time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, b.url+"/session", nil)
	if err != nil {
		return err
	}
	resp, err := b.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("probe -> %d", resp.StatusCode)
	}
	return nil
}

// spawnLocked 拉起 `opencode serve`（工作目录默认 $HOME，TAILCAT_OPENCODE_DIR 覆盖）。
// 子进程输出进网关日志；异常退出只记录，下次 ensureBackend 再拉（带 3s 最小间隔）。
func (b *agOC) spawnLocked(ctx context.Context) error {
	if time.Since(b.lastSpawn) < 3*time.Second {
		return errors.New("opencode 拉起过于频繁，稍后重试")
	}
	ocPath, err := exec.LookPath("opencode")
	if err != nil {
		// 常见安装位兜底（官方安装器默认路径）
		for _, cand := range []string{os.Getenv("HOME") + "/.opencode/bin/opencode", "/usr/local/bin/opencode"} {
			if st, serr := os.Stat(cand); serr == nil && !st.IsDir() {
				ocPath = cand
				break
			}
		}
		if ocPath == "" {
			return errors.New("找不到 opencode 可执行文件（PATH 与 ~/.opencode/bin 都没有）")
		}
	}
	port := "4096"
	if u, perr := url.Parse(b.url); perr == nil && u.Port() != "" {
		port = u.Port()
	}
	dir := os.Getenv("TAILCAT_OPENCODE_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = home
	}
	cmd := exec.Command(ocPath, "serve", "--port", port, "--hostname", "127.0.0.1")
	cmd.Dir = dir
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		b.lastSpawn = time.Now()
		return fmt.Errorf("拉起 opencode 失败: %w", err)
	}
	b.lastSpawn = time.Now()
	b.cmd = cmd
	b.logf("按需拉起 opencode serve（pid=%d dir=%s port=%s）", cmd.Process.Pid, dir, port)
	go func() {
		sc := bufio.NewScanner(io.MultiReader(stdout, stderr))
		for sc.Scan() {
			b.logf("[opencode] %s", sc.Text())
		}
	}()
	go func() {
		err := cmd.Wait()
		b.mu.Lock()
		b.cmd = nil
		b.mu.Unlock()
		b.logf("opencode 子进程退出: %v（下次请求会重新拉起）", err)
	}()
	return nil
}

// ---------- HTTP ----------

func (b *agOC) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.url+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.hc.Do(req)
	if err != nil {
		return fmt.Errorf("opencode %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bs, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("opencode %s %s -> %d: %s", method, path, resp.StatusCode, string(bs))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// dirQuery 为写操作路由目录（会话属于别的项目时要带上，1.18 实测读不需要）。
func (b *agOC) dirQuery(sessionID string) string {
	b.mu.Lock()
	d := b.dirs[sessionID]
	b.mu.Unlock()
	if d == "" {
		return ""
	}
	return "?directory=" + url.QueryEscape(d)
}

func (b *agOC) rememberDir(sessionID, dir string) {
	if sessionID == "" || dir == "" {
		return
	}
	b.mu.Lock()
	b.dirs[sessionID] = dir
	b.mu.Unlock()
}

// ---------- 会话操作（hub 调用） ----------

func (b *agOC) listSessions(ctx context.Context) ([]agSession, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, err
	}
	var ocs []ocpSession
	if err := b.do(ctx, http.MethodGet, "/session", nil, &ocs); err != nil {
		return nil, err
	}
	var raw map[string]struct {
		Type string `json:"type"`
	}
	_ = b.do(ctx, http.MethodGet, "/session/status", nil, &raw) // 拉不到不阻塞列表
	out := make([]agSession, 0, len(ocs))
	for _, s := range ocs {
		st := raw[s.ID].Type
		if st == "" {
			b.mu.Lock()
			st = b.statuses[s.ID]
			b.mu.Unlock()
		} else {
			b.mu.Lock()
			b.statuses[s.ID] = st
			b.mu.Unlock()
		}
		b.rememberDir(s.ID, s.Directory)
		out = append(out, agSession{
			ID: s.ID, Title: s.Title, Directory: s.Directory, Status: st,
			TimeCreated: s.Time.Created, TimeUpdated: s.Time.Updated, Version: s.Version,
		})
	}
	return out, nil
}

func (b *agOC) createSession(ctx context.Context, title, directory string) (*agSession, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, err
	}
	body := map[string]any{}
	if title != "" {
		body["title"] = title
	}
	// opencode 1.18.31 的会话目录只认 **?directory= 查询参数**（POST body 里的
	// directory 字段会被静默忽略、回落实例 cwd——2026-09-16 本机实测；之前记录的
	// 「body 生效」是假阳性：测试实例的 cwd 恰好同路径）。
	// App 传的是 files 服务的 SFTP 沙箱路径（/x/y）：filesRoot 已配则换算成宿主绝对路径
	//（见 resolveHostDir）；否则视为已是绝对路径原样传。
	pathSuffix := ""
	if directory != "" {
		directory = resolveHostDir(b.filesRoot, directory)
		pathSuffix = "?directory=" + url.QueryEscape(directory)
	}
	var oc ocpSession
	if err := b.do(ctx, http.MethodPost, "/session"+pathSuffix, body, &oc); err != nil {
		return nil, err
	}
	b.rememberDir(oc.ID, oc.Directory)
	s := b.mapSession(oc)
	return &s, nil
}

func (b *agOC) readSession(ctx context.Context, id string) (*agSession, []agMessage, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, nil, err
	}
	var oc ocpSession
	if err := b.do(ctx, http.MethodGet, "/session/"+id, nil, &oc); err != nil {
		return nil, nil, err
	}
	var rows []struct {
		Info  ocpMessage         `json:"info"`
		Parts []json.RawMessage  `json:"parts"`
	}
	if err := b.do(ctx, http.MethodGet, "/session/"+id+"/message", nil, &rows); err != nil {
		return nil, nil, err
	}
	msgs := make([]agMessage, 0, len(rows))
	for _, r := range rows {
		msgs = append(msgs, b.mapMessage(r.Info, r.Parts))
	}
	b.rememberDir(oc.ID, oc.Directory)
	s := b.mapSession(oc)
	return &s, msgs, nil
}

func (b *agOC) deleteSession(ctx context.Context, id string) error {
	if err := b.ensureBackend(ctx); err != nil {
		return err
	}
	return b.do(ctx, http.MethodDelete, "/session/"+id+b.dirQuery(id), nil, nil)
}

func (b *agOC) renameSession(ctx context.Context, id, title string) (*agSession, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, err
	}
	var oc ocpSession
	if err := b.do(ctx, http.MethodPatch, "/session/"+id, map[string]any{"title": title}, &oc); err != nil {
		return nil, err
	}
	s := b.mapSession(oc)
	return &s, nil
}

func (b *agOC) sendPrompt(ctx context.Context, sessionID, text, modelID string) error {
	if err := b.ensureBackend(ctx); err != nil {
		return err
	}
	body := map[string]any{
		"parts": []map[string]any{{"type": "text", "text": text}},
	}
	if modelID != "" {
		if i := strings.Index(modelID, "/"); i > 0 {
			body["model"] = map[string]string{"providerID": modelID[:i], "modelID": modelID[i+1:]}
		}
	}
	return b.do(ctx, http.MethodPost, "/session/"+sessionID+"/prompt_async"+b.dirQuery(sessionID), body, nil)
}

func (b *agOC) interrupt(ctx context.Context, sessionID string) error {
	if err := b.ensureBackend(ctx); err != nil {
		return err
	}
	return b.do(ctx, http.MethodPost, "/session/"+sessionID+"/abort"+b.dirQuery(sessionID), nil, nil)
}

// respondApproval：统一 decision（allow/allow-always/deny）→ opencode 的 once/always/reject。
func (b *agOC) respondApproval(ctx context.Context, approvalID, decision string) error {
	if err := b.ensureBackend(ctx); err != nil {
		return err
	}
	b.mu.Lock()
	perm, known := b.approvals[approvalID]
	b.mu.Unlock()
	if !known {
		return fmt.Errorf("未知的审批请求 %s（可能已被答复或网关重启）", approvalID)
	}
	resp := "once"
	switch decision {
	case "allow":
		resp = "once"
	case "allow-always":
		resp = "always"
	case "deny":
		resp = "reject"
	default:
		return fmt.Errorf("非法 decision: %s", decision)
	}
	return b.do(ctx, http.MethodPost, "/session/"+perm.SessionID+"/permissions/"+approvalID,
		map[string]any{"response": resp}, nil)
}

func (b *agOC) listModels(ctx context.Context) ([]agModel, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, err
	}
	var resp ocpProvidersResp
	if err := b.do(ctx, http.MethodGet, "/config/providers", nil, &resp); err != nil {
		return nil, err
	}
	var out []agModel
	for _, p := range resp.Providers {
		ids := make([]string, 0, len(p.Models))
		for id := range p.Models {
			ids = append(ids, id)
		}
		sortStrings(ids)
		for _, id := range ids {
			m := p.Models[id]
			mid := m.ID
			if mid == "" {
				mid = id
			}
			var ctxLim int64
			if m.Limit != nil && m.Limit.Context > 0 {
				ctxLim = m.Limit.Context
			}
			out = append(out, agModel{
				ID: p.ID + "/" + mid, ProviderID: p.ID, ModelID: mid,
				Name: m.Name, Status: m.Status, ContextLimit: ctxLim,
			})
		}
	}
	return out, nil
}

// ---------- SSE 消费与翻译 ----------

// Start 启动事件消费（阻塞至 ctx 取消）。global 端点优先（跨目录），
// 老版本 404 时回退普通 /event。
func (b *agOC) Start(ctx context.Context) {
	backoff := 500 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		global := true
		n, err := b.consumeOnce(ctx, global)
		if n && err != nil && isHTTPStatus(err, 404) {
			global = false
			n, err = b.consumeOnce(ctx, global)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			b.logf("sse: %v（%s 后重连）", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 15*time.Second {
			backoff = 15 * time.Second
		}
	}
}

func isHTTPStatus(err error, code int) bool {
	return err != nil && strings.Contains(err.Error(), fmt.Sprintf("-> %d", code))
}

type ocpSSE struct {
	c           *http.Client
	base        string
	events      chan ocpSSEEvent
	firstGlobal bool // 首个事件是否到达过（证明链路通）
}

func (b *agOC) consumeOnce(ctx context.Context, global bool) (ok bool, err error) {
	path := "/event"
	if global {
		path = "/global/event"
	}
	hc := *b.hc
	hc.Timeout = 0
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("SSE %s -> %s", path, resp.Status)
	}

	r := bufio.NewReader(resp.Body)
	var data []byte
	flush := func() {
		if len(data) == 0 {
			return
		}
		raw := data
		data = data[:0]
		// /global/event 有 payload 包裹
		if global {
			var ge ocpGlobalEvent
			if json.Unmarshal(raw, &ge) == nil && ge.Payload.Type != "" {
				b.emit(ge.Payload)
				ok = true
				return
			}
			// 包裹解析失败按裸事件兜底
		}
		var ev ocpSSEEvent
		if json.Unmarshal(raw, &ev) != nil || ev.Type == "" {
			return
		}
		b.emit(ev)
		if ev.Type == "server.connected" {
			ok = true
		}
	}
	for {
		line, rerr := r.ReadBytes('\n')
		trimmed := bytes.TrimRight(line, "\r\n")
		if rerr == nil {
			if bytes.HasPrefix(trimmed, []byte("data: ")) {
				data = append(data, trimmed[6:]...)
			} else if len(trimmed) == 0 {
				flush()
			}
			continue
		}
		flush()
		return ok, rerr
	}
}

func (b *agOC) emit(ev ocpSSEEvent) {
	switch ev.Type {
	case "server.connected", "server.heartbeat":
		return
	}
	b.translate(ev)
}

func (b *agOC) notify(method string, params any) {
	select {
	case b.out <- agNtfOut{method: method, params: params}:
	default:
		b.logf("统一通知队列满，丢弃 %s", method)
	}
}

func (b *agOC) translate(ev ocpSSEEvent) {
	switch ev.Type {
	case "message.updated":
		var p struct {
			Info ocpMessage `json:"info"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil {
			return
		}
		msg := b.mapMessage(p.Info, nil)
		b.notify(agNMessageUpdated, map[string]any{"message": msg})
		if msg.Role == "assistant" && msg.Tokens != nil {
			c := 0.0
			if msg.Cost != nil {
				c = *msg.Cost
			}
			b.notify(agNUsageUpdated, map[string]any{
				"sessionId": msg.SessionID, "messageId": msg.ID,
				"tokens": msg.Tokens, "cost": c,
			})
		}

	case "message.part.updated":
		var p struct {
			Part  json.RawMessage `json:"part"`
			Delta string          `json:"delta"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil {
			return
		}
		part := b.mapPart(p.Part)
		b.notify(agNPartUpdated, map[string]any{
			"sessionId": part.SessionID, "messageId": part.MessageID,
			"part": part, "delta": p.Delta,
		})

	case "message.part.delta":
		var p struct {
			SessionID string `json:"sessionID"`
			MessageID string `json:"messageID"`
			PartID    string `json:"partID"`
			Delta     string `json:"delta"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil || p.Delta == "" {
			return
		}
		part := agPart{ID: p.PartID, SessionID: p.SessionID, MessageID: p.MessageID}
		b.notify(agNPartUpdated, map[string]any{
			"sessionId": p.SessionID, "messageId": p.MessageID,
			"part": part, "delta": p.Delta,
		})

	case "session.created", "session.updated":
		var p struct {
			Info ocpSession `json:"info"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil {
			return
		}
		b.rememberDir(p.Info.ID, p.Info.Directory)
		b.notify(agNSessionUpdated, map[string]any{"session": b.mapSession(p.Info)})

	case "session.deleted":
		var p struct {
			Info ocpSession `json:"info"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil {
			return
		}
		b.mu.Lock()
		delete(b.statuses, p.Info.ID)
		delete(b.dirs, p.Info.ID)
		b.mu.Unlock()
		b.notify(agNSessionDeleted, map[string]any{"sessionId": p.Info.ID})

	case "session.status":
		var p struct {
			SessionID string `json:"sessionID"`
			Status    struct {
				Type string `json:"type"`
			} `json:"status"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil {
			return
		}
		b.mu.Lock()
		b.statuses[p.SessionID] = p.Status.Type
		b.mu.Unlock()
		b.notify(agNSessionUpdated, map[string]any{"session": agSession{ID: p.SessionID, Status: p.Status.Type}})

	case "session.idle":
		var p struct {
			SessionID string `json:"sessionID"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil {
			return
		}
		b.mu.Lock()
		b.statuses[p.SessionID] = "idle"
		b.mu.Unlock()
		b.notify(agNSessionUpdated, map[string]any{"session": agSession{ID: p.SessionID, Status: "idle"}})

	case "permission.asked", "permission.updated":
		var asked struct {
			ID         string         `json:"id"`
			SessionID  string         `json:"sessionID"`
			Permission string         `json:"permission"`
			Patterns   []string       `json:"patterns"`
			Metadata   map[string]any `json:"metadata"`
			Tool       *struct {
				MessageID string `json:"messageID"`
				CallID    string `json:"callID"`
			} `json:"tool"`
			Type      string `json:"type"`
			Pattern   string `json:"pattern"`
			MessageID string `json:"messageID"`
			CallID    string `json:"callID"`
			Title     string `json:"title"`
		}
		if json.Unmarshal(ev.Properties, &asked) != nil {
			return
		}
		perm := ocpPermission{
			ID: asked.ID, SessionID: asked.SessionID,
			Type: asked.Permission, Pattern: asked.Pattern,
			MessageID: asked.MessageID, CallID: asked.CallID,
			Title: asked.Title, Metadata: asked.Metadata,
		}
		if ev.Type == "permission.asked" {
			if perm.Type == "" {
				perm.Type = asked.Type
			}
			if len(asked.Patterns) > 0 && perm.Pattern == "" {
				perm.Pattern = asked.Patterns[0]
			}
			if asked.Tool != nil {
				perm.MessageID = asked.Tool.MessageID
				perm.CallID = asked.Tool.CallID
			}
			if perm.Title == "" {
				if cmd, ok := asked.Metadata["command"].(string); ok && cmd != "" {
					perm.Title = cmd
				} else {
					perm.Title = perm.Type
				}
			}
		}
		if perm.ID == "" || perm.SessionID == "" {
			return
		}
		b.mu.Lock()
		b.approvals[perm.ID] = perm
		b.mu.Unlock()
		b.notify(agNApprovalRequested, map[string]any{"approval": b.mapPermission(perm)})

	case "permission.replied":
		var p struct {
			RequestID    string `json:"requestID"`
			PermissionID string `json:"permissionID"`
			Reply        string `json:"reply"`
			Response     string `json:"response"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil {
			return
		}
		id := p.RequestID
		if id == "" {
			id = p.PermissionID
		}
		d := p.Reply
		if d == "" {
			d = p.Response
		}
		b.mu.Lock()
		delete(b.approvals, id)
		b.mu.Unlock()
		b.notify(agNApprovalResolved, map[string]any{"approvalId": id, "decision": d})

	case "session.error":
		var p struct {
			SessionID string `json:"sessionID"`
			Error     *struct {
				Name    string `json:"name"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(ev.Properties, &p) != nil {
			return
		}
		msg := "会话错误"
		if p.Error != nil && p.Error.Message != "" {
			msg = p.Error.Name + ": " + p.Error.Message
		}
		b.notify(agNError, map[string]any{"message": msg, "sessionId": p.SessionID})
	}
}

// ---------- 映射 ----------

func (b *agOC) mapSession(s ocpSession) agSession {
	st := ""
	b.mu.Lock()
	st = b.statuses[s.ID]
	b.mu.Unlock()
	out := agSession{
		ID: s.ID, Title: s.Title, Directory: s.Directory,
		Status: st, TimeCreated: s.Time.Created, TimeUpdated: s.Time.Updated,
		Version: s.Version,
	}
	if s.Model != nil {
		out.ModelID = s.Model.ID
		out.ModelProvider = s.Model.ProviderID
	}
	return out
}

func (b *agOC) mapMessage(m ocpMessage, parts []json.RawMessage) agMessage {
	out := agMessage{
		ID: m.ID, SessionID: m.SessionID, Role: m.Role,
		CreatedAt: m.Time.Created, CompletedAt: m.Time.Completed,
		ModelID: m.ModelID, ProviderID: m.ProviderID, Finish: m.Finish, Cost: m.Cost,
	}
	if m.Tokens != nil {
		cr := int64(0)
		if m.Tokens.Cache != nil {
			cr = m.Tokens.Cache.Read
		}
		out.Tokens = &agTokens{Input: m.Tokens.Input, Output: m.Tokens.Output, Reasoning: m.Tokens.Reasoning, CacheRead: cr}
	}
	if m.Error != nil {
		me := &agMsgError{Name: m.Error.Name, Message: m.Error.Message}
		if me.Message == "" && m.Error.Data != nil {
			if s, ok := m.Error.Data["message"].(string); ok {
				me.Message = s
			}
		}
		out.Error = me
	}
	for _, raw := range parts {
		out.Parts = append(out.Parts, b.mapPart(raw))
	}
	return out
}

func (b *agOC) mapPart(raw json.RawMessage) agPart {
	var op ocpPart
	if err := json.Unmarshal(raw, &op); err != nil {
		return agPart{ID: "?", Type: "text", Text: string(raw)}
	}
	p := agPart{ID: op.ID, SessionID: op.SessionID, MessageID: op.MessageID}
	switch op.Type {
	case "text", "reasoning":
		p.Type = op.Type
		p.Text = op.Text
	case "tool":
		p.Type = "tool"
		ti := &agToolInfo{CallID: op.CallID, Name: op.Tool}
		if len(op.State) > 0 {
			var st struct {
				Status string         `json:"status"`
				Input  map[string]any `json:"input"`
				Raw    string         `json:"raw"`
				Title  string         `json:"title"`
				Output string         `json:"output"`
				Error  string         `json:"error"`
			}
			if json.Unmarshal(op.State, &st) == nil {
				ti.Status, ti.Input, ti.Raw, ti.Title, ti.Output, ti.Error =
					st.Status, st.Input, st.Raw, st.Title, st.Output, st.Error
			}
		}
		p.Tool = ti
	case "patch":
		p.Type = "patch"
		pi := &agPatchInfo{Hash: op.Hash}
		_ = json.Unmarshal(op.Files, &pi.Files)
		p.Patch = pi
	default:
		p.Type = op.Type
		meta := map[string]any{}
		_ = json.Unmarshal(raw, &meta)
		delete(meta, "id")
		delete(meta, "sessionID")
		delete(meta, "messageID")
		delete(meta, "type")
		p.Meta = meta
	}
	return p
}

func (b *agOC) mapPermission(perm ocpPermission) agApproval {
	return agApproval{
		ID: perm.ID, SessionID: perm.SessionID, MessageID: perm.MessageID, CallID: perm.CallID,
		Type: perm.Type, Title: perm.Title, Pattern: perm.Pattern, Metadata: perm.Metadata,
		Time: perm.Time.Created,
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
