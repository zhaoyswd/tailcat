//go:build !cshared

// agentgateway_codex.go — codex app-server 后端：spawn `codex app-server`（stdio JSONL）、
// JSON-RPC 往返与事件翻译到统一协议（agSession/agMessage/agPart）。
//
// 映射（统一 ← codex）：
//   session    ← thread（id/name/status/createdAt 秒→毫秒/updatedAt）
//   message    ← turn（assistant 行 id=turnId）+ userMessage item（user 行 id=itemId）
//   part.text  ← item agentMessage / userMessage
//   part.reasoning ← item reasoning（content[] 拼接）
//   part.tool  ← item commandExecution / mcpToolCall / dynamicToolCall
//   part.patch ← item fileChange（changes[] → agFileDiff）
//   其余 item   ← part 事件行（meta 保留原文）
//   审批        ← codex server→client 请求（*RequestApproval）→ approval.requested；
//                approval/respond → 对该请求回 JSON-RPC result（decision: accept/
//                acceptForSession/deny——对应 allow/allow-always/deny）
//   steer      ← turn/steer（expectedTurnId 用活跃 turn，接口层透出能力位）
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/logger"
)

// ---------- codex 原始形状（只取统一模型用得到的字段；未知字段原样进 meta） ----------

type cdxThread struct {
	ID         string `json:"id"`
	Name       *string `json:"name"`
	Status     *struct {
		Type string `json:"type"`
	} `json:"status"`
	CreatedAt int64 `json:"createdAt"` // 秒
	UpdatedAt int64 `json:"updatedAt"` // 秒
	Cwd       string `json:"cwd"`
	ModelProvider string `json:"modelProvider"`
}

type cdxTurn struct {
	ID    string          `json:"id"`
	Items []json.RawMessage `json:"items"`
}

type cdxItem struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	// userMessage / agentMessage / plan
	Text string `json:"text"`
	// userMessage.content = [{type:"text", text}]；reasoning.content = ["…"]（两种形态并用）
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	ContentStrings []string `json:"-"` // reasoning content 的字符串数组（UnmarshalJSON 里填）
	Summary []struct {
		Text string `json:"text"`
	} `json:"summary"`
	// commandExecution
	Command string `json:"command"`
	ExitCode *int  `json:"exitCode"`
	AggregatedOutput string `json:"aggregatedOutput"`
	// mcpToolCall / dynamicToolCall
	Server string `json:"server"`
	Tool   string `json:"tool"`
	Error  string `json:"error"`
	Result json.RawMessage `json:"result"`
	Arguments json.RawMessage `json:"arguments"`
	// fileChange
	Changes []struct {
		Path      string `json:"path"`
		Additions int    `json:"additions"`
		Deletions int    `json:"deletions"`
	} `json:"changes"`

	// 原始 JSON（default 分支 meta 保留原文）
	RawJSON json.RawMessage `json:"-"`
}

func (c *cdxItem) UnmarshalJSON(b []byte) error {
	type alias cdxItem
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*c = cdxItem(a)
	c.RawJSON = append(json.RawMessage(nil), b...)
	// reasoning.content 是字符串数组（与 userMessage 的对象数组互斥）——单独解析
	var raw struct {
		Content []json.RawMessage `json:"content"`
	}
	if json.Unmarshal(b, &raw) == nil {
		for _, rc := range raw.Content {
			var s string
			if json.Unmarshal(rc, &s) == nil && s != "" {
				c.ContentStrings = append(c.ContentStrings, s)
			}
		}
	}
	return nil
}

type cdxModel struct {
	ID         string `json:"id"`
	ProviderID string `json:"providerID"`
	ModelID    string `json:"modelID"`
	Name       string `json:"name"`
	Status     string `json:"status"`
}

// ---------- 后端 ----------

type agCodex struct {
	logf logger.Logf
	out  chan agNtfOut

	filesRoot string // serve --files 的宿主目录；App 传 SFTP 沙箱路径时换算（见 resolveHostDir）

	mu       sync.Mutex
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	nextID   int
	pending  map[int]chan json.RawMessage
	statuses map[string]string   // threadId → idle|busy|…
	activeTurn map[string]string // threadId → 活跃 turnId（steer/interrupt 用）
	approvals  map[string]cdxApproval // 统一审批 id → 待答复
	lastSpawn time.Time
}

type cdxApproval struct {
	CodexReqID json.RawMessage // 原始 JSON-RPC id（应答回这个）
	SessionID  string
}

func newAGCodex(logf logger.Logf) *agCodex {
	return &agCodex{
		logf:      logger.WithPrefix(logf, "[codex] "),
		out:       make(chan agNtfOut, 256),
		pending:   map[int]chan json.RawMessage{},
		statuses:  map[string]string{},
		activeTurn: map[string]string{},
		approvals: map[string]cdxApproval{},
	}
}

func (b *agCodex) caps() agCaps {
	return agCaps{Backend: "codex", Steer: true, Approvals: true, Models: true, Usage: true}
}

func (b *agCodex) notifications() <-chan agNtfOut { return b.out }

// ---------- 子进程与 JSON-RPC ----------

func (b *agCodex) ensureBackend(ctx context.Context) error {
	b.mu.Lock()
	ready := b.cmd != nil && b.stdin != nil
	b.mu.Unlock()
	if ready {
		return nil
	}
	if time.Since(b.lastSpawn) < 3*time.Second {
		return fmt.Errorf("codex 拉起过于频繁，稍后重试")
	}
	b.lastSpawn = time.Now()

	codexPath, err := exec.LookPath("codex")
	if err != nil {
		for _, cand := range []string{os.Getenv("HOME") + "/.opencode/bin/codex", "/opt/homebrew/bin/codex", "/usr/local/bin/codex"} {
			if st, serr := os.Stat(cand); serr == nil && !st.IsDir() {
				codexPath = cand
				break
			}
		}
		if codexPath == "" {
			return fmt.Errorf("找不到 codex 可执行文件")
		}
	}
	home, _ := os.UserHomeDir()
	cmd := exec.CommandContext(ctx, codexPath, "app-server")
	cmd.Dir = home
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("拉起 codex app-server 失败: %w", err)
	}
	b.mu.Lock()
	b.cmd = cmd
	b.stdin = stdin
	b.mu.Unlock()
	b.logf("按需拉起 codex app-server（pid=%d）", cmd.Process.Pid)

	go b.readLoop(bufio.NewReaderSize(stdout, 1<<20))
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			b.logf("[app-server.err] %s", sc.Text())
		}
	}()
	go func() {
		err := cmd.Wait()
		b.mu.Lock()
		b.cmd = nil
		b.stdin = nil
		b.mu.Unlock()
		b.logf("codex 子进程退出: %v（下次请求会重新拉起）", err)
	}()

	// 握手
	var resp json.RawMessage
	resp, err = b.call(ctx, "initialize", map[string]any{
		"clientInfo": map[string]string{"name": "tailcat-agent-gateway", "version": "1.0"},
	})
	if err != nil {
		return fmt.Errorf("codex 握手失败: %w", err)
	}
	b.logf("codex 就绪: %s", strings.TrimSpace(string(resp)))
	return nil
}

func (b *agCodex) readLoop(br *bufio.Reader) {
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			b.handleLine(line)
		}
		if err != nil {
			return
		}
	}
}

type cdxFrame struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (b *agCodex) handleLine(line []byte) {
	var f cdxFrame
	if json.Unmarshal(line, &f) != nil || f.Method == "" && f.ID == nil {
		return
	}
	if f.Method == "" && f.ID != nil {
		// 响应
		b.mu.Lock()
		ch := b.pending[int(idOf(f.ID))]
		delete(b.pending, int(idOf(f.ID)))
		b.mu.Unlock()
		if ch != nil {
			if f.Error != nil {
				ch <- json.RawMessage(fmt.Sprintf(`{"error":{"code":%d,"message":%q}}`, f.Error.Code, f.Error.Message))
			} else {
				ch <- f.Result
			}
		}
		return
	}
	if f.Method != "" && f.ID != nil {
		// server→client 请求（审批）
		b.handleServerRequest(f)
		return
	}
	// 通知
	b.translateNotify(f.Method, f.Params)
}

func idOf(raw json.RawMessage) float64 {
	var v float64
	_ = json.Unmarshal(raw, &v)
	return v
}

func (b *agCodex) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	b.mu.Lock()
	if b.stdin == nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("codex app-server 未运行")
	}
	id := b.nextID
	b.nextID++
	ch := make(chan json.RawMessage, 1)
	b.pending[id] = ch
	stdin := b.stdin
	b.mu.Unlock()
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	bs, _ := json.Marshal(req)
	if _, err := stdin.Write(append(bs, '\n')); err != nil {
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
		return nil, err
	}
	select {
	case r := <-ch:
		var e struct {
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(r, &e) == nil && e.Error != nil {
			return nil, fmt.Errorf("codex %s: %s", method, e.Error.Message)
		}
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(60 * time.Second):
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
		return nil, fmt.Errorf("codex %s 超时", method)
	}
}

// ---------- 审批（codex server→client 请求） ----------

func (b *agCodex) handleServerRequest(f cdxFrame) {
	if !strings.Contains(f.Method, "RequestApproval") {
		// 未知的服务端请求：统一回空 result，别让 codex 卡死
		b.replyServer(f.ID, map[string]any{})
		return
	}
	var p struct {
		ThreadID string `json:"threadId"`
		ItemID   string `json:"itemId"`
		Command  string `json:"command"`
	}
	_ = json.Unmarshal(f.Params, &p)
	ourID := fmt.Sprintf("cdx-%d", time.Now().UnixNano())
	b.mu.Lock()
	b.approvals[ourID] = cdxApproval{CodexReqID: f.ID, SessionID: p.ThreadID}
	b.mu.Unlock()
	title := p.Command
	if title == "" {
		title = strings.TrimSuffix(f.Method[strings.LastIndex(f.Method, "/")+1:], "RequestApproval")
	}
	b.notify(agNApprovalRequested, map[string]any{"approval": agApproval{
		ID: ourID, SessionID: p.ThreadID, MessageID: p.ItemID,
		Type: "codex", Title: title,
	}})
}

func (b *agCodex) replyServer(id json.RawMessage, result any) {
	b.mu.Lock()
	stdin := b.stdin
	b.mu.Unlock()
	if stdin == nil {
		return
	}
	resp := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result}
	bs, _ := json.Marshal(resp)
	stdin.Write(append(bs, '\n'))
}

func (b *agCodex) respondApproval(ctx context.Context, approvalID, decision string) error {
	b.mu.Lock()
	ap, ok := b.approvals[approvalID]
	delete(b.approvals, approvalID)
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("未知的审批请求 %s", approvalID)
	}
	dec := "deny"
	switch decision {
	case "allow":
		dec = "accept"
	case "allow-always":
		dec = "acceptForSession"
	case "deny":
		dec = "deny"
	default:
		return fmt.Errorf("非法 decision: %s", decision)
	}
	b.replyServer(ap.CodexReqID, map[string]any{"decision": dec})
	return nil
}

// ---------- 会话操作 ----------

func (b *agCodex) listSessions(ctx context.Context) ([]agSession, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, err
	}
	resp, err := b.call(ctx, "thread/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var r struct {
		Data []cdxThread `json:"data"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return nil, err
	}
	out := make([]agSession, 0, len(r.Data))
	for _, t := range r.Data {
		s := b.mapThread(t)
		out = append(out, s)
	}
	return out, nil
}

func (b *agCodex) mapThread(t cdxThread) agSession {
	st := ""
	if t.Status != nil {
		st = t.Status.Type
	}
	b.mu.Lock()
	if st != "" {
		b.statuses[t.ID] = st
	} else {
		st = b.statuses[t.ID]
	}
	b.mu.Unlock()
	name := ""
	if t.Name != nil {
		name = *t.Name
	}
	return agSession{
		ID: t.ID, Title: name, Status: st,
		TimeCreated: t.CreatedAt * 1000, TimeUpdated: t.UpdatedAt * 1000,
		Directory: t.Cwd, ModelProvider: t.ModelProvider,
	}
}

func (b *agCodex) createSession(ctx context.Context, title, directory string) (*agSession, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, err
	}
	// 会话目录：thread/start 收 `cwd`（0.154 的 app-server schema 里是正式参数，实测生效），
	// 不传就继承 app-server 自己的 cwd（= $HOME）——那样会话的工作区根是家目录、
	// thread.cwd 也只报家目录（App 会话页副标题就显示 $HOME，且会话 cell 的类型图标
	// 匹配不上项目 absPath）。参数不存在的路径也不报错，所以直接传，不做 stat 兜底。
	params := map[string]any{}
	if d := resolveHostDir(b.filesRoot, directory); d != "" {
		params["cwd"] = d
	}
	resp, err := b.call(ctx, "thread/start", params)
	if err != nil {
		return nil, err
	}
	var r struct {
		Thread cdxThread `json:"thread"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return nil, err
	}
	s := b.mapThread(r.Thread)
	// thread/start 响应里的 name 可能为空；title 参数 codex 没有直接对应（name 由首轮自动生成）
	return &s, nil
}

func (b *agCodex) readSession(ctx context.Context, id string) (*agSession, []agMessage, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, nil, err
	}
	// thread/read 只给元数据（0.154 实测 turns 恒空）；内容走 thread/turns/list
	resp, err := b.call(ctx, "thread/read", map[string]any{"threadId": id})
	if err != nil {
		return nil, nil, err
	}
	var tr struct {
		Thread struct {
			ID        string   `json:"id"`
			Name      *string  `json:"name"`
			Status    *struct {
				Type string `json:"type"`
			} `json:"status"`
			CreatedAt int64  `json:"createdAt"`
			UpdatedAt int64  `json:"updatedAt"`
			Cwd       string `json:"cwd"`
			Model     string `json:"model"`
			ModelProvider string `json:"modelProvider"`
		} `json:"thread"`
	}
	if err := json.Unmarshal(resp, &tr); err != nil {
		return nil, nil, err
	}
	th := cdxThread{ID: tr.Thread.ID, Name: tr.Thread.Name, CreatedAt: tr.Thread.CreatedAt,
		UpdatedAt: tr.Thread.UpdatedAt, Cwd: tr.Thread.Cwd, ModelProvider: tr.Thread.ModelProvider}
	if tr.Thread.Status != nil {
		th.Status = tr.Thread.Status
	}
	s := b.mapThread(th)
	s.ModelID = tr.Thread.Model

	tlResp, err := b.call(ctx, "thread/turns/list", map[string]any{"threadId": id})
	if err != nil {
		return &s, nil, nil // 元数据可用即返回，内容缺省
	}
	var tl struct {
		Data []cdxTurn `json:"data"`
	}
	if err := json.Unmarshal(tlResp, &tl); err != nil {
		return &s, nil, nil
	}

	msgs := make([]agMessage, 0)
	for _, turn := range tl.Data {
		var user *agMessage
		asst := agMessage{ID: turn.ID, SessionID: id, Role: "assistant"}
		hasAsst := false
		for _, raw := range turn.Items {
			var it cdxItem
			if json.Unmarshal(raw, &it) != nil {
				continue
			}
			switch it.Type {
			case "userMessage":
				u := agMessage{ID: it.ID, SessionID: id, Role: "user", Parts: []agPart{{ID: it.ID, SessionID: id, Type: "text", Text: itemText(it)}}}
				user = &u
			case "agentMessage":
				asst.Parts = append(asst.Parts, agPart{ID: it.ID, SessionID: id, MessageID: turn.ID, Type: "text", Text: it.Text})
				hasAsst = true
			case "reasoning":
				asst.Parts = append(asst.Parts, agPart{ID: it.ID, SessionID: id, MessageID: turn.ID, Type: "reasoning", Text: itemText(it)})
				hasAsst = true
			case "commandExecution", "mcpToolCall", "dynamicToolCall", "collabAgentToolCall":
				p := agPart{ID: it.ID, SessionID: id, MessageID: turn.ID, Type: "tool", Tool: &agToolInfo{}}
				p.Tool.Name = toolName(it)
				p.Tool.Status = "completed"
				if it.Command != "" {
					p.Tool.Raw = it.Command
					p.Tool.Input = map[string]any{"command": it.Command}
				}
				if len(it.Arguments) > 0 {
					_ = json.Unmarshal(it.Arguments, &p.Tool.Input)
				}
				p.Tool.Output = it.AggregatedOutput
				if len(it.Result) > 0 {
					p.Tool.Output = string(it.Result)
				}
				p.Tool.Error = it.Error
				if it.ExitCode != nil && *it.ExitCode != 0 {
					p.Tool.Status = "error"
				}
				asst.Parts = append(asst.Parts, p)
				hasAsst = true
			case "fileChange":
				p := agPart{ID: it.ID, SessionID: id, MessageID: turn.ID, Type: "patch", Patch: &agPatchInfo{}}
				for _, ch := range it.Changes {
					p.Patch.Files = append(p.Patch.Files, agFileDiff{File: ch.Path, Additions: ch.Additions, Deletions: ch.Deletions})
				}
				asst.Parts = append(asst.Parts, p)
				hasAsst = true
			default:
				meta := map[string]any{}
				_ = json.Unmarshal(it.RawJSON, &meta)
				delete(meta, "id")
				p := agPart{ID: it.ID, SessionID: id, MessageID: turn.ID, Type: it.Type, Meta: meta}
				if it.Text != "" {
					p.Text = it.Text
				}
				asst.Parts = append(asst.Parts, p)
				hasAsst = true
			}
		}
		if user != nil {
			msgs = append(msgs, *user)
		}
		if hasAsst {
			msgs = append(msgs, asst)
		}
	}
	return &s, msgs, nil
}

func itemText(it cdxItem) string {
	if it.Text != "" {
		return it.Text
	}
	var sb strings.Builder
	for _, c := range it.Content {
		sb.WriteString(c.Text)
	}
	for _, s := range it.ContentStrings {
		sb.WriteString(s)
	}
	if sb.Len() > 0 {
		return sb.String()
	}
	for _, s := range it.Summary {
		sb.WriteString(s.Text)
	}
	return sb.String()
}

func toolName(it cdxItem) string {
	if it.Tool != "" {
		return it.Tool
	}
	if it.Server != "" {
		return it.Server
	}
	return it.Type
}

func (b *agCodex) deleteSession(ctx context.Context, id string) error {
	if err := b.ensureBackend(ctx); err != nil {
		return err
	}
	_, err := b.call(ctx, "thread/delete", map[string]any{"threadId": id})
	return err
}

func (b *agCodex) renameSession(ctx context.Context, id, title string) (*agSession, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, err
	}
	resp, err := b.call(ctx, "thread/name/set", map[string]any{"threadId": id, "name": title})
	if err != nil {
		return nil, err
	}
	var r struct {
		Thread cdxThread `json:"thread"`
	}
	_ = json.Unmarshal(resp, &r)
	s := b.mapThread(r.Thread)
	if s.ID == "" {
		s = agSession{ID: id, Title: title}
	}
	return &s, nil
}

func (b *agCodex) sendPrompt(ctx context.Context, sessionID, text, modelID string) error {
	if err := b.ensureBackend(ctx); err != nil {
		return err
	}
	params := map[string]any{
		"threadId": sessionID,
		"input":    []map[string]any{{"type": "text", "text": text}},
	}
	if modelID != "" {
		m := modelID
		if i := strings.Index(modelID, "/"); i >= 0 {
			m = modelID[i+1:]
		}
		params["model"] = m
	}
	_, err := b.call(ctx, "turn/start", params)
	return err
}

func (b *agCodex) interrupt(ctx context.Context, sessionID string) error {
	b.mu.Lock()
	turnID := b.activeTurn[sessionID]
	b.mu.Unlock()
	if turnID == "" {
		return fmt.Errorf("没有正在进行的 turn 可中断")
	}
	_, err := b.call(ctx, "turn/interrupt", map[string]any{"threadId": sessionID, "turnId": turnID})
	return err
}

func (b *agCodex) steer(ctx context.Context, sessionID, text string) error {
	b.mu.Lock()
	turnID := b.activeTurn[sessionID]
	b.mu.Unlock()
	if turnID == "" {
		return fmt.Errorf("没有正在进行的 turn 可转向")
	}
	_, err := b.call(ctx, "turn/steer", map[string]any{
		"threadId": sessionID, "expectedTurnId": turnID,
		"input": []map[string]any{{"type": "text", "text": text}},
	})
	return err
}

func (b *agCodex) listModels(ctx context.Context) ([]agModel, error) {
	if err := b.ensureBackend(ctx); err != nil {
		return nil, err
	}
	resp, err := b.call(ctx, "model/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var r struct {
		Data []cdxModel `json:"data"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return nil, err
	}
	out := make([]agModel, 0, len(r.Data))
	for _, m := range r.Data {
		mid := m.ModelID
		if mid == "" {
			mid = m.ID
		}
		pid := m.ProviderID
		full := mid
		if pid != "" {
			full = pid + "/" + mid
		}
		out = append(out, agModel{ID: full, ProviderID: pid, ModelID: mid, Name: m.Name, Status: m.Status})
	}
	return out, nil
}

// ---------- 事件消费（stdout 通知直接进本后端，无 SSE） ----------

func (b *agCodex) Start(ctx context.Context) {
	// codex 的事件来自子进程 stdout（readLoop 已在跑）；此方法仅为对齐后端接口，
	// 阻塞至 ctx 取消。
	<-ctx.Done()
}

func (b *agCodex) notify(method string, params any) {
	select {
	case b.out <- agNtfOut{method: method, params: params}:
	default:
		b.logf("统一通知队列满，丢弃 %s", method)
	}
}

func (b *agCodex) translateNotify(method string, params json.RawMessage) {
	switch method {
	case "thread/status/changed":
		var p struct {
			ThreadID string `json:"threadId"`
			Status   struct {
				Type string `json:"type"`
			} `json:"status"`
		}
		if json.Unmarshal(params, &p) != nil {
			return
		}
		b.mu.Lock()
		b.statuses[p.ThreadID] = p.Status.Type
		b.mu.Unlock()
		b.notify(agNSessionUpdated, map[string]any{"session": agSession{ID: p.ThreadID, Status: p.Status.Type}})

	case "turn/started":
		var p struct {
			ThreadID string `json:"threadId"`
			Turn     struct {
				ID string `json:"id"`
			} `json:"turn"`
		}
		if json.Unmarshal(params, &p) != nil {
			return
		}
		b.mu.Lock()
		b.activeTurn[p.ThreadID] = p.Turn.ID
		b.mu.Unlock()

	case "turn/completed":
		var p struct {
			ThreadID string  `json:"threadId"`
			Turn     cdxTurn `json:"turn"`
		}
		if json.Unmarshal(params, &p) != nil {
			return
		}
		b.mu.Lock()
		delete(b.activeTurn, p.ThreadID)
		b.mu.Unlock()
		// 把完成的 items 全量补发（App 按 partId 原位更新/补建）
		b.emitTurnItems(p.ThreadID, p.Turn)

	case "item/started", "item/completed":
		var p struct {
			ThreadID string `json:"threadId"`
			TurnID   string `json:"turnId"`
			Item     json.RawMessage `json:"item"`
		}
		if json.Unmarshal(params, &p) != nil {
			return
		}
		var it cdxItem
		if json.Unmarshal(p.Item, &it) != nil {
			return
		}
		if method == "item/started" {
			b.mu.Lock()
			b.activeTurn[p.ThreadID] = p.TurnID
			b.mu.Unlock()
		}
		b.emitItem(p.ThreadID, p.TurnID, it, method == "item/completed")

	case "item/agentMessage/delta", "item/reasoning/textDelta", "item/commandExecution/outputDelta":
		var p struct {
			ThreadID string `json:"threadId"`
			TurnID   string `json:"turnId"`
			ItemID   string `json:"itemId"`
			Delta    string `json:"delta"`
		}
		if json.Unmarshal(params, &p) != nil || p.Delta == "" {
			return
		}
		typ := ""
		if strings.Contains(method, "agentMessage") {
			typ = "text"
		} else if strings.Contains(method, "reasoning") {
			typ = "reasoning"
		} else {
			typ = "tool-out"
		}
		var part agPart
		if typ == "tool-out" {
			part = agPart{ID: p.ItemID, SessionID: p.ThreadID, MessageID: p.TurnID, Type: "tool",
				Tool: &agToolInfo{Output: p.Delta}}
		} else {
			part = agPart{ID: p.ItemID, SessionID: p.ThreadID, MessageID: p.TurnID, Type: typ}
		}
		b.notify(agNPartUpdated, map[string]any{
			"sessionId": p.ThreadID, "messageId": p.TurnID, "part": part, "delta": p.Delta,
		})

	case "thread/name/updated":
		var p struct {
			ThreadID string  `json:"threadId"`
			Name     *string `json:"name"`
		}
		if json.Unmarshal(params, &p) != nil {
			return
		}
		name := ""
		if p.Name != nil {
			name = *p.Name
		}
		b.notify(agNSessionUpdated, map[string]any{"session": agSession{ID: p.ThreadID, Title: name}})

	case "thread/tokenUsage/updated":
		var p struct {
			ThreadID string `json:"threadId"`
			Tokens   struct {
				Input     int64 `json:"input"`
				Output    int64 `json:"output"`
				Reasoning int64 `json:"reasoning"`
				Cache     *struct {
					Read int64 `json:"read"`
				} `json:"cache"`
			} `json:"tokens"`
		}
		if json.Unmarshal(params, &p) != nil {
			return
		}
		cr := int64(0)
		if p.Tokens.Cache != nil {
			cr = p.Tokens.Cache.Read
		}
		tk := &agTokens{Input: p.Tokens.Input, Output: p.Tokens.Output, Reasoning: p.Tokens.Reasoning, CacheRead: cr}
		b.notify(agNUsageUpdated, map[string]any{"sessionId": p.ThreadID, "tokens": tk})
		// ctx 环依赖消息级 tokens：发一条挂在活跃 turn 上的 message.updated
		b.mu.Lock()
		turn := b.activeTurn[p.ThreadID]
		b.mu.Unlock()
		if turn != "" {
			c := 0.0
			b.notify(agNMessageUpdated, map[string]any{"message": agMessage{
				ID: turn, SessionID: p.ThreadID, Role: "assistant", Tokens: tk, Cost: &c,
			}})
		}
	}
}

func (b *agCodex) emitTurnItems(threadID string, turn cdxTurn) {
	for _, raw := range turn.Items {
		var it cdxItem
		if json.Unmarshal(raw, &it) != nil {
			continue
		}
		b.emitItem(threadID, turn.ID, it, true)
	}
}

func (b *agCodex) emitItem(threadID, turnID string, it cdxItem, completed bool) {
	switch it.Type {
	case "userMessage":
		b.notify(agNMessageUpdated, map[string]any{"message": agMessage{
			ID: it.ID, SessionID: threadID, Role: "user",
			Parts: []agPart{{ID: it.ID, SessionID: threadID, Type: "text", Text: it.Text}},
		}})
	case "agentMessage":
		b.notify(agNPartUpdated, map[string]any{
			"sessionId": threadID, "messageId": turnID,
			"part": agPart{ID: it.ID, SessionID: threadID, MessageID: turnID, Type: "text", Text: it.Text},
		})
	case "reasoning":
		b.notify(agNPartUpdated, map[string]any{
			"sessionId": threadID, "messageId": turnID,
			"part": agPart{ID: it.ID, SessionID: threadID, MessageID: turnID, Type: "reasoning", Text: itemText(it)},
		})
	case "commandExecution", "mcpToolCall", "dynamicToolCall", "collabAgentToolCall":
		p := agPart{ID: it.ID, SessionID: threadID, MessageID: turnID, Type: "tool", Tool: &agToolInfo{}}
		p.Tool.Name = toolName(it)
		p.Tool.Status = "running"
		if completed {
			p.Tool.Status = "completed"
		}
		if it.Command != "" {
			p.Tool.Raw = it.Command
			p.Tool.Input = map[string]any{"command": it.Command}
		}
		if len(it.Arguments) > 0 {
			_ = json.Unmarshal(it.Arguments, &p.Tool.Input)
		}
		p.Tool.Output = it.AggregatedOutput
		if len(it.Result) > 0 {
			p.Tool.Output = string(it.Result)
		}
		p.Tool.Error = it.Error
		if it.ExitCode != nil && *it.ExitCode != 0 {
			p.Tool.Status = "error"
		}
		b.notify(agNPartUpdated, map[string]any{"sessionId": threadID, "messageId": turnID, "part": p})
	case "fileChange":
		p := agPart{ID: it.ID, SessionID: threadID, MessageID: turnID, Type: "patch", Patch: &agPatchInfo{}}
		for _, ch := range it.Changes {
			p.Patch.Files = append(p.Patch.Files, agFileDiff{File: ch.Path, Additions: ch.Additions, Deletions: ch.Deletions})
		}
		b.notify(agNPartUpdated, map[string]any{"sessionId": threadID, "messageId": turnID, "part": p})
	default:
		meta := map[string]any{}
		_ = json.Unmarshal(it.RawJSON, &meta)
		delete(meta, "id")
		p := agPart{ID: it.ID, SessionID: threadID, MessageID: turnID, Type: it.Type, Meta: meta}
		if it.Text != "" {
			p.Text = it.Text
		}
		b.notify(agNPartUpdated, map[string]any{"sessionId": threadID, "messageId": turnID, "part": p})
	}
}

