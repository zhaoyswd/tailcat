//go:build !cshared

// agentgateway.go — 内嵌 agent-gateway：tailcat serve 进程内的一个常驻回环监听，
// 把 tier App 的统一 WS+JSON-RPC 协议翻译到 opencode（见 agentgateway_oc.go）。
//
// 生命周期：随 serve 起停（serveMain 里一行 go startAgentGateway(...) 挂载）。
// 监听 127.0.0.1:7777（TAILCAT_AGENT_GATEWAY_PORT 覆盖）；监听失败只记日志、
// 不影响 serve——agent 能力不可用而已。
// 无应用层鉴权：能连上 = 通过了隧道（端口转发）的 WireGuard 认证。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/types/logger"
)

// resolveHostDir 把 App 传来的 files 服务 SFTP 沙箱路径换算成宿主真实绝对路径
// ——files 服务基于 os.Root，故意不暴露根位置，后端（opencode/codex）要的都是宿主
// 绝对路径，所以换算只能在这里做。空目录（未选项目）或未配 filesRoot（路径本就当
// 绝对路径用）时原样返回。
func resolveHostDir(filesRoot, directory string) string {
	if directory == "" || filesRoot == "" {
		return directory
	}
	return filepath.Join(filesRoot, filepath.Clean(directory))
}

// filesRoot：serve 的 --files 目录（同一进程内拿到，见 resolveHostDir）。
// 空 = 未配 files，路径原样透传。
func startAgentGateway(logf logger.Logf, filesRoot string) {
	defer func() {
		if r := recover(); r != nil {
			logf("panic: %v", r)
		}
	}()
	port := os.Getenv("TAILCAT_AGENT_GATEWAY_PORT")
	if port == "" {
		port = "7777"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		logf("监听 127.0.0.1:%s 失败（agent 远程会话不可用，不影响 serve）: %v", port, err)
		return
	}
	oc := newAGOC(logger.WithPrefix(logf, "[opencode] "))
	oc.filesRoot = filesRoot
	cx := newAGCodex(logf)
	cx.filesRoot = filesRoot
	hub := &agHub{
		backends:  map[string]agBackend{"opencode": oc, "codex": cx},
		filesRoot: filesRoot,
		clients:   map[*agClientConn]struct{}{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go oc.Start(ctx)
	go cx.Start(ctx)
	go hub.runEvents()
	logf("agent-gateway 就绪 ws://127.0.0.1:%s/ws（opencode: %s；codex app-server 按需拉起）", port, oc.url)
	for {
		c, err := ln.Accept()
		if err != nil {
			logf("accept: %v", err)
			return
		}
		go hub.serveConn(c)
	}
}

// ---------- hub ----------

// agBackend 是一个可被 gateway 驱动的 agent 后端（opencode / codex / …）。
// 连接在 initialize 时按 params.backend 绑定到其中一个；事件按绑定分发。
type agBackend interface {
	caps() agCaps
	ensureBackend(ctx context.Context) error
	listSessions(ctx context.Context) ([]agSession, error)
	createSession(ctx context.Context, title, directory string) (*agSession, error)
	readSession(ctx context.Context, id string) (*agSession, []agMessage, error)
	deleteSession(ctx context.Context, id string) error
	renameSession(ctx context.Context, id, title string) (*agSession, error)
	sendPrompt(ctx context.Context, sessionID, text, modelID string) error
	interrupt(ctx context.Context, sessionID string) error
	steer(ctx context.Context, sessionID, text string) error
	respondApproval(ctx context.Context, approvalID, decision string) error
	listModels(ctx context.Context) ([]agModel, error)
	Start(ctx context.Context)
	notifications() <-chan agNtfOut
}

type agClientConn struct {
	ws   *agWSConn
	send chan []byte
	hub  *agHub
	be   agBackend // initialize 时绑定（默认 opencode）
}

type agHub struct {
	backends map[string]agBackend
	// filesRoot：serve --files 的宿主目录（与 resolveHostDir 同一个值）。空 = 未配 files
	// （此时 App 拿不到宿主根，只能退回沙箱路径比较）。经 `files/root` 下发给 App。
	filesRoot string
	mu        sync.Mutex
	clients   map[*agClientConn]struct{}
}

func (h *agHub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

func (h *agHub) serveConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	// 先读一个字节做超时控制（握手等太久就放弃）
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	ws, err := agWSAccept(c, br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	cl := &agClientConn{ws: ws, send: make(chan []byte, 128), hub: h}
	h.mu.Lock()
	h.clients[cl] = struct{}{}
	h.mu.Unlock()
	h.logf("客户端接入（在线 %d）", h.count())

	go cl.writePump()
	cl.readPump()

	h.mu.Lock()
	delete(h.clients, cl)
	h.mu.Unlock()
	close(cl.send)
	h.logf("客户端断开（在线 %d）", h.count())
}

func (h *agHub) logf(format string, args ...any) {
	h.backends["opencode"].(*agOC).logf("[hub] "+format, args...)
}

func (h *agHub) runEvents() {
	// 每个后端一个分发 goroutine：只发给绑定到该后端的连接
	for name, be := range h.backends {
		go func(name string, be agBackend) {
			for n := range be.notifications() {
				b, err := json.Marshal(agNotification{JSONRPC: agJSONRPCVersion, Method: n.method, Params: n.params})
				if err != nil {
					continue
				}
				h.mu.Lock()
				for cl := range h.clients {
					if cl.be == nil || cl.be != be {
						continue
					}
					select {
					case cl.send <- b:
					default:
					}
				}
				h.mu.Unlock()
			}
		}(name, be)
	}
	// 常驻（分发 goroutine 生命周期与 hub 一致）
	select {}
}

func (cl *agClientConn) writePump() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case b, ok := <-cl.send:
			if !ok {
				cl.ws.Close()
				return
			}
			if err := cl.ws.WriteMessage(b); err != nil {
				cl.ws.markClosed()
				return
			}
		case <-ticker.C:
			if err := cl.ws.WritePing(); err != nil {
				cl.ws.markClosed()
				return
			}
		}
	}
}

func (cl *agClientConn) readPump() {
	defer cl.ws.markClosed()
	for {
		data, err := cl.ws.ReadMessage()
		if err != nil {
			return
		}
		cl.dispatch(data)
	}
}

func (cl *agClientConn) dispatch(data []byte) {
	var req agRequest
	if err := json.Unmarshal(data, &req); err != nil || req.Method == "" {
		if req.ID != nil {
			cl.reply(req.ID, nil, &agRPCError{Code: agCodeParse, Message: "无法解析的请求"})
		}
		return
	}
	result, rpcErr := cl.handle(&req)
	if req.ID == nil {
		return
	}
	if rpcErr != nil {
		cl.reply(req.ID, nil, rpcErr)
		return
	}
	cl.reply(req.ID, result, nil)
}

func (cl *agClientConn) reply(id json.RawMessage, result any, rpcErr *agRPCError) {
	b, err := json.Marshal(agResponse{JSONRPC: agJSONRPCVersion, ID: id, Result: result, Error: rpcErr})
	if err != nil {
		return
	}
	select {
	case cl.send <- b:
	default:
	}
}

func agUnmarshalParams(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (cl *agClientConn) handle(req *agRequest) (any, *agRPCError) {
	ctx := context.Background()
	b := cl.be
	if b == nil {
		b = cl.hub.backends["opencode"]
		cl.be = b
	}
	switch req.Method {
	case agMInitialize:
		var p struct {
			Backend string `json:"backend"`
		}
		if agUnmarshalParams(req.Params, &p) != nil {
			return nil, agBadParams()
		}
		if p.Backend != "" {
			be, ok := cl.hub.backends[p.Backend]
			if !ok {
				return nil, &agRPCError{Code: agCodeBadParams, Message: "未知后端: " + p.Backend}
			}
			cl.be = be
			b = be
		}
		return map[string]any{
			"capabilities": b.caps(),
			"serverInfo":   map[string]any{"name": "tailcat-agent-gateway", "version": "1.0", "backend": b.caps().Backend},
		}, nil

	case agMFilesRoot:
		// hub 级（与 backend 无关，也不要求 initialize 先跑）：files 服务的宿主根。
		// App 用它把「项目目录（SFTP 沙箱路径）」拼成宿主绝对路径，与
		// session.directory（后端返回的宿主绝对路径）落在同一命名空间里做精确匹配。
		// 未配 files 时为空串，App 侧据此回退（不猜）。
		return map[string]any{"root": cl.hub.filesRoot}, nil

	case agMSessionList:
		sessions, err := b.listSessions(ctx)
		if err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"sessions": sessions}, nil

	case agMSessionCreate:
		var p struct {
			Title     string `json:"title"`
			Directory string `json:"directory"` // 项目目录（空 = 后端默认目录）；opencode 原生跨目录
		}
		if agUnmarshalParams(req.Params, &p) != nil {
			return nil, agBadParams()
		}
		s, err := b.createSession(ctx, p.Title, p.Directory)
		if err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"session": *s}, nil

	case agMSessionRead:
		var p struct {
			SessionID string `json:"sessionId"`
		}
		if agUnmarshalParams(req.Params, &p) != nil || p.SessionID == "" {
			return nil, agBadParams()
		}
		s, msgs, err := b.readSession(ctx, p.SessionID)
		if err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"session": *s, "messages": msgs}, nil

	case agMSessionDelete:
		var p struct {
			SessionID string `json:"sessionId"`
		}
		if agUnmarshalParams(req.Params, &p) != nil || p.SessionID == "" {
			return nil, agBadParams()
		}
		if err := b.deleteSession(ctx, p.SessionID); err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"ok": true}, nil

	case agMSessionRename:
		var p struct {
			SessionID string `json:"sessionId"`
			Title     string `json:"title"`
		}
		if agUnmarshalParams(req.Params, &p) != nil || p.SessionID == "" || p.Title == "" {
			return nil, agBadParams()
		}
		s, err := b.renameSession(ctx, p.SessionID, p.Title)
		if err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"session": *s}, nil

	case agMPromptSend:
		var p struct {
			SessionID string `json:"sessionId"`
			Text      string `json:"text"`
			ModelID   string `json:"modelId"`
		}
		if agUnmarshalParams(req.Params, &p) != nil || p.SessionID == "" || p.Text == "" {
			return nil, agBadParams()
		}
		if err := b.sendPrompt(ctx, p.SessionID, p.Text, p.ModelID); err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"ok": true}, nil

	case agMTurnInterrupt:
		var p struct {
			SessionID string `json:"sessionId"`
		}
		if agUnmarshalParams(req.Params, &p) != nil || p.SessionID == "" {
			return nil, agBadParams()
		}
		if err := b.interrupt(ctx, p.SessionID); err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"ok": true}, nil

	case agMTurnSteer:
		var p struct {
			SessionID string `json:"sessionId"`
			Text      string `json:"text"`
		}
		if agUnmarshalParams(req.Params, &p) != nil || p.SessionID == "" || p.Text == "" {
			return nil, agBadParams()
		}
		if !b.caps().Steer {
			return nil, &agRPCError{
				Code:    agCodeUnsupported,
				Message: "当前后端 " + b.caps().Backend + " 不支持 turn/steer（能力位 steer=false）",
			}
		}
		if err := b.steer(ctx, p.SessionID, p.Text); err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"ok": true}, nil

	case agMApprovalRespond:
		var p struct {
			ApprovalID string `json:"approvalId"`
			Decision   string `json:"decision"`
		}
		if agUnmarshalParams(req.Params, &p) != nil || p.ApprovalID == "" || p.Decision == "" {
			return nil, agBadParams()
		}
		if err := b.respondApproval(ctx, p.ApprovalID, p.Decision); err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"ok": true}, nil

	case agMModelList:
		models, err := b.listModels(ctx)
		if err != nil {
			return nil, agBackendErr(err)
		}
		return map[string]any{"models": models}, nil

	default:
		return nil, &agRPCError{Code: agCodeMethodNF, Message: "未知方法: " + req.Method}
	}
}

func agBadParams() *agRPCError {
	return &agRPCError{Code: agCodeBadParams, Message: "参数缺失或非法"}
}

func agBackendErr(err error) *agRPCError {
	return &agRPCError{Code: agCodeBackend, Message: err.Error()}
}

// 保留 io 引用（handshake 的 400 响应用 io.WriteString；go1.24 下防 import 漂移）。
var _ = io.WriteString
