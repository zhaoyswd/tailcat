//go:build !cshared

// agentgateway_proto.go — tier App ↔ tailcat 内嵌 agent-gateway 的统一协议类型。
//
// 设计（2026-09-15 定案）：
//   - 域模型取 opencode 的形状（Session/Message/Part，无 Turn），后端差异用能力位表达；
//   - App 侧零配置：主机固定监听 127.0.0.1:7777，opencode 地址主机侧自决
//     （默认 http://127.0.0.1:4096，TAILCAT_OPENCODE_URL 覆盖；按需拉起子进程）；
//   - 无应用层鉴权：能连上 = 通过了隧道（端口转发）的 WireGuard 认证，隧道即凭证。
//
// Part 类型映射表 —— App 渲染契约，只可增列不可改语义：
//
//	text        正文卡（Markdown 流式，delta 增量追加）
//	reasoning   思考折叠块（Text 承载内容）
//	tool        工具行（Tool.Status: pending|running|completed|error）
//	patch       diff 折叠块（Patch.Files: []FileDiff，带增删行数）
//	step-start/step-finish/snapshot/agent/retry/compaction/subtask/file
//	            系统事件行（Meta 保留后端原字段，App 一行摘要可展开）
package main

import "encoding/json"

const agJSONRPCVersion = "2.0"

// ---------- 信封 ----------

type agRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type agResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *agRPCError     `json:"error,omitempty"`
}

type agNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type agRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	agCodeParse      = -32700
	agCodeMethodNF   = -32601
	agCodeBadParams  = -32602
	agCodeBackend    = -32000
	agCodeUnsupported = -32001
)

// ---------- 方法与通知 ----------

const (
	agMInitialize      = "initialize"
	agMSessionList     = "session/list"
	agMSessionCreate   = "session/create"
	agMSessionRead     = "session/read"
	agMSessionDelete   = "session/delete"
	agMSessionRename   = "session/rename"
	agMPromptSend      = "prompt/send"
	agMTurnInterrupt   = "turn/interrupt"
	agMTurnSteer       = "turn/steer" // opencode 后端不支持，返回 agCodeUnsupported
	agMApprovalRespond = "approval/respond"
	agMModelList       = "model/list"
)

const (
	agNSessionUpdated    = "session.updated"
	agNSessionDeleted    = "session.deleted"
	agNMessageUpdated    = "message.updated"
	agNPartUpdated       = "part.updated"
	agNApprovalRequested = "approval.requested"
	agNApprovalResolved  = "approval.resolved"
	agNUsageUpdated      = "usage.updated"
	agNError             = "error"
)

// ---------- 域模型（字段允许部分填充，App 按 id 合并） ----------

type agCaps struct {
	Backend   string `json:"backend"`
	Steer     bool   `json:"steer"`
	Approvals bool   `json:"approvals"`
	Models    bool   `json:"models"`
	Usage     bool   `json:"usage"`
}

type agSession struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Directory   string `json:"directory,omitempty"`
	Status      string `json:"status,omitempty"` // idle|busy|retry
	TimeCreated int64  `json:"timeCreated,omitempty"`
	TimeUpdated int64  `json:"timeUpdated,omitempty"`
	Version     string `json:"version,omitempty"`
	/** 会话当前在用的模型（opencode session.model 透传）。 */
	ModelID      string `json:"modelId,omitempty"`
	ModelProvider string `json:"modelProvider,omitempty"`
}

type agMsgError struct {
	Name    string `json:"name"`
	Message string `json:"message,omitempty"`
}

type agTokens struct {
	Input     int64 `json:"input"`
	Output    int64 `json:"output"`
	Reasoning int64 `json:"reasoning"`
	CacheRead int64 `json:"cacheRead"`
}

type agPart struct {
	ID        string         `json:"id"`
	SessionID string         `json:"sessionId,omitempty"`
	MessageID string         `json:"messageId,omitempty"`
	Type      string         `json:"type"` // 见文件头映射表；"" = delta-only
	Text      string         `json:"text,omitempty"`
	Tool      *agToolInfo    `json:"tool,omitempty"`
	Patch     *agPatchInfo   `json:"patch,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
}

type agToolInfo struct {
	CallID string         `json:"callId,omitempty"`
	Name   string         `json:"name"`
	Status string         `json:"status"`
	Title  string         `json:"title,omitempty"`
	Input  map[string]any `json:"input,omitempty"`
	Raw    string         `json:"raw,omitempty"`
	Output string         `json:"output,omitempty"`
	Error  string         `json:"error,omitempty"`
}

type agPatchInfo struct {
	Hash  string       `json:"hash,omitempty"`
	Files []agFileDiff `json:"files"`
}

type agFileDiff struct {
	File      string `json:"file"`
	Before    string `json:"before,omitempty"`
	After     string `json:"after,omitempty"`
	Additions int    `json:"additions,omitempty"`
	Deletions int    `json:"deletions,omitempty"`
}

type agMessage struct {
	ID          string      `json:"id"`
	SessionID   string      `json:"sessionId"`
	Role        string      `json:"role"`
	CreatedAt   int64       `json:"createdAt,omitempty"`
	CompletedAt int64       `json:"completedAt,omitempty"`
	ModelID     string      `json:"modelId,omitempty"`
	ProviderID  string      `json:"providerId,omitempty"`
	Finish      string      `json:"finish,omitempty"`
	Error       *agMsgError `json:"error,omitempty"`
	Cost        *float64    `json:"cost,omitempty"`
	Tokens      *agTokens   `json:"tokens,omitempty"`
	Parts       []agPart    `json:"parts,omitempty"`
}

type agApproval struct {
	ID        string         `json:"id"`
	SessionID string         `json:"sessionId"`
	MessageID string         `json:"messageId,omitempty"`
	CallID    string         `json:"callId,omitempty"`
	Type      string         `json:"type,omitempty"`
	Title     string         `json:"title,omitempty"`
	Pattern   string         `json:"pattern,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Time      int64          `json:"time,omitempty"`
}

type agModel struct {
	ID           string `json:"id"` // "provider/model"
	ProviderID   string `json:"providerId"`
	ModelID      string `json:"modelId"`
	Name         string `json:"name"`
	Status       string `json:"status,omitempty"`
	ContextLimit int64  `json:"contextLimit,omitempty"` // limit.context
}
