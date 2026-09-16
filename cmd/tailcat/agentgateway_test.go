//go:build !cshared

// agentgateway_test.go — 内嵌 agent-gateway 的测试：
//   1) 手写 WS：握手（接受/拒绝）、帧往返（含掩码/大帧/ping-pong/close）；
//   2) hub：JSON-RPC 路由（initialize/session 列表/能力位拒绝/未知方法）；
//   3) 集成：Go 版 mock opencode（SSE 可编程）→ 翻译 → 客户端收到统一通知
//      （覆盖 1.18 真实协议：permission.asked / message.part.delta / global 包裹）。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- WS 基元 ----------

func TestAgWSHandshakeRoundTrip(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()

	errCh := make(chan error, 1)
	var ws *agWSConn
	go func() {
		var err error
		ws, err = agWSAccept(srv, bufio.NewReader(srv))
		errCh <- err
	}()
	cbr, err := agWSClientHandshake(cli, "/ws")
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server accept: %v", err)
	}

	// net.Pipe 零缓冲：Write 需要并发 Read 消费，对端操作必须放 goroutine
	cws := &agWSConn{c: cli, br: cbr}

	// 客户端 → 服务端：掩码 text 帧
	gotCh := make(chan []byte, 1)
	errCh2 := make(chan error, 1)
	go func() {
		m, err := ws.ReadMessage()
		if err != nil {
			errCh2 <- err
			return
		}
		gotCh <- m
	}()
	if err := agWSWriteFrameMasked(cli, agWSText, []byte(`{"hello":"世界"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-gotCh:
		if string(got) != `{"hello":"世界"}` {
			t.Fatalf("payload = %s", got)
		}
	case err := <-errCh2:
		t.Fatalf("server read: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server read 超时")
	}

	// 服务端 → 客户端：未掩码 text 帧
	go func() {
		_ = ws.WriteMessage([]byte("pong-回复"))
	}()
	got2, err := cws.ReadMessage()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got2) != "pong-回复" {
		t.Fatalf("payload = %s", got2)
	}
}

func TestAgWSBigPayloadAndFragmentation(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	errCh := make(chan error, 1)
	var ws *agWSConn
	go func() {
		var err error
		ws, err = agWSAccept(srv, bufio.NewReader(srv))
		errCh <- err
	}()
	cbr, err := agWSClientHandshake(cli, "/ws")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	// 200KB 大帧（64 位长度路径），双向各一次；对端放 goroutine（零缓冲管道）
	big := []byte(strings.Repeat("x", 200_000))
	gotCh := make(chan int, 1)
	errCh2 := make(chan error, 1)
	go func() {
		m, err := ws.ReadMessage()
		if err != nil {
			errCh2 <- err
			return
		}
		gotCh <- len(m)
	}()
	if err := agWSWriteFrameMasked(cli, agWSText, big); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-gotCh:
		if n != 200_000 {
			t.Fatalf("server got len = %d", n)
		}
	case err := <-errCh2:
		t.Fatalf("server read big: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server read 超时")
	}

	cws := &agWSConn{c: cli, br: cbr}
	go func() {
		_ = ws.WriteMessage(big)
	}()
	got, err := cws.ReadMessage()
	if err != nil {
		t.Fatalf("client read big: %v", err)
	}
	if len(got) != 200_000 {
		t.Fatalf("len = %d", len(got))
	}
}

func TestAgWSRejectsPlainHTTP(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		_, _ = agWSAccept(srv, bufio.NewReader(srv))
	}()
	cli.Write([]byte("GET /ws HTTP/1.1\r\nHost: x\r\n\r\n"))
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(cli)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Fatalf("应回 400, got %q", line)
	}
}

// ---------- mock opencode（Go 版，可编程 SSE） ----------

type agMockOC struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	sseRes  []http.ResponseWriter
	sseFlus []http.Flusher
	sessions map[string]map[string]any
}

func newAgMockOC(t *testing.T) *agMockOC {
	m := &agMockOC{t: t, sessions: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/global/event", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		m.mu.Lock()
		m.sseRes = append(m.sseRes, w)
		m.sseFlus = append(m.sseFlus, fl)
		m.mu.Unlock()
		w.Write([]byte("data: {\"payload\":{\"type\":\"server.connected\",\"properties\":{}}}\n\n"))
		fl.Flush()
		<-r.Context().Done()
	})
	mux.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			id := "ses_mock_1"
			m.sessions[id] = map[string]any{"id": id, "title": "t", "directory": "/tmp/x", "time": map[string]any{"created": 1, "updated": 1}}
			json.NewEncoder(w).Encode(m.sessions[id])
			return
		}
		out := []any{}
		for _, s := range m.sessions {
			out = append(out, s)
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/session/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{})
	})
	mux.HandleFunc("/config/providers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"providers": []map[string]any{{
				"id": "mockp", "name": "Mock",
				"models": map[string]map[string]string{"m1": {"id": "m1", "name": "M1"}},
			}},
			"default": map[string]string{"mockp": "m1"},
		})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// push 向全部 SSE 客户端推一个事件（global 包裹形态）。
func (m *agMockOC) push(evType string, props any) {
	p, _ := json.Marshal(props)
	frame := "data: " + string(p) + "\n\n"
	wrapped := "data: {\"payload\":{\"type\":\"" + evType + "\",\"properties\":" + string(p) + "}}\n\n"
	_ = frame
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, fl := range m.sseFlus {
		_, _ = m.sseRes[i].Write([]byte(wrapped))
		fl.Flush()
	}
}

// ---------- 集成：hub + 翻译 + 广播 ----------

type agTestClient struct {
	conn net.Conn
	ws   *agWSConn
}

func agDialHub(t *testing.T, hub *agHub) *agTestClient {
	srvEnd, cliEnd := net.Pipe()
	go hub.serveConn(srvEnd)
	cbr, err := agWSClientHandshake(cliEnd, "/ws")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return &agTestClient{conn: cliEnd, ws: &agWSConn{c: cliEnd, br: cbr}}
}

func (c *agTestClient) call(t *testing.T, id int, method string, params any) map[string]any {
	pb, _ := json.Marshal(params)
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = json.RawMessage(pb)
	}
	rb, _ := json.Marshal(req)
	if err := agWSWriteFrameMasked(c.conn, agWSText, rb); err != nil {
		t.Fatalf("send: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := c.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var resp map[string]any
		if json.Unmarshal(msg, &resp) != nil {
			continue
		}
		if resp["method"] != nil {
			continue // 通知，跳过等响应
		}
		if n, ok := resp["id"].(float64); ok && int(n) == id {
			return resp
		}
	}
	t.Fatalf("请求超时: %s", method)
	return nil
}

func (c *agTestClient) waitNotice(t *testing.T, method string, timeout time.Duration) map[string]any {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msg, err := c.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var n map[string]any
		if json.Unmarshal(msg, &n) != nil || n["method"] == nil {
			continue
		}
		if n["method"] == method {
			return n
		}
	}
	t.Fatalf("等通知超时: %s", method)
	return nil
}

func TestAgentGatewayEndToEnd(t *testing.T) {
	mock := newAgMockOC(t)
	oc := newAGOC(func(format string, args ...any) {})
	oc.url = mock.srv.URL
	oc.hc = mock.srv.Client()
	hub := &agHub{
		backends: map[string]agBackend{"opencode": oc},
		clients:  map[*agClientConn]struct{}{},
	}
	// cleanup 顺序（LIFO）：先 cancel（断 SSE）再让 newAgMockOC 里注册的 srv.Close 运行，
	// 否则 SSE handler 卡在 <-ctx.Done()、srv.Close 永远等不完（实测死锁在 cleanup）。
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go oc.Start(ctx)
	go hub.runEvents()
	time.Sleep(200 * time.Millisecond) // 等 SSE 连上

	c := agDialHub(t, hub)
	defer c.conn.Close()

	// 1) initialize 能力位
	resp := c.call(t, 1, "initialize", nil)
	caps := resp["result"].(map[string]any)["capabilities"].(map[string]any)
	if caps["backend"] != "opencode" || caps["steer"] != false || caps["approvals"] != true {
		t.Fatalf("caps = %v", caps)
	}

	// 2) steer（opencode 能力位 false）→ unsupported；缺 text 参数 → badParams
	resp = c.call(t, 2, "turn/steer", map[string]any{"sessionId": "x", "text": "改主意"})
	if code := resp["error"].(map[string]any)["code"].(float64); int(code) != agCodeUnsupported {
		t.Fatalf("steer code = %v", code)
	}
	resp = c.call(t, 6, "turn/steer", map[string]any{"sessionId": "x"})
	if code := resp["error"].(map[string]any)["code"].(float64); int(code) != agCodeBadParams {
		t.Fatalf("steer 缺参 code = %v", code)
	}

	// 3) 未知方法
	resp = c.call(t, 3, "no/such", nil)
	if code := resp["error"].(map[string]any)["code"].(float64); int(code) != agCodeMethodNF {
		t.Fatalf("unknown code = %v", code)
	}

	// 4) model/list（providers 对象套对象解析）
	resp = c.call(t, 4, "model/list", nil)
	models := resp["result"].(map[string]any)["models"].([]any)
	if len(models) != 1 || models[0].(map[string]any)["id"] != "mockp/m1" {
		t.Fatalf("models = %v", models)
	}

	// 5) session/create → mock
	resp = c.call(t, 5, "session/create", map[string]any{"title": ""})
	sid := resp["result"].(map[string]any)["session"].(map[string]any)["id"].(string)
	if sid != "ses_mock_1" {
		t.Fatalf("sid = %v", sid)
	}

	// 6) SSE 翻译链：mock 推 1.18 真实形态事件 → 客户端收统一通知
	mock.push("session.status", map[string]any{"sessionID": sid, "status": map[string]string{"type": "busy"}})
	n := c.waitNotice(t, agNSessionUpdated, 3*time.Second)
	if n["params"].(map[string]any)["session"].(map[string]any)["status"] != "busy" {
		t.Fatalf("status not busy: %v", n)
	}

	mock.push("message.part.delta", map[string]any{
		"sessionID": sid, "messageID": "m1", "partID": "p1", "field": "text", "delta": "你"})
	n = c.waitNotice(t, agNPartUpdated, 3*time.Second)
	p := n["params"].(map[string]any)
	if p["delta"] != "你" || p["part"].(map[string]any)["id"] != "p1" || p["part"].(map[string]any)["type"] != "" {
		t.Fatalf("delta 通知形状不对: %v", n)
	}

	mock.push("permission.asked", map[string]any{
		"id": "per_1", "sessionID": sid, "permission": "bash",
		"patterns": []string{"echo x"}, "metadata": map[string]string{"command": "echo x"},
		"tool": map[string]string{"messageID": "m1", "callID": "c1"}})
	n = c.waitNotice(t, agNApprovalRequested, 3*time.Second)
	ap := n["params"].(map[string]any)["approval"].(map[string]any)
	if ap["type"] != "bash" || ap["title"] != "echo x" || ap["callId"] != "c1" {
		t.Fatalf("approval = %v", ap)
	}

	// 7) 双客户端广播
	c2 := agDialHub(t, hub)
	defer c2.conn.Close()
	_ = c2.call(t, 1, "initialize", nil)
	mock.push("session.idle", map[string]any{"sessionID": sid})
	n2 := c2.waitNotice(t, agNSessionUpdated, 3*time.Second)
	if n2["params"].(map[string]any)["session"].(map[string]any)["status"] != "idle" {
		t.Fatalf("c2 idle: %v", n2)
	}
}

// ---------- 按需拉起的禁用路径 ----------

func TestEnsureBackendSpawnDisabled(t *testing.T) {
	t.Setenv("TAILCAT_OPENCODE_SPAWN", "off")
	oc := newAGOC(func(format string, args ...any) {})
	oc.url = "http://127.0.0.1:1" // 不可达
	err := oc.ensureBackend(context.Background())
	if err == nil || !strings.Contains(err.Error(), "禁用自动拉起") {
		t.Fatalf("err = %v", err)
	}
}
