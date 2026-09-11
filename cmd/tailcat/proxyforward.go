// proxyforward.go — 出口侧「被转发的用户流量经上游代理」（本移植私有）。
//
// 为什么需要它：出口节点必须让**自己的打洞 socket** 直连（一旦经过 TUN 型代理，包会被代理
// 用自己的 socket 重发 ⇒ 对端拿到的 NAT 映射不属于 tailcat ⇒ 打洞失败，见
// docs/EXIT-NODE-SETUP.md §2.1）；但被转发的用户流量通常仍希望经代理出网（境内直连、
// 境外走代理）。TUN 型代理下这两件事无法同时满足，于是这里让转发流量**显式**走代理，
// 而出口自身的 socket 保持直连。
//
// 用法：
//
//	tailcat --forward-via-proxy=socks5://127.0.0.1:6153 \
//
// 环境变量：TAILCAT_FORWARD_PROXY。
//
//   - TCP 转发：经代理拨出（socks5:// 走 SOCKS5 CONNECT，http:// 走 HTTP CONNECT）。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"
)

// forwardProxy 非空时，被转发的 TCP 连接经它拨出。
var forwardProxy *url.URL

// setupForwarding 解析 --forward-via-proxy（可省略）。
func setupForwarding(proxyStr string) error {
	if proxyStr != "" {
		u, err := url.Parse(proxyStr)
		if err != nil {
			return fmt.Errorf("--forward-via-proxy %q: %v", proxyStr, err)
		}
		switch u.Scheme {
		case "socks5", "socks5h", "http":
		default:
			return fmt.Errorf("--forward-via-proxy %q: 仅支持 socks5:// 与 http://", proxyStr)
		}
		if u.Host == "" {
			return fmt.Errorf("--forward-via-proxy %q: 缺少主机:端口", proxyStr)
		}
		forwardProxy = u
	}
	return nil
}

// dialForward 按需要经代理拨 TCP；未配置代理时等价于 net.Dial。
func dialForward(ctx context.Context, addr string) (net.Conn, error) {
	if forwardProxy == nil {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	switch forwardProxy.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u := forwardProxy.User; u != nil {
			pw, _ := u.Password()
			auth = &proxy.Auth{User: u.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", forwardProxy.Host, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return d.Dial("tcp", addr)
	case "http":
		return dialViaHTTPConnect(ctx, forwardProxy, addr)
	}
	return nil, fmt.Errorf("forward proxy %q: 不支持的协议", forwardProxy.Scheme)
}

// dialViaHTTPConnect 用 HTTP CONNECT 穿过 http 代理拨一条裸 TCP。
// （标准库的 http.Transport 只服务 HTTP 语义；裸 TCP 得自己发 CONNECT。）
func dialViaHTTPConnect(ctx context.Context, p *url.URL, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", p.Host)
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if u := p.User; u != nil {
		pw, _ := u.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + pw))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		c.Close()
		return nil, fmt.Errorf("CONNECT %v: %v (%s)", addr, resp.Status, bytes.TrimSpace(body))
	}
	return &bufferedConn{Conn: c, r: br}, nil
}

// bufferedConn 把 CONNECT 应答后可能残留在 bufio 里的字节包回连接。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// 出错时回 SERVFAIL，让对端立刻重试而不是等超时。

// 让对端立刻重试而不是干等超时。query 太短（不是 DNS 查询）时返回 nil。
