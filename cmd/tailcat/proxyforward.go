// proxyforward.go — 出口侧「被转发的用户流量经上游代理」与「DNS 走 DoH」（本移植私有）。
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
//	        --dns-doh=https://223.5.5.5/dns-query serve --key=exit.key exit-node
//
// 环境变量：TAILCAT_FORWARD_PROXY / TAILCAT_DNS_DOH。
//
//   - TCP 转发：经代理拨出（socks5:// 走 SOCKS5 CONNECT，http:// 走 HTTP CONNECT）。
//   - UDP 转发：只有 DNS（:53）被接管，改由 --dns-doh 的端点解析（同样经代理）。理由是
//     家用代理对 UDP 的支持参差不齐（实测 Surge 6.9.0 的本地 SOCKS5 对 UDP ASSOCIATE
//     直接回 05 07），而 DoH 是 TCP，能稳定穿过代理，还顺带避开出口线路上的 DNS 污染；
//     其它 UDP（QUIC 等）仍按原样直连转发。
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
	"time"

	"golang.org/x/net/proxy"

	"github.com/tailscale/tailcat"
)

// forwardProxy 非空时，被转发的 TCP 连接经它拨出。
var forwardProxy *url.URL

// dnsDoH 非空时，隧道内的 UDP DNS 查询改由该 DoH 端点解析（经 forwardProxy）。
var dnsDoH string

// setupForwarding 解析 --forward-via-proxy / --dns-doh。两者都可省略。
func setupForwarding(proxyStr, dohStr string) error {
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
	if dohStr != "" {
		if _, err := url.Parse(dohStr); err != nil {
			return fmt.Errorf("--dns-doh %q: %v", dohStr, err)
		}
		dnsDoH = dohStr
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

// dohHTTPClient 返回走代理（若配置了）的 DoH 客户端。
func dohHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return forwardProxy, nil },
		},
	}
}

// dohQuery 把 DNS 线格式查询交给 DoH 端点，返回线格式应答。
func dohQuery(ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dnsDoH, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %v: %v", dnsDoH, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8192))
}

// serveDoHFlow 接管一条隧道内的 UDP DNS 流：每个查询走 DoH，应答按原查询 ID 回写；
// 出错时回 SERVFAIL，让对端立刻重试而不是等超时。
func serveDoHFlow(c tailcat.ConnPacketConn) {
	defer c.Close()
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := dohQuery(ctx, query)
			if err != nil || len(resp) < 12 {
				c.Write(servfailReply(query))
				return
			}
			c.Write(resp)
		}()
	}
}

// servfailReply 造一个 RCODE=SERVFAIL 的 DNS 应答（保留原查询的 ID、QUESTION 段），
// 让对端立刻重试而不是干等超时。query 太短（不是 DNS 查询）时返回 nil。
func servfailReply(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	// 找到 QUESTION 段的结尾：跳过 qname、qtype、qclass。
	i := 12
	for i < len(query) && query[i] != 0 {
		if query[i]&0xc0 == 0xc0 { // 压缩指针
			i += 2
			break
		}
		i += int(query[i]) + 1
	}
	i += 5
	if i > len(query) {
		return nil
	}
	out := make([]byte, i)
	copy(out, query[:i])
	out[2] = 0x80 // QR=1
	out[3] = 0x02 // RCODE=SERVFAIL
	out[6], out[7] = 0, 0
	out[8], out[9], out[10], out[11] = 0, 0, 0, 0
	return out
}
