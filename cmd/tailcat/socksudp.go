//go:build !cshared

// socksudp.go — SOCKS5 的 UDP 客户端（UDP ASSOCIATE + 逐包封装），CLI/上游向。
//
// 为什么自己写：出口的 --forward-via-proxy 需要「被转发的 UDP 也走代理」，而
// golang.org/x/net/proxy 只做 CONNECT（没有 UDP ASSOCIATE），tailscale.com/net/socks5
// 是**服务端**实现（`tailcat socks` 用的就是它）⇒ UA 侧得自己写。
// 协议见 RFC 1928 §7（UDP 请求/应答报文）、§3/§5（方法协商、UDP ASSOCIATE 命令）。
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/logger"
)

const (
	socks5Version             = 0x05
	socks5CmdUDPAssociate     = 0x03
	socks5AtypIPv4            = 0x01
	socks5AtypDomain          = 0x03
	socks5AtypIPv6            = 0x04
	socks5RepSuccess          = 0x00
	socks5RepNotAllowed       = 0x02
	socks5RepCommandNotSupprt = 0x07

	socks5MethodNoAuth   = 0x00
	socks5MethodUserPass = 0x02
)

// maxSocks5UDPDatagram 是「SOCKS5 UDP 头 + 净荷」的整包上限。头最大 22 字节
// （v6 目标：RSV 2 + FRAG 1 + ATYP 1 + 16 + 2），净荷按隧道保证的
// tailcat.MaxUDPPayload（1232）算，再留一点余量给对端发来的超限包 —— 超过这个
// 大小的包一律丢弃（不转发半截数据）。
const maxSocks5UDPDatagram = tailcat.MaxUDPPayload + 64

// socks5UDPEncapsulationLen 返回封装的固定开销：v4 目标 10 字节、v6 目标 22 字节。
// 封装头加在 SOCKS5 的 UDP 报文上（即代理链路上），不占用隧道内的净荷预算，
// 但日志里要如实给出，免得误以为可以发满 MaxUDPPayload + 头。
func socks5UDPEncapsulationLen(dst netip.AddrPort) int {
	if dst.Addr().Unmap().Is4() {
		return 10
	}
	return 22
}

// appendSocks5UDPHeader 按 RFC 1928 §7 生成 UDP 请求头：
// RSV(2)=0 | FRAG(1)=0 | ATYP(1) | DST.ADDR | DST.PORT。
func appendSocks5UDPHeader(b []byte, dst netip.AddrPort) ([]byte, error) {
	addr := dst.Addr().Unmap()
	b = append(b, 0, 0, 0) // RSV, RSV, FRAG=0（不做分片）
	switch {
	case addr.Is4():
		a := addr.As4()
		b = append(b, socks5AtypIPv4)
		b = append(b, a[:]...)
	case addr.Is6():
		a := addr.As16()
		b = append(b, socks5AtypIPv6)
		b = append(b, a[:]...)
	default:
		return nil, fmt.Errorf("SOCKS5 UDP：不支持的目标地址 %v", dst.Addr())
	}
	return binary.BigEndian.AppendUint16(b, dst.Port()), nil
}

var errSocks5ShortPacket = errors.New("SOCKS5 UDP 报文太短")

// parseSocks5UDPHeader 解析中继回来的 UDP 报文头，返回头的字节数、源地址与 FRAG。
// 地址按 ATYP 解析（1/3/4 都可能出现 —— 实测中继回复不一定用 IPv4 形态）；
// FRAG≠0 表示分片，调用方应当丢弃（RFC 1928：不支持的 FRAG 必须丢）。
// 域名形态下 src 为零值、domain 非空。
func parseSocks5UDPHeader(b []byte) (hdrLen int, src netip.AddrPort, domain string, frag byte, err error) {
	if len(b) < 4 {
		return 0, netip.AddrPort{}, "", 0, errSocks5ShortPacket
	}
	if b[0] != 0 || b[1] != 0 {
		return 0, netip.AddrPort{}, "", 0, fmt.Errorf("SOCKS5 UDP：RSV 非零 (%d %d)", b[0], b[1])
	}
	frag = b[2]
	off := 4
	switch b[3] {
	case socks5AtypIPv4:
		if len(b) < off+4+2 {
			return 0, netip.AddrPort{}, "", frag, errSocks5ShortPacket
		}
		ip, ok := netip.AddrFromSlice(b[off : off+4])
		if !ok {
			return 0, netip.AddrPort{}, "", frag, errSocks5ShortPacket
		}
		return off + 6, netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[off+4:])), "", frag, nil
	case socks5AtypIPv6:
		if len(b) < off+16+2 {
			return 0, netip.AddrPort{}, "", frag, errSocks5ShortPacket
		}
		ip, ok := netip.AddrFromSlice(b[off : off+16])
		if !ok {
			return 0, netip.AddrPort{}, "", frag, errSocks5ShortPacket
		}
		return off + 18, netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[off+16:])), "", frag, nil
	case socks5AtypDomain:
		if len(b) < off+1 {
			return 0, netip.AddrPort{}, "", frag, errSocks5ShortPacket
		}
		n := int(b[off])
		if len(b) < off+1+n+2 {
			return 0, netip.AddrPort{}, "", frag, errSocks5ShortPacket
		}
		d := string(b[off+1 : off+1+n])
		port := binary.BigEndian.Uint16(b[off+1+n:])
		return off + 1 + n + 2, netip.AddrPortFrom(netip.IPv4Unspecified(), port), d, frag, nil
	default:
		return 0, netip.AddrPort{}, "", frag, fmt.Errorf("SOCKS5 UDP：未知 ATYP %d", b[3])
	}
}

// readSocks5Addr 读取一个 SOCKS5 地址（ATYP + ADDR + PORT），用于 UDP ASSOCIATE 的应答。
func readSocks5Addr(r io.Reader) (netip.AddrPort, string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return netip.AddrPort{}, "", err
	}
	switch atyp[0] {
	case socks5AtypIPv4:
		var b [6]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		ip, _ := netip.AddrFromSlice(b[:4])
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[4:])), "", nil
	case socks5AtypIPv6:
		var b [18]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		ip, _ := netip.AddrFromSlice(b[:16])
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[16:])), "", nil
	case socks5AtypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		buf := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return netip.AddrPort{}, "", err
		}
		return netip.AddrPortFrom(netip.IPv4Unspecified(), binary.BigEndian.Uint16(buf[len(buf)-2:])), string(buf[:len(buf)-2]), nil
	default:
		return netip.AddrPort{}, "", fmt.Errorf("SOCKS5：应答里未知 ATYP %d", atyp[0])
	}
}

// socks5Greet 做方法协商（RFC 1928 §3），需要时再做用户名/口令认证（RFC 1929）。
func socks5Greet(c net.Conn, p *url.URL) error {
	methods := []byte{socks5MethodNoAuth}
	if p.User != nil {
		methods = append(methods, socks5MethodUserPass)
	}
	req := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("SOCKS5：版本 %d 不是 5", resp[0])
	}
	switch resp[1] {
	case socks5MethodNoAuth:
		return nil
	case socks5MethodUserPass:
		if p.User == nil {
			return errors.New("SOCKS5：代理要求用户名/口令，但代理地址里没有")
		}
		pw, _ := p.User.Password()
		user := p.User.Username()
		if len(user) > 255 || len(pw) > 255 {
			return errors.New("SOCKS5：用户名或口令过长")
		}
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pw)))
		auth = append(auth, pw...)
		if _, err := c.Write(auth); err != nil {
			return err
		}
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil {
			return err
		}
		if ar[1] != 0 {
			return errors.New("SOCKS5：用户名/口令认证失败")
		}
		return nil
	default:
		return fmt.Errorf("SOCKS5：代理不接受任何可用认证方式（method=%d）", resp[1])
	}
}

// socks5UDPAssociateOnce 发一次 UDP ASSOCIATE（RFC 1928 §5），返回 REP 与中继地址。
// rep != 0 时 err 为 nil（由调用方决定怎么解释这个 REP）。
func socks5UDPAssociateOnce(c net.Conn, bind netip.AddrPort) (rep byte, relay netip.AddrPort, err error) {
	req := []byte{socks5Version, socks5CmdUDPAssociate, 0x00}
	if bind.IsValid() {
		if req, err = appendSocks5UDPHeader(req, bind); err != nil {
			return 0, netip.AddrPort{}, err
		}
	} else {
		req = append(req, socks5AtypIPv4, 0, 0, 0, 0, 0, 0)
	}
	if _, err := c.Write(req); err != nil {
		return 0, netip.AddrPort{}, err
	}
	var hdr [3]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if hdr[0] != socks5Version {
		return 0, netip.AddrPort{}, fmt.Errorf("SOCKS5：UDP ASSOCIATE 应答版本 %d 不是 5", hdr[0])
	}
	ap, _, err := readSocks5Addr(c)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return hdr[1], ap, nil
}

// socks5UDPAssociate 与 p 建一条 UDP 关联（方法协商 → UDP ASSOCIATE），返回控制连接与
// 中继地址。hint 用于「少数实现要求 ASSOCIATE 报文里填真实目标」时的第二次尝试。
//
// 收尾约定：err != nil 时 ctrl 已关闭并返回 nil；err == nil 时 ctrl 一定非 nil，
// **由调用方负责关闭** —— rep != 0（代理拒绝）时也如此，这样调用方能先看一眼 REP 再收工。
func socks5UDPAssociate(ctx context.Context, p *url.URL, hint netip.AddrPort) (ctrl net.Conn, relay netip.AddrPort, rep byte, err error) {
	var d net.Dialer
	ctrl, err = d.DialContext(ctx, "tcp", p.Host)
	if err != nil {
		return nil, netip.AddrPort{}, 0, fmt.Errorf("连代理 %v 失败: %w", p.Host, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		ctrl.SetDeadline(dl)
	}
	if err := socks5Greet(ctrl, p); err != nil {
		ctrl.Close()
		return nil, netip.AddrPort{}, 0, fmt.Errorf("与代理 %v 协商失败: %w", p.Host, err)
	}
	// 先按 RFC 的语义报 0.0.0.0:0（"我会用哪个源地址还不确定"）；少数实现要求填真实
	// 目标地址才肯给关联，所以 REP != 0 时再用真实目标重试一次。
	for _, bind := range []netip.AddrPort{{}, hint} {
		rep, relay, err = socks5UDPAssociateOnce(ctrl, bind)
		if err != nil {
			ctrl.Close()
			return nil, netip.AddrPort{}, 0, fmt.Errorf("UDP ASSOCIATE 失败: %w", err)
		}
		if rep == socks5RepSuccess || rep == socks5RepCommandNotSupprt || rep == socks5RepNotAllowed {
			break // 成功，或被确定性拒绝（重试没有意义）
		}
	}
	if rep != socks5RepSuccess {
		return ctrl, netip.AddrPort{}, rep, nil // ctrl 交给调用方关
	}
	if relay.Addr().IsUnspecified() {
		// 0.0.0.0 / :: 表示「用控制连接的那个地址」，用控制连接的远端 IP 补上。
		tcpAddr, ok := ctrl.RemoteAddr().(*net.TCPAddr)
		if !ok || relay.Port() == 0 {
			ctrl.Close()
			return nil, netip.AddrPort{}, 0, fmt.Errorf("代理 %v 给的中继地址不可用：%v", p.Host, relay)
		}
		ip, ok := netip.AddrFromSlice(tcpAddr.IP)
		if !ok {
			ctrl.Close()
			return nil, netip.AddrPort{}, 0, fmt.Errorf("代理 %v 的控制连接地址不可解析：%v", p.Host, tcpAddr)
		}
		relay = netip.AddrPortFrom(ip.Unmap(), relay.Port())
	}
	return ctrl, relay, rep, nil
}

// dialRelayUDP 连到关联的中继地址（连上后只收发该地址的包，读写更简单）。
func dialRelayUDP(ctx context.Context, relay netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", relay.String())
	if err != nil {
		return nil, fmt.Errorf("连代理中继 %v 失败: %w", relay, err)
	}
	return c, nil
}

// dialSOCKS5UDP 与 p 建一条 UDP 关联，并把它接到 dst 上。
// 返回的连接实现了 tailcat.ConnPacketConn（net.Conn + net.PacketConn）。
func dialSOCKS5UDP(ctx context.Context, p *url.URL, dst netip.AddrPort) (*socksUDPConn, error) {
	ctrl, relay, rep, err := socks5UDPAssociate(ctx, p, dst)
	if err != nil {
		return nil, err
	}
	if rep != socks5RepSuccess {
		return nil, fmt.Errorf("代理 %v 拒绝 UDP ASSOCIATE：%s", p.Host, socks5RepString(rep))
	}
	relayConn, err := dialRelayUDP(ctx, relay)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	ctrl.SetDeadline(time.Time{}) // 控制连接要长期持有，清掉握手用的 deadline
	return newSocksUDPConn(ctrl, relayConn, dst), nil
}

func newSocksUDPConn(ctrl, relay net.Conn, dst netip.AddrPort) *socksUDPConn {
	return &socksUDPConn{
		ctrl:    ctrl,
		relay:   relay,
		dst:     dst,
		logf:    forwardLogf(),
		readBuf: make([]byte, maxSocks5UDPDatagram),
	}
}

func socks5RepString(rep byte) string {
	switch rep {
	case socks5RepSuccess:
		return "成功"
	case 0x01:
		return "一般性失败"
	case socks5RepNotAllowed:
		return "规则不允许（0x02）"
	case 0x03:
		return "网络不可达"
	case 0x04:
		return "主机不可达"
	case 0x05:
		return "连接被拒绝"
	case 0x06:
		return "TTL 过期"
	case socks5RepCommandNotSupprt:
		return "不支持该命令（0x07，即代理不支持 UDP）"
	case 0x08:
		return "地址类型不支持"
	default:
		return fmt.Sprintf("未知 REP=0x%02x", rep)
	}
}

// socksUDPConn 是一条经 SOCKS5 中继的 UDP 流（每个目的地址一条关联）。
//
// 读写语义按包：Write 一包一写（加 SOCKS5 UDP 头），Read 一次返回一包（去头）；
// 分片包（FRAG≠0）、协议错包、超过缓冲的包一律**丢弃并计数**，绝不转发半截数据。
type socksUDPConn struct {
	ctrl  net.Conn // TCP 控制连接：关掉它等于撤销这条关联
	relay net.Conn // 连到代理中继地址的 UDP socket
	dst   netip.AddrPort
	logf  logger.Logf

	readBuf []byte

	closeOnce sync.Once

	mu             sync.Mutex
	fragDropped    int
	badDropped     int
	oversizeDropped int
}

func (c *socksUDPConn) Write(p []byte) (int, error) { return c.writeTo(c.dst, p) }

// writeTo 按 dst 封装一包发出（Write 用流的固定目标；探测会临时换目标，故单独一个方法）。
func (c *socksUDPConn) writeTo(dst netip.AddrPort, p []byte) (int, error) {
	buf, err := appendSocks5UDPHeader(make([]byte, 0, len(p)+socks5UDPEncapsulationLen(dst)), dst)
	if err != nil {
		return 0, err
	}
	buf = append(buf, p...)
	if _, err := c.relay.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socksUDPConn) Read(p []byte) (int, error) {
	for {
		n, err := c.relay.Read(c.readBuf)
		if err != nil {
			return 0, err
		}
		if n == len(c.readBuf) {
			// 缓冲被填满 ⇒ 报文可能被 UDP 层截断，丢了它（不转发半截数据）。
			c.countDrop(&c.oversizeDropped, "超过 %d 字节的包", len(c.readBuf))
			continue
		}
		hdrLen, _, _, frag, err := parseSocks5UDPHeader(c.readBuf[:n])
		if err != nil {
			c.countDrop(&c.badDropped, "解析失败（%v）", err)
			continue
		}
		if frag != 0 {
			c.countDrop(&c.fragDropped, "FRAG=%d 的分片包", frag)
			continue
		}
		payload := c.readBuf[hdrLen:n]
		if len(payload) > len(p) {
			c.countDrop(&c.oversizeDropped, "比调用方缓冲（%d 字节）还大", len(p))
			continue
		}
		return copy(p, payload), nil
	}
}

// countDrop 只报第一次和每 64 次，避免坏包刷屏（值不值得查是另一回事，日志里能看见）。
func (c *socksUDPConn) countDrop(n *int, format string, args ...any) {
	c.mu.Lock()
	*n = *n + 1
	v := *n
	c.mu.Unlock()
	if v == 1 || v%64 == 0 {
		c.logf("udp/socks5 -> %v: 丢弃包（%s，第 %d 个）", c.dst, fmt.Sprintf(format, args...), v)
	}
}

func (c *socksUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(c.dst), nil
}

func (c *socksUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func (c *socksUDPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.relay.Close()
		if cerr := c.ctrl.Close(); cerr != nil && err == nil {
			err = cerr
		}
	})
	return err
}

func (c *socksUDPConn) LocalAddr() net.Addr  { return c.relay.LocalAddr() }
func (c *socksUDPConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.dst) }

func (c *socksUDPConn) SetDeadline(t time.Time) error {
	if err := c.relay.SetDeadline(t); err != nil {
		return err
	}
	return c.ctrl.SetDeadline(t)
}

func (c *socksUDPConn) SetReadDeadline(t time.Time) error  { return c.relay.SetReadDeadline(t) }
func (c *socksUDPConn) SetWriteDeadline(t time.Time) error { return c.relay.SetWriteDeadline(t) }
