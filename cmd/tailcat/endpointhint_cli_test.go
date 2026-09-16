//go:build !cshared

package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/opt"
)

func ap4(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	p, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mkReport(gv4 netip.AddrPort, varies opt.Bool) *netcheck.Report {
	r := &netcheck.Report{UDP: true, IPv4: gv4.IsValid(), MappingVariesByDestIP: varies}
	if gv4.IsValid() {
		r.GlobalV4 = gv4
		r.GlobalV4Counters = map[netip.AddrPort]int{gv4: 3}
	}
	return r
}

func oneHint(t *testing.T, hints []tailcat.EndpointHint) tailcat.EndpointHint {
	t.Helper()
	if len(hints) != 1 {
		t.Fatalf("want exactly 1 hint, got %d: %v", len(hints), hints)
	}
	return hints[0]
}

// 任务 2.2 要求的四类「剔除/降档」输入 + 三个可信来源 + 手动项 + v6。

func TestEndpointClassifyTrustedViaUPnP(t *testing.T) {
	// 健康的 UPnP 场景：STUN 端口 == 监听端口（路由器的静态映射管住全部出入），
	// 候选端口取映射端口。
	obs := tailcat.EndpointHintObservation{
		Report:     mkReport(ap4(t, "114.242.60.128:41641"), opt.NewBool(false)),
		MappedPort: 41641,
		ListenPort: 41641,
	}
	hints, basis := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	h := oneHint(t, hints)
	if h.Tier != tailcat.EndpointHintTrusted || h.AddrPort.String() != "114.242.60.128:41641" {
		t.Errorf("UPnP: got %+v", h)
	}
	if !strings.Contains(basis, "UPnP映射") || !strings.Contains(basis, "①可信") {
		t.Errorf("basis missing evidence: %s", basis)
	}
}

func TestEndpointClassifyUPnPButRewrittenExcluded(t *testing.T) {
	// 冒烟实测教训（2026-09-14，本机 Surge 对未放行端口）：STUN 报「代理出口 IP +
	// 临时端口」时，即使 UPnP 映射成功，「UPnP 端口 + STUN IP」也会拼出不可达的
	// 假候选 —— 坑 29 的端口自洽剔除必须优先于①档证据。
	obs := tailcat.EndpointHintObservation{
		Report:     mkReport(ap4(t, "203.175.12.168:37843"), opt.NewBool(false)), // 代理 IP
		MappedPort: 45141,
		ListenPort: 45141,
	}
	hints, basis := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	if len(hints) != 0 {
		t.Errorf("rewritten+UPnP: want no hints, got %v", hints)
	}
	if !strings.Contains(basis, "源端口被改写") || !strings.Contains(basis, "不带端点提示") {
		t.Errorf("basis: %s", basis)
	}
}

func TestEndpointClassifyTrustedLocalPublic(t *testing.T) {
	gv4 := ap4(t, "123.56.218.212:41641") // 公网 IP 直接在网卡上（云主机）
	obs := tailcat.EndpointHintObservation{Report: mkReport(gv4, opt.NewBool(false)), ListenPort: 41641}
	hints, _ := endpointClassify(obs, []netip.Addr{netip.MustParseAddr("123.56.218.212")}, nil, nil, time.Unix(1, 0))
	h := oneHint(t, hints)
	if h.Tier != tailcat.EndpointHintTrusted || h.AddrPort != gv4 {
		t.Errorf("local-public: got %+v", h)
	}
}

func TestEndpointClassifyTrustedAdvertisePort(t *testing.T) {
	obs := tailcat.EndpointHintObservation{
		Report:        mkReport(ap4(t, "114.242.60.128:41641"), opt.NewBool(false)),
		ListenPort:    41641,
		AdvertisePort: 41642, // 静态转发：路由器把外部 41642 转到本机 41641
	}
	hints, _ := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	h := oneHint(t, hints)
	if h.Tier != tailcat.EndpointHintTrusted || h.AddrPort.String() != "114.242.60.128:41642" {
		t.Errorf("advertise-port: got %+v", h)
	}
}

func TestEndpointClassifyBestEffortConeNAT(t *testing.T) {
	// 锥形 NAT、只有 STUN 临时映射（没 UPnP、没显式端口、网卡上也没公网 IP）。
	gv4 := ap4(t, "114.242.60.128:54321")
	obs := tailcat.EndpointHintObservation{Report: mkReport(gv4, opt.NewBool(false)), ListenPort: 41641}
	// ListenPort 与 STUN 端口不一致？锥形 NAT 下本机监听 41641、STUN 看到 54321
	// 是 NAT 改写——注意：这其实是「端口不自洽」场景。锥形 NAT 的映射端口本来就
	// 可以不等于监听端口（NAT 任意分配外部端口），所以只有「对同一目标的多次
	// 观测一致」才有意义。这里给 ListenPort=0（未钉端口）代表典型随机端口场景。
	obs.ListenPort = 0
	hints, basis := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	h := oneHint(t, hints)
	if h.Tier != tailcat.EndpointHintBestEffort || h.AddrPort != gv4 {
		t.Errorf("cone NAT: got %+v", h)
	}
	if !strings.Contains(basis, "②尽力") {
		t.Errorf("basis: %s", basis)
	}
}

func TestEndpointClassifySymmetricNATExcluded(t *testing.T) {
	obs := tailcat.EndpointHintObservation{
		Report:     mkReport(ap4(t, "114.242.60.128:54321"), opt.NewBool(true)),
		MappedPort: 41641, // 即使拿到了映射，映射随目标变化也不可信
		ListenPort: 41641,
	}
	hints, basis := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	if len(hints) != 0 {
		t.Errorf("symmetric NAT: want no hints, got %v", hints)
	}
	if !strings.Contains(basis, "对称NAT") || !strings.Contains(basis, "不带端点提示") {
		t.Errorf("basis: %s", basis)
	}
}

func TestEndpointClassifyPortRewrittenExcluded(t *testing.T) {
	// 坑 29：TUN 型代理改写源端口——钉了 41641，STUN 却看到 55557。
	obs := tailcat.EndpointHintObservation{
		Report:     mkReport(ap4(t, "114.242.60.128:55557"), opt.NewBool(false)),
		ListenPort: 41641,
	}
	hints, basis := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	if len(hints) != 0 {
		t.Errorf("port rewritten: want no hints, got %v", hints)
	}
	if !strings.Contains(basis, "源端口被改写") {
		t.Errorf("basis: %s", basis)
	}
}

func TestEndpointClassifyNoMappingNoSTUN(t *testing.T) {
	// 无映射（无 UPnP、锥形 NAT）与无 STUN 结果两种输入：前者②、后者无候选。
	obs := tailcat.EndpointHintObservation{Report: mkReport(ap4(t, "1.2.3.4:41641"), opt.NewBool(false))}
	hints, _ := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	if len(hints) != 1 || hints[0].Tier != tailcat.EndpointHintBestEffort {
		t.Errorf("no mapping: got %v", hints)
	}

	obs.Report = &netcheck.Report{UDP: false} // 无 STUN 结果
	hints, basis := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	if len(hints) != 0 || !strings.Contains(basis, "v4=无STUN映射") {
		t.Errorf("no STUN: hints=%v basis=%s", hints, basis)
	}

	obs.Report = nil
	hints, basis = endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
	if len(hints) != 0 || !strings.Contains(basis, "无netcheck") {
		t.Errorf("nil report: hints=%v basis=%s", hints, basis)
	}
}

func TestEndpointClassifyIPv6AndManual(t *testing.T) {
	gv6 := netip.MustParseAddrPort("[2606:4700::1]:41641")
	r := mkReport(ap4(t, "114.242.60.128:41641"), opt.NewBool(false))
	r.IPv6 = true
	r.GlobalV6 = gv6
	obs := tailcat.EndpointHintObservation{Report: r, ListenPort: 41641}
	manual := []netip.AddrPort{ap4(t, "203.0.113.4:41641")}
	hints, basis := endpointClassify(obs, nil, nil, manual, time.Unix(1, 0))
	if len(hints) != 3 {
		t.Fatalf("want v4+v6+manual = 3 hints, got %d: %v", len(hints), hints)
	}
	if hints[0].Tier != tailcat.EndpointHintBestEffort || hints[0].AddrPort.String() != "114.242.60.128:41641" {
		t.Errorf("v4 hint（无 UPnP/显式端口/本机公网 ⇒ ② 尽力）: %+v", hints[0])
	}
	if hints[1].Tier != tailcat.EndpointHintBestEffort || hints[1].AddrPort != gv6 {
		t.Errorf("v6 hint: %+v", hints[1])
	}
	if hints[2].Tier != tailcat.EndpointHintManual || hints[2].AddrPort != manual[0] {
		t.Errorf("manual hint: %+v", hints[2])
	}
	if !strings.Contains(basis, "手动=") || !strings.Contains(basis, "③手动") {
		t.Errorf("basis: %s", basis)
	}
}

func TestEndpointClassifyPrivateOrCGNATExcluded(t *testing.T) {
	// STUN 返回私网/CGNAT 段：异常输入，不作为候选（避免把内网地址发给对端）。
	for _, s := range []string{"192.168.3.5:41641", "100.64.1.2:41641", "127.0.0.1:41641"} {
		obs := tailcat.EndpointHintObservation{Report: mkReport(ap4(t, s), opt.NewBool(false))}
		hints, _ := endpointClassify(obs, nil, nil, nil, time.Unix(1, 0))
		if len(hints) != 0 {
			t.Errorf("%s: want no hints, got %v", s, hints)
		}
	}
	if !tsaddr.CGNATRange().Contains(netip.MustParseAddr("100.64.1.2")) {
		t.Errorf("tsaddr CGNAT range sanity")
	}
}

// TestPublishEndpointHintsDisabledAnnouncesPlain 锁住单次打印契约的禁用分支：
// --endpoint-hint=false 时必须**立即** announce 原版地址（一次、不带提示）。
func TestPublishEndpointHintsDisabledAnnouncesPlain(t *testing.T) {
	flagEndpointHint = new(bool) // false
	ci := &tailcat.ConnInfo{RegionID: 304}
	plain := ci.Addr()
	got := make(chan tailcat.Addr, 2)
	publishEndpointHints(nil, ci, plain, func(string, ...any) {}, func(a tailcat.Addr) { got <- a })
	select {
	case a := <-got:
		if a != plain {
			t.Errorf("announced %v; want plain %v", a, plain)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disabled path did not announce")
	}
	select {
	case a := <-got:
		t.Errorf("announced twice: %v", a)
	case <-time.After(300 * time.Millisecond):
	}
}

// ————— ④LAN 档（openspec direct-handshake-connect） —————

func TestLANAddrsFromIfaces(t *testing.T) {
	mk := func(name string, flags net.Flags, ips ...string) lanIfAddrs {
		var addrs []net.Addr
		for _, ip := range ips {
			addrs = append(addrs, &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(24, 32)})
		}
		return lanIfAddrs{name: name, flags: flags, addrs: addrs}
	}
	ifaces := []lanIfAddrs{
		mk("en0", net.FlagUp, "192.168.3.12"),     // 物理 + RFC1918 → 收
		mk("docker0", net.FlagUp, "172.17.0.1"),   // 容器桥 → 排除
		mk("vethabc123", net.FlagUp, "10.88.0.1"), // veth → 排除
		mk("lo0", net.FlagUp|net.FlagLoopback, "127.0.0.1"),
		mk("en5", net.FlagUp, "100.64.5.5"),   // CGNAT → 排除（不是家庭 LAN）
		mk("en6", net.FlagUp, "203.0.113.9"),  // 公网 v4 → 不属 LAN 档
		mk("en7", 0, "192.168.4.4"),           // down → 排除
		mk("utun3", net.FlagUp, "192.168.9.9"), // VPN 虚拟 → 排除
	}
	got := lanAddrsFromIfaces(ifaces)
	if len(got) != 1 || got[0] != netip.MustParseAddr("192.168.3.12") {
		t.Fatalf("lanAddrsFromIfaces = %v; want [192.168.3.12]", got)
	}
}

func TestEndpointClassifyLANHint(t *testing.T) {
	obs := tailcat.EndpointHintObservation{
		ListenPort: 41641,
		Report:     nil, // LAN 是本机接口事实，不依赖 netcheck
	}
	lan := []netip.Addr{netip.MustParseAddr("192.168.3.12")}
	hints, basis := endpointClassify(obs, nil, lan, nil, time.Unix(1, 0))
	if len(hints) != 1 {
		t.Fatalf("want 1 LAN hint, got %d: %v", len(hints), hints)
	}
	want := netip.MustParseAddrPort("192.168.3.12:41641")
	if hints[0].AddrPort != want || hints[0].Tier != tailcat.EndpointHintLAN {
		t.Fatalf("LAN hint = %+v; want %v tier④", hints[0], want)
	}
	if !strings.Contains(basis, "④LAN") {
		t.Errorf("basis missing ④LAN: %s", basis)
	}
}

func TestEndpointClassifyLANWithoutListenPort(t *testing.T) {
	obs := tailcat.EndpointHintObservation{Report: mkReport(ap4(t, "114.242.60.128:41641"), opt.NewBool(false))}
	lan := []netip.Addr{netip.MustParseAddr("192.168.3.12")}
	hints, basis := endpointClassify(obs, nil, lan, nil, time.Unix(1, 0))
	for _, h := range hints {
		if h.Tier == tailcat.EndpointHintLAN {
			t.Fatalf("ListenPort=0 仍写了④LAN: %+v", h)
		}
	}
	if !strings.Contains(basis, "监听端口未钉死") {
		t.Errorf("basis missing skip note: %s", basis)
	}
}

func TestEndpointClassifyCapsAtMax(t *testing.T) {
	// 1(v4) + 1(v6) + 7(LAN) + 3(manual) = 12 > MaxEndpointHints(8) ⇒ 截 4。
	r := mkReport(ap4(t, "114.242.60.128:41641"), opt.NewBool(false))
	r.IPv6 = true
	r.GlobalV6 = netip.MustParseAddrPort("[2606:4700::1]:41641")
	obs := tailcat.EndpointHintObservation{Report: r, ListenPort: 41641}
	var lan []netip.Addr
	for i := 2; i <= 8; i++ { // 192.168.0.2 .. 192.168.0.8 = 7 条
		lan = append(lan, netip.MustParseAddr(fmt.Sprintf("192.168.0.%d", i)))
	}
	var manual []netip.AddrPort
	for i := 1; i <= 3; i++ {
		manual = append(manual, ap4(t, fmt.Sprintf("203.0.113.%d:41641", i)))
	}
	hints, basis := endpointClassify(obs, nil, lan, manual, time.Unix(1, 0))
	if len(hints) != tailcat.MaxEndpointHints {
		t.Fatalf("want cap %d hints, got %d", tailcat.MaxEndpointHints, len(hints))
	}
	// 截的是尾部（manual 优先出局）。
	for _, h := range hints {
		if h.Tier == tailcat.EndpointHintManual {
			t.Errorf("manual hint survived cap: %+v", h)
		}
	}
	if !strings.Contains(basis, "候选超上限") {
		t.Errorf("basis missing cap note: %s", basis)
	}
}
