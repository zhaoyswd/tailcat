// localaddr_test.go — 通告地址过滤的纯函数单测（判据见 localaddr.go）。
package tailcat

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

func mustIfaces(t *testing.T, spec map[string][]string) []ifaceAddrs {
	t.Helper()
	var out []ifaceAddrs
	for name, addrs := range spec {
		var as []net.Addr
		for _, s := range addrs {
			ip, ipn, err := net.ParseCIDR(s)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", s, err)
			}
			ipn.IP = ip
			as = append(as, ipn)
		}
		out = append(out, ifaceAddrs{name: name, flags: net.FlagUp, addrs: as})
	}
	return out
}

// 真机事故里的那批地址（Mac 出口 + 手机）：全部要被挡在通告之外，
// 物理网卡上的正常地址要保留。
func TestLocalAddrExclusionsRealWorld(t *testing.T) {
	ifaces := mustIfaces(t, map[string][]string{
		"lo0":       {"127.0.0.1/8"},
		"en0":       {"192.168.3.12/24"},
		"bridge100": {"192.168.139.3/23"},
		"bridge101": {"192.168.215.0/24"},
		"utun4":     {"198.18.0.1/15"},
		"ancowlan0": {"10.126.126.2/30", "172.17.1.1/16"},
		"wlan0":     {"192.168.3.56/24", "2408:8207:2518:2550:147a:7d2b:7c6a:d716/64"},
		"eth0":      {"10.9.9.0/24"}, // 物理网卡上的 .0（配置错误）也要挡
	})
	self := netip.MustParseAddr("10.126.126.2")
	got := localAddrExclusions(ifaces, []netip.Addr{self})

	for _, want := range []string{
		"127.0.0.1", "192.168.139.3", "192.168.215.0", "198.18.0.1", "10.126.126.2", "172.17.1.1", "10.9.9.0",
	} {
		if _, ok := got[netip.MustParseAddr(want)]; !ok {
			t.Errorf("%s 应被排除，实际保留了", want)
		}
	}
	for _, keep := range []string{"192.168.3.12", "192.168.3.56", "2408:8207:2518:2550:147a:7d2b:7c6a:d716"} {
		if _, ok := got[netip.MustParseAddr(keep)]; ok {
			t.Errorf("%s 不该被排除（原因 %q）", keep, got[netip.MustParseAddr(keep)])
		}
	}
	// 理由要能区分开，日志才有诊断价值。
	if why := got[netip.MustParseAddr("192.168.3.12")]; why != "" {
		t.Errorf("物理网卡地址不应有排除理由，得到 %q", why)
	}
	if !strings.Contains(got[netip.MustParseAddr("198.18.0.1")], "虚拟接口") {
		t.Errorf("198.18.0.1 的理由 = %q，期望虚拟接口", got[netip.MustParseAddr("198.18.0.1")])
	}
	if !strings.Contains(got[netip.MustParseAddr("10.9.9.0")], "网段地址") {
		t.Errorf("10.9.9.0 的理由 = %q，期望网段地址", got[netip.MustParseAddr("10.9.9.0")])
	}
	// 同一地址命中多条判据时取最具体的：bridge101 上的 .0 是「虚拟接口」，不是「网段地址」。
	if !strings.Contains(got[netip.MustParseAddr("192.168.215.0")], "虚拟接口") {
		t.Errorf("192.168.215.0 的理由 = %q，期望虚拟接口", got[netip.MustParseAddr("192.168.215.0")])
	}
	if !strings.Contains(got[self], "隧道地址") {
		t.Errorf("隧道地址理由 = %q", got[self])
	}
}

func TestIsNetworkBase(t *testing.T) {
	cases := []struct {
		addr string
		ones int
		want bool
	}{
		{"192.168.215.0", 24, true},
		{"192.168.3.0", 24, true},
		{"192.168.3.56", 24, false},
		{"10.0.0.1", 8, false},
		// /31、/32 是点对点/主机地址：没有「网络地址」的概念
		{"10.1.2.0", 31, false},
		{"10.1.2.3", 32, false},
		{"2408:8207:2518:25af::", 64, true},
		{"2408:8207:2518:2550:147a:7d2b:7c6a:d716", 64, false},
		{"fd00::1", 128, false},
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.addr)
		var mask net.IPMask
		if a.Is4() {
			mask = net.CIDRMask(c.ones, 32)
		} else {
			mask = net.CIDRMask(c.ones, 128)
		}
		if got := isNetworkBase(a, mask); got != c.want {
			t.Errorf("isNetworkBase(%s/%d) = %v, want %v", c.addr, c.ones, got, c.want)
		}
	}
}

func TestIsVirtualInterfaceNames(t *testing.T) {
	for _, name := range []string{
		"lo0", "utun4", "tun0", "vpn-tun", "ancowlan0", "bridge100", "vmenet0",
		"docker0", "veth1a2b", "hw_sate_vnet", "dummy0", "ifb0", "tunl0", "sit0", "awdl0",
	} {
		if !IsVirtualInterface(name) {
			t.Errorf("%s 应判为虚拟接口", name)
		}
	}
	for _, name := range []string{"en0", "wlan0", "wlan1", "eth0", "rmnet0"} {
		if IsVirtualInterface(name) {
			t.Errorf("%s 不该判为虚拟接口", name)
		}
	}
}

func TestSkippedAddrsSummaryStable(t *testing.T) {
	m := map[netip.Addr]string{
		netip.MustParseAddr("192.168.215.0"): "网段地址（网络地址）",
		netip.MustParseAddr("198.18.0.1"):    "虚拟接口 utun4",
	}
	first := skippedAddrsSummary(m)
	if first != skippedAddrsSummary(m) {
		t.Fatalf("同一集合的摘要必须稳定：%q", first)
	}
	if !strings.HasPrefix(first, "192.168.215.0（") {
		t.Fatalf("摘要应按地址排序，得到 %q", first)
	}
	if got := skippedAddrsSummary(nil); got != "" {
		t.Fatalf("空集合摘要应为空串，得到 %q", got)
	}
}

// UPnP 候选列表要与通告过滤同一份判据：虚拟接口（bridge/docker/utun）与回环、
// 链路本地、组播都不该进候选；输出排序去重，日志才有可读性。
func TestUpnpIPv4Candidates(t *testing.T) {
	got := upnpIPv4Candidates(map[string][]netip.Prefix{
		"lo0":       {netip.MustParsePrefix("127.0.0.1/8")},
		"en0":       {netip.MustParsePrefix("192.168.3.12/24")},
		"bridge100": {netip.MustParsePrefix("192.168.139.3/23")},
		"bridge101": {netip.MustParsePrefix("192.168.215.0/24")},
		"utun4":     {netip.MustParsePrefix("198.18.0.1/15")},
		"wlan0":     {netip.MustParsePrefix("192.168.3.12/24"), netip.MustParsePrefix("169.254.7.7/16")},
		"en7":       {netip.MustParsePrefix("::1/128")},
	})
	want := []string{"192.168.3.12"}
	if len(got) != len(want) {
		t.Fatalf("候选 = %v，期望 %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Fatalf("候选[%d] = %s，期望 %s", i, got[i], w)
		}
	}
	// 排序：给两个候选（map 顺序随机）验证确定性。
	multi := upnpIPv4Candidates(map[string][]netip.Prefix{
		"en0":  {netip.MustParsePrefix("192.168.3.12/24")},
		"en10": {netip.MustParsePrefix("10.0.0.9/24")},
	})
	if len(multi) != 2 || multi[0].String() != "10.0.0.9" || multi[1].String() != "192.168.3.12" {
		t.Fatalf("候选未按地址排序/去重：%v", multi)
	}
}
