// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go4.org/mem"
	"tailscale.com/types/key"
)

func hintKey() NodePublic {
	var a [32]byte
	a[1], a[2], a[31] = 1, 2, 31
	return NodePublic{key.NodePublicFromRaw32(mem.B(a[:]))}
}

func mustAddrPort(t *testing.T, s string) (ap netip.AddrPort) {
	t.Helper()
	if err := ap.UnmarshalText([]byte(s)); err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", s, err)
	}
	return ap
}

// TestAddrEndpointHintRoundTrip 锁住提示字段的编码往返：带/不带提示、
// 多候选（v4+v6）、档位与生成时间逐字段往返。
func TestAddrEndpointHintRoundTrip(t *testing.T) {
	in := ConnInfo{
		ServerPublic: hintKey(),
		RegionID:     304,
		EndpointHints: []EndpointHint{
			{AddrPort: mustAddrPort(t, "114.242.60.128:41641"), Tier: EndpointHintTrusted, Generated: 1758143000},
			{AddrPort: mustAddrPort(t, "[2606:4700::1]:443"), Tier: EndpointHintBestEffort, Generated: 1758143000},
			{AddrPort: mustAddrPort(t, "123.56.218.212:41641"), Tier: EndpointHintManual, Generated: 0},
		},
	}
	got, err := ParseAddr(in.Addr())
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	want := in
	want.RegionID = 304 // unchanged through the round trip
	if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.AddrPort{})); diff != "" {
		t.Errorf("round trip diff (-want +got):\n%s", diff)
	}
}

// TestAddrWithoutHintsUnchanged 锁住「不带提示的地址与现版本逐字段一致」：
// 同一 ConnInfo 不带提示时的编码是老黄金串（TestAddr 已覆盖精确编码），
// 这里再验证提示字段不会出现在无提示地址的 wire 形态里，且往返稳定。
func TestAddrWithoutHintsUnchanged(t *testing.T) {
	ci := ConnInfo{ServerPublic: hintKey(), RegionID: 304}
	addr := ci.Addr()
	raw, err := ParseAddrRaw(addr)
	if err != nil {
		t.Fatalf("ParseAddrRaw: %v", err)
	}
	j, err := json.Marshal(raw)
	if err != nil || strings.Contains(string(j), "EndpointHints") {
		t.Errorf("hint-less address carries hints? json=%s err=%v", j, err)
	}
	again, err := ParseAddr(addr)
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if again.EndpointHints != nil {
		t.Errorf("hint-less address parsed %d hints", len(again.EndpointHints))
	}
	if addr != again.Addr() {
		t.Errorf("re-encode not stable: %s != %s", addr, again.Addr())
	}
}

// TestParseAddrMalformedHints 恶意/畸形输入必须整条地址报错，与
// null region 的处理同风格，而不是静默探测垃圾端点。
func TestParseAddrMalformedHints(t *testing.T) {
	goodCI := ConnInfo{ServerPublic: hintKey(), RegionID: 304}
	good := goodCI.Addr()

	build := func(hints []*wireEndpointHint) Addr {
		w, err := parseWire(good)
		if err != nil {
			t.Fatal(err)
		}
		w.EndpointHints = hints
		x, err := cbor.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		return "tc" + Addr(base64.RawURLEncoding.EncodeToString(x))
	}

	for _, tt := range []struct {
		name  string
		hints []*wireEndpointHint
	}{
		{"null_entry", []*wireEndpointHint{nil}},
		{"bad_hostport", []*wireEndpointHint{{AddrPort: "not-an-endpoint", Tier: 1}}},
		{"missing_port", []*wireEndpointHint{{AddrPort: "1.2.3.4", Tier: 1}}},
		{"zero_tier", []*wireEndpointHint{{AddrPort: "1.2.3.4:443"}}},
		{"too_many", func() []*wireEndpointHint {
			hs := make([]*wireEndpointHint, MaxEndpointHints+1)
			for i := range hs {
				hs[i] = &wireEndpointHint{AddrPort: "1.2.3.4:443", Tier: 1}
			}
			return hs
		}()},
	} {
		if _, err := ParseAddr(build(tt.hints)); err == nil {
			t.Errorf("%s: ParseAddr succeeded, want error", tt.name)
		}
	}
}

// TestClientInitStoresFreshHints 锁住客户端消费链的前半段：initLocked 把地址里
// 未过期的候选存进 lb.serverHints（netmap 的 peer Endpoints 就取它；initLocked
// 不做网络访问，可直接调用）。后半段（Endpoints 进 netmap → magicsock 探测）
// 由真机矩阵验证（核日志对候选端点的探测）。
func TestClientInitStoresFreshHints(t *testing.T) {
	now := time.Now()
	in := ConnInfo{
		ServerPublic:      hintKey(),
		ServerDiscoPublic: DiscoPublic{key.NewDisco().Public()},
		RegionID:          304,
		EndpointHints: []EndpointHint{
			{AddrPort: mustAddrPort(t, "114.242.60.128:41641"), Tier: EndpointHintTrusted, Generated: now.Unix()},
			{AddrPort: mustAddrPort(t, "2.2.2.2:443"), Tier: EndpointHintBestEffort, Generated: now.Add(-2 * EndpointHintTTL).Unix()}, // 超时
		},
	}
	c := NewClient(in.Addr())
	c.Logf = func(string, ...any) {} // 静音 connect: 候选行
	if err := c.initLocked(); err != nil {
		t.Fatalf("initLocked: %v", err)
	}
	if len(c.lb.serverHints) != 1 || c.lb.serverHints[0].String() != "114.242.60.128:41641" {
		t.Errorf("serverHints = %v; want only the fresh 114.242.60.128:41641", c.lb.serverHints)
	}
}

// TestClientInitNoHintsServerHintsNil 无提示地址不产生候选。
func TestClientInitNoHintsServerHintsNil(t *testing.T) {
	in := ConnInfo{ServerPublic: hintKey(), ServerDiscoPublic: DiscoPublic{key.NewDisco().Public()}, RegionID: 304}
	c := NewClient(in.Addr())
	c.Logf = func(string, ...any) {}
	if err := c.initLocked(); err != nil {
		t.Fatalf("initLocked: %v", err)
	}
	if len(c.lb.serverHints) != 0 {
		t.Errorf("serverHints = %v; want none", c.lb.serverHints)
	}
}

// TestFreshEndpointHints 是客户端 TTL 过滤的纯函数单测（任务 3.3）。
func TestFreshEndpointHints(t *testing.T) {
	now := time.Unix(1758143000, 0)
	hints := []EndpointHint{
		{AddrPort: mustAddrPort(t, "1.1.1.1:443"), Tier: 1, Generated: now.Unix() - int64(time.Hour/time.Second)},       // fresh
		{AddrPort: mustAddrPort(t, "2.2.2.2:443"), Tier: 2, Generated: now.Unix() - int64(EndpointHintTTL/time.Second)}, // exactly TTL old: stale
		{AddrPort: mustAddrPort(t, "3.3.3.3:443"), Tier: 3, Generated: now.Unix() + int64(time.Hour/time.Second)},       // from the future: stale (clock skew guard)
		{AddrPort: mustAddrPort(t, "4.4.4.4:443"), Tier: 1, Generated: 0},                                               // unknown: fresh
	}
	fresh, skipped := FreshEndpointHints(hints, now)
	if len(fresh) != 2 || skipped != 2 {
		t.Fatalf("fresh=%d skipped=%d; want 2/2", len(fresh), skipped)
	}
	if fresh[0].AddrPort != mustAddrPort(t, "1.1.1.1:443") || fresh[1].AddrPort != mustAddrPort(t, "4.4.4.4:443") {
		t.Errorf("unexpected fresh set: %v", fresh)
	}
	if f, s := FreshEndpointHints(nil, now); f != nil || s != 0 {
		t.Errorf("nil hints: fresh=%v skipped=%d; want nil/0", f, s)
	}
}
