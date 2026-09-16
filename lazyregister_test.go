// lazyregister_test.go — 服务端懒注册（openspec direct-handshake-connect）
// 的单元测试：peerConfig 对未知 key 放行并记 (tcAddr→key) 索引、准入名单
// 语义、peerByIP 的索引兜底回程路由、索引过期清理。
package tailcat

import (
	"testing"
	"time"

	"net/netip"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func newLazyTestBackend() (*locoBackend, key.NodePublic, PresharedKey) {
	server := key.NewNode() // serverPub 零 = 我们是服务端
	psk := NewPresharedKey()
	b := &locoBackend{presharedKey: psk}
	return b, server.Public(), psk
}

func TestLazyPeerConfigAdmitsUnknownKey(t *testing.T) {
	b, _, psk := newLazyTestBackend()
	k := key.NewNode().Public()

	conf, ok := b.peerConfig(k)
	if !ok {
		t.Fatal("peerConfig rejected unknown key; want lazy admission")
	}
	if conf.PresharedKey != device.NoisePresharedKey(psk) {
		t.Fatalf("lazy peer PSK = %x, want global PSK %x", conf.PresharedKey, psk)
	}
	want := pfxOf(tcAddrForKey(k))
	if len(conf.AllowedIPs) != 1 || conf.AllowedIPs[0] != want {
		t.Fatalf("lazy peer AllowedIPs = %v, want [%v]", conf.AllowedIPs, want)
	}
	// 防刷表：懒放行绝不写 b.clients（其进入条件仍只有经 DERP 的 meow
	// 注册）。伪造 initiation 最多留下一条 TTL 内的索引死数据。
	if len(b.clients) != 0 {
		t.Fatalf("lazy admission wrote %d b.clients entries; want 0", len(b.clients))
	}
}

func TestLazyPeerConfigAllowedClients(t *testing.T) {
	b, _, _ := newLazyTestBackend()
	member := key.NewNode().Public()
	outsider := key.NewNode().Public()
	b.allowedClients = map[key.NodePublic]bool{member: true}

	if _, ok := b.peerConfig(outsider); ok {
		t.Fatal("peerConfig admitted key outside allowedClients")
	}
	if _, ok := b.peerConfig(member); !ok {
		t.Fatal("peerConfig rejected key in allowedClients")
	}
}

func TestLazyPeerConfigRegisteredKeyUnchanged(t *testing.T) {
	b, _, _ := newLazyTestBackend()
	k := key.NewNode().Public()
	b.clients = map[key.NodePublic]*tailcfg.Node{
		k: {Key: k, AllowedIPs: []netip.Prefix{pfxOf(tcAddrForKey(k))}},
	}

	conf, ok := b.peerConfig(k)
	if !ok {
		t.Fatal("peerConfig rejected registered key")
	}
	if got := conf.AllowedIPs; len(got) != 1 || got[0].Addr() != tcAddrForKey(k) {
		t.Fatalf("registered peer AllowedIPs = %v", got)
	}
	// 已注册路径不应往懒索引里塞东西。
	b.lazyMu.Lock()
	n := len(b.lazyPeers)
	b.lazyMu.Unlock()
	if n != 0 {
		t.Fatalf("registered-key lookup wrote %d lazy index entries; want 0", n)
	}
}

func TestLazyPeerByIPFallback(t *testing.T) {
	b, _, _ := newLazyTestBackend()
	k := key.NewNode().Public()
	addr := tcAddrForKey(k)

	// 未放行过：miss。
	if got, ok := b.peerByIP(addr); ok {
		t.Fatalf("peerByIP = %v for unknown addr; want miss", got)
	}
	// peerConfig 放行后：索引兜底命中。
	if _, ok := b.peerConfig(k); !ok {
		t.Fatal("lazy admission failed")
	}
	got, ok := b.peerByIP(addr)
	if !ok || got != k {
		t.Fatalf("peerByIP = %v, %v; want %v, true", got, ok, k)
	}
	// meow 注册落地后：主路径命中（clients 优先于索引）。
	b.clients = map[key.NodePublic]*tailcfg.Node{
		k: {Key: k, AllowedIPs: []netip.Prefix{pfxOf(tcAddrForKey(k))}},
	}
	got, ok = b.peerByIP(addr)
	if !ok || got != k {
		t.Fatalf("peerByIP with client registered = %v, %v; want %v, true", got, ok, k)
	}
}

func TestLazyPeerIndexTTL(t *testing.T) {
	b, _, _ := newLazyTestBackend()
	old := key.NewNode().Public()
	fresh := key.NewNode().Public()

	b.noteLazyPeer(old)
	// 手动把 old 的条目拨回 TTL 之外，再插入 fresh 触发清理。
	b.lazyMu.Lock()
	e := b.lazyPeers[tcAddrForKey(old)]
	e.at = time.Now().Add(-lazyPeerTTL - time.Minute)
	b.lazyPeers[tcAddrForKey(old)] = e
	b.lazyMu.Unlock()

	b.noteLazyPeer(fresh)

	if _, ok := b.lazyPeerByAddr(tcAddrForKey(old)); ok {
		t.Error("stale lazy index entry survived TTL eviction")
	}
	if _, ok := b.lazyPeerByAddr(tcAddrForKey(fresh)); !ok {
		t.Error("fresh lazy index entry missing after eviction sweep")
	}
}

func TestLazyPathsDoNotAffectClientMode(t *testing.T) {
	server := key.NewNode().Public()
	psk := NewPresharedKey()
	b := &locoBackend{serverPub: server, presharedKey: psk}
	other := key.NewNode().Public()

	if _, ok := b.peerConfig(other); ok {
		t.Error("client-mode peerConfig admitted a non-server key")
	}
	if got, ok := b.peerByIP(tcAddrForKey(other)); !ok || got != server {
		t.Errorf("client-mode peerByIP = %v, %v; want server key, true", got, ok)
	}
	if _, ok := b.peerConfig(server); !ok {
		t.Error("client-mode peerConfig rejected the server key")
	}
}
