// lazy_peer_cap_test.go — 懒注册索引的上限回归：插入只需本机公钥（持 token 者即可
// 构造 initiation），TTL 窗口内若不封顶可被无界撑大（对照 magicsock 侧
// provisionalEndpointMax=32 有界）。判据：灌 33+ 个伪 key 后 len 恒 ≤ lazyPeerMax，
// 且被逐出的是最旧条目、活跃条目不受影响。
package tailcat

import (
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestLazyPeerCap(t *testing.T) {
	b := &locoBackend{}
	// 预置一个「最旧但仍在 TTL 内」的条目：它应当是第一个被逐出的。
	oldest := key.NewNode()
	oldestAddr := tcAddrForKey(oldest.Public())
	b.noteLazyPeer(oldest.Public())
	b.lazyMu.Lock()
	e := b.lazyPeers[oldestAddr]
	e.at = time.Now().Add(-time.Hour) // 1h 前，仍在 24h TTL 内
	b.lazyPeers[oldestAddr] = e
	b.lazyMu.Unlock()

	for range lazyPeerMax + 4 {
		b.noteLazyPeer(key.NewNode().Public())
	}

	b.lazyMu.Lock()
	defer b.lazyMu.Unlock()
	if len(b.lazyPeers) != lazyPeerMax {
		t.Fatalf("lazyPeers len = %d, want %d", len(b.lazyPeers), lazyPeerMax)
	}
	if _, ok := b.lazyPeers[oldestAddr]; ok {
		t.Fatal("oldest entry survived; cap eviction must drop it first")
	}
}
