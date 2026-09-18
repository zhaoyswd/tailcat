// buildcaps_test.go — 出口地址里「构建号」字段的压缩规则（诊断用，见 buildcaps.go）。
package main

import (
	"strings"
	"testing"
)

func TestTruncateBuildTag(t *testing.T) {
	// 发行版 tag（≤ 上限）原样保留：地址里读到的就是 Releases 页上的版本。
	for _, tag := range []string{"v0.6.0-udp.20", "v0.6.0-udp.18", "dev", "unknown"} {
		if got := truncateBuildTag(tag); got != tag {
			t.Errorf("truncateBuildTag(%q) = %q，期望原样保留", tag, got)
		}
	}

	// 伪版本号（go build 无 tag 时）掐头留尾，而不是整个换成 dev —— 换成 dev
	// 会丢掉「出口跑的是哪个构建」这条诊断信息。
	pseudo := "v0.6.1-0.20260917023950-067ae990d51f+dirty"
	got := truncateBuildTag(pseudo)
	if len(got) != buildTagMaxLen {
		t.Fatalf("压缩后长度 = %d（%q），期望 %d", len(got), got, buildTagMaxLen)
	}
	if !strings.HasPrefix(got, pseudo[:buildTagHead]) || got[buildTagHead] != '~' {
		t.Fatalf("压缩后 = %q，期望「头 %d 字节 + ~ …」", got, buildTagHead)
	}
	if !strings.HasSuffix(got, pseudo[len(pseudo)-buildTagTail:]) {
		t.Fatalf("压缩后 = %q，期望以原串末尾 %d 字节结尾（留住提交哈希/dirty 标记）",
			got, buildTagTail)
	}
	if strings.Contains(got, "dev") {
		t.Fatalf("压缩后 = %q，不该退化成 dev", got)
	}
}
