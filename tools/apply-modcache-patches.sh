#!/usr/bin/env bash
# 给 Go module cache 里那份 tailscale.com 打「零 DERP 直连引导」补丁（route A：
# 补丁在仓库、被改的源码在 module cache 里）。
#
# 为什么出口也要这份补丁：零 DERP 首连需要**服务端**接受并回应「netmap 里没有的 key」
# 的 WireGuard 握手（tailcat 没有控制面，出口就是靠这次握手认识客户端的），
# 相关改动在 magicsock 里（见 patch 头部与 tier 仓库 tools/tailcat/PATCHES.md §2.10）。
# ⚠️ 漏打补丁照样编译成功，只是能力静默消失 —— 所以 CI 必须显式跑这一步 + 校验。
#
# 幂等；版本取自本仓库 go.mod 的 pin；打不上直接失败（绝不半打）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH_DIR="$ROOT/tools/modcache-patches"

WANT="$(sed -n 's/^[[:space:]]*tailscale\.com \(v[^[:space:]]*\).*/\1/p' "$ROOT/go.mod" | head -1)"
if [ -z "$WANT" ]; then
  echo "error: 无法从 $ROOT/go.mod 解析 tailscale.com 版本" >&2
  exit 1
fi

MODCACHE="$(go env GOMODCACHE)"
MOD="$MODCACHE/tailscale.com@$WANT"
if [ ! -d "$MOD" ]; then
  echo "error: module cache 里没有 tailscale.com@$WANT（$MOD）" >&2
  echo "  先跑 go mod download（CI 里由 setup-go + 构建自动完成）" >&2
  exit 1
fi

apply() {
  local name="$1" file="$2" marker="$3" patch="$4"
  if grep -q -- "$marker" "$file" 2>/dev/null; then
    echo "[skip] ${name}: 已应用"
    return 0
  fi
  chmod -R u+w "$MOD" 2>/dev/null || true
  if ( cd "$MOD" && patch -p1 --forward --silent < "$patch" ); then
    echo "[ok]   ${name}: 已打补丁"
  else
    echo "error: ${name} 打补丁失败（上游版本变了？先 patch --dry-run 验锚点）" >&2
    exit 1
  fi
}

# marker 取「最新一版补丁才有」的标识：老 marker（PATCH(tier): bootstrap candidates）在第一版
# 补丁里就有，拿它判「已应用」会让「cache 里是旧一版补丁」被静默跳过 —— 旧补丁照样编得过、
# CI 也照样绿，少掉的只是同 LAN 优先 / 发送失败降权 / 日志节流 / DERP 回退摘除那批修复。
# tierNoHairpinAddr 是 2026-09-18 那批修复新增的。
MARKER="tierNoHairpinAddr"

if grep -q -- "PATCH(tier)" "$MOD/wgengine/magicsock/endpoint.go" \
   && ! grep -q -- "$MARKER" "$MOD/wgengine/magicsock/endpoint.go"; then
  echo "error: ${MOD} 里是**旧一版**补丁（有 PATCH(tier) 但没有 ${MARKER}）" >&2
  echo "  修法：删掉该模块目录（${MOD}）后重新 go mod download，再跑本脚本" >&2
  exit 1
fi

apply "magicsock 直连引导" \
  "$MOD/wgengine/magicsock/endpoint.go" \
  "$MARKER" \
  "$PATCH_DIR/0001-magicsock-direct-bootstrap.patch"

check() {
  local file="$1" marker="$2"
  if ! grep -q -- "$marker" "$file"; then
    echo "error: 校验失败，补丁不完整（缺 ${marker}）：${file}" >&2
    exit 1
  fi
}
check "$MOD/wgengine/magicsock/endpoint.go" "$MARKER"
check "$MOD/wgengine/magicsock/magicsock.go" "PATCH(tier)"
check "$MOD/wgengine/magicsock/derp.go" "PATCH(tier #8)"
check "$MOD/wgengine/magicsock/peermap.go" "rekeyEndpointLocked"
check "$MOD/wgengine/magicsock/magicsock_test.go" "TestTierRoamingLearn"
echo "[ok] tailscale.com@$WANT 补丁就绪（客户端 SetBootstrapCandidates / 出口 SetAcceptProvisionalInitiators + 候选策略/日志/DERP 回退修复）"
