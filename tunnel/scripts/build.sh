#!/bin/bash
# 一键编译三端。默认产出 Linux 版 relay/home + macOS 版 client。
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(cat VERSION 2>/dev/null || echo "2.0.0")
LDFLAGS="-s -w -X main.buildVersion=${VERSION}"
mkdir -p bin

# 依赖已全部 vendor 到 third_party/（gvisor netstack、btree、rate），
# 只有 golang.org/x/sys 走模块缓存，因此默认离线编译，避免无谓的网络等待。
export GOFLAGS="${GOFLAGS:--mod=mod}"
if [ -z "${GOPROXY:-}" ]; then
  export GOPROXY=off
fi

echo "▸ go test（协议层 + 转发层）"
go test ./internal/ -count=1 -timeout 120s

echo "▸ relay   → linux/amd64"
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o bin/relay.linux-amd64 ./cmd/relay/

echo "▸ home    → linux/amd64"
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o bin/home.linux-amd64 ./cmd/home/

echo "▸ client  → darwin/$(go env GOARCH)"
GOOS=darwin GOARCH=$(go env GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o bin/client ./cmd/client/

# 本机联调用（同一台机器模拟三端）
echo "▸ 本机测试版 relay/home → darwin/$(go env GOARCH)"
GOOS=darwin GOARCH=$(go env GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o bin/relay.local ./cmd/relay/
GOOS=darwin GOARCH=$(go env GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o bin/home.local ./cmd/home/

# 重新打包菜单栏 App，保证 App 内嵌的二进制与 bin/ 版本一致
if [ -x app/build-app.sh ]; then
  echo "▸ 打包菜单栏 App"
  bash app/build-app.sh >/dev/null
  echo "▸ 已更新 TunnelBar.app"
fi

echo
echo "产物："
du -h bin/* 2>/dev/null | awk '{printf "  %-32s %s\n", $2, $1}'
echo "完成。协议版本 v2 —— 三端必须同时升级。"
