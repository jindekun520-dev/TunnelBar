#!/bin/bash
# 编译并打包 TunnelBar.app（菜单栏管理工具）
#
# 产出：<项目>/TunnelBar.app，可直接双击运行
# 依赖：Xcode 命令行工具（swiftc），以及先跑过 scripts/build.sh 生成 bin/client 等
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TUNNEL="$(cd "$HERE/.." && pwd)"
OUT="${1:-$(cd "$TUNNEL/.." && pwd)/TunnelBar.app}"
APP="$OUT"
BUILD="$TUNNEL/app/.build"

echo "▸ 编译 Swift 源码 ..."
mkdir -p "$BUILD"
swiftc -O -swift-version 5 \
  -target "$(uname -m)-apple-macosx12.0" \
  -o "$BUILD/TunnelBar" \
  "$HERE/TunnelBar/main.swift"

echo "▸ 组装 app bundle ..."
# 图标：缺了就先跑生成脚本（需要 Pillow）
if [ ! -f "$HERE/app.icns" ]; then
  echo "▸ 生成 app.icns ..."
  python3 "$TUNNEL/make_app_icon.py"
fi
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BUILD/TunnelBar" "$APP/Contents/MacOS/TunnelBar"
cp "$HERE/Info.plist" "$APP/Contents/Info.plist"
# 版本号统一取 tunnel/VERSION，别让 Info.plist 里的 2.0.0 变成假版本
VER="$(cat "$TUNNEL/VERSION" 2>/dev/null || echo "0.0.0")"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VER" "$APP/Contents/Info.plist" >/dev/null 2>&1 || true
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VER" "$APP/Contents/Info.plist" >/dev/null 2>&1 || true
echo "▸ 版本：$VER"
cp "$HERE/app.icns" "$APP/Contents/Resources/app.icns"
cp "$HERE/testsrv.py" "$APP/Contents/Resources/testsrv.py"

# 隧道二进制：client（生产）与 relay/home（本机自测需要）
for f in client relay.local home.local; do
  if [ -f "$TUNNEL/bin/$f" ]; then
    cp "$TUNNEL/bin/$f" "$APP/Contents/Resources/$f"
  else
    echo "⚠️  缺少 $TUNNEL/bin/$f（先跑 scripts/build.sh）" >&2
  fi
done

chmod +x "$APP/Contents/MacOS/TunnelBar" "$APP/Contents/Resources/client" 2>/dev/null || true

echo "▸ ad-hoc 签名 ..."
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || echo "⚠️  签名失败，可忽略（ad-hoc 环境下不影响本机运行）"

echo "▸ 完成：$APP"
du -sh "$APP" | awk '{print "  体积：" $1}'
