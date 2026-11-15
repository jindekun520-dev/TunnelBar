#!/bin/bash
# 双击本文件：启动菜单栏工具 TunnelBar
# 启动后图标在屏幕右上角（盾牌），所有操作都在它的菜单里。
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$(cd "$DIR/.." && pwd)/TunnelBar.app"

if pgrep -f "TunnelBar.app/Contents/MacOS/TunnelBar" >/dev/null 2>&1; then
  osascript -e 'display notification "已在运行，点屏幕右上角的盾牌图标" with title "TunnelBar"' 2>/dev/null
  exit 0
fi

if [ ! -d "$APP" ]; then
  echo "找不到 $APP"
  echo "先在 tunnel/ 下执行：bash app/build-app.sh"
  exit 1
fi

open "$APP"
exit 0
