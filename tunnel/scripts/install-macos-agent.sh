#!/bin/bash
# 在本机安装 launchd 开机自启（macOS）。
#
# v1 的 plist 有两处硬伤导致 launchctl bootstrap 直接报 I/O error：
#   1) <key>KeepAlive</string> —— 闭合标签写成了 </string>，XML 本身就是坏的；
#   2) 二进制放在 ~/Desktop 下，launchd 拉起时容易撞上 TCC 目录保护。
# 本脚本把二进制装到 ~/Library/Application Support/ 下，并生成合法 plist。
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$HOME/Library/Application Support/Tunnel"
BIN="$APP_DIR/client"
PLIST="$HOME/Library/LaunchAgents/com.jindekun.tunnel.client.plist"
LABEL="com.jindekun.tunnel.client"
LOG_DIR="$HOME/Library/Logs/tunnel"

RELAY="${TUNNEL_RELAY:-relay.example.com:7100}"
SOCKS="${TUNNEL_SOCKS:-1080}"
FORWARD="${TUNNEL_FORWARD-}"
DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

if [ -z "${TUNNEL_KEY:-}" ]; then
  cat >&2 <<'EOF'
✗ 没有设置预共享密钥。用法：

    TUNNEL_KEY='与 relay/home 一致的那把密钥' \
    TUNNEL_RELAY='你的中继地址:7100' \
    ./scripts/install-macos-agent.sh

  TUNNEL_FORWARD 可选（形如 18443:10.0.0.10:443），不填则不装固定转发。
EOF
  exit 1
fi

echo "▸ 安装目录 $APP_DIR"
mkdir -p "$APP_DIR" "$LOG_DIR" "$(dirname "$PLIST")"

if [ -x "$SRC/bin/client" ]; then
  cp "$SRC/bin/client" "$BIN"
else
  echo "✗ 找不到 $SRC/bin/client，请先运行 scripts/build.sh" >&2
  exit 1
fi
chmod +x "$BIN"

# 构造 ProgramArguments
ARGS_XML="        <string>$BIN</string>
        <string>-relay</string>
        <string>$RELAY</string>
        <string>-socks</string>
        <string>$SOCKS</string>
        <string>-key</string>
        <string>$TUNNEL_KEY</string>"
if [ -n "$FORWARD" ]; then
  ARGS_XML="$ARGS_XML
        <string>-forward</string>
        <string>$FORWARD</string>"
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
$ARGS_XML
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/client.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/client.err.log</string>
</dict>
</plist>
EOF

chmod 600 "$PLIST"
echo "▸ 写入 $PLIST"

# XML 必须是合法 plist，否则 bootstrap 会直接失败
if ! plutil -lint "$PLIST" >/dev/null 2>&1; then
  echo "✗ plist 语法校验失败" >&2
  plutil -lint "$PLIST"
  exit 1
fi
echo "▸ plist 语法校验通过"

if [ "$DRY_RUN" = "1" ]; then
  echo "（--dry-run，不加载 launchd）"
  exit 0
fi

UID_NUM=$(id -u)
DOMAIN="gui/$UID_NUM"

bootout() {
  launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  # 兼容老写法
  launchctl unload "$PLIST" 2>/dev/null || true
}

bootout
sleep 0.3

BOOT_OK=0
if launchctl bootstrap "$DOMAIN" "$PLIST" 2>/dev/null; then
  BOOT_OK=1
  echo "▸ launchd 已加载：$LABEL"
else
  echo "⚠️  launchctl bootstrap 返回 I/O error，改用 legacy load" >&2
  if launchctl load -w "$PLIST" 2>/dev/null; then
    BOOT_OK=1
    echo "▸ legacy load 成功"
  fi
fi

if [ "$BOOT_OK" = "0" ]; then
  cat >&2 <<'TIP'

✗ 自动加载失败（launchctl 返回 Input/output error）。
  这通常不是 plist 的问题（本脚本已用 plutil 校验通过），
  而是当前终端进程缺少向 launchd 用户域注册的权限。

  请在「终端.app」里手动执行一次：

     launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.jindekun.tunnel.client.plist"

  仍然失败的话，用系统设置的官方入口：
     系统设置 → 通用 → 登录项与扩展 → 打开「登录时打开」下的「+」
     选择  ~/Library/Application Support/Tunnel/client
  或直接把 TunnelClient.app 加进登录项（菜单栏版）。

TIP
  exit 1
fi

launchctl enable "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl kickstart -k "$DOMAIN/$LABEL" 2>/dev/null || true

sleep 1.5
echo
if launchctl print "$DOMAIN/$LABEL" 2>/dev/null | grep -q "state = running"; then
  echo "✅ 客户端已由 launchd 拉起（开机自启生效）"
else
  echo "⚠️  已加载但当前未处于 running 状态，查看日志："
  echo "   tail -f $LOG_DIR/client.err.log"
fi
echo
echo "常用命令："
echo "  状态  launchctl print $DOMAIN/$LABEL | head -20"
echo "  日志  tail -f $LOG_DIR/client.log"
echo "  停止  launchctl bootout $DOMAIN/$LABEL"
echo "  卸载  rm '$PLIST' '$BIN'"
