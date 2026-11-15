#!/bin/bash
# tunnel-home 看门狗：检查状态文件 last_seen 是否过旧
# 由 systemd timer 每分钟执行一次。若 home 端超过 3 分钟未更新 last_seen，
# 说明到中继的连接已断（即使进程在跑，NAT/防火墙可能已静默丢弃），记录告警。
STATUS_FILE=/var/run/tunnel-home.status
ALERT_FILE=/var/run/tunnel-home.alert
TIMEOUT=180  # 秒，超过该时间未更新视为掉线

now=$(date +%s)
if [ ! -f "$STATUS_FILE" ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] 状态文件缺失，home 可能未启动" >> "$ALERT_FILE"
  exit 0
fi

last_seen=$(grep -o '"last_seen_unix"[[:space:]]*:[[:space:]]*[0-9]*' "$STATUS_FILE" | grep -o '[0-9]*$')
connected=$(grep -o '"connected"[[:space:]]*:[[:space:]]*\(true\|false\)' "$STATUS_FILE" | grep -o '\(true\|false\)$')

if [ "$connected" != "true" ]; then
  # 未连接，connectLoop 会持续重试；仅在超过 TIMEOUT 仍连不上时告警一次
  if [ -n "$last_seen" ] && [ "$last_seen" -gt 0 ]; then
    # 曾经连上过，现在断了，记录一次
    ago=$(( now - last_seen ))
    if [ "$ago" -gt "$TIMEOUT" ]; then
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] home 到中继连接已断开 ${ago}s，connectLoop 重试中" >> "$ALERT_FILE"
      logger -t tunnel-home-watchdog "home 到中继连接已断开 ${ago}s"
    fi
  fi
fi
