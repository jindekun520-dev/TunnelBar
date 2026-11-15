#!/bin/bash
# tunnel-home 启动失败告警脚本
# 由 systemd OnFailure 触发。可在此扩展：发邮件/钉钉/企业微信 webhook。
ALERT_FILE=/var/run/tunnel-home.alert
TS=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TS] tunnel-home 服务进入 failed 状态，请检查家中网络与中继可达性" >> "$ALERT_FILE"
# 写系统日志，方便 journalctl -t tunnel-home 查看
logger -t tunnel-home-alert "tunnel-home 启动失败，请检查家中网络/中继 203.0.113.10:7000 是否可达"

# ===== 可选：企业微信/钉钉 webhook 推送 =====
# WEBHOOK="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY"
# curl -sS -X POST "$WEBHOOK" -H 'Content-Type: application/json' \
#   -d "{\"msgtype\":\"text\",\"text\":{\"content\":\"[隧道告警] tunnel-home 启动失败 @ $TS\"}}"
