#!/bin/bash
# 隧道 v2 端到端测试：本机起 relay + home + client，走 SOCKS5 代理验证。
# 用法：./scripts/e2e-test.sh [工作目录]   （不传则用临时目录，自建二进制与测试服务）
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN=${1:-$(mktemp -d "${TMPDIR:-/tmp}/tunnel-e2e.XXXXXX")}
KEY="test-psk-2026"
RH=17000   # relay home 端口
RC=17100   # relay client 端口
SP=11080   # 本地 SOCKS
SRC=18080  # 「内网」服务端口
ST=17911   # relay 状态端点

mkdir -p "$BIN/conc"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null; done
  pkill -f "$BIN/srv.py" 2>/dev/null
}
trap cleanup EXIT

pass=0; fail=0
ok()   { echo "  ✅ $1"; pass=$((pass+1)); }
bad()  { echo "  ❌ $1"; fail=$((fail+1)); }

wait_port() { # host port timeout_s
  local h=$1 p=$2 t=${3:-10} i=0
  while [ $i -lt $((t*20)) ]; do
    if nc -z "$h" "$p" 2>/dev/null; then return 0; fi
    sleep 0.05; i=$((i+1))
  done
  return 1
}

# 三端二进制：工作目录里没有就现场编译，保证测的是当前源码
if [ ! -x "$BIN/relay" ] || [ ! -x "$BIN/home" ] || [ ! -x "$BIN/client" ]; then
  echo "── 编译测试二进制 ──"
  ( cd "$ROOT" && go build -o "$BIN/relay" ./cmd/relay/ \
      && go build -o "$BIN/home" ./cmd/home/ \
      && go build -o "$BIN/client" ./cmd/client/ ) || { echo "  ❌ 编译失败"; exit 1; }
fi

# 测试用「内网」服务
if [ ! -f "$BIN/srv.py" ]; then
  cat > "$BIN/srv.py" <<'PYEOF'
import hashlib
import http.server
import socketserver

BIG = hashlib.sha256(b"seed").digest() * (20 * 1024 * 1024 // 32)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = BIG if self.path.startswith("/big") else b"hello-through-tunnel"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


with S(("127.0.0.1", 18080), H) as s:
    s.serve_forever()
PYEOF
fi

echo "── 启动测试服务 ──"
pkill -f "tt/srv.py" 2>/dev/null
python3 "$BIN/srv.py" >"$BIN/srv.log" 2>&1 & PIDS+=($!)
wait_port 127.0.0.1 $SRC 10 && echo "  内网服务 :$SRC 就绪" || { echo "  ❌ 内网服务启动失败"; exit 1; }

echo "── 启动 relay / home / client ──"
"$BIN/relay" -home $RH -client $RC -key "$KEY" -status 127.0.0.1:$ST >"$BIN/relay.log" 2>&1 & PIDS+=($!)
wait_port 127.0.0.1 $RH 10 || { echo "  ❌ relay 未就绪"; cat "$BIN/relay.log"; exit 1; }

"$BIN/home" -relay 127.0.0.1:$RH -key "$KEY" -status "$BIN/home.status" -v >"$BIN/home.log" 2>&1 & PIDS+=($!)
sleep 0.6

"$BIN/client" -relay 127.0.0.1:$RC -key "$KEY" -socks $SP -forward "" -v >"$BIN/client.log" 2>&1 & PIDS+=($!)
wait_port 127.0.0.1 $SP 15 || { echo "  ❌ client SOCKS 未就绪"; cat "$BIN/client.log"; exit 1; }
sleep 0.5

echo
echo "── 用例 1：基础连通 ──"
out=$(curl -s --max-time 10 --socks5-hostname 127.0.0.1:$SP http://127.0.0.1:$SRC/hello)
if [ "$out" = "hello-through-tunnel" ]; then ok "SOCKS5 → 隧道 → 目标 返回正确内容"; else bad "内容不符: $out"; fi

echo "── 用例 2：20MB 大文件完整性 ──"
want=$(python3 -c "
import hashlib
print(hashlib.sha256(hashlib.sha256(b'seed').digest()*(20*1024*1024//32)).hexdigest())")
got=$(curl -s --max-time 60 --socks5-hostname 127.0.0.1:$SP http://127.0.0.1:$SRC/big | shasum -a 256 | awk '{print $1}')
if [ "$want" = "$got" ]; then ok "20MB 下载 sha256 一致（无丢包/无截断）"; else bad "sha256 不一致: want=$want got=$got"; fi

echo "── 用例 3：并发 20 条连接 ──"
rm -f "$BIN/conc"/*.out; mkdir -p "$BIN/conc"
CPIDS=()
for i in $(seq 1 20); do
  ( curl -s --max-time 20 --socks5-hostname 127.0.0.1:$SP "http://127.0.0.1:$SRC/hello" > "$BIN/conc/$i.out" ) &
  CPIDS+=($!)
done
for p in "${CPIDS[@]}"; do wait "$p" 2>/dev/null; done
good=$(grep -l "hello-through-tunnel" "$BIN/conc"/*.out 2>/dev/null | wc -l | tr -d ' ')
if [ "$good" = "20" ]; then ok "20/20 并发连接成功"; else bad "并发仅 $good/20 成功"; fi

echo "── 用例 4：目标不可达应快速失败 ──"
t0=$(python3 -c 'import time;print(time.time())')
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 --socks5-hostname 127.0.0.1:$SP http://127.0.0.1:18099/nope 2>/dev/null)
t1=$(python3 -c 'import time;print(time.time())')
el=$(python3 -c "print(round($t1-$t0,2))")
if [ "$code" = "000" ]; then ok "不可达目标明确失败，耗时 ${el}s（未挂死）"; else bad "预期失败，实际 http=$code"; fi
python3 -c "import sys; sys.exit(0 if $el < 5 else 1)" && ok "失败在 5s 内返回（无长时间挂起）" || bad "失败耗时 ${el}s 过长"

echo "── 用例 5：多路复用（同一隧道连接承载多条流）──"
# 顺序发 30 个请求，全部复用同一条到 relay 的连接
n=0
for i in $(seq 1 30); do
  r=$(curl -s --max-time 10 --socks5-hostname 127.0.0.1:$SP http://127.0.0.1:$SRC/hello)
  [ "$r" = "hello-through-tunnel" ] && n=$((n+1))
done
if [ "$n" = "30" ]; then ok "30 次串行请求全部成功（sid 复用正常）"; else bad "仅 $n/30 成功"; fi

echo "── 用例 6：半关闭（HTTP/1.0 带 Content-Length 的完整响应）──"
body=$(curl -s --max-time 10 -H "Connection: close" --socks5-hostname 127.0.0.1:$SP http://127.0.0.1:$SRC/hello)
if [ "$body" = "hello-through-tunnel" ]; then ok "Connection: close 场景响应完整"; else bad "半关闭场景内容缺失: '$body'"; fi

echo "── 用例 7：relay 状态端点 ──"
st=$(curl -s --max-time 5 http://127.0.0.1:$ST/status)
case "$st" in
  *'"home_online":true'*) ok "状态端点显示 home 在线";;
  *) bad "状态端点异常: $st";;
esac

echo
echo "── 用例 8：client 断线自愈（重启 relay）──"
kill "${PIDS[1]}" 2>/dev/null; sleep 1
"$BIN/relay" -home $RH -client $RC -key "$KEY" -status 127.0.0.1:$ST >>"$BIN/relay.log" 2>&1 & PIDS+=($!)
sleep 6   # 等 client 重连（退避最大 10s，这里给足）
out2=$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:$SP http://127.0.0.1:$SRC/hello)
if [ "$out2" = "hello-through-tunnel" ]; then ok "relay 重启后自动恢复"; else bad "恢复失败: '$out2'"; fi

echo
echo "════════════════════════════"
echo "  通过 $pass 项，失败 $fail 项"
echo "════════════════════════════"
if [ $fail -gt 0 ]; then
  echo "--- client.log ---"; tail -20 "$BIN/client.log"
  echo "--- home.log ---";   tail -20 "$BIN/home.log"
  echo "--- relay.log ---";  tail -20 "$BIN/relay.log"
fi
exit $fail
