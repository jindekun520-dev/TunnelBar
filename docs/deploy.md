# 部署

三个二进制 + 一个可选的 Web 网关。全部静态编译（`CGO_ENABLED=0`），扔到目标机就能跑。

## 0. 编译

```bash
cd tunnel
./scripts/build.sh
```

产物：

| 文件 | 目标平台 | 部署到 |
|---|---|---|
| `bin/relay.linux-amd64` | Linux | 公网服务器 |
| `bin/home.linux-amd64` | Linux | 内网主机 |
| `bin/client` | macOS（本机架构） | 本机 |
| `bin/relay.local` / `bin/home.local` | macOS | 仅本机联调 |
| `TunnelBar.app` | macOS | 打包自动更新（见 [macos-app.md](macos-app.md)） |

脚本内置 `go test ./internal/`，测试不过不产出二进制。依赖已 vendor 到 `third_party/`，默认 `GOPROXY=off` 离线编译。

网关：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/gateway.linux-amd64 ./cmd/gateway/
```

## 1. relay（公网服务器）

```bash
scp bin/relay.linux-amd64 root@203.0.113.10:/usr/local/bin/tunnel-relay
scp configs/tunnel-relay.service root@203.0.113.10:/etc/systemd/system/
ssh root@203.0.113.10 '
  chmod +x /usr/local/bin/tunnel-relay
  sed -i "s/在此填入与两端一致的预共享密钥/'"$PSK"'/" /etc/systemd/system/tunnel-relay.service
  systemctl daemon-reload && systemctl enable --now tunnel-relay
  systemctl --no-pager status tunnel-relay | head -5'
```

- 放行 **7000/TCP**（home 连入）与 **7100/TCP**（client 连入）；
- `-status 127.0.0.1:9911` 开一个只读状态端点，绑回环，不要对公网开：

```bash
curl -s http://127.0.0.1:9911/status
# {"home_online":true,"home_gen":3,"clients":1,"active_flows":2,...}
```

资源占用参考：单核、几十 MB 内存即可跑满千兆；relay 不做加密运算（它只转发密文），CPU 花在 `copy` 上。

## 2. home（内网主机）

```bash
scp bin/home.linux-amd64 root@10.0.0.12:/usr/local/bin/tunnel-home
scp configs/tunnel-home.service root@10.0.0.12:/etc/systemd/system/
ssh root@10.0.0.12 '
  chmod +x /usr/local/bin/tunnel-home
  sed -i "s/在此填入与两端一致的预共享密钥/'"$PSK"'/" /etc/systemd/system/tunnel-home.service
  systemctl daemon-reload && systemctl enable --now tunnel-home
  cat /run/tunnel-home.status'
```

- home 只需要**出站**能连到 relay 的 7000，不需要任何入站端口；
- 建议给 `CAP_NET_RAW`（或用 root 跑）：ICMP 真探测优先用原始套接字，拿不到权限时自动退回 fork `ping` 进程（首包会有 600~1000ms 尖刺）；
- `-status /run/tunnel-home.status` 写的状态文件供看门狗读取；
- `-wol-addr 127.0.0.1:9912` 起网络唤醒接口（默认值，留空则关闭）。它只监听回环，远端经隧道访问时是 home 自己去 `Dial` 这个地址，所以回环就够，**局域网里其它机器连不上**；
- `-wol-token` 可选令牌。只有在把接口改成监听局域网地址时才需要，否则留空；
- `-wol-port 9` 魔术包 UDP 端口（少数老网卡只认 7）。

### 看门狗（可选）

`configs/` 里有 `tunnel-home-watchdog.{sh,service,timer}` 与 `tunnel-home-alert.sh`：状态文件超过阈值没更新就重启 home，并按需推企业微信机器人告警。

```bash
scp configs/tunnel-home-watchdog.sh root@10.0.0.12:/usr/local/bin/
scp configs/tunnel-home-watchdog.{service,timer} root@10.0.0.12:/etc/systemd/system/
ssh root@10.0.0.12 'systemctl daemon-reload && systemctl enable --now tunnel-home-watchdog.timer'
```

## 3. client（本机）

### 方式 A：菜单栏 App（推荐）

双击 `TunnelBar.app`，「连接」即可。App 自己拉起内嵌 client，退出时一并收尾，不留孤儿进程。

### 方式 B：launchd 开机自启

```bash
TUNNEL_KEY='你的PSK' TUNNEL_RELAY='203.0.113.10:7100' ./scripts/install-macos-agent.sh
```

脚本把 client 装到 `~/Library/Application Support/Tunnel/client`（放 Desktop 会被 TCC 拦），并生成合法 plist。注意：**与 App 里的「开机自启」二选一**，别同时开。

### 方式 C：前台跑

```bash
./bin/client -relay 203.0.113.10:7100 -key '你的PSK' -socks 1080 -status 127.0.0.1:9908
```

之后浏览器 / 终端设 SOCKS5 `127.0.0.1:1080`：

```bash
# SSH 走隧道
ssh -o ProxyCommand="nc -x 127.0.0.1:1080 %h %p" root@10.0.0.12

# curl 走隧道（注意用 socks5-hostname，让 DNS 也在对端解析）
curl -s --socks5-hostname 127.0.0.1:1080 http://10.0.0.11/ -o /dev/null -w '%{http_code}\n'
```

> 若 `~/.ssh/config` 给内网段配了走 `127.0.0.1:1080` 的 `ProxyCommand`，**client 没跑时连这些地址必然失败**（kex 阶段被秒关）。先确认 1080 在监听。

## 4. gateway（可选的 Web 入口）

前置：本机已有一个 client 在跑（只要 SOCKS，不需要 TUN）。

```bash
# 1) 目录
mkdir -p /etc/tunnelbar /var/log/tunnelbar

# 2) 二进制
scp bin/gateway.linux-amd64 root@203.0.113.10:/usr/local/bin/tunnelbar-gateway

# 3) 配置（示例见 examples/gateway.example.json）
scp examples/gateway.example.json root@203.0.113.10:/etc/tunnelbar/gateway.json

# 4) 首次启动会用配置里的 password 生成密码哈希文件（0600）
ssh root@203.0.113.10 'chmod +x /usr/local/bin/tunnelbar-gateway
  systemctl enable --now tunnelbar-gateway'
```

完整配置字段、子域/端口两种暴露方式、密码体系、Guacamole 接入见 [gateway.md](gateway.md)。

## 5. 升级顺序

**协议不向下兼容，三端必须同时升到 v2。** 推荐顺序：

```
relay  →  home  →  client
```

这个顺序下，旧 client 会在 relay 换成 v2 后短暂断连（v2 client 对 v1 relay 发 hello 无响应），换完即恢复。反过来先换 client，会一直重连失败。

```bash
systemctl restart tunnel-relay tunnel-home
```

**scp 覆盖正在运行的二进制会报 `ETXTBSY`**，先 `systemctl stop`，再拷，再 `start`。

## 6. 目录与权限约定（参考）

网关部署在公网机上时，一个可用的落地布局：

```
/usr/local/bin/tunnelbar-gateway      二进制
/usr/local/bin/tunnelbar-client       网关专用 client（Linux，只开 SOCKS + 端口转发）
/etc/tunnelbar/gateway.json           配置（0644 可，但别含长期密码）
/etc/tunnelbar/passwd                 门户密码哈希（0600，改密走门户，不要手改）
/var/log/tunnelbar/                   日志
/root/frp/ssl/                        TLS 证书（如 Let's Encrypt 泛域名，certReloader 按 mtime 热加载）
```

systemd 单元两条就够：

```ini
[Unit]
Description=TunnelBar SOCKS client (gateway upstream)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/tunnelbar-client -relay 203.0.113.10:7100 -key PSK -socks 127.0.0.1:1080 -forward 10022:10.0.0.12:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

> `-forward` 用来给 Gateway 提供 Guacamole 之类的「固定本地端口」入口：`10022:10.0.0.12:22` 让 `127.0.0.1:10022` 等价于内网那台机的 22 端口。

## 7. 自检清单

```bash
# relay 看得到 home 吗
curl -s http://127.0.0.1:9911/status | grep -o '"home_online":[a-z]*'

# client 就绪吗
curl -s http://127.0.0.1:9908/status | python3 -m json.tool | head -20

# 隧道真的通吗
curl -s --socks5-hostname 127.0.0.1:1080 --max-time 8 http://10.0.0.11/ -o /dev/null -w '%{http_code}\n'

# 网关活着吗
curl -sk https://127.0.0.1:8443/__health -H 'Host: portal.example.com'
```
