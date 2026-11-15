# TunnelBar · 用自己的服务器，把内网搬到任何一台设备上

> 一台公网中转 + 一台家里主机 + 一个菜单栏 App，让出差途中的 Mac、车机浏览器、临时借来的电脑，**像坐在家里一样**访问内网——不限网段、不限端口：整段 `10.0.0.0/24`、另一个机房的 `192.168.1.0/24`、甚至只是某台设备的单个 3389，指哪连哪。

<p>
<img alt="Go" src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white">
<img alt="macOS" src="https://img.shields.io/badge/macOS-13%2B-000000?logo=apple&logoColor=white">
<img alt="Linux" src="https://img.shields.io/badge/Linux-amd64-FCC624?logo=linux&logoColor=black">
<img alt="License" src="https://img.shields.io/badge/License-MIT-green">
<img alt="Deps" src="https://img.shields.io/badge/third--party%20deps-0-blue">
</p>

---

## 目录

- [这是什么](#这是什么)
- [三个真实使用现场](#三个真实使用现场)
- [架构](#架构)
- [核心能力](#核心能力)
- [亮点与设计取舍](#亮点与设计取舍)
- [组件一览](#组件一览)
- [快速开始](#快速开始)
- [Web 端：给只有浏览器的设备](#web-端给只有浏览器的设备)
- [目录结构](#目录结构)
- [文档](#文档)
- [安全须知](#安全须知)
- [已知限制](#已知限制)
- [License](#license)

---

## 这是什么

家里（或机房）的内网设备在 NAT 后面，没有公网 IP。想在外网用它们，通常要面临三选一：

| 常见做法 | 痛点 |
|---|---|
| frp / ngrok 逐个端口映射 | 一台设备一条规则，端口越开越多；内网管理界面直接裸奔在公网 |
| ZeroTier / Tailscale | 依赖厂商的控制面与账号体系；要给每台设备装客户端 |
| 商业远控 | 装客户端、画面走厂商服务器、按并发收费 |

**TunnelBar 换了个思路：只借一台有公网 IP 的服务器做「会合点」，其余全靠你自己的一把预共享密钥。**

- 内网主机（`home`）主动外连，穿透 NAT，不需要任何端口映射；
- 你的设备（`client`）也主动外连，全局只能看到 **1 个端口**；
- 中继（`relay`）只按流 ID 转发**密文帧**，不落地、不解密、不认人；
- 没有账号体系、没有控制面、没有第三方服务，**唯一凭证就是那把 PSK**。

三端之外，还有两样东西让它真正好用：一个 macOS 菜单栏 App（TunnelBar.app），和一个可选部署的 **Web 网关**——后者让车机、借来的电脑、家人的手机，只要有浏览器就能进内网，连客户端都不用装。

---

## 三个真实使用现场

**① 出差路上，Mac 像在办公室**
菜单栏点一下「连接」，SOCKS5 与固定端口转发同时就绪。SSH 直连内网主机、浏览器开 ESXi / NAS / 路由器管理页、`rdp` 连 Windows 桌面，都不用改任何配置。

**② 车机 / 借来的电脑，只有一个浏览器**
打开 `https://portal.<你的域名>` → 登录 → 门户页列出所有内网入口，点卡片直接进；点「远程桌面」还能在浏览器里开出 SSH 终端和 Windows 桌面（基于 Apache Guacamole，已做成免二次登录）。

**③ 家里的手机、平板**
同上，浏览器即可。不需要装 App，不需要配代理。

---

## 架构

```
   ┌─────────────┐       加密 TCP (7000)       ┌──────────────────┐
   │  home       │ ◄─────────────────────────► │  relay           │
   │ 内网 Linux  │   主动外连，穿透 NAT         │  公网服务器      │
   │ 10.0.0.12   │                              │  只转发密文帧    │
   └──────┬──────┘                              └────────▲─────────┘
          │ Dial 10.0.0.x:任意端口                        │
          ▼                                              │ 加密 TCP (7100)
   ┌──────────────────┐                                  │ 连接池 × N
   │ 内网设备          │                       ┌──────────┴─────────┐
   │ ESXi / NAS / 路由 │                       │  client            │
   │ Windows / Linux  │                       │  SOCKS5 + 端口转发 │
   └──────────────────┘                       │  + 可选 TUN        │
                                              └──────────┬─────────┘
                                                         │
                            ┌────────────────────────────┼───────────────────────────┐
                            ▼                            ▼                           ▼
                    Mac 菜单栏 App              Web 网关 (gateway)          命令行 / curl
                    TunnelBar.app               单端口 + 泛域名 + 登录门      --socks5-hostname
                                                  └─► Guacamole（浏览器远程桌面）
```

四条设计主线：

1. **控制面为零。** 没有注册、没有心跳服务器、没有配置下发。三端用同一把 PSK 派生会话密钥，谁有钥匙谁就能连。
2. **一条连接扛很多流。** `client ↔ relay` 之间是自研多路复用（类 HTTP/2 的 stream），浏览器、SSH、端口转发、TUN 里的所有连接共享这几条 TCP，避免 TCP 队头阻塞。
3. **中继是哑的。** relay 不解密、不缓存、不写盘，只做「按 streamID 把密文帧交给对端」。它被打穿也拿不到内容。
4. **Web 端是旁路。** gateway 完全不碰隧道协议，所有出站都拨本机 `127.0.0.1:1080`（也就是 client 的 SOCKS），因此它可以随时启停、单独升级。

---

## 核心能力

| 能力 | 说明 | 组件 |
|---|---|---|
| 内网穿透 | home 主动外连，无需公网 IP、无需端口映射 | `home` + `relay` |
| SOCKS5 代理 | 标准 SOCKS5，浏览器 / curl / `ProxyCommand` 直接用 | `client` |
| 固定端口转发 | `本地端口:目标主机:目标端口`，给不认代理的程序 | `client` |
| 全局直连（TUN） | 建虚拟网卡，内网网段直接路由进隧道，**程序完全不用配代理** | `client`（需 root） |
| 连接池 | 默认 6 条并发通道，轮询分摊带宽，坏连接自动隔离重建 | `client` |
| 资产模型 | 「去哪 / 用什么连 / 用谁的账号」三要素一条记录，SSH / RDP / VNC / SMB 一键打开 | `TunnelBar.app` |
| 浏览器内网入口 | 单端口 + 泛域名，一台资产一个子域，绝对路径与 WebSocket 全兼容 | `gateway` |
| 浏览器远程桌面 | Web 端 SSH 终端 + Windows RDP，网关代登录，不用二次输密码 | `gateway` + Guacamole |
| 登录门 | HMAC Cookie（14 天）+ PBKDF2 密码哈希 + 在线改密 + 改密即全端失效 | `gateway` |
| 证书热加载 | 按 mtime 自动重读，`certbot renew` 后不用重启 | `gateway` |
| 网络唤醒（WoL） | 关机设备一点就醒：由 home 在内网广播魔术包，浏览器门户和菜单栏都能触发，并自动等到目标上线 | `gateway` + `home` + `TunnelBar.app` |
| 状态可观测 | client / relay 都暴露 JSON 状态端点，池内每条连接的 RTT、流量、重传一目了然 | `client` `relay` |
| 自检与测试 | 协议层单测 + 本机全链路 e2e（含 20MB 完整性校验）+ App 内一键自测 | 全部 |

---

## 亮点与设计取舍

**1. 一条 PSK，没有账号体系**
不做用户、不做设备注册、不做控制台。代价是「知道密钥的人就能进」，收益是零运维：没有数据库、没有过期 token、没有掉线重认证。密钥不对就握不上手，日志里只有一句「解密失败」。

**2. 三条通道的密码学，按「跨连接不重用 nonce」设计**
握手时两端交换随机 salt，用 HKDF-SHA256 为**每一条连接**派生独立密钥；nonce 里带方向位并严格递增校验。很多自研隧道挂在这里：AES-GCM 的 nonce 在不同连接间重复，加密强度直接归零（v1 就踩过，见 [docs/architecture.md](docs/architecture.md)）。

**3. 用背压代替丢包**
复用层通道满了不再 `select/default` 丢帧，而是阻塞投递 + 有界等待。慢流只会拖慢自己，超过 `-linger` 才单独重置。**下载大文件不会再损坏**——这是 v1 最致命的问题。

**4. 帧头带独立 flags，数据永远不被误判**
建连结果不再借用「1 字节 payload」表达。OPEN / OK / ERR / DATA / FIN / RST 与数据彻底分离，一个内容恰好是 `0x01` 的字节不会再把连接掐断。

**5. 显式半关闭，两个方向各自收尾**
任一方向 EOF 不再整体 `Close`。HTTP/1.0、SSH 会话、长下载这类「客户端先说完、服务端还在吐」的场景不会被中途砍断。

**6. 单端口 + 泛域名，而不是一堆端口**
网关只开 **1 个端口**，按 `Host` 头分流：`esxi.example.com`、`nas.example.com`……为什么不是 `/esxi/` 这类路径前缀？因为 ESXi、TrueNAS 的前端全部按**绝对路径**取资源、还带 WebSocket，挂在子路径下会碎得很干净。子域名下它们以为自己就在根路径，**一个字节都不用改**。

**7. Cookie 带上 `Domain`，四个子域只登一次**
子域名方案最容易漏的一步：不写 `Domain=.example.com`，每个子域都要重新登录。这里登录 Cookie 是 `HMAC-SHA256(secret, 用户|日期|密码指纹)`，`HttpOnly + Secure + SameSite=Lax`。

**8. 改密码 = 全端下线**
密码哈希的指纹被拼进 Cookie 签名，所以改密后**所有设备上的旧 Cookie 立即失效**，不需要逐个去清。密码本身以 `pbkdf2-sha256` 存独立文件（0600、原子写），配置文件里只留初始密码。

**9. 浏览器里免二次登录的远程桌面**
Guacamole 自带用户体系，正常要再登一次。网关的做法是：抓上游 HTML，在 `</head>` 前注入一小段脚本，脚本向 `/__guaccred`（在登录门之后）取账号密码，填表并**只派发一次** submit。地址栏始终干净，HTML 里没有明文密码。走过的死路（注入 token、改 fragment 跳转）也写进文档，别再踩一遍。

**10. TUN 模式让「配代理」这件事消失**
建 `utun` 虚拟网卡，把你指定的网段（`-tun-routes` 可给多条，如 `10.0.0.0/24,192.168.1.0/24`）直接路由进隧道，任何程序（含 IDE、数据库客户端）都不需要认代理。附带解决 ICMP：ping 由家里那侧用原始套接字**真的发一次**，不可达就是超时，不会出现「ping 什么都通」的假象。

**11. 菜单栏 App 零第三方依赖**
纯 AppKit + `swiftc` 手写构建，没有 SwiftPM、没有 Electron、没有 100MB 运行时。图标走 SF Symbols 模板图，颜色随深浅色菜单栏自动反转；状态靠**形状**区分（盾牌 / 对勾 / 感叹号 / 斜线）。

**12. 唤醒关机设备，关键在「谁在内网」**
魔术包是**链路层广播**，公网服务器发往 `10.0.0.255` 只会被路由丢掉（定向广播默认关闭），也跨不过 NAT。所以唤醒请求的终点不是网关，而是**家里那台 `home`**：网关经 SOCKS 把请求转给它，由它按本机每块网卡算出定向广播地址再发。Web 门户与菜单栏两个入口共用这套逻辑，各按钮都同时尝试「本机直发」和「隧道代发」——人在家里前者就够，人在外面只有后者有效。按下去之后门户会盯着目标端口轮询，**真的起来了才说「已上线」**，否则用户只会反复点。

**13. 可观测性做在文件系统里的 JSON 上**
`curl 127.0.0.1:9908/status` 直接拿到池内每条连接的 `rtt_ms / idle_ms / resets / stalled / tx_bytes`。不需要 Prometheus，也不妨碍你自己接监控。

---

## 组件一览

| 二进制 | 跑在哪 | 作用 | 需要 root |
|---|---|---|---|
| `relay` | 公网 Linux | 只做双向转发与会合，不解密 | 否 |
| `home` | 内网 Linux | 收 OPEN → Dial 内网目标 → 双向桥接 | 建议（ICMP 真探测要 `CAP_NET_RAW`） |
| `client` | macOS（Linux 亦可用，无 TUN） | SOCKS5 + 端口转发 + 连接池 + 状态接口 | TUN 模式需要 |
| `gateway` | 公网 Linux | Web 门户 / 子域反代 / 登录门 / Guacamole 代登录 | 否 |
| `TunnelBar.app` | macOS 13+ | 菜单栏控制台：连接、资产、延迟、流量、日志 | 否 |

---

## 快速开始

### 第 0 步：30 秒本机自测（不需要服务器）

在本机把三端和测试站点一起拉起来，跑完连通性 + 20MB 完整性校验：

```bash
git clone https://github.com/<you>/tunnelbar.git && cd tunnelbar/tunnel
./scripts/build.sh
bash app/build-app.sh
../TunnelBar.app/Contents/MacOS/TunnelBar --selftest
```

期望输出：

```
▸ 拉起本机自测三端（relay / home / 站点 / client）...
✓ 状态接口就绪：协议 v2，池 2/2
✓ SOCKS 探测通过：1 ms
✓ 20MB 传输完整（20971520 字节）
✓ 不可达目标快速失败：2 ms
SELFTEST OK
```

也可以直接命令行跑：

```bash
go test ./internal/ -race      # 协议层单测（加解密、重放、半关闭、流 ID）
./scripts/e2e-test.sh          # 端到端 9 项
```

### 第 1 步：公网服务器（relay）

```bash
scp bin/relay.linux-amd64 root@203.0.113.10:/usr/local/bin/tunnel-relay
scp configs/tunnel-relay.service root@203.0.113.10:/etc/systemd/system/
ssh root@203.0.113.10 'chmod +x /usr/local/bin/tunnel-relay
  sed -i "s/在此填入与两端一致的预共享密钥/你的PSK/" /etc/systemd/system/tunnel-relay.service
  systemctl daemon-reload && systemctl enable --now tunnel-relay'
```

防火墙只需要放行 **7000/TCP**（home 连入）与 **7100/TCP**（client 连入）。

> PSK 生成建议：`openssl rand -base64 32`。三端必须完全一致。

### 第 2 步：内网主机（home）

```bash
scp bin/home.linux-amd64 root@10.0.0.12:/usr/local/bin/tunnel-home
scp configs/tunnel-home.service root@10.0.0.12:/etc/systemd/system/
ssh root@10.0.0.12 'chmod +x /usr/local/bin/tunnel-home
  sed -i "s/在此填入与两端一致的预共享密钥/你的PSK/" /etc/systemd/system/tunnel-home.service
  systemctl daemon-reload && systemctl enable --now tunnel-home'
```

`home` 默认会在 `127.0.0.1:9912` 起一个唤醒接口（`-wol-addr` 可改、留空则关闭），
供网关和菜单栏 App 经隧道调用来发魔术包——详见 [Web 端](#web-端给只有浏览器的设备) 与
[docs/macos-app.md](docs/macos-app.md)。

### 第 3 步：本机（client）

```bash
# 开机自启（推荐）
TUNNEL_KEY='你的PSK' TUNNEL_RELAY='203.0.113.10:7100' ./scripts/install-macos-agent.sh

# 或前台跑
./bin/client -relay 203.0.113.10:7100 -key '你的PSK' -socks 1080 -status 127.0.0.1:9908
```

然后：

```bash
curl -s --socks5-hostname 127.0.0.1:1080 http://10.0.0.11/ -o /dev/null -w '%{http_code}\n'
ssh -o ProxyCommand="nc -x 127.0.0.1:1080 %h %p" root@10.0.0.12
```

**或者直接双击 `TunnelBar.app`**，在菜单里「连接」——它会拉起内嵌的 client 并持续显示池内连接数、收发流量与真实 RTT。

---

## Web 端：给只有浏览器的设备

车机、借来的电脑、家人的手机装不了客户端，做法是在公网服务器上再跑一个 `client`（只要 SOCKS）+ `gateway`：

```
浏览器 --HTTPS(单端口)--> gateway --SOCKS--> client --> relay --> home --> 内网设备
```

最小配置（`/etc/tunnelbar/gateway.json`，完整字段见 [docs/gateway.md](docs/gateway.md)）：

```json
{
  "listen": "0.0.0.0:8443",
  "socks": "127.0.0.1:1080",
  "domain": "example.com",
  "portal_sub": "portal",
  "public_port": 8443,
  "user": "admin",
  "password": "首次启动用的初始密码",
  "passwd_file": "/etc/tunnelbar/passwd",
  "tls_cert": "/etc/letsencrypt/live/example.com/fullchain.pem",
  "tls_key": "/etc/letsencrypt/live/example.com/privkey.pem",
  "assets": [
    { "sub": "esxi", "name": "ESXi 宿主机", "target": "10.0.0.10:443", "scheme": "https", "icon": "▣", "note": "虚拟化",
      "mac": "c4:83:4f:18:02:1b" },
    { "sub": "nas",  "name": "NAS 管理",   "target": "10.0.0.11:5001", "scheme": "https", "icon": "▤" },
    { "name": "Windows 工作站", "target": "10.0.0.23:3389", "note": "开机后才连得上",
      "mac": "00:1a:2b:3c:4d:5e" }
  ],
  "paths": { "/guacamole/": "http://127.0.0.1:8089" },
  "guacamole": { "path": "/guacamole/", "target": "http://127.0.0.1:8089", "user": "gcuser", "password": "gcpass" },
  "wol": { "endpoint": "127.0.0.1:9912", "token": "", "port": 9, "wait_seconds": 90 }
}
```

访问 `https://portal.example.com:8443` → 登录 → 卡片式门户 → 点哪进哪。四个要点：

- 用**泛域名证书** `*.example.com`（裸域名不被覆盖，所以门户必须挂在 `portal.` 子域上）；
- 只有 1 个端口需要映射，新增资产只加一条 `assets`；
- `/__health` 无需登录，方便探活；
- 密码在门户最下面一行可以直接改（`/__passwd`），改完整网所有旧 Cookie 立即失效。

### 关机设备也能一点就醒

给资产填上 `mac`，门户上那张卡片右边就多一个「唤醒」按钮；只填 `mac` 不填 `sub`/`port` 的资产就是一台「纯唤醒设备」（比如只在你开机之后才连得上的 Windows 工作站）：

```json
"wol": { "endpoint": "127.0.0.1:9912", "token": "", "port": 9, "wait_seconds": 90 }
```

请求的走向跟网页访问**不同**：网关不在内网，魔术包必须由家里的 `home` 发。

```
浏览器 --POST /__wake--> gateway --SOCKS--> client --> relay --> home --UDP 广播--> 目标网卡
```

`home` 端默认就带这个接口（`-wol-addr 127.0.0.1:9912`，只听回环，所以局域网里其他机器连不上），网关的 `wol.endpoint` 填的就是**从 home 视角看的地址**。点下去之后门户会每 3 秒探一次目标端口，真的通了才显示「已上线」，超时（默认 90 秒）会说清楚没等到。

---

## 目录结构

```
tunnelbar/
├── tunnel/                      Go 源码（协议 / 三端 / 网关 / 菜单栏 App）
│   ├── cmd/
│   │   ├── relay/               中继：路由表 + 双向转发
│   │   ├── home/                内网端：收 OPEN → Dial → 桥接；ICMP 真探测
│   │   ├── client/              SOCKS5 + 连接池 + 端口转发 + TUN + 状态端点
│   │   └── gateway/             Web 门户 / 子域反代 / 登录门 / Guacamole 代登录
│   ├── internal/
│   │   ├── proto.go             帧格式、握手、HKDF 派生、nonce 校验
│   │   ├── mux.go               流复用、背压、半关闭、流 ID 分配
│   │   ├── nat.go               TUN 模式的用户态 TCP/UDP/ICMP 处理
│   │   └── tun_darwin.go        utun 设备与路由
│   ├── app/TunnelBar/           macOS 菜单栏 App（AppKit，无第三方依赖）
│   ├── scripts/                 build.sh / e2e-test.sh / install-macos-agent.sh
│   └── third_party/             vendor：gvisor netstack 子集等
├── configs/                     systemd 单元、看门狗脚本
├── examples/                    最小可用配置示例
├── docs/                       详细设计、部署、排障文档
└── legacy-v1/                  v1 窗口版（已停用，仅存档）
```

---

## 文档

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 协议、帧格式、密钥派生、复用层与 v1→v2 的修复清单 |
| [docs/deploy.md](docs/deploy.md) | 三端 + 网关的部署、systemd、看门狗、升级顺序 |
| [docs/client.md](docs/client.md) | client 全部参数、TUN 模式、连接池读数、状态接口字段 |
| [docs/gateway.md](docs/gateway.md) | Web 网关配置、子域/端口两种模式、密码体系、Guacamole 接入、网络唤醒 |
| [docs/macos-app.md](docs/macos-app.md) | 菜单栏 App 用法、资产模型、网络唤醒、配置项、图标与打包 |
| [docs/performance.md](docs/performance.md) | 从 340KB/s 到 1.67MB/s 的调优记录与实测数据 |
| [docs/troubleshooting.md](docs/troubleshooting.md) | 按现象排查：连不上 / 慢 / 登录进不去 / 证书 / 端口占用 |
| [docs/security.md](docs/security.md) | 威胁模型、PSK 管理、公网暴露面、加固清单 |

---

## 安全须知

- 传输加密 **AES-256-GCM**，密钥由 **HKDF-SHA256** 从 PSK 派生，**每条连接独立**；握手带随机 salt，跨连接不重用 nonce；重放帧直接丢弃。
- **PSK 是唯一凭证**：拿到它既能用隧道，也能冒充你的 home。不要提交到仓库、不要写进共享文档、不要截图。
- relay 不落地明文，只转发密文帧 —— 但它仍能观察流量特征（时间、大小、连接数）。
- 网关把内网管理界面暴露到公网，**必须先改初始密码**，并尽量只对固定来源 IP 开放；Guacamole 的 `user-mapping.xml` 含内网账号密码（明文），注意文件权限与备份策略。
- 建议给 home 侧限定可访问网段，并把 relay 的 7000/7100 只对必要来源开放。

完整加固清单见 [docs/security.md](docs/security.md)。

---

## 已知限制

- **协议不向下兼容**：v2 与 v1 三端不能混跑，升级顺序 relay → home → client。
- macOS 的 TUN 模式依赖 `utun` 与路由表操作，需要 root（App 会写一条 `sudoers.d` 只授权自身的包装脚本）；Linux 上的 client 目前没有 TUN。
- RDP 密码无法代填（`.rdp` 里必须是 Windows DPAPI 密文，macOS 算不出来），首次需手输并勾选「记住我」。
- Windows 版客户端尚未提供。
- 规划中：relay 侧流 ID 单调化、Web 端健康检查面板、IPv6 目标、配置热加载。

---

## License

[MIT](LICENSE) © 2026 jindekun

---

<details>
<summary>English</summary>

**TunnelBar** is a self-hosted reverse tunnel: one public relay, one home host, and a macOS menu-bar app — plus an optional single-port HTTPS gateway so any browser-only device (car head unit, borrowed laptop, phone) can reach the home LAN.

- Zero control plane: a single pre-shared key, no accounts, no third-party service.
- Own multiplexing layer with backpressure and explicit half-close — no frame drops, no corrupted downloads.
- AES-256-GCM with per-connection HKDF keys and strictly monotonic nonces; replay frames rejected.
- Web gateway does subdomain routing on **one port**, so ESXi/NAS style absolute-path + WebSocket UIs work unmodified; includes a login gate (PBKDF2) and Guacamole single-sign-on for in-browser SSH/RDP.
- Optional TUN mode: route the LAN subnet into the tunnel, no proxy configuration in any app.

Docs are in Chinese; the code is heavily commented in Chinese. Issues and PRs are welcome in either language.

</details>
