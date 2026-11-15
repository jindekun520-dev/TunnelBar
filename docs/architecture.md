# 架构与协议

## 1. 三端角色

| 角色 | 部署位置 | 职责 | 是否需要公网 |
|---|---|---|---|
| `relay` | 有固定公网 IP 的服务器 | 接受 home 与 client 的连接，按 `streamID` 把密文帧交给对端 | 是 |
| `home` | 内网 Linux | 收到 `OPEN` 后 `Dial` 内网目标，双向桥接；ICMP 由它真探测 | 否（主动外连） |
| `client` | macOS / Linux | 本地 SOCKS5、固定端口转发、连接池、可选 TUN、状态接口 | 否（主动外连） |
| `gateway` | 公网服务器（可与 relay 同机） | Web 门户、子域反代、登录门、Guacamole 代登录 | 是 |

`gateway` 不参与隧道协议，出站一律拨 `127.0.0.1:1080`（本机 client 的 SOCKS）。

```
home ──(7000)──► relay ◄──(7100)── client ◄── SOCKS/端口转发/TUN ── 本机程序
                                    ▲
                              gateway ──► 浏览器
```

## 2. 握手与密钥派生

明文 hello 共 18 字节：`magic('T') + version(1) + salt(16)`。salt 公开无碍。

```
salt_pair = 发起方 salt || 响应方 salt     （顺序固定，两端一致）
session_key = HKDF-SHA256(PSK, salt_pair, "tunnel/v2/psk")
```

- 每条 TCP 连接都走一次握手，因此**每条连接都有独立会话密钥**；
- 同一 PSK 在多条连接、多次重连下都不会产生重复的 `(key, nonce)` 组合；
- 密钥不一致时不会「连上但乱码」，而是第一帧就 `ErrDecrypt`，日志明确写「解密失败（密钥不一致）」；
- `SecureConn.KeyFingerprint()` 返回会话密钥前 8 字节，用于两端比对排查，无需暴露密钥本身。

## 3. 帧格式

密文帧在 wire 上的布局：

```
┌────────────┬──────────────┬───────────────────────────────────────┐
│ ctLen (4B) │ nonce (12B)  │ ciphertext = AES-256-GCM(明文)         │
└────────────┴──────────────┴───────────────────────────────────────┘
                              明文 = streamID(4B) + flags(1B) + payload(≤32KB)
```

`nonce = [方向 4B][单调计数 8B]`，前 4 字节是 `0x01000000`（发起方）或 `0x02000000`（响应方）。接收端严格校验方向位与计数递增，**重放、乱序、反射帧直接丢弃**。

### flags

| flag | 含义 |
|---|---|
| `0x01 OPEN` | 建连请求，payload = 目标地址编码（host + port + proto） |
| `0x02 OPEN_OK` | 建连成功 |
| `0x04 OPEN_ERR` | 建连失败，`payload[0]` 为错误码（`1` 不可达 / `2` 拒绝 / `3` 格式错） |
| `0x08 DATA` | 数据 |
| `0x10 FIN` | 半关闭：本方向不再发数据 |
| `0x20 RST` | 异常终止整条流 |
| `0x40 PING` / `0x80 PONG` | 心跳，仅 `streamID=0` |

`MaxPayload = 32KB`，`maxCipherLen = MaxPayload + 64` 用于快速拒绝畸形帧；单帧写入有 10s 兜底超时（发送窗口长期为 0 时不能无限等，否则所有流一起挂死）。

## 4. 复用层（`internal/mux.go`）

一条 TCP 上跑 N 条流，关键行为：

| 行为 | 实现 | 为什么 |
|---|---|---|
| 流 ID 分配 | `uint32` **单调递增、不复用** | v1 用 free 列表 LIFO 复用，新 OPEN 会被尚未收尾的旧流吞掉，表现是「每个请求先卡 3 秒」 |
| 重复 OPEN | 若该 ID 仍存在，**先 terminate + drop 旧流再接新流** | 宁可错杀残留流，也不让新 OPEN 被吞 |
| 投递 | 非阻塞入队，上限 4MB / 1024 帧；超限只重置那一条流 | v1 的「阻塞等待 30s」会让一条没人读的流卡死整个读循环 |
| 慢流 | 超过 `-linger`（默认 60s）单方向收尾后重置 | 背压代替丢包，同时不允许永久占用 |
| 半关闭 | `FIN` 逐方向传递，两方向都收尾才 `Close` | v1 任一方向 EOF 就整体 Close，HTTP/1.0 与长下载被砍断 |
| 心跳 | 5s 一次，12s 判死 | 移动热点/家用 NAT 常在空闲十几秒后静默丢映射 |
| 选路 | 优先 `IdleSince() <= 6s` 的连接，全陈旧时退化取最不陈旧 | 避免把新流丢进一条刚断的死连接 |

`Bridge` 做半关闭转发时用 `interface{ CloseWrite() error }` 断言，**不能写死 `*net.TCPConn`**：TUN 模式下是 `*gonet.TCPConn`，写死会导致数据收完却不发 FIN，`curl` 挂到超时。

## 5. 连接池

client 启动即向 relay 建 `-pool`（默认 6）条独立加密连接，每条内部再按流 ID 多路复用。目的不是「更快」，而是**避免 TCP 队头阻塞**：单条连接丢一个包，拥塞窗口下滑，其上所有流一起卡（表现为页面白屏）。

- 每条连接独立心跳与 RTT 观测（`PingSentAt` / `LastRTT`），**只做观测，不参与调度**；
- 45s 无响应（新值 12s）自动摘出池并重建；
- `/status` 的 `pool` 数组把每条连接的 `rtt_ms / idle_ms / resets / stalled / err` 全抖出来。

## 6. TUN 模式

见 [client.md](client.md#tun-全局直连模式)。要点：`utun` 必须配 IPv4 地址（本端与对端同为 `198.18.0.1`），否则 `route add` 返回 0 但内核拒绝；路由加完要用 `route -n get` 复核实际出口。

## 7. v1 → v2：为什么必须重写

v1 的问题不是「不够快」，而是**数据会错**。以下每条都真实导致过故障：

| v1 缺陷 | 后果 | v2 的做法 |
|---|---|---|
| 复用层 `select/default` 投递，通道满即丢帧 | 下载大文件必损坏、连接随机卡死 | 阻塞投递 + 有界等待，用背压代替丢包 |
| 用「1 字节 payload」兼作建连结果，`data[0]==1` 判失败 | 正常传输中的一个 `0x01` 字节被误判，连接被掐 | 帧头带独立 `flags`，与数据彻底分离 |
| 任一方向 EOF 就整体 `Close` | HTTP/1.0、SSH、长下载中途被砍 | 显式半关闭，两方向各自 FIN |
| AES-GCM nonce 是每端独立计数器、跨连接从 0 重来 | **同一 PSK 下 nonce 复用，加密实际失效** | 握手交换随机 salt → HKDF 派生每连接密钥；nonce 带方向位 + 严格递增 |
| `copy(k, []byte(key))` 截断/补零当密钥 | 短口令被零填充成弱密钥 | HKDF-SHA256 派生，密钥长度不限 |
| relay 里 `close(homeCh)` 被两处调用 | double-close panic，中继进程崩 | 路由表单一所有权，删除与通知严格配对 |
| 旧 home 断线时无条件 `setHome(nil)` | 新 home 已连上却被置空，隧道假死 | generation 号，只有当前代际允许清理 |
| 建连应答无超时 | SOCKS 请求永久挂起，浏览器转圈 | `OPEN` 等待带超时（默认 3s），失败重试或明确报错 |
| relay 在每帧路径打日志 | 高吞吐时自己把自己拖死 | 数据面零日志，`-v` 才输出 |
| streamID 用 `uint16` 递增，溢出撞上控制帧 0 | 跑够 65536 条流后全乱 | `uint32` 单调递增 |
| macOS plist 写成 `<key>KeepAlive</string>` | XML 畸形，`launchctl bootstrap` 报 I/O error | 修正并用 `plutil -lint` 卡在校验环节 |

**协议不向下兼容：三端必须同时升级。** 升级顺序 relay → home → client（此顺序下旧 client 只短暂断开）。

## 8. 目录与代码地图

| 路径 | 内容 |
|---|---|
| `internal/proto.go` | 帧编解码、握手、HKDF、nonce 校验、`SecureConn` |
| `internal/mux.go` | 流复用、背压、半关闭、流 ID、心跳与选路 |
| `internal/pipe.go` | `Stream ↔ net.Conn` 双向桥接（含半关闭） |
| `internal/nat.go` | TUN 模式下的用户态 TCP/UDP/ICMP 处理（gvisor netstack） |
| `internal/tun_darwin.go` | `utun` 设备创建、路由增删、IP 包头处理 |
| `cmd/relay/main.go` | 路由表、home/client 分类、状态端点 |
| `cmd/home/main.go` | 收 OPEN、Dial、桥接、ICMP 真探测（原始套接字） |
| `cmd/client/main.go` | SOCKS5 服务、连接池、端口转发、TUN、`/status` |
| `cmd/gateway/*.go` | 门户、子域反代、登录门、改密、Guacamole 代登录 |
