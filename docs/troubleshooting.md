# 故障排查

按现象查。

## 连不上内网任何设备

```bash
lsof -nP -iTCP:1080 -sTCP:LISTEN          # 本机 SOCKS 是否在听
curl -s http://127.0.0.1:9908/status | python3 -m json.tool | head   # client 视角
curl -s http://127.0.0.1:9911/status      # relay 视角：home 在线吗
systemctl status tunnel-home              # 家里主机上的 home 在跑吗
nc -z 203.0.113.10 7000                   # 家里能不能连到 relay
```

判断顺序：**home 在线 → client 就绪 → SOCKS 监听了 → 目标端口通**。任何一环断了，后面的都是白费。

## 日志说「握手失败: 解密失败」

三端 `-key` 不一致。用 `KeyFingerprint()` 比对两端密钥指纹，不必打印密钥本身：

```bash
./bin/relay -key "$PSK" -v 2>&1 | grep -i fingerprint
```

注意 shell 里的 `!`、`$`、引号可能吃掉密钥字符，建议用单引号并把 PSK 放文件里读。

## 日志说「协议版本不匹配」

还有一端跑的是 v1 二进制。三端都要换成 v2，顺序 relay → home → client。

## 菜单栏一直「启动中」或「连不上中继」

v2 的 client 对 v1 的 relay 发 hello，v1 不认识、不回包，客户端读 hello 超时，池内连接数一直是 0。菜单栏会直接给结论：

```
连不上中继 · 已重试 1 次
中继无 v2 握手响应（5s 前）：服务端大概率仍是 v1，需先升级 relay
```

点这一行可复制完整报错。原始报错形如：

```
连接 relay 失败: tunnel: 握手失败: 读取 hello: read tcp ...: i/o timeout
```

```bash
curl -s http://127.0.0.1:9908/status | python3 -m json.tool
# ready=false、pool_alive=0、ok_count=0、fail_count>0 → 中继没接上
```

## 能连上但访问很慢

1. `-pool` 调到 8 试；
2. 看 `/status` 的 `pool[]`：某一条 `rtt_ms` 明显偏大 → 这条通道有问题（会自动隔离重建）；
3. 全都慢 → 本机网络；池正常但端到端慢 → relay ↔ home 那一跳；
4. 大包卡、小包通 → `-tun-mtu 1280`。

## 网页白屏 / 资源加载失败（走网关时）

- 检查是不是用了 `/path` 前缀暴露 ESXi / NAS：它们的 JS 用绝对路径，挂子路径必碎。改用子域名；
- 检查 `paths` 的判断是否排在门户之前——否则 `/guacamole/` 会被门户吃掉。

## 门户登录后点资产又要登录一次

Cookie 没带 `Domain`。必须是 `Domain=.example.com`，否则每个子域各自持有独立 Cookie。

## 改密码后旧设备还进得去

检查 `secret` 是否被改动过、`passwd` 文件是否真的写成功（`ls -l` 看 mtime）。正常情况下改密会改 `passTag`，旧 Cookie 立刻失效。

## 忘记门户密码

删掉 `passwd` 文件再重启网关，会用配置里的 `password` 重新初始化——**等于恢复初始密码**，所以别把旧密码留在配置里。

## `/guacamole/` 转圈、一直「正在进入远程桌面…」

按顺序排：

1. 容器起来了吗：`docker ps | grep guac`；
2. 首页取不到 → 网关会自动回落原生登录页，如果原生页也是白的，说明上游挂了；
3. 手动登录能进但页面卡住 → **连接名含中文**，看 `docker logs <guac 容器>` 有没有 `btoa ... outside of the Latin1 range`；
4. 登录页反复要求登录、几次后被封 → `ban-max-invalid-attempts: 0` 没设；
5. 点连接时报 `Failed to open TCP connection` → 连接里的 hostname 用了容器内名字，改 `127.0.0.1`；
6. `UnknownHostException: guacd` → properties 里 guacd 地址没写实地址；
7. `Server refused connection (wrong security type?)` 且端口通 → 调 RDP 的 `security`。

完整机制见 [gateway.md](gateway.md#5-guacamole浏览器里的远程桌面--终端)。

## 证书报错（NET::ERR_CERT）

- 泛域名证书**不含裸域名**：用 `portal.example.com`，别用 `example.com`；
- 续期后仍报旧证书 → `certReloader` 按 mtime 重载，确认新文件的 mtime 变了（`stat` 一下），否则说明续期脚本写到了别处；
- 直接访问 IP 一定报错，证书只对域名有效。

## 端口被占用 / 启动失败

```bash
ss -ltnp | grep <端口>
```

同一台机器上别的容器（compose 里 `ports: "8443:8443"`）是常见来源。让出端口用「注释掉那条 ports + `docker compose -f ... up -d --no-deps <service>`」，别整机 `down`。

## `scp` 覆盖二进制报 ETXTBSY

正在运行的二进制不能被覆盖写。先 `systemctl stop <svc>`，拷完再 `start`。

## 密集 ssh 后突然 Permission denied

多数服务器 sshd 有连接限流（`MaxStartups`），连着几条 `scp`/`ssh` 会短时拒绝，等 30~60 秒自动恢复，**不是密码错**。批量操作加 `ControlMaster` 复用连接即可避免。

## 开机自启没生效（macOS）

```bash
plutil -lint ~/Library/LaunchAgents/com.jindekun.tunnel.client.plist
launchctl print gui/$(id -u)/com.jindekun.tunnel.client | head -20
```

`launchctl bootstrap` 报 `Input/output error` 一般是 plist 本身 XML 不合法（v1 曾把 `<key>KeepAlive</string>` 写坏）。仍失败就用图形入口：系统设置 → 通用 → 登录项与扩展 → 添加 `~/Library/Application Support/Tunnel/client`。

## TUN 模式路由不生效

```bash
route -n get 10.0.0.12        # 看 actual interface 是不是 utunN
ifconfig utunN                # 有没有 198.18.0.1 这个地址
```

`route add` 退出码为 0 但内核拒绝是常见现象（接口没配 IPv4 时）。两个都要核对。

## 唤醒按了没反应（WoL）

先分清「包没发出去」还是「发出去但没醒」：

```bash
# 1) home 侧真的发出去了吗（有这行说明包已经进了内网广播域）
journalctl -u tunnel-home | grep 唤醒包

# 2) 菜单栏 App 两条路各自的结论（不用点菜单）
/Applications/TunnelBar.app/Contents/MacOS/TunnelBar --woltest AA:BB:CC:DD:EE:FF

# 3) 网关转发给谁（改了 endpoint 之后最容易出错的地方）
journalctl -u carweb-gateway | grep -i wol
```

- **「连不上家里主机的唤醒接口」**：`wol.endpoint` 是**从 home 视角**看的地址，通常就是 `127.0.0.1:9912`。写成 `10.0.0.12:9912` 一般也能通（那是 home 自己的地址），但写成公网 IP 一定不通。
- **`sent: 0` 或提示没有可用广播地址**：home 那台机器只有回环、或者网卡都没 `BROADCAST` 标志。检查 `ip -4 addr`。
- **包发出去了但机器不醒**，按可能性从高到低查：
  1. MAC 填错（最常见）。在**目标开机时**用 `ip neigh | grep <IP>` 或路由器 DHCP 绑定表核对。**注意**：目标关机时 ARP 表里的记录可能是别的设备（代理 ARP / 静态绑定），不能拿来当准；
  2. BIOS/UEFI 里没开 Wake-on-LAN（有的叫 `Power On by PCIe`、`ErP` 要关掉）；
  3. 操作系统里网卡没允许唤醒：Windows「设备管理器 → 网卡 → 电源管理 → 允许此设备唤醒计算机」，Linux `ethtool -s eth0 wol g`（**很多网卡断电后不保留这个设置**）；
  4. 交换机/路由器丢弃广播，或目标接在 Wi-Fi 上（无线唤醒多数不支持）；
  5. 端口不对：老网卡只认 7，把 `wol.port` / `wolPort` 改成 7 试试。
- **门户显示「已上线」但打不开**：`check` 探的是 TCP 端口，可能探到了别的服务。显式给资产填 `check` 指到真正的服务端口。

## ping 通但 TCP 不通 / 反向

- ping 通 TCP 不通：目标主机的防火墙只放了 ICMP；
- TCP 通 ping 不通：home 侧拿不到 `CAP_NET_RAW` 且没有 `ping` 命令，ICMP 探测失败（会自动退回 fork `ping`，日志里写「原始套接字不可用」）。
