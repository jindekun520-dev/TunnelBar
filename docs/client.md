# client（本机端）

`client` 负责把隧道变成一个「本机可用的网络出口」：SOCKS5、固定端口转发、可选 TUN 虚拟网卡，外加一个只读状态接口给菜单栏 App / 监控用。

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-relay` | `relay.example.com:7100` | relay 的 client 端口 |
| `-key` | 必填 | 预共享密钥，三端一致 |
| `-socks` | `1080` | 本地 SOCKS5 监听端口 |
| `-forward` | 空 | 固定端口转发，逗号分隔：`18443:10.0.0.10:443,10022:10.0.0.12:22` |
| `-pool` | `6` | 到 relay 的并发连接数 |
| `-open-timeout` | `3s` | 等待对端建连应答的超时（踩到死连接时只损失 3s） |
| `-dial-timeout` | `10s` | 连 relay 的超时 |
| `-linger` | `60s` | 单方向结束后等另一方向的最长时间 |
| `-fin-guard` | 见 `internal.DefaultFinGuard` | 关闭流前多等一会儿再发 FIN，规避 relay 路由 ID 复用的串包 |
| `-status` | 空 | 状态接口监听地址，如 `127.0.0.1:9908` |
| `-tun` | 关 | 全局直连模式（**需要 root**） |
| `-tun-routes` | `10.0.0.0/24` | TUN 接管的网段，逗号分隔 |
| `-tun-mtu` | `1400` | TUN 接口 MTU（隧道再套一层 TCP，留余量避免二次分片） |
| `-hedge` | 关 | 建流超时并行发起第二条（需新版 relay，默认关） |
| `-v` | 关 | 详细日志 |

## SOCKS5

标准 SOCKS5，支持 CONNECT，UDP ASSOCIATE / BIND 明确回「命令不支持」（不会莫名掐断连接）。建议用 `socks5h://` 形式让 DNS 在对端解析，避免内网域名在本地解析失败：

```bash
curl -s --socks5-hostname 127.0.0.1:1080 http://10.0.0.11/ -o /dev/null -w '%{http_code}\n'
ssh -o ProxyCommand="nc -x 127.0.0.1:1080 %h %p" root@10.0.0.12
```

浏览器（Chrome 需装 SwitchyOmega，Safari 跟随系统代理）指向 `127.0.0.1:1080` 即可。

## 固定端口转发

给**不认代理**的程序用（老式管理界面、某些客户端软件、需要固定端口的数据库工具）。

```
-forward 18443:10.0.0.10:443,10022:10.0.0.12:22
         └本地端口┘ └─目标主机─┘ └端口┘
```

之后访问 `127.0.0.1:18443` 等价于内网 `10.0.0.10:443`。

> **https 站点请用与目标一致的端口号**。浏览器不会把证书和站点名映射到别的端口：`10.0.0.10:443` 的证书只对「访问 443」有效，映射到 18443 会报证书错误——除非你本来就打算用 18443 那个端口访问。

## TUN 全局直连模式

不配代理、不配端口转发，像坐在家里一样直接访问内网 IP（含 ping、任意端口、UDP）。

```bash
sudo ./bin/client -relay 203.0.113.10:7100 -key '你的PSK' \
  -tun -tun-routes 10.0.0.0/24 -status 127.0.0.1:9908
```

实现要点（都是踩过的坑）：

- 打开 `utun` 后**必须给接口配 IPv4 地址**（本端与对端同为 `198.18.0.1`）。否则 `route add -net ... -interface utunN` 退出码仍是 0，但内核实际拒绝（`Network is unreachable`），表现为「路由加了却不生效」。
- 路由加完要用 `route -n get <网段>` 复核实际出口接口；只看 `route` 退出码会漏判。
- 半关闭转发必须用 `interface{ CloseWrite() error }` 断言，不能写死 `*net.TCPConn`：TUN 下是 `*gonet.TCPConn`，写死会导致数据收完却不发 FIN，`curl` 挂到超时。
- ICMP 不是本地伪造应答：隧道只承载 TCP/UDP，client 收到 echo request 后向 home 开一条 `ProtoICMP` 流，home 在目标网段**真的发一次** ICMP echo，可达才回。**不可达就是超时**，不会出现「ping 什么都通」。
- 以 root 运行的 client 启动时会先清理同路径的残留实例，避免 App 被强杀后孤儿进程占着 9908/1080 导致新实例起不来。
- 每 5s 给每条池连接发 PING，12s 无响应摘出池并重建（移动热点/家用 NAT 常在空闲十几秒后悄悄丢映射）。

### ping 的延迟为什么「3 个快、1 个慢」

不是网络问题：可达结果有 3s 正向缓存，命中的包在本地立刻回包（0.3~0.7ms，纯属合成），过期那一包才真的跑一趟往返（80~110ms）。**慢的那些才是真实 RTT**。不希望被干扰的话，把 `internal/nat.go` 里「可达结果缓存」关掉（只保留 2s 的不可达缓存以抑制探测流堆积），重新编译即可。

另外合成应答直接照抄请求的 IP 头，**`ttl` 恒为 64**，这是 TUN 模式的正常特征。

### 菜单栏里的 TUN 授权

首次开启会弹一次管理员授权，写入两个文件：

- `/usr/local/bin/tunnelbar-client`：无空格路径的包装脚本（安装路径带空格，写不进 sudoers 的命令字段）
- `/etc/sudoers.d/tunnelbar`：仅授权上面这个脚本以 root 运行

不想要了，删掉这两个文件即可恢复。

## 状态接口

`-status 127.0.0.1:9908`，只读 JSON：

```bash
curl -s http://127.0.0.1:9908/status | python3 -m json.tool
```

```json
{"protocol":2,"relay":"203.0.113.10:7100","socks":"127.0.0.1:1080","ready":true,
 "pool_alive":6,"pool_total":6,"active":2,"opened":37,
 "tx_bytes":184320,"rx_bytes":20481024,"resets":0,"stalled":0,"uptime_s":126,"pid":88494,
 "last_error_age_s":-1,"fail_count":0,"ok_count":6,
 "tun":{"enabled":true,"device":"utun7","mtu":1400,"routes":["10.0.0.0/24"],
        "tcp_total":12,"udp_total":3,"tcp_active":2,"udp_active":0,
        "icmp_replies":4,"outbound_drops":0},
 "pool":[{"i":0,"alive":true,"suspect":false,"age_s":126,"idle_ms":120,
          "rtt_ms":58,"active":1,"opened":12,"tx_bytes":8123,"rx_bytes":91002,
          "resets":0,"stalled":0,"err":""}]}
```

连不上时多出诊断字段：

```json
{"ready":false,"pool_alive":0,"pool_total":0,
 "last_error":"tunnel: 握手失败: 读取 hello: read tcp ...: i/o timeout",
 "last_error_age_s":5,"fail_count":1,"ok_count":0}
```

`ok_count=0 且 fail_count>0` 表示一次都没成功过，属于「连不上」而不是「正在连」。状态接口与 SOCKS 在进程启动瞬间就监听，不等中继握手，所以 `uptime_s` 很小时也能立刻查询。

## 连接池读数

`6/6` = 池内**存活通道数 / 目标通道数**。

| 读数 | 含义 | 处理 |
|---|---|---|
| 6/6 | 全部就绪，正常稳态 | 不用管 |
| 5/6 且几秒内回满 | 掉了一条已自动补回 | 自愈，不用管 |
| 长期 < 6 或反复掉 | 链路质量差 / 中继不稳 / 本地网络受限 | 看 `last_error` |
| 0/6 | 中继不通、密钥不对、relay 没起 | 必查 |

**池里的 RTT 是「到中继」，不是端到端**：心跳 PING 由 relay 直接回 PONG。端到端延迟请走隧道探一个内网目标。两者配合定位：

- 全都慢 → 本机网络；
- 只有一条慢 → 这条通道有问题；
- 池 RTT 正常但端到端慢 → relay ↔ home 那一跳。

## 信号与退出

- `Ctrl-C` / `SIGTERM`：停 SOCKS、关池、删 `utun`（TUN 模式下）、结束所有活跃流；
- 后台进程被强杀后，新实例启动时会清理同名残留实例占用（仅 root，TUN 模式）；
- 退出时若有 `-status` 端点，会先返回 503 再关闭，方便探活脚本区分「正在退出」与「崩了」。
