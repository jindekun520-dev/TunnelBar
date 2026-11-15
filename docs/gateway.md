# Web 网关（gateway）

给**只有浏览器**的设备用：车机、借来的电脑、家人的手机、平板。它们装不了客户端，也配不了 SOCKS。

```
浏览器 ──HTTPS(单端口)──► gateway ──SOCKS──► client ──► relay ──► home ──► 内网设备
```

gateway 自身**完全不碰隧道协议**，所有出站连接都拨本机 `127.0.0.1:1080`。因此它可以独立启停、独立升级，挂了也不影响隧道本身。

## 1. 两种暴露方式

### 方式 A：子域名（推荐）

一张泛域名证书 + 一个端口，按 `Host` 头分流：

| 对外地址 | 内容 |
|---|---|
| `https://portal.example.com:8443` | 门户页 + `/guacamole/`（浏览器里 SSH / 桌面） |
| `https://esxi.example.com:8443` | ESXi `10.0.0.10:443` |
| `https://nas.example.com:8443` | NAS `10.0.0.11:5001` |
| `https://router.example.com:8443` | 路由器 `10.0.0.1:443` |

**为什么是子域名而不是 `/path` 前缀**：ESXi、TrueNAS 这类前端全部按**绝对路径**取资源、还带 WebSocket，挂在 `/g/esxi/` 下会碎得很干净（JS 里的 `/ui/...` 不会带上你的前缀）。子域名下它们以为自己就在根路径，**一个字节都不用改**。

三个必须注意的点：

- **泛域名证书不覆盖裸域名**。`*.example.com` 不含 `example.com`，所以门户必须挂在 `portal.` 上；直接用裸域名会在 TLS 握手阶段就报证书错误。想用裸域名，得签一张同时含 `example.com` + `*.example.com` 的证书。
- DNS 需要 `*.example.com` 的 A 记录指向网关服务器。
- **Cookie 必须带 `Domain`**：登录 Cookie 写成 `Domain=.example.com`，登录一次四个子域通用。不写 Domain 的话每个子域都要重新登一次——这是子域名方案最容易踩的坑。

### 方式 B：一个端口一台资产（备用）

没有泛域名证书时用：给资产填 `port`，每个端口独占一台设备，全部待在自己 URL 的根路径上。

```json
{ "port": 8444, "name": "ESXi", "target": "10.0.0.10:443", "scheme": "https" }
```

缺点：端口多（防火墙要一条条映射）、同一域名下 Cookie 不区分端口。两种模式可以共存——有 `port` 走端口，没 `port` 走子域名。

## 2. 配置文件

`gateway.json`（默认路径 `/home/carweb/etc/gateway.json`，用 `-config` 覆盖）：

```json
{
  "listen": "0.0.0.0:8443",
  "bind": "",
  "socks": "127.0.0.1:1080",
  "domain": "example.com",
  "portal_sub": "portal",
  "public_port": 8443,
  "user": "admin",
  "password": "首次启动用的初始密码",
  "secret": "随机 32 字节，签 Cookie 用",
  "passwd_file": "/home/carweb/etc/passwd",
  "tls_cert": "/root/ssl/cert.pem",
  "tls_key": "/root/ssl/key.pem",
  "assets": [
    { "sub": "esxi", "name": "ESXi 宿主机", "target": "10.0.0.10:443",
      "scheme": "https", "icon": "▣", "note": "虚拟化 10.0.0.10", "public_port": 0 }
  ],
  "paths": { "/guacamole/": "http://127.0.0.1:8089" },
  "extra": {},
  "guacamole": {
    "path": "/guacamole/",
    "target": "http://127.0.0.1:8089",
    "user": "gcuser",
    "password": "gcpass"
  },
  "wol": { "endpoint": "127.0.0.1:9912", "port": 9, "wait_seconds": 90 }
}
```

| 字段 | 说明 |
|---|---|
| `listen` | 主监听地址（门户 + 路径入口 + 子域反代都在这一个端口上） |
| `bind` | 资产独立端口绑定的地址，留空沿用 `listen` 的主机部分 |
| `socks` | 上游 SOCKS5，一般就是本机 client |
| `domain` | 主域名，子域匹配与 Cookie Domain 都用它 |
| `portal_sub` | 门户所在子域前缀，默认 `portal` |
| `public_port` | **对外**端口。防火墙做了 外部 443 → 内部 8443 时填 443（或 0），门户链接里就不会带端口号 |
| `user` / `password` | 初始账号与**初始**密码（见下节：一旦生成密码文件，这里就被忽略） |
| `secret` | Cookie 签名密钥，建议 `openssl rand -hex 32`，**换掉它等于强制全员重新登录** |
| `passwd_file` | 密码哈希文件，留空用配置文件同目录下的 `passwd` |
| `tls_cert` / `tls_key` | 都填才启 HTTPS；留空跑明文（只适合本机调试） |
| `assets[]` | 资产列表，见下 |
| `paths` | 挂在**门户端口**上的路径前缀 → 本机地址，省一次端口映射（Guacamole 用这个） |
| `extra` | 整个子域名 → 本机端口（不经 SOCKS），老式入口 |
| `guacamole` | 代登录配置，见第 5 节 |
| `wol` | 网络唤醒配置，见第 6 节；不填则门户上不出现「唤醒」按钮 |

### assets 字段

| 字段 | 说明 |
|---|---|
| `sub` | 子域前缀（`esxi` → `esxi.example.com`） |
| `port` | 独立监听端口，`0` 表示只走子域名 |
| `name` / `note` / `icon` | 门户卡片上的标题、说明、字符图标（用字符不用图片，老浏览器也能显示） |
| `target` | 内网地址 `host:port` |
| `scheme` | 后端协议 `http` / `https` |
| `public_port` | 该资产的对外端口（仅 `port` 模式需要） |
| `mac` | 唤醒目标的 MAC。填了门户上就有「唤醒」按钮；只填它、不填 `sub`/`port` 就是纯唤醒设备 |
| `check` | 唤醒后探测「起来了没有」的 `host:port`，默认取 `target` |

## 3. 请求路由顺序

`ServeHTTP` 里的判断顺序**不能乱改**：

1. `/__health` — 无需登录，运维探活用；
2. `/__login` — 登录提交；
3. **登录门**（未登录一律返回登录页）；
4. `/__passwd` — 改密码；
5. `/__guaccred` — 代登录脚本取 Guacamole 凭据（在登录门之后）；
6. `guacSSO` — 抓取并注入 Guacamole 首页；
7. `paths` — 路径前缀反代（**必须排在门户前面**，否则 `/guacamole/` 会被门户的「根域名」分支吃掉）；
8. 门户——`portal.<domain>`、裸域名、`www.`；
9. `extra` — 子域名直连本机端口；
10. 资产子域名反代；
11. 其余 404。

## 4. 登录门与密码

### Cookie

```
值   = HMAC-SHA256(secret, "carweb|user|日期|密码指纹")[:32] + "." + 日期
属性 = Path=/; Domain=.example.com; HttpOnly; Secure; SameSite=Lax; MaxAge=14d
```

- 值里带**签发日期**，14 天后失效；当天与前一天都认，跨零点不会把人踢出去；
- **密码指纹**（密码哈希的 SHA-256 前 16 位）被一起签进 Cookie：**改密码 → 所有设备旧 Cookie 立即失效**，不用逐个去清；
- 失败登录固定 `sleep 800ms`，拖慢爆破；
- `Domain` 放在父域上，子域名方案才能「登录一次全站通用」。

### 密码存储

不以明文长期保存。`passwd` 文件格式：

```
pbkdf2-sha256$120000$<base64 salt>$<base64 hash>
```

- 权限 `0600`，写入走「临时文件 → `fsync` → `rename`」，被杀或断电不会留下半截文件；
- 初始密码来自 `gateway.json` 的 `password`，**首次启动时生成哈希写入 `passwd`，之后该字段就被忽略**（改密码走门户，别改配置）；
- `passwd` 文件丢了/想回滚：删掉它再重启，会重新用配置里的 `password` 初始化。**删文件等于恢复初始密码**，注意别把旧密码留在配置里；
- 配置文件是明文、还会被备份和截图，别把长期密码留在里面。

### 改密码（`/__passwd`）

门户页最后一行有入口。要求：已登录 + 再输一次当前密码；新密码 ≥ 8 位、不能与旧密码相同。改完清 Cookie 回登录页。实现见 `cmd/gateway/passwd.go`——PBKDF2 是手写的，网关保持**零第三方依赖**。

## 5. Guacamole：浏览器里的远程桌面 / 终端

`/guacamole/` 下挂的是 Apache Guacamole，一个纯 Web 的 RDP/SSH 客户端。典型的 docker 部署：`guacd`（把 RDP/SSH 画面转成 WebSocket）+ `guacamole`（前端 + API）。

```
浏览器 ─► gateway /guacamole/ ─► (127.0.0.1:8089) guacamole ─► guacd ─► 127.0.0.1:10022/13389 ─► client 转发 ─► 内网
```

### 为什么原来要输两次密码

Guacamole 是独立应用，有自己的一套用户体系（`user-mapping.xml` 里的 `authorize`），和网关的登录门互不相干，所以点进去还得再登一次。

### 现在的做法：网关代登录（注入脚本自动填表）

网关把 Guacamole 首页抓下来，在 `</head>` 前注入一小段脚本；脚本向 `/__guaccred` 取账号密码（要过网关门才给），填表并**只派发一次** `submit`，走它自己的登录流程。地址栏始终是 `/guacamole/`，没有跳转、没有 URL 残留。

- 页面带 `Cache-Control: no-store`，凭据是现取的，HTML 里没有明文密码；
- 想用原生登录页（换账号、排查问题）：`/guacamole/?manual=1`；
- 取首页失败（容器挂了、密码改了）自动回落原生登录页，不会白屏；
- **改 `user-mapping.xml` 必须 `docker restart <guac 容器>`**，它只在启动时读。

### 走过的死路（别再试）

1. **注入 token 不可行**。Guacamole 1.6 前端把登录态放在内存对象里，`localStorage['GUAC_AUTH_TOKEN']` 只是裸 token；`GET /api/tokens/{token}` 在这个版本上直接 **405**，页面刷新后没有任何接口能把裸 token 换回登录态。往 `sessionStorage` 里塞 token，前端根本不认。
2. **注入页跳 `/guacamole/#/` 也不行**。注入页自己的地址就是 `/guacamole/`，**只改 fragment 属于同文档导航，浏览器不发请求**，页面永远停在「正在进入远程桌面…」的转圈上。

### 两个必须在 Guacamole 侧解决的问题

- **连接名不能含非 ASCII**。Guacamole 用 `btoa(连接ID)` 生成 URL 里的对象 ID，而 `user-mapping.xml` 拿**连接名**当 ID。名字含中文 → `InvalidCharacterError: btoa ... outside of the Latin1 range`，登录 POST 明明 200、权限与连接树接口也都 200，但页面切换被异常打断，**表现就是登录成功却一直停在登录页**。用 `Windows-203`、`Debian-200` 这类纯 ASCII 名。
- **暴力破解封禁会误伤自己**。Guacamole 自带 ban 扩展，默认 5 次失败封 300 秒；而前端每次打开登录页都会先发一次匿名 `POST /api/tokens`（必然 403），正常刷新几下就把自己的 IP 封了。设 `ban-max-invalid-attempts: 0`（外网入口有网关门 + 强密码，风险可控）。

### guacd 的三条硬约束

只验证登录页是不够的，**真正发起连接时才会暴露**：

1. **`guacamole.properties` 里必须写真实地址**：写 `guacd-hostname: guacd` 会 `UnknownHostException: guacd`。而且 compose 里的 `GUACD_HOSTNAME` 环境变量**完全不生效**——它只在镜像首次生成 properties 时用；我们挂载了 `config/`，文件已存在，环境变量就被忽略。
2. **guacd 只听 `127.0.0.1:4822` 时容器连不到宿主回环**。guacd 必须待在 host 网络（它要连 `127.0.0.1` 上 client 的转发端口），但监听地址不能是 `127.0.0.1`。解法：给 compose 网络固定子网 `172.28.0.0/16`，guacd 用 `-b 172.28.0.1` 只听 docker 网段那一侧（公网网卡上不出现 4822），properties 里写 `guacd-hostname: 172.28.0.1`。**子网改了两处要一起改**。
3. **连接里的 `hostname` 不能写 `host.docker.internal`**：那是容器内才有的名字，guacd 在 host 网络里解析不了，报 `Failed to open TCP connection`。写 `127.0.0.1`，端口用 client 的转发端口。

排查口诀（看容器日志）：

| 现象 | 原因 |
|---|---|
| `UnknownHostException: guacd` | 第 1 条 |
| `Failed to open TCP connection` | 第 3 条 |
| `Server refused connection (wrong security type?)` 且端口确实通 | 调连接里的 `security`（`any` / `nla` / `rdp`） |

### 第三层密码

Guacamole 连进去之后，SSH/RDP 各自主机还要一次系统密码。给各连接配好 `<param name="password">`，点进去直接就是终端/桌面。代价是密码明文躺在 `user-mapping.xml`（该文件 0644，因为容器内非 root 要读），注意这台机器的访问控制与备份策略。

## 6. 网络唤醒（WoL）

给资产填上 `mac`，门户卡片右侧会出现「唤醒」按钮：

```json
{
  "assets": [
    { "sub": "esxi", "name": "ESXi 宿主机", "target": "10.0.0.10:443", "mac": "c4:83:4f:18:02:1b" },
    { "name": "Windows 工作站", "target": "10.0.0.23:3389", "mac": "00:1a:2b:3c:4d:5e" }
  ],
  "wol": {
    "endpoint": "127.0.0.1:9912",
    "token": "",
    "port": 9,
    "broadcast": [],
    "wait_seconds": 90
  }
}
```

| 字段 | 说明 |
|---|---|
| `assets[].mac` | 唤醒目标。填了才有按钮；只填 `mac` 而不填 `sub`/`port` 就是「纯唤醒设备」 |
| `assets[].check` | 唤醒后判断「起来了没有」的地址，默认用 `target`；一台机器有多个身份时可指定 |
| `wol.endpoint` | home 端唤醒接口地址，**从 home 的角度看**，通常就是 `127.0.0.1:9912` |
| `wol.token` | 与 home 的 `-wol-token` 一致；home 没配令牌就留空 |
| `wol.port` | 魔术包 UDP 端口，默认 9（少数老网卡只认 7） |
| `wol.broadcast` | 指定广播地址；**推荐留空**，由 home 按各网卡自动算 |
| `wol.wait_seconds` | 门户等待「上线」的上限，默认 90 秒 |

### 为什么必须绕到 home 去发

魔术包是**链路层广播**。网关通常在有公网 IP 的另一台机器上，甚至另一个网段：

- 发往 `10.0.0.255` 的包会被路由器丢掉（定向广播默认关闭）；
- 就算放行，也跨不过 NAT，目标网卡根本收不到；
- 关机状态的网卡只认**自己所在广播域**里的帧。

所以唤醒请求的终点是家里的 `home`：

```
浏览器 --POST /__wake--> gateway --SOCKS--> client --> relay --> home --UDP 广播--> 网卡
```

`home` 的唤醒接口默认只监听 `127.0.0.1:9912`。这不是笔误：远端经隧道访问时，是 **home 自己去 `Dial` 那个地址**，落到它自己的回环上。好处是同一局域网的其它机器**根本连不上**这个接口，不需要额外 ACL；坏处是你不能拿局域网里另一台机器直接调它——那也用不上，本机广播就够了。

### 两个接口

| 接口 | 方法 | 作用 |
|---|---|---|
| `/__wake?k=<资产标识>` | POST | 转给 home 发魔术包，返回实际发出的广播地址与份数 |
| `/__wolstatus?k=<资产标识>` | GET | 探一次目标端口，返回 `{"up":bool,"ms":int}` |

两者都在登录门之后。资产标识优先用 `sub`，没填 `sub` 时用 `name`。

### 门户上的交互

点「唤醒」后：

1. 按钮变成「等待开机…」并置灰；
2. 状态行显示「唤醒包已发出（10.0.0.255 / 255.255.255.255）· 等目标上线…」；
3. 之后每 3 秒调一次 `/__wolstatus`，目标端口通了就显示绿色「已上线（12 ms）」，按钮变「已开机」；
4. 超过 `wait_seconds` 仍未通，显示黄色「还没等到上线」，按钮恢复可点。

**为什么要轮询**：按下按钮到能连上要 30~90 秒（BIOS POST + 系统启动 + 服务起来）。这期间如果页面没有任何反馈，用户只会反复点，然后认为功能坏了。

交互脚本是纯 ES5 + `XMLHttpRequest`，没有 `fetch` / Promise / 箭头函数——车机和借来的旧电脑不一定支持，Guacamole 代登录当初就栽在这上面。

## 7. TLS 与证书热加载

`certReloader` 按证书文件 **mtime** 判断是否重读，`certbot renew` 换完文件即生效，**不需要重启网关**（「证书续了但服务还在用旧的」是最常见的过期事故来源）。读失败时退回上一次成功的证书，避免续期瞬间握手全挂。

泛域名证书用 DNS-01 签发（需要 `*.example.com`），续期脚本里记得 `systemctl reload` 可省，因为网关自己会重载。

## 8. 运维

```bash
# 位置
/usr/local/bin/tunnelbar-gateway         # 二进制
/etc/tunnelbar/gateway.json              # 配置
/etc/tunnelbar/passwd                    # 密码哈希（0600，改密码走门户，不要手改）
/var/log/tunnelbar/gateway.log

# 服务
systemctl status tunnelbar-gateway
systemctl restart tunnelbar-gateway       # 改完配置

# 探活（不需要登录）
curl -sk https://127.0.0.1:8443/__health -H 'Host: portal.example.com'
```

**改配置不用重启的情况**：只有证书能热加载。`assets` / `paths` / 密码以外的改动都要 `restart`。

**端口被占用排查**：

```bash
ss -ltnp | grep 8443
```

一个常见来源是同一台机器上别的容器（compose 里发布了 `8443:8443`）。要让出端口又不破坏原服务，把它 compose 里那条 `ports` 注释掉再单独 `up -d --no-deps <service>`，别整机 `down`。
