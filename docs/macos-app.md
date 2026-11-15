# macOS 菜单栏 App（TunnelBar.app）

纯 AppKit + `swiftc` 手写构建，**零第三方依赖**（没有 SwiftPM、没有 Electron）。它做的事：替你拉起 / 托管 client 进程，并把「隧道状态 + 内网资产」塞进菜单栏。

## 菜单栏图标

模板图渲染，颜色跟随菜单栏自动变化（浅色菜单栏=深色，深色菜单栏=白色），和 WiFi、电池、时钟一致。**状态靠形状区分**：

| 状态 | 图标 |
|---|---|
| 已连接 | 盾牌 + 对勾 `checkmark.shield` |
| 部分可用 / 连接中 | 盾牌 `shield` |
| 池内连接不全 | 盾牌 + 感叹号 `exclamationmark.shield` |
| 未连接 | 斜线盾牌 `shield.slash` |

## 菜单项

| 菜单项 | 作用 |
|---|---|
| 顶部四行 | 连接状态、池内连接数、收发流量、活跃流、运行时长 |
| 延迟 | 每 15s 通过隧道探一次 `probe` 目标，显示真实 RTT（`probe` 为空则不显示） |
| 连接 / 断开 | 拉起或停止内嵌 client，退出 App 时一并收尾，不留孤儿进程 |
| 测试连通性 ⌘T | 走 SOCKS5 实际建连一次，失败给出三类可能原因 |
| **资产 ▸** | 一个列表管所有内网入口。每行：名称 + 地址 + 账号，前面的 `●`/`○` 表示它依赖的本地转发端口是否就绪。点一下先弹面板（地址、连接方式、账号、密码状态），面板里可「打开 / 编辑 / 复制账号 / 复制密码」；下面是「添加资产…」「编辑资产 ▸」「移除资产 ▸」 |
| **端口转发 ▸** | 底层管道视图。规则全部由资产派生（填了本地端口的资产才会出现），点一条等于打开对应资产面板，旁边小字是资产名。改端口请去「编辑资产」。底部保留「添加临时转发…」给临时开端口、不建资产的场景 |
| **唤醒设备 ▸** | 列出所有配了 `mac` 的资产，点一下发魔术包；底部「唤醒全部」一次唤醒所有配了 MAC 的设备。资产面板里也会多一个「唤醒」按钮 
| **连接池 ▸** | 逐条列出池里每条连接：到中继的 RTT、当前承载流数、空闲时长、收发光、RST/卡死计数，隔离中的会标出来。点一行复制它的完整明细；另有「复制池诊断」「重建连接池」（重启 client，不动 App） |
| 启动本机自测 | 本机起 relay + home + 测试站点 + client（17000/17100/11080/18080），不碰生产端口 |
| 打开日志 ⌘L | `~/Library/Logs/TunnelBar/client.log` |
| 打开配置 ⌘, | `~/Library/Application Support/Tunnel/config.json` |
| 重新加载配置 ⌘R | 改完配置不用重启 App |
| 复制 SOCKS 地址 ⌘C | 得到 `socks5h://127.0.0.1:1080` |
| 开机自启 | 写入并加载 `~/Library/LaunchAgents/com.jindekun.tunnelbar.plist`（与 `scripts/install-macos-agent.sh` 二选一） |

「资产」「端口转发」「连接池」子菜单在每次菜单弹出时重建（`menuWillOpen`），所以端口状态永远是实时的。主菜单显式关闭 `autoenablesItems`——否则带 submenu 却没有 action 的父项会被 AppKit 判成不可用、显示成灰色。

## 资产模型

一条资产回答三个问题：**去哪**（host:port）、**用什么连**（protocol）、**用谁的身份**（账号 + 钥匙串密码）。

```json
{
  "id": "UUID",
  "name": "ESXi 宿主机",
  "host": "10.0.0.10",
  "port": 443,
  "scheme": "https",
  "user": "root",
  "localPort": 18443,
  "note": "",
  "mac": "c4:83:4f:18:02:1b"
}
```

`mac` 可选，填了这台资产就能被网络唤醒（见下节）。

- `localPort` 有值 → 派生 `18443:10.0.0.10:443` 传给 client 的 `-forward`；`null` → 直连（依赖 TUN 或 SOCKS）。
- **什么时候需要本地端口**：只有浏览器这类不认代理的程序才需要。SSH、curl 直连就行。
- **改端口只需改一处**：以前改转发端口会让资源清单里的 URL 失效；现在两者是同一条记录。
- **删除资产**会连带删掉它的本地转发和钥匙串里的密码。
- 老配置里的 `resources` + `forwards` 会在首次启动时自动配对合并，一条不丢；原始配置备份在 `~/Library/Application Support/Tunnel/config.before-assets-*.json`。

## 打开方式

### SSH（`scheme = ssh`）

```
ssh -p 2022 -o StrictHostKeyChecking=accept-new -o NumberOfPasswordPrompts=1 root@127.0.0.1
```

- **必须写成 `ssh -p 端口 账号@主机`**，不能写 `ssh 127.0.0.1:2022`——后者 OpenSSH 会把冒号后整段当主机名去 DNS 解析，报 `Could not resolve hostname`。
- 密码存**系统钥匙串**（service=`TunnelBar`），配置文件里只有一个「有没有密码」的间接判断，永远不出现明文。
- 自动填密码靠 `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`（需要 OpenSSH ≥ 8.4）：App 在 `~/Library/Caches/TunnelBar/askpass/` 写一个 0700 的临时脚本，内容只有密码的 base64，终端命令末尾带 `rm -f` 在会话结束时删掉。
- `-o NumberOfPasswordPrompts=1` 防止密码错反复重试把账号锁掉；`StrictHostKeyChecking=accept-new` 只自动接受首次主机密钥，之后密钥一变仍报错。
- App 是 ad-hoc 签名，每次重新签名后首次读取密码，系统可能弹一次钥匙串授权，点「始终允许」即可。

### RDP（`scheme = rdp`）

生成 `.rdp` 文件交给 **Windows App**（原 Microsoft Remote Desktop）打开：

```
~/Library/Caches/TunnelBar/rdp/<资产ID>.rdp

full address:s:10.0.0.20:3389
username:s:youruser
prompt for credentials:i:0
authentication level:i:2
screen mode id:i:2
```

- **不能用 `rdp://主机:端口`**。Windows App 只认微软旧版 RDP URI 语法，裸 URL 会被回一句「URL 无效」。直接写 `.rdp` 文件是微软文档里给的自动化方式。
- 账号会自动填好，**密码填不了**：`.rdp` 里必须是 Windows DPAPI 密文（`password 51:b:...`），macOS 算不出来。首次输完勾「记住我」即可。
- 一个资产固定一个文件名，避免每点一次就在「保存的设备」里多一张重复卡片。
- `localPort` 有值时连 `127.0.0.1:<本地端口>`，否则直连内网 IP。

### VNC（`scheme = vnc`）

用系统自带「屏幕共享」，URL 为 `vnc://账号@主机:端口`，密码由系统对话框接管。

### SMB / HTTP(S)

`smb://` 走系统挂载，`https://` 交给默认浏览器。指向 `127.0.0.1:<端口>` 的条目会自动关联同名本地转发，用于显示 `●`/`○` 状态。

## 网络唤醒

给资产填上 MAC（编辑资产 → 最后一行 `MAC`，`AA:BB:CC:DD:EE:FF`、`aa-bb-…`、裸 12 位都认），菜单「资产」里就多一个 **唤醒设备 ▸**。

点一次会**同时走两条路**，都失败才算失败：

| 路径 | 什么时候有效 | 说明 |
|---|---|---|
| 本机 UDP 广播 | Mac 和目标在同一网段（人在家里） | 按每块网卡的掩码算定向广播地址（`10.0.0.1/24` → `10.0.0.255`），逐个发 102 字节魔术包 |
| 经隧道由 home 代发 | 人在外面 | 走本机 SOCKS → relay → home → home 在自己的广播域广播 |

两条都发没有任何副作用：魔术包幂等，重复发不会把机器搞乱。结果会实打实告诉你哪条通、哪条不通。

```json
"wolPort": 9,
"wolViaTunnel": true,
"wolEndpoint": "127.0.0.1:9912",
"wolBroadcast": []
```

| 字段 | 说明 |
|---|---|
| `wolPort` | 魔术包 UDP 端口，默认 9；少数老网卡只认 7 |
| `wolViaTunnel` | 是否经隧道让 home 代发，默认开 |
| `wolEndpoint` | home 端唤醒接口地址，**从 home 视角**看通常是 `127.0.0.1:9912` |
| `wolBroadcast` | 手动指定广播地址；**留空推荐**，自动按网卡算 |

命令行自检（不用点菜单，排查用）：

```bash
/Applications/TunnelBar.app/Contents/MacOS/TunnelBar --woltest AA:BB:CC:DD:EE:FF
```

输出会依次给出：MAC 是否解析成功与规范化结果、魔术包结构校验、本机广播地址列表、本机发出份数、经隧道的成功/失败原因。

## 配置

```json
{
  "relay": "203.0.113.10:7100",
  "key": "三端一致的预共享密钥",
  "socksPort": 1080,
  "statusPort": 9908,
  "pool": 6,
  "forwards": ["18443:10.0.0.10:443", "10022:10.0.0.12:22"],
  "assets": [],
  "probe": "10.0.0.12:22",
  "autoConnect": true,
  "pinToScreen": "main",
  "menuBarTitle": "隧道",
  "tunEnabled": false,
  "tunRoutes": ["10.0.0.0/24"],
  "tunMTU": 1400,
  "wolPort": 9,
  "wolViaTunnel": true,
  "wolEndpoint": "127.0.0.1:9912",
  "wolBroadcast": []
}
```

| 字段 | 说明 |
|---|---|
| `relay` | 中继地址（client 端口） |
| `key` | 预共享密钥。**首次请自己在设置里填**，仓库里的默认值是空的 |
| `probe` | 延迟探测目标 `host:port`，走隧道访问；留空则菜单不显示延迟 |
| `pool` | 池内并发连接数 |
| `pinToScreen` | `main`（锁定含坐标原点的主屏）/ `cursor`（鼠标所在屏）/ `none`（交给系统）。多显示器下系统可能把状态项摆到没有菜单栏的那块屏、停在屏幕外，`main` 会在启动后 1/3/8 秒各校正一次纵向落点 |
| `menuBarTitle` | 图标旁的文字，留空只显示图标 |
| `tunRoutes` / `tunMTU` | TUN 模式接管的网段与 MTU |
| `wolPort` / `wolViaTunnel` / `wolEndpoint` / `wolBroadcast` | 网络唤醒参数，见上节 |

配置解码是**逐字段容错**的：老配置文件缺新字段时取默认值，不会因为一处缺失把整份配置重置。

## 图标重做 / 换图标

```bash
python3 tunnel/make_app_icon.py --preview        # 生成 app.icns + 各尺寸预览，先肉眼过一遍
codesign --force --deep --sign - TunnelBar.app   # 改了 Resources 就必须重签，否则启动即 SIGKILL
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$PWD/TunnelBar.app"
```

三步少一步就会看到旧图标或者干脆空白。`Info.plist` 靠 `CFBundleIconFile = app.icns` 指向；`build-app.sh` 会自动复制 icns。

## 打包

```bash
cd tunnel && bash app/build-app.sh      # 产出项目根目录的 TunnelBar.app
```

`Contents/Resources/` 会自带 client、relay.local、home.local，所以 `scripts/build.sh` 跑完会自动重新打包，避免 App 内嵌二进制与 `bin/` 不一致。

## 找不到菜单栏图标时

App 已在运行时再从访达双击一次 `TunnelBar.app`，菜单会直接弹在鼠标位置。图标实际落点记录在 `~/Library/Logs/TunnelBar/app.log` 的「状态项位置」行（形如 `{{480, 868}, {63, 30}} → 屏#0`）。
