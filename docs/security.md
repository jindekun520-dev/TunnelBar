# 安全

## 威胁模型

| 角色 | 能看到什么 | 信任假设 |
|---|---|---|
| relay（公网服务器） | 密文帧、连接的源/目的时间与大小、流数量 | 假设它可能被攻破；攻破也拿不到内容，但能看到流量特征 |
| home（内网主机） | 内网目标的明文流量（它就是终点） | 完全可信 |
| client（本机） | 本机程序的明文流量 | 完全可信 |
| 网络中间人 | 密文 | 无法解密、无法重放（nonce 校验） |
| 网关 gateway | 浏览器与会话、Guacamole 凭据、内网明文 HTTP | 直接暴露公网，是最大攻击面，必须加固 |

## 传输层

- **AES-256-GCM**，密钥由 **HKDF-SHA256** 从 PSK 派生；握手明文交换 16 字节随机 salt，`session_key = HKDF(PSK, 发起方salt || 响应方salt, "tunnel/v2/psk")`。
- **每条连接独立密钥**：同一 PSK、多次重连都不会出现 `(key, nonce)` 复用。这是 v1 最严重的漏洞（nonce 跨连接从 0 重来，加密强度实际归零）。
- **nonce = 方向位(4B) + 单调计数(8B)**，接收端校验方向与递增，重放 / 乱序 / 反射帧直接丢弃。
- 帧长有上限（`MaxPayload + 64`），畸形帧快速拒绝；单帧写入 10s 兜底超时。

## PSK 管理

**PSK 是唯一凭证**：拿到它既能用隧道，也能冒充你的 home 顶替真实内网主机。

- 生成：`openssl rand -base64 32`；
- 存放：systemd 单元 / 环境变量 / App 配置（`~/Library/Application Support/Tunnel/config.json`，权限 600）。**不要**提交到仓库、写进共享文档、贴进截图、放在 shell 历史里；
- 比对：用 `KeyFingerprint()`（会话密钥前 8 字节），不要打印密钥本身；
- 轮换：三端同时换，顺序 relay → home → client；轮换期间旧 client 会连不上，属预期；
- 泄露处置：立刻换 PSK，并检查 relay 日志里的连接来源。

## 攻击面清单

| 面 | 风险 | 加固 |
|---|---|---|
| relay 7000/7100 | 公网可达，可被扫描与爆破 | 只对必要来源放行；PSK 足够长（≥32 字节随机）；不要在 relay 上跑别的服务 |
| 网关 HTTPS 端口 | 内网管理界面暴露公网 | **先改初始密码**；`secret` 用随机值；能限来源 IP 就限；不要关 HTTPS |
| 网关 Cookie | 窃取后可 14 天免密 | `HttpOnly + Secure + SameSite=Lax`；改密码可一键全端失效 |
| Guacamole `user-mapping.xml` | 内网账号密码明文 | 文件权限最小化；这台机器的 root 权限等于内网入口；备份时加密 |
| guacd 4822 | 若监听在公网网卡会被直接连 | 用 `-b <docker 网段地址>` 只听内部网段 |
| TUN 模式的 sudo 授权 | 包装脚本可被替换则提权 | `/etc/sudoers.d/tunnelbar` 只授权固定路径脚本；脚本内容由 App 安装时写入，注意不要给同目录写权限 |
| 中继可见的元数据 | 流量特征分析 | 无法在应用层完全消除；敏感场景请自行在应用层再加一层加密 |

## 密码体系（网关）

```
pbkdf2-sha256$120000$<salt>$<hash>     存 /etc/tunnelbar/passwd，0600，原子写
Cookie = HMAC-SHA256(secret, "carweb|user|日期|密码指纹")[:32] + "." + 日期
```

- 迭代 120000 次；盐每用户随机；密码明文不进配置文件（`password` 只是**首次**初始化用）；
- 失败登录固定 `sleep 800ms`；
- **改密码即全端失效**：密码指纹混在 Cookie 签名里；
- 换 `secret` 等于强制所有设备重新登录（应急手段）。

## 部署加固清单

- [ ] PSK 为 32 字节以上随机值，未出现在任何仓库 / 文档 / 截图里
- [ ] relay 的 7000/7100 只对必要来源开放
- [ ] 网关初始密码已修改，`secret` 为随机值
- [ ] 泛域名证书有效期监控（`certReloader` 只负责热加载，不负责续期）
- [ ] `passwd` 与 `user-mapping.xml` 权限收紧，备份加密
- [ ] home 侧限定可访问网段（只允许必要的内网目标）
- [ ] 网关日志留存与异常登录告警（`/var/log/tunnelbar/gateway.log`）
- [ ] Guacamole 各连接使用专用低权账号，不用域管理员
- [ ] 定期确认 `systemctl status` 无异常重启（反复重启常意味着被爆破或资源耗尽）

## 报告安全问题

请勿公开提 issue。用仓库主页的邮箱私下联系，或在 GitHub 上开 Security Advisory。
