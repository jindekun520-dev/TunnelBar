# 参与贡献

欢迎 issue 和 PR。中文、英文都可以。

## 本地开发

```bash
git clone https://github.com/<you>/tunnelbar.git && cd tunnelbar/tunnel
./scripts/build.sh          # 编译 + 跑单测 + 重新打包 App
./scripts/e2e-test.sh       # 本机全链路（不碰生产端口）
go test ./internal/ -race   # 只跑协议层
```

要求 Go 1.25+（`go.mod` 里 `go 1.25.0`）。依赖已 vendor 到 `third_party/`，默认离线编译。

## 提 PR 之前

- `go vet ./cmd/... ./internal/` 干净；
- `go test ./internal/ -race` 通过；
- 涉及协议 / 帧格式的改动，先开 issue 讨论——**协议不向下兼容**，改动要让三端同时升级；
- 涉及 macOS App 的改动，附上 `bash app/build-app.sh` 能过；
- 不要提交：`bin/`、`tunnel/app/.build/`、`TunnelBar.app/`、任何 `*.bak-*`、任何含真实密钥/密码/内网地址的配置。

## 代码风格

- 注释用中文，解释**为什么**而不是**做了什么**；踩过的坑写清楚，比抽象描述有价值；
- 数据面（每帧路径）不要打日志，只在控制面 / 错误路径打；
- 新增参数要有合理默认值，并在 `docs/` 里补一行说明。

## 报告问题

请附：版本（`VERSION`）、三端各自平台、`/status` 输出（脱敏）、能复现的最小步骤。**不要贴 PSK**。

安全问题请走私下渠道，见 [docs/security.md](docs/security.md#报告安全问题)。
