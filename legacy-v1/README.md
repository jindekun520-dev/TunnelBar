# legacy-v1（存档，已停用）

第一代实现，仅供对照参考，**不要部署**。协议与 v2 不兼容。

- `gui-fyne/main.go`：Fyne 窗口版客户端（有 GUI，但不含菜单栏与资产模型）
- `TunnelClient.app`：v1 打包产物，含二进制与大字体文件，**未入库**（体积原因）；需要时从旧发布包取

v1 的主要缺陷（会导致数据错误，不是"慢"）以及 v2 的修复方式见
[../docs/architecture.md](../docs/architecture.md#7-v1--v2为什么必须重写)。
