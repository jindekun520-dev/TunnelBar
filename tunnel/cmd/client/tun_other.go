//go:build !darwin

// TUN 模式目前只在 macOS 上实现（utun + gvisor netstack）。
// 其它平台保留编译占位，避免三端共用代码时构建失败。
package main

import (
	"fmt"
)

type tunManager struct {
	errMsg string
}

func startTUN(t *tunnel, routeSpec string, mtu int) (*tunManager, error) {
	return nil, fmt.Errorf("TUN 模式当前仅支持 macOS")
}

func (m *tunManager) Close() {}
