//go:build !linux

package main

import "time"

// probeICMPHost 非 Linux 平台（本机联调用的 macOS）没有可移植的原始套接字
// 实现，直接走系统 ping 兜底。仅用于本地调试，生产 home 跑在 Linux 上。
func probeICMPHost(host string, timeout time.Duration) (bool, error) {
	return pingFallback(host, timeout)
}
