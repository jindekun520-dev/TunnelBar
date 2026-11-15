package main

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

// pingFallback 在拿不到原始套接字权限时，退回系统 ping 做一次探测。
// 精度差一点（多一次 fork），但有结果总比功能整体不可用强。
func pingFallback(host string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()

	args := []string{"-c", "1", "-n", "-W", "1", host}
	if runtime.GOOS == "darwin" {
		args = []string{"-c", "1", "-n", "-t", "1", host}
	}
	if err := exec.CommandContext(ctx, "ping", args...).Run(); err != nil {
		return false, nil
	}
	return true, nil
}
