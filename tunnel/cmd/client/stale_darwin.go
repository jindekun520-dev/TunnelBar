//go:build darwin

// 启动前清理残留的旧实例。
//
// TUN 模式下 client 以 root 运行：如果上层 App 被强制结束（kill -9、崩溃），
// 这个 root 子进程会变成孤儿继续占着 9908/1080 和各个转发端口，
// 新实例随后会因为端口被占而直接退出，表现就是「开了 TUN 却没有任何效果」。
// 只有 root 才有权结束这些孤儿，所以这段逻辑仅在 euid==0 时执行。
package main

import (
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// killStaleInstances 结束同一可执行文件的其它实例（不含自己与父进程）。
func killStaleInstances() {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return
	}
	out, err := exec.Command("/usr/bin/pgrep", "-f", exe).Output()
	if err != nil {
		return // 没有其它实例时 pgrep 返回 1
	}
	self := os.Getpid()
	parent := os.Getppid()
	var killed []int
	for _, field := range strings.Fields(string(out)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid == self || pid == parent {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err == nil {
			killed = append(killed, pid)
		}
	}
	if len(killed) == 0 {
		return
	}
	log.Printf("[client] 结束残留实例 %v", killed)

	// 给它们一点时间做收尾（删路由、关 utun），之后再强杀没退的。
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		alive := false
		for _, pid := range killed {
			if syscall.Kill(pid, 0) == nil {
				alive = true
				break
			}
		}
		if !alive {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, pid := range killed {
		if syscall.Kill(pid, 0) == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	time.Sleep(300 * time.Millisecond)
}
