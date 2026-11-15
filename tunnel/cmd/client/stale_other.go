//go:build !darwin

// 非 macOS 平台没有 utun/TUN 模式，也就不需要清理 root 孤儿实例。
package main

func killStaleInstances() {}
