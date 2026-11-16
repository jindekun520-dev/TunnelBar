package main

// 建连失败日志去重。
//
// 背景：菜单栏 App 会周期性探测资产状态（默认 60 秒一轮，历史上是 2 秒一轮
// 探一个写死的地址）。一台关机设备的失败足以把 client.log 刷成几万行——
// 真正的问题全被埋在噪声里，用户看到的是「日志一直在报错」。
//
// 这里按「目标地址」记状态：连续失败只在第一次记一条，恢复时补一条。
// 一个目标从早到晚不可达，日志就是一行，而不是一行乘上探测次数。

import (
	"log"
	"sync"
)

var (
	dialLogMu   sync.Mutex
	dialFailing = map[string]bool{}
)

// logDial 记录一次拨号结果，err == nil 表示成功。
//
// 只有同目标的「状态翻转」才落日志：
//
//	首次失败 → 记一条（之后重复失败静默）
//	恢复成功 → 记一条
//
// 非 verbose 模式直接返回，零开销（公网机上的 client 一般不开 -v）。
func logDial(target string, err error) {
	if !verbose {
		return
	}

	dialLogMu.Lock()
	wasFailing := dialFailing[target]
	if err != nil {
		dialFailing[target] = true
	} else if wasFailing {
		delete(dialFailing, target)
	}
	dialLogMu.Unlock()

	switch {
	case err != nil && !wasFailing:
		log.Printf("[client] %s 建连失败: %v（恢复前不再重复记录）", target, err)
	case err == nil && wasFailing:
		log.Printf("[client] %s 已恢复", target)
	}
}
