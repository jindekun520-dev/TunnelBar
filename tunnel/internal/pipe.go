package internal

import (
	"io"
	"net"
	"sync"
	"time"
)

// Bridge 在一条复用流与一个本地 net.Conn 之间双向转发，并正确处理半关闭。
//
// v1 的致命问题在这里：只要任一方向结束就整体 Close，
// 导致 HTTP/1.0、SSH、长下载这类依赖半关闭的协议被中途砍断。
// 正确语义是：某一方向读到 EOF 只发 FIN，另一方向继续，直到双方都收尾或超时。
func Bridge(st TunnelStream, c net.Conn, linger, finGuard time.Duration) {
	done := make(chan struct{}, 2)

	var closeOnce sync.Once
	abort := func() {
		closeOnce.Do(func() { _ = c.Close() })
	}

	// 本地 → 隧道
	go func() {
		_, err := io.Copy(st, c)
		if err != nil {
			// 本地连接异常（RST 等）：直接终止两端，避免另一方向永久阻塞。
			st.Reset(err)
			abort()
		} else {
			// 延迟一点再发 FIN：relay 一看到 FIN 就把这条流的路由 ID 回收进
			// freeRID 池，紧接着就把同一个 ID 分配给下一个新流。而对端此时
			// 可能还有几个字节在途（它刚收到 FIN、正在收尾），这些「旧流的
			// 残留帧」会被按新 ID 转发给下一个流 —— 表现就是新连接刚建好、
			// 数据发出去就被打断（浏览器白屏 / SSL_ERROR_SYSCALL）。
			// 多压一小会儿再收尾，就能让这段残留数据在旧路由上消化掉。
			if finGuard > 0 {
				time.Sleep(finGuard)
			}
			_ = st.CloseWrite()
		}
		done <- struct{}{}
	}()

	// 隧道 → 本地
	go func() {
		_, err := io.Copy(c, st)
		if err != nil {
			abort()
			st.Reset(err)
		} else if cw, ok := c.(interface{ CloseWrite() error }); ok {
			// 对端已 FIN，把半关闭传给本地，让上层知道没有更多数据。
			//
			// 这里必须用接口断言而不是 *net.TCPConn：TUN 模式下 c 是
			// *gonet.TCPConn，类型断言会失败，结果就是数据收完了却不发 FIN，
			// 上层（curl、浏览器）一直等到自己超时。
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	select {
	case <-done:
	case <-time.After(linger):
		// 另一方向长时间不结束：强制收尾，防止连接堆积。
		abort()
	}
}
