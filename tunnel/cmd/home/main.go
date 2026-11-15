// home 运行在家里主机上，主动连 relay，把家里内网暴露给远端 client。
//
// 相比 v1 的改动：
//   - 先占位再 Dial，修掉「Dial 期间到达的数据被当成新请求、导致重复建连串流」的问题。
//   - 完整的半关闭语义：两个方向各自 FIN，不再出现下载中途被砍。
//   - 看门狗协程不再泄漏（用 context 统一收敛）。
//   - 状态文件原子写入，避免看门狗脚本读到半个 JSON。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"tunnel/internal"
)

var (
	relayAddr  string
	homeKey    string
	statusFile string
	dialTO     time.Duration
	lingerTO   time.Duration
	verbose    bool
)

const (
	// 心跳必须比「中间设备丢映射」的速度更快。家用宽带/移动热点常在
	// 空闲十几秒后悄悄丢弃 NAT 映射，此时连接看似 ESTAB 实际不转发。
	// 原来 20s 探活 + 60s 判死，最坏要一分钟才能发现死连接；
	// 期间所有新请求都落在这条死连接上，表现为整条隧道「罢工」。
	pingInterval   = 5 * time.Second
	deadThreshold  = 12 * time.Second
	reconnectDelay = 3 * time.Second
	statusInterval = 10 * time.Second
	// icmpProbeTO 单次 ICMP 探测的等待上限。
	// 要小于 client 侧等应答的 3s，否则对方先超时、白探一次。
	icmpProbeTO = 1500 * time.Millisecond
)

func init() {
	flag.StringVar(&relayAddr, "relay", "relay.example.com:7000", "relay 的 home 端口地址")
	flag.StringVar(&homeKey, "key", "", "预共享密钥（三端必须一致）")
	flag.StringVar(&statusFile, "status", "/var/run/tunnel-home.status", "运行状态文件路径（留空不写）")
	flag.DurationVar(&dialTO, "dial-timeout", 8*time.Second, "连接内网目标超时")
	flag.DurationVar(&lingerTO, "linger", 60*time.Second, "单方向结束后等待另一方向的最长时间")
	flag.BoolVar(&verbose, "v", false, "输出详细日志")
}

// statusInfo 是写给看门狗脚本的状态快照。
type statusInfo struct {
	Connected bool   `json:"connected"`
	Relay     string `json:"relay"`
	LastSeen  int64  `json:"last_seen_unix"`
	UpdatedAt int64  `json:"updated_at_unix"`
	Protocol  int    `json:"protocol"`
	Streams   int64  `json:"open_streams"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	DialFails uint64 `json:"dial_failures"`
}

// dialFails 累计目标连接失败次数，仅用于状态上报。
var dialFails atomic.Uint64

// postStatus 非阻塞上报状态，避免慢消费者拖住连接协程。
func postStatus(ch chan statusInfo, s statusInfo) {
	select {
	case ch <- s:
	default:
	}
}

func writeStatusAtomic(path string, info statusInfo) {
	if path == "" {
		return
	}
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".tunnel-status-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(name)
		return
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
	}
}

// serveICMP 代本机做一次 ICMP 可达性探测。
//
// 隧道只承载 TCP/UDP，ICMP 穿不过去；所以由家里这侧向目标发一个真实的
// echo，通就回 1，不通就拒绝。本机只有在收到 1 时才给上层回 echo reply，
// 而本机**不缓存可达结果**，所以 macOS 量到的 RTT 是真实的端到端往返。
func serveICMP(st *internal.Stream, host string) {
	ok, err := probeICMPHost(host, icmpProbeTO)
	if err != nil {
		// 没有原始套接字权限时退化到系统 ping，别让功能整体不可用。
		if verbose {
			log.Printf("[home] 原始套接字不可用(%v)，退化到系统 ping", err)
		}
		ok, err = pingFallback(host, icmpProbeTO)
	}
	if err != nil || !ok {
		dialFails.Add(1)
		if verbose {
			log.Printf("[home] 探测 %s 不通: %v", host, err)
		}
		st.Reject(internal.ErrCodeDial)
		return
	}
	if err := st.AcceptOK(); err != nil {
		return
	}
	if _, err := st.Write([]byte{1}); err != nil {
		return
	}
	st.Close()
	if verbose {
		log.Printf("[home] 探测 %s 通", host)
	}
}

// onOpen 处理 relay 转来的建连请求。
func onOpen(st *internal.Stream, target internal.Target) {
	addr := net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))

	if target.Proto == internal.ProtoICMP {
		serveICMP(st, target.Host)
		return
	}
	if target.Proto == internal.ProtoUDP {
		serveUDP(st, addr)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTO)
	defer cancel()
	var d net.Dialer
	rc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		dialFails.Add(1)
		if verbose {
			log.Printf("[home] 连接 %s 失败: %v", addr, err)
		}
		st.Reject(internal.ErrCodeDial)
		return
	}
	if tc, ok := rc.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
	}
	if err := st.AcceptOK(); err != nil {
		rc.Close()
		return
	}
	if verbose {
		log.Printf("[home] 流 %d ↔ %s 已建立", st.ID, addr)
	}

	pipe(st, rc, lingerTO)

	rc.Close()
	st.Close()
	if verbose {
		log.Printf("[home] 流 %d 关闭", st.ID)
	}
}

// serveUDP 把一条流当成 UDP 会话：两边都用 [2B 长度][报文] 分帧。
//
// UDP 没有半关闭语义，因此由任一端关闭即整条会话结束；本地 socket 在读上
// 是阻塞的，所以额外挂一个监听流的协程，流一断就关 socket 把它解开。
func serveUDP(st *internal.Stream, addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTO)
	defer cancel()
	var d net.Dialer
	rc, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		dialFails.Add(1)
		if verbose {
			log.Printf("[home] UDP 连接 %s 失败: %v", addr, err)
		}
		st.Reject(internal.ErrCodeDial)
		return
	}
	defer rc.Close()

	if err := st.AcceptOK(); err != nil {
		return
	}
	if verbose {
		log.Printf("[home] 流 %d ↔ udp %s 已建立", st.ID, addr)
	}

	done := make(chan struct{}, 2)

	// 流 -> 本地 UDP
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			b, err := internal.ReadDatagram(st)
			if err != nil {
				return
			}
			if _, err := rc.Write(b); err != nil {
				return
			}
		}
	}()

	// 本地 UDP -> 流
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, internal.MaxDatagram)
		for {
			n, err := rc.Read(buf)
			if err != nil {
				return
			}
			if err := internal.WriteDatagram(st, buf[:n]); err != nil {
				return
			}
		}
	}()

	// 流一断就关掉本地 socket，把阻塞中的 Read 解开。
	go func() {
		select {
		case <-st.Done():
			rc.Close()
		case <-done:
		}
	}()

	<-done
	st.Close()
	if verbose {
		log.Printf("[home] UDP 流 %d 关闭", st.ID)
	}
}

// pipe 在流与本地 TCP 连接之间双向转发，并正确处理半关闭。
func pipe(st *internal.Stream, rc net.Conn, linger time.Duration) {
	done := make(chan struct{}, 2)

	// 目标 → 隧道
	go func() {
		_, _ = io.Copy(st, rc)
		// 与 client 侧同理：relay 收到 FIN 就回收路由 ID 并立刻复用，
		// 对端可能还有几个字节在途，会被按新 ID 转给下一个流。
		// 多压一小会儿，让残留帧在旧路由上消化掉。
		time.Sleep(internal.DefaultFinGuard)
		_ = st.CloseWrite()
		done <- struct{}{}
	}()

	// 隧道 → 目标
	go func() {
		_, _ = io.Copy(rc, st)
		if tc, ok := rc.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	// 一个方向结束不代表整条连接结束（HTTP/1.0、SSH 都需要半关闭）。
	// 等另一方向自然收尾，超时则强制断。
	select {
	case <-done:
	case <-time.After(linger):
	}
}

func connectOnce(psk []byte) *internal.Mux {
	sec, err := internal.DialSecure(relayAddr, psk, 10*time.Second)
	if err != nil {
		log.Printf("[home] 连接 relay 失败: %v", err)
		return nil
	}
	log.Printf("[home] 已连上 relay %s (协议 v%d)", relayAddr, internal.ProtocolVersion)

	sec.SetNoDelay()
	return internal.NewMux(sec, onOpen)
}

func run(psk []byte) {
	var lastOK atomic.Int64
	notify := make(chan statusInfo, 1)

	// 状态写盘协程：与连接生命周期解耦，避免每次重连都重新起协程。
	go func() {
		t := time.NewTicker(statusInterval)
		defer t.Stop()
		cur := statusInfo{Relay: relayAddr, Protocol: internal.ProtocolVersion}
		for {
			select {
			case s := <-notify:
				cur = s
			case <-t.C:
			}
			cur.UpdatedAt = time.Now().Unix()
			writeStatusAtomic(statusFile, cur)
		}
	}()

	first := true
	for {
		m := connectOnce(psk)
		if m == nil {
			postStatus(notify, statusInfo{Relay: relayAddr, Connected: false, LastSeen: lastOK.Load(), Protocol: internal.ProtocolVersion})
			time.Sleep(reconnectDelay)
			continue
		}
		if first {
			log.Printf("[home] 就绪，等待 relay 转发请求")
			first = false
		}

		// 心跳 + 死连接探测
		stop := make(chan struct{})
		go func(mux *internal.Mux) {
			t := time.NewTicker(pingInterval)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-mux.Done():
					return
				case <-t.C:
					if err := mux.Sec().WriteFrame(internal.Frame{StreamID: internal.CtrlStreamID, Flags: internal.FlagPing}); err != nil {
						mux.Close(err)
						return
					}
					if mux.IdleSince() > deadThreshold {
						log.Printf("[home] %v 无任何入向帧，判定连接已死，重建", deadThreshold)
						mux.Close(internal.ErrMuxClosed)
						return
					}
				}
			}
		}(m)

		// 周期性上报状态
		go func(mux *internal.Mux) {
			t := time.NewTicker(statusInterval)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-mux.Done():
					return
				case <-t.C:
					lastOK.Store(time.Now().Unix())
					postStatus(notify, statusInfo{
						Relay:     relayAddr,
						Connected: true,
						LastSeen:  lastOK.Load(),
						Protocol:  internal.ProtocolVersion,
						Streams:   mux.Stats.Active.Load(),
						RxBytes:   mux.Stats.RxBytes.Load(),
						TxBytes:   mux.Stats.TxBytes.Load(),
						DialFails: dialFails.Load(),
					})
				}
			}
		}(m)

		<-m.Done()
		close(stop)
		log.Printf("[home] 与 relay 断开: %v", m.Err())
		lastOK.Store(time.Now().Unix())
		postStatus(notify, statusInfo{Relay: relayAddr, Connected: false, LastSeen: lastOK.Load(), Protocol: internal.ProtocolVersion})
		time.Sleep(reconnectDelay)
	}
}

func main() {
	flag.Parse()
	if homeKey == "" {
		log.Fatal("[home] 必须通过 -key 指定预共享密钥")
	}
	log.Printf("[home] 启动, 中继=%s, 协议 v%d", relayAddr, internal.ProtocolVersion)
	run([]byte(homeKey))
}
