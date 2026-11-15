// client 跑在本机，连 relay 后开一个本地 SOCKS5 代理（以及可选的固定端口转发）。
//
// 相比 v1 的改动：
//   - SOCKS5 协商完整（校验版本、方法、地址类型），UDP/BIND 明确回「命令不支持」而不是直接掐断。
//   - 建连等待带超时，隧道异常时立即失败，不再让浏览器无限转圈。
//   - 连接池故障转移：一条到 relay 的连接挂掉时自动换池中其他连接重试。
//   - 半关闭正确透传，大文件下载与 SSH 会话不再被中途掐断。
//   - 消除 v1 中 t.pool 的空切片除零与无锁读 data race。
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tunnel/internal"
)

// hedgeDelay 对冲建流：首条连接超过这个时间没有应答，就在另一条上同时发起。
// 正常 RTT 50~90ms，OPEN_OK 通常 200ms 内回来，700ms 足够区分「慢」与「卡死」。
const hedgeDelay = 700 * time.Millisecond

var (
	relayAddr  string
	socksPort  int
	clientKey  string
	forwards   string
	poolSize   int
	openTO     time.Duration
	dialTO     time.Duration
	lingerTO   time.Duration
	statusAddr string
	verbose    bool

	tunEnabled bool
	hedgeOpen  bool
	tunRoutes  string
	tunMTU     int
	finGuard   time.Duration
)

func init() {
	flag.StringVar(&relayAddr, "relay", "relay.example.com:7100", "relay 的 client 端口地址")
	flag.IntVar(&socksPort, "socks", 1080, "本地 SOCKS5 监听端口")
	flag.StringVar(&clientKey, "key", "", "预共享密钥（三端必须一致）")
	flag.StringVar(&forwards, "forward", "", "本地端口转发，逗号分隔 localPort:remoteHost:remotePort（留空则不启用）")
	flag.IntVar(&poolSize, "pool", 6, "到 relay 的并发连接数")
	// 建流应答超时。RTT 通常 50ms 上下，正常 OPEN_OK 在 200ms 内回来；
	// 原来给 10s，一旦某条池连接半死，用户就要干等 10 秒才换连接，
	// 表现为「时快时慢、偶尔卡到超时」。3s 足够容忍抖动，又能快速切换。
	flag.DurationVar(&openTO, "open-timeout", 3*time.Second, "等待对端建连应答的超时")
	flag.DurationVar(&dialTO, "dial-timeout", 10*time.Second, "连接 relay 的超时")
	flag.DurationVar(&lingerTO, "linger", 60*time.Second, "单方向结束后等待另一方向的最长时间")
	flag.DurationVar(&finGuard, "fin-guard", internal.DefaultFinGuard, "关闭流之前多等一会儿再发 FIN，规避 relay 路由 ID 复用导致的串包")
	flag.StringVar(&statusAddr, "status", "", "本地状态接口监听地址，如 127.0.0.1:9908（留空则不启用）")
	flag.BoolVar(&verbose, "v", false, "输出详细日志")

	flag.BoolVar(&hedgeOpen, "hedge", false, "建流超时时并行发起第二条（需新版 relay，旧版 relay 会因流 ID 复用误杀，默认关闭）")
	flag.BoolVar(&tunEnabled, "tun", false, "启用 TUN 全局直连模式（需要 root）：直接访问内网 IP，无需代理或端口转发")
	flag.StringVar(&tunRoutes, "tun-routes", "10.0.0.0/24", "TUN 模式接管的路由段，逗号分隔，如 10.0.0.0/24,192.168.1.0/24")
	flag.IntVar(&tunMTU, "tun-mtu", 1400, "TUN 接口 MTU")
}

var errNoTunnel = errors.New("client: 隧道未就绪")

// tunnel 维护到 relay 的连接池，并在断线后自愈。
type tunnel struct {
	addr string
	psk  []byte
	size int

	mu    sync.RWMutex
	muxes []*internal.Mux
	idx   atomic.Uint32

	// 最近一次连接失败的信息，供菜单栏/监控展示"为什么连不上"
	lastErr   atomic.Value // string
	lastErrAt atomic.Int64 // Unix 纳秒
	failCount atomic.Uint64
	okCount   atomic.Uint64

	// lastKA 上次池连接心跳的时间，只在 maintain 协程里读写
	lastKA time.Time

	// suspect 记录「近期建流超时」的池连接及其被标记的时间。
	// 这类连接多半只是暂时拥塞（对端读循环被慢流卡住），
	// 直接关闭会把同一条连接上其它正在传输的流一起掐死，
	// 浏览器表现为「页面白屏/资源加载失败」。所以先隔离观察，
	// 由心跳复核：恢复就放回池子，持续无响应才真正丢弃。
	suspect map[*internal.Mux]time.Time
}

func newTunnel(addr string, psk []byte, size int) *tunnel {
	if size < 1 {
		size = 1
	}
	return &tunnel{addr: addr, psk: psk, size: size, suspect: make(map[*internal.Mux]time.Time)}
}

// markSuspect 把一条建流超时的池连接标记为「可疑」，暂时不再往上开新流。
func (t *tunnel) markSuspect(m *internal.Mux) {
	if m == nil {
		return
	}
	t.mu.Lock()
	if t.suspect == nil {
		t.suspect = make(map[*internal.Mux]time.Time)
	}
	if _, ok := t.suspect[m]; !ok {
		t.suspect[m] = time.Now()
	}
	t.mu.Unlock()
}

// suspectSince 返回连接被标记为可疑的时间与是否仍可疑。
func (t *tunnel) suspectSince(m *internal.Mux) (time.Time, bool) {
	t.mu.RLock()
	at, ok := t.suspect[m]
	t.mu.RUnlock()
	return at, ok
}

func (t *tunnel) clearSuspect(m *internal.Mux) {
	t.mu.Lock()
	delete(t.suspect, m)
	t.mu.Unlock()
}

func (t *tunnel) dialOne() (*internal.Mux, error) {
	sec, err := internal.DialSecure(t.addr, t.psk, dialTO)
	if err != nil {
		return nil, err
	}
	return internal.NewMux(sec, nil), nil
}

// maintain 保证池中始终有 size 条可用连接。
func (t *tunnel) maintain() {
	backoff := 500 * time.Millisecond
	for {
		// 定期给池连接发心跳：家用宽带/移动热点常在空闲十几秒后
		// 悄悄丢弃 NAT 映射，连接看起来还是 ESTAB，实际已经不转发。
		// 不主动探活的话，请求会时不时卡到超时。
		if time.Since(t.lastKA) > 5*time.Second {
			t.lastKA = time.Now()
			t.keepAlive()
		}
		t.mu.RLock()
		n := len(t.muxes)
		t.mu.RUnlock()

		if n >= t.size {
			// 清理已断的连接
			t.mu.Lock()
			alive := t.muxes[:0]
			for _, m := range t.muxes {
				if !m.Closed() {
					alive = append(alive, m)
				}
			}
			t.muxes = alive
			t.mu.Unlock()
			time.Sleep(time.Second)
			continue
		}

		m, err := t.dialOne()
		if err != nil {
			t.lastErr.Store(err.Error())
			t.lastErrAt.Store(time.Now().UnixNano())
			t.failCount.Add(1)
			if verbose {
				log.Printf("[client] 连接 relay 失败: %v（%v 后重试）", err, backoff)
			}
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 500 * time.Millisecond
		t.okCount.Add(1)
		t.mu.Lock()
		t.muxes = append(t.muxes, m)
		t.mu.Unlock()
		if verbose {
			log.Printf("[client] 隧道连接建立 -> %s（池内 %d/%d）", t.addr, len(t.muxes), t.size)
		}
	}
}

// pick 从池里挑一条连接发起新流。
//
// 优先挑「刚刚收到过帧」的连接：中间网络（移动热点/家用 NAT）会把空闲连接
// 悄悄丢掉，这种连接看起来还是 ESTAB，写进去的数据却根本到不了对端，
// 新流于是卡到 OPEN 超时才失败。用心跳回包时间做筛选，
// 基本可以把「时不时卡一下」消掉。
func (t *tunnel) pick(exclude *internal.Mux) *internal.Mux {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := len(t.muxes)
	if n == 0 {
		return nil
	}
	start := int(t.idx.Add(1))
	var fallback *internal.Mux
	fallbackIdle := time.Duration(-1)
	var suspectFallback *internal.Mux
	suspectIdle := time.Duration(-1)
	for i := 0; i < n; i++ {
		m := t.muxes[(start+i)%n]
		if m == exclude || m.Closed() {
			continue
		}
		idle := m.IdleSince()
		if _, bad := t.suspect[m]; bad {
			// 可疑连接只在没有干净连接可用时才兜底，且优先挑回包最新的。
			if suspectFallback == nil || idle < suspectIdle {
				suspectFallback, suspectIdle = m, idle
			}
			continue
		}
		if idle <= 6*time.Second {
			return m
		}
		if fallback == nil || idle < fallbackIdle {
			fallback = m
			fallbackIdle = idle
		}
	}
	if fallback != nil {
		return fallback
	}
	return suspectFallback
}

// open 在池中选择连接发起流，隧道故障时换连接重试。
func (t *tunnel) open(host string, port uint16) (*internal.Stream, error) {
	return t.openTarget(internal.Target{Host: host, Port: port, Proto: internal.ProtoTCP})
}

// openTarget 按目标协议开流，供 SOCKS/转发（TCP）与 TUN（TCP+UDP）共用。
func (t *tunnel) openTarget(target internal.Target) (*internal.Stream, error) {
	// 数据报类（UDP/ICMP）没有「建连应答延迟」的痛点，且对一个 UDP 目标
	// 同时开两条路会产生两个源端口，反而添乱。TCP 才做对冲。
	if !hedgeOpen || target.Proto != internal.ProtoTCP {
		return t.openSingle(target)
	}
	return t.openHedged(target)
}

// openSingle 是原来的串行版本：一条连接失败后再试下一条。
func (t *tunnel) openSingle(target internal.Target) (*internal.Stream, error) {
	var lastErr error = errNoTunnel
	var exclude *internal.Mux
	for attempt := 0; attempt < 4; attempt++ {
		m := t.pick(exclude)
		if m == nil {
			break
		}
		st, err := m.OpenTarget(target, openTO)
		if err == nil {
			return st, nil
		}
		lastErr = err
		if errors.Is(err, internal.ErrDialFailed) {
			return nil, err
		}
		t.noteOpenErr(m, err)
		exclude = m
	}
	return nil, lastErr
}

// noteOpenErr 按失败类型处理池连接：超时先隔离（不关闭，避免连坐同连接上的
// 其它流），连接真断了才摘除。
func (t *tunnel) noteOpenErr(m *internal.Mux, err error) {
	switch {
	case errors.Is(err, internal.ErrStreamStalled):
		t.markSuspect(m)
	case errors.Is(err, internal.ErrMuxClosed):
		t.dropMux(m)
	}
}

// openHedged 对冲建流：先在一条连接上发起，若 hedgeDelay 内没有应答，
// 立刻在另一条连接上再发起一次，谁先返回 OPEN_OK 就用谁，另一条重置掉。
//
// 为什么要对冲：relay 端的读/写队列一旦被某条慢流卡住，这条路径上的
// OPEN_OK 会被推迟好几秒（甚至十几秒）。串行重试意味着用户先干等一个
// 完整的 openTO 才有第二次机会；对冲把最坏情况压到 hedgeDelay + RTT，
// 页面加载才不会有「卡三秒」的观感。
func (t *tunnel) openHedged(target internal.Target) (*internal.Stream, error) {
	const maxParallel = 3

	ch := make(chan openTry, maxParallel)
	used := make(map[*internal.Mux]bool)
	pending := 0
	var lastErr error = errNoTunnel

	launch := func() bool {
		m := t.pickFree(used)
		if m == nil {
			return false
		}
		used[m] = true
		pending++
		go func(mu *internal.Mux) {
			st, err := mu.OpenTarget(target, openTO)
			ch <- openTry{m: mu, st: st, err: err}
		}(m)
		return true
	}

	// 收尾：赢家之外的尝试还在路上，等它们返回后关掉，避免残留流与协程泄漏。
	drain := func(n int) {
		if n <= 0 {
			return
		}
		go func() {
			for i := 0; i < n; i++ {
				r := <-ch
				if r.st != nil {
					r.st.Reset(internal.ErrStreamClosed)
				}
			}
		}()
	}

	if !launch() {
		return nil, errNoTunnel
	}

	timer := time.NewTimer(hedgeDelay)
	defer timer.Stop()
	burst := 1
	for {
		select {
		case r := <-ch:
			pending--
			if r.err == nil {
				drain(pending)
				return r.st, nil
			}
			lastErr = r.err
			t.noteOpenErr(r.m, r.err)
			if errors.Is(r.err, internal.ErrDialFailed) && pending == 0 {
				// 对端明确说目标不可达，再换路也没用。
				return nil, r.err
			}
			if pending == 0 {
				if burst >= maxParallel || !launch() {
					return nil, lastErr
				}
				burst++
			}
		case <-timer.C:
			if burst < maxParallel && launch() {
				burst++
				timer.Reset(hedgeDelay)
				continue
			}
			// 已经开到上限，只能等现有的尝试各自超时返回。
			if pending == 0 {
				return nil, lastErr
			}
			timer.Reset(openTO)
		}
	}
}

// pickFree 在 pick 的基础上再排除本次请求已经尝试过的连接。
func (t *tunnel) pickFree(used map[*internal.Mux]bool) *internal.Mux {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := len(t.muxes)
	if n == 0 {
		return nil
	}
	start := int(t.idx.Add(1))
	var fallback, suspectFallback *internal.Mux
	fallbackIdle := time.Duration(-1)
	suspectIdle := time.Duration(-1)
	for i := 0; i < n; i++ {
		m := t.muxes[(start+i)%n]
		if used[m] || m.Closed() {
			continue
		}
		idle := m.IdleSince()
		if _, bad := t.suspect[m]; bad {
			if suspectFallback == nil || idle < suspectIdle {
				suspectFallback, suspectIdle = m, idle
			}
			continue
		}
		if idle <= 6*time.Second {
			return m
		}
		if fallback == nil || idle < fallbackIdle {
			fallback, fallbackIdle = m, idle
		}
	}
	if fallback != nil {
		return fallback
	}
	return suspectFallback
}

// openTry 是一次对冲尝试的结果。
type openTry struct {
	m   *internal.Mux
	st  *internal.Stream
	err error
}

// keepAlive 给每条池连接发一个 PING，并把长时间无响应的连接换掉。
func (t *tunnel) keepAlive() {
	t.mu.RLock()
	snapshot := append([]*internal.Mux(nil), t.muxes...)
	t.mu.RUnlock()

	for _, m := range snapshot {
		if m.Closed() {
			continue
		}
		// IdleSince 对「刚建好、还没收到过帧」的连接用建立时间兜底，
		// 不会把新连接误判成久无响应。
		idle := m.IdleSince()
		if at, isSuspect := t.suspectSince(m); isSuspect {
			if idle <= 6*time.Second {
				// 又能收到对端帧了，说明只是短暂拥塞，放回池子。
				log.Printf("[client] 池连接已恢复响应，解除隔离")
				t.clearSuspect(m)
			} else if time.Since(at) > 20*time.Second {
				log.Printf("[client] 池连接隔离 %.0f 秒仍无响应，重建", time.Since(at).Seconds())
				t.dropMux(m)
				continue
			}
		} else if idle > 12*time.Second {
			log.Printf("[client] 池连接已 %.0f 秒无任何响应，主动重建", idle.Seconds())
			t.dropMux(m)
			continue
		}
		// 先记发出时刻再写帧：PONG 由 relay 直接回，回得快时可能先于下一行执行。
		m.PingSentAt.Store(time.Now().UnixNano())
		_ = m.Sec().WriteFrame(internal.Frame{StreamID: internal.CtrlStreamID, Flags: internal.FlagPing})
	}
}

// dropMux 把一条出问题的池连接从池里摘掉并关闭，由 maintain 重新建立。
func (t *tunnel) dropMux(m *internal.Mux) {
	if m == nil {
		return
	}
	t.mu.Lock()
	kept := make([]*internal.Mux, 0, len(t.muxes))
	removed := false
	for _, x := range t.muxes {
		if x == m {
			removed = true
			continue
		}
		kept = append(kept, x)
	}
	t.muxes = kept
	delete(t.suspect, m)
	t.mu.Unlock()

	if removed {
		m.Close(internal.ErrMuxClosed)
		log.Printf("[client] 池连接异常，已移出池并重连（剩余 %d 条）", len(kept))
	}
}

func (t *tunnel) ready() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, m := range t.muxes {
		if !m.Closed() {
			return true
		}
	}
	return false
}

// ─── SOCKS5 ─────────────────────────────────────────────────────

const (
	socksVersion = 0x05
	cmdConnect   = 0x01
	atypIPv4     = 0x01
	atypDomain   = 0x03
	atypIPv6     = 0x04
)

func socksReply(c net.Conn, rep byte) {
	_, _ = c.Write([]byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}

func serveSocks(t *tunnel) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		return err
	}
	log.Printf("[client] SOCKS5 就绪 127.0.0.1:%d", socksPort)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("[client] SOCKS accept 失败: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handleSocks(c, t)
	}
}

func handleSocks(c net.Conn, t *tunnel) {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	// 方法协商
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != socksVersion {
		return
	}
	n := int(hdr[1])
	if n == 0 {
		return
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{socksVersion, 0xFF})
		return
	}
	if _, err := c.Write([]byte{socksVersion, 0x00}); err != nil {
		return
	}

	// 请求
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != socksVersion {
		return
	}
	switch req[1] {
	case cmdConnect:
		// 继续
	case 0x02, 0x03: // BIND / UDP ASSOCIATE
		socksReply(c, 0x07) // command not supported
		if verbose {
			log.Printf("[client] 拒绝不支持的 SOCKS 命令 %d", req[1])
		}
		return
	default:
		socksReply(c, 0x07)
		return
	}

	host, port, err := readSocksAddr(c, req[3])
	if err != nil {
		socksReply(c, 0x08) // address type not supported
		return
	}

	st, err := t.open(host, port)
	if err != nil {
		if verbose {
			log.Printf("[client] %s:%d 建连失败: %v", host, port, err)
		}
		socksReply(c, 0x05) // connection refused
		return
	}
	if _, err := c.Write([]byte{socksVersion, 0x00, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		st.Reset(err)
		return
	}

	_ = c.SetDeadline(time.Time{})
	internal.Bridge(st, c, lingerTO, finGuard)
	st.Close()
}

func readSocksAddr(c net.Conn, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, errors.New("空域名")
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, errors.New("未知地址类型")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(pb), nil
}

// ─── 本地固定端口转发 ───────────────────────────────────────────

type forwardSpec struct {
	localPort  int
	remoteHost string
	remotePort uint16
}

func parseForwards(s string) ([]forwardSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var specs []forwardSpec
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Split(part, ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("forward 格式错误: %q（应为 localPort:remoteHost:remotePort）", part)
		}
		lp, err := strconv.Atoi(fields[0])
		if err != nil || lp <= 0 || lp > 65535 {
			return nil, fmt.Errorf("本地端口非法: %q", fields[0])
		}
		rp, err := strconv.Atoi(fields[2])
		if err != nil || rp <= 0 || rp > 65535 {
			return nil, fmt.Errorf("远端端口非法: %q", fields[2])
		}
		if fields[1] == "" {
			return nil, fmt.Errorf("远端主机为空: %q", part)
		}
		specs = append(specs, forwardSpec{localPort: lp, remoteHost: fields[1], remotePort: uint16(rp)})
	}
	return specs, nil
}

func runForward(t *tunnel, spec forwardSpec) {
	addr := fmt.Sprintf("127.0.0.1:%d", spec.localPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[client] 本地转发监听 %s 失败: %v", addr, err)
		return
	}
	log.Printf("[client] 本地转发就绪 %s -> %s:%d", addr, spec.remoteHost, spec.remotePort)
	for {
		c, err := ln.Accept()
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			st, err := t.open(spec.remoteHost, spec.remotePort)
			if err != nil {
				if verbose {
					log.Printf("[client] 转发 %s:%d 失败: %v", spec.remoteHost, spec.remotePort, err)
				}
				return
			}
			internal.Bridge(st, c, lingerTO, finGuard)
			st.Close()
		}(c)
	}
}

func main() {
	flag.Parse()
	if clientKey == "" {
		log.Fatal("[client] 必须通过 -key 指定预共享密钥")
	}
	// 以 root 运行（TUN 模式）时，先清掉上次遗留的孤儿实例，
	// 否则端口被占会导致本实例刚起来就退出。
	if os.Geteuid() == 0 {
		killStaleInstances()
	}
	log.Printf("[client] 协议 v%d 启动，relay=%s，池大小=%d", internal.ProtocolVersion, relayAddr, poolSize)

	startedAt := time.Now()
	t := newTunnel(relayAddr, []byte(clientKey), poolSize)
	go t.maintain()

	specs, err := parseForwards(forwards)
	if err != nil {
		log.Fatal("[client] 解析 -forward 失败: ", err)
	}
	var fwdDesc []string
	for _, spec := range specs {
		fwdDesc = append(fwdDesc, fmt.Sprintf("%d:%s:%d", spec.localPort, spec.remoteHost, spec.remotePort))
		go runForward(t, spec)
	}

	// TUN 全局直连：可选模块，启动失败不影响 SOCKS/转发这两条老路径。
	var tunMgr *tunManager
	if tunEnabled {
		m, err := startTUN(t, tunRoutes, tunMTU)
		if err != nil {
			log.Printf("[client] TUN 模式启动失败: %v（SOCKS 与端口转发继续可用）", err)
		} else {
			tunMgr = m
		}
	}

	// 退出时把路由清理干净，避免把整段内网路由留在系统里导致断网。
	if tunMgr != nil {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			s := <-sig
			log.Printf("[client] 收到 %v，清理 TUN 后退出", s)
			tunMgr.Close()
			os.Exit(0)
		}()
	}

	serveStatus(t, statusAddr, startedAt, fwdDesc)

	// 首次连接结果只在后台观察并记日志。
	// 之前这里是同步等 15s，导致 SOCKS/状态接口迟迟不监听，
	// 菜单栏那边就一直停在"启动中"，看不出到底是慢还是错。
	go func() {
		deadline := time.Now().Add(15 * time.Second)
		for !t.ready() && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		if t.ready() {
			log.Printf("[client] 已连上 relay")
		} else {
			log.Printf("[client] 暂未连上 relay，将在后台继续重试")
		}
	}()

	if err := serveSocks(t); err != nil {
		log.Fatal("[client] SOCKS 监听失败: ", err)
	}
}
