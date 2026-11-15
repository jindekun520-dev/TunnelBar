// relay 运行在有公网 IP 的服务器上，是 client 与 home 之间的中继。
//
// 相比 v1 的改动：
//   - 用 generation 号防止「旧 home 连接断开把新 home 覆盖成 nil」导致的隧道假死。
//   - 转发表与流生命周期严格配对，消除 v1 的 close 竞态（double close panic）。
//   - 去掉了数据面的逐帧日志与 channel 中转，直接转发，吞吐和延迟都更稳。
//   - 未知/失效路由明确回 RST，不再让对端无限等待。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tunnel/internal"
)

var (
	homePort    int
	clientPort  int
	key         string
	statusAddr  string
	verbose     bool
	homeTimeout time.Duration
)

func init() {
	flag.IntVar(&homePort, "home", 7000, "home 侧监听端口")
	flag.IntVar(&clientPort, "client", 7100, "client 侧监听端口")
	flag.StringVar(&key, "key", "", "预共享密钥（三端必须一致）")
	flag.StringVar(&statusAddr, "status", "", "状态 HTTP 监听地址，如 127.0.0.1:9911（留空则不启用）")
	flag.BoolVar(&verbose, "v", false, "输出详细日志")
	flag.DurationVar(&homeTimeout, "home-timeout", 90*time.Second, "home 无响应多久判定掉线")
}

// route 描述一条「relay 流 ID → 目标客户端流」的映射。
type route struct {
	sess      *clientSess
	clientSID uint32
	createdAt time.Time
}

// clientSess 是一条客户端连接及其流映射。
type clientSess struct {
	sec    *internal.SecureConn
	mu     sync.Mutex
	bySID  map[uint32]uint32 // clientSID -> relayRID
	id     uint64
	closed bool
}

type homeConn struct {
	sec      *internal.SecureConn
	gen      uint64
	lastRecv atomic.Int64 // unix nano
}

type relay struct {
	mu      sync.RWMutex
	home    *homeConn
	homeGen uint64
	since   time.Time

	rmu     sync.Mutex
	routes  map[uint32]*route
	nextRID uint32

	clientsMu sync.RWMutex
	clients   map[*clientSess]struct{}

	totalHome  atomic.Uint64
	totalConn  atomic.Uint64
	activeFlow atomic.Int64
}

var rl = &relay{
	routes:  make(map[uint32]*route),
	clients: make(map[*clientSess]struct{}),
}

// ─── home 侧 ────────────────────────────────────────────────────

func (r *relay) currentHome() *homeConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.home
}

func (r *relay) registerHome(h *homeConn) *homeConn {
	r.mu.Lock()
	old := r.home
	r.homeGen++
	h.gen = r.homeGen
	r.home = h
	r.since = time.Now()
	r.mu.Unlock()
	r.totalHome.Add(1)
	return old
}

// unregisterHome 只在 generation 匹配时清理，避免旧连接退出时误清新连接。
func (r *relay) unregisterHome(gen uint64) {
	r.mu.Lock()
	if r.home != nil && r.home.gen == gen {
		r.home = nil
	}
	r.mu.Unlock()
}

func (r *relay) serveHome() {
	ln, err := net.Listen("tcp", listenAddr(homePort))
	if err != nil {
		log.Fatalf("[relay] home 端口监听失败: %v", err)
	}
	log.Printf("[relay] home 端口就绪 :%d", homePort)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("[relay] home accept 失败: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go r.handleHomeConn(c)
	}
}

func (r *relay) handleHomeConn(c net.Conn) {
	sec, err := internal.ServerSecure(c, []byte(key))
	if err != nil {
		log.Printf("[relay] home 握手失败(%s): %v", c.RemoteAddr(), err)
		return
	}
	h := &homeConn{sec: sec}
	h.lastRecv.Store(time.Now().UnixNano())
	old := r.registerHome(h)
	if old != nil {
		log.Printf("[relay] 新 home 上线，主动断开旧连接 gen=%d", old.gen)
		old.sec.Close()
	}
	log.Printf("[relay] home 已注册 gen=%d from %s", h.gen, c.RemoteAddr())

	stop := make(chan struct{})
	// 心跳：保持 NAT 映射，同时探测对端存活。
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := h.sec.WriteFrame(internal.Frame{StreamID: internal.CtrlStreamID, Flags: internal.FlagPing}); err != nil {
					return
				}
				if time.Since(time.Unix(0, h.lastRecv.Load())) > homeTimeout {
					log.Printf("[relay] home gen=%d 心跳超时，断开", h.gen)
					h.sec.Close()
					return
				}
			}
		}
	}()

	r.homeReadLoop(h)
	close(stop)
	r.unregisterHome(h.gen)
	log.Printf("[relay] home gen=%d 已断开", h.gen)
}

func (r *relay) homeReadLoop(h *homeConn) {
	for {
		f, err := h.sec.ReadFrame()
		if err != nil {
			if verbose {
				log.Printf("[relay] home 读帧结束: %v", err)
			}
			r.dropAllRoutes()
			return
		}
		h.lastRecv.Store(time.Now().UnixNano())

		if f.StreamID == internal.CtrlStreamID {
			if f.Flags&internal.FlagPing != 0 {
				_ = h.sec.WriteFrame(internal.Frame{StreamID: internal.CtrlStreamID, Flags: internal.FlagPong})
			}
			continue
		}

		rt := r.lookupRoute(f.StreamID)
		if rt == nil {
			if f.Flags&internal.FlagRST == 0 {
				_ = h.sec.WriteFrame(internal.Frame{StreamID: f.StreamID, Flags: internal.FlagRST})
			}
			continue
		}

		fwd := internal.Frame{StreamID: rt.clientSID, Flags: f.Flags, Payload: f.Payload}
		if err := rt.sess.sec.WriteFrame(fwd); err != nil {
			r.dropRouteByRID(f.StreamID)
			continue
		}
		if f.Flags&(internal.FlagFIN|internal.FlagRST) != 0 {
			r.dropRouteByRID(f.StreamID)
		}
	}
}

// ─── client 侧 ──────────────────────────────────────────────────

func (r *relay) serveClient() {
	ln, err := net.Listen("tcp", listenAddr(clientPort))
	if err != nil {
		log.Fatalf("[relay] client 端口监听失败: %v", err)
	}
	log.Printf("[relay] client 端口就绪 :%d", clientPort)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("[relay] client accept 失败: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go r.handleClientConn(c)
	}
}

func (r *relay) handleClientConn(c net.Conn) {
	sec, err := internal.ServerSecure(c, []byte(key))
	if err != nil {
		log.Printf("[relay] client 握手失败(%s): %v", c.RemoteAddr(), err)
		return
	}
	sess := &clientSess{sec: sec, bySID: make(map[uint32]uint32), id: uint64(time.Now().UnixNano())}
	r.clientsMu.Lock()
	r.clients[sess] = struct{}{}
	r.clientsMu.Unlock()
	r.totalConn.Add(1)
	log.Printf("[relay] client 已接入 %s", c.RemoteAddr())

	r.clientReadLoop(sess)

	r.clientsMu.Lock()
	delete(r.clients, sess)
	r.clientsMu.Unlock()
	sess.cleanup(r)
	log.Printf("[relay] client 断开 %s", c.RemoteAddr())
}

func (r *relay) clientReadLoop(sess *clientSess) {
	for {
		f, err := sess.sec.ReadFrame()
		if err != nil {
			return
		}

		if f.StreamID == internal.CtrlStreamID {
			if f.Flags&internal.FlagPing != 0 {
				_ = sess.sec.WriteFrame(internal.Frame{StreamID: internal.CtrlStreamID, Flags: internal.FlagPong})
			}
			continue
		}

		h := r.currentHome()
		if h == nil {
			// 无 home 在线：立即明确拒绝，而不是让客户端干等。
			_ = sess.sec.WriteFrame(internal.Frame{
				StreamID: f.StreamID,
				Flags:    internal.FlagOpenErr,
				Payload:  []byte{internal.ErrCodeRefuse},
			})
			continue
		}

		if f.Flags&internal.FlagOpen != 0 {
			rid, ok := r.allocRID()
			if !ok {
				_ = sess.sec.WriteFrame(internal.Frame{
					StreamID: f.StreamID,
					Flags:    internal.FlagOpenErr,
					Payload:  []byte{internal.ErrCodeRefuse},
				})
				continue
			}
			if err := r.bindRoute(rid, sess, f.StreamID); err != nil {
				_ = sess.sec.WriteFrame(internal.Frame{
					StreamID: f.StreamID,
					Flags:    internal.FlagOpenErr,
					Payload:  []byte{internal.ErrCodeRefuse},
				})
				continue
			}
			if err := h.sec.WriteFrame(internal.Frame{StreamID: rid, Flags: internal.FlagOpen, Payload: f.Payload}); err != nil {
				r.dropRouteByRID(rid)
				_ = sess.sec.WriteFrame(internal.Frame{
					StreamID: f.StreamID,
					Flags:    internal.FlagOpenErr,
					Payload:  []byte{internal.ErrCodeRefuse},
				})
			}
			continue
		}

		rid, ok := sess.ridOf(f.StreamID)
		if !ok {
			if f.Flags&internal.FlagRST == 0 {
				_ = sess.sec.WriteFrame(internal.Frame{StreamID: f.StreamID, Flags: internal.FlagRST})
			}
			continue
		}
		if err := h.sec.WriteFrame(internal.Frame{StreamID: rid, Flags: f.Flags, Payload: f.Payload}); err != nil {
			r.dropRouteByRID(rid)
			continue
		}
		if f.Flags&(internal.FlagFIN|internal.FlagRST) != 0 {
			r.dropRouteByRID(rid)
		}
	}
}

// ─── 路由表 ─────────────────────────────────────────────────────

// allocRID 分配一个路由 ID。
// 必须单调递增、**绝不复用刚释放的 ID**：home 侧还在收尾的旧流可能仍有几个
// 帧在途（尤其是 FIN 之后紧跟的 RST / 尾部 DATA），这些帧会按 rid 查路由。
// 若 rid 已被下一个新流拿走，残留帧就会被转发给新流，新连接刚发出
// ClientHello 就被打断（浏览器表现为白屏、curl 报 SSL_ERROR_SYSCALL）。
// 32 位空间足够大，绕回前不会耗尽，不做回收池。
func (r *relay) allocRID() (uint32, bool) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	for i := 0; i < 1<<20; i++ {
		r.nextRID++
		if r.nextRID == internal.CtrlStreamID {
			r.nextRID = 1
		}
		if _, used := r.routes[r.nextRID]; !used {
			return r.nextRID, true
		}
	}
	return 0, false
}

func (r *relay) bindRoute(rid uint32, sess *clientSess, clientSID uint32) error {
	r.rmu.Lock()
	if _, used := r.routes[rid]; used {
		r.rmu.Unlock()
		return internal.ErrBadFrame
	}
	r.routes[rid] = &route{sess: sess, clientSID: clientSID, createdAt: time.Now()}
	r.rmu.Unlock()

	sess.mu.Lock()
	if sess.closed {
		sess.mu.Unlock()
		r.dropRouteByRID(rid)
		return internal.ErrMuxClosed
	}
	sess.bySID[clientSID] = rid
	sess.mu.Unlock()

	r.activeFlow.Add(1)
	return nil
}

func (r *relay) lookupRoute(rid uint32) *route {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	return r.routes[rid]
}

func (r *relay) dropRouteByRID(rid uint32) {
	r.rmu.Lock()
	rt, ok := r.routes[rid]
	if ok {
		// 不回收 rid，见 allocRID 注释。
		delete(r.routes, rid)
	}
	r.rmu.Unlock()
	if !ok {
		return
	}
	rt.sess.mu.Lock()
	delete(rt.sess.bySID, rt.clientSID)
	rt.sess.mu.Unlock()
	r.activeFlow.Add(-1)
}

// dropAllRoutes 在 home 掉线时清理全部路由，并通知各客户端流已重置。
func (r *relay) dropAllRoutes() {
	r.rmu.Lock()
	victims := r.routes
	r.routes = make(map[uint32]*route)
	r.rmu.Unlock()

	r.activeFlow.Store(0)
	for _, rt := range victims {
		rt.sess.mu.Lock()
		delete(rt.sess.bySID, rt.clientSID)
		rt.sess.mu.Unlock()
		_ = rt.sess.sec.WriteFrame(internal.Frame{StreamID: rt.clientSID, Flags: internal.FlagRST})
	}
	if len(victims) > 0 {
		log.Printf("[relay] home 掉线，已重置 %d 条流", len(victims))
	}
}

func (sess *clientSess) ridOf(sid uint32) (uint32, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	rid, ok := sess.bySID[sid]
	return rid, ok
}

// cleanup 在客户端断开后回收其全部路由。
func (sess *clientSess) cleanup(r *relay) {
	sess.mu.Lock()
	sess.closed = true
	rids := make([]uint32, 0, len(sess.bySID))
	for _, rid := range sess.bySID {
		rids = append(rids, rid)
	}
	sess.bySID = make(map[uint32]uint32)
	sess.mu.Unlock()

	h := r.currentHome()
	for _, rid := range rids {
		r.rmu.Lock()
		_, ok := r.routes[rid]
		delete(r.routes, rid)
		r.rmu.Unlock()
		if ok {
			r.activeFlow.Add(-1)
			if h != nil {
				_ = h.sec.WriteFrame(internal.Frame{StreamID: rid, Flags: internal.FlagRST})
			}
		}
	}
	sess.sec.Close()
}

// ─── 状态端点 ───────────────────────────────────────────────────

func (r *relay) serveStatus() {
	if statusAddr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, req *http.Request) {
		r.mu.RLock()
		homeUp := r.home != nil
		since := r.since
		gen := r.homeGen
		r.mu.RUnlock()

		r.clientsMu.RLock()
		nClients := len(r.clients)
		r.clientsMu.RUnlock()

		type snapshot struct {
			Home       bool   `json:"home_online"`
			HomeGen    uint64 `json:"home_gen"`
			HomeSince  int64  `json:"home_since_unix"`
			Clients    int    `json:"clients"`
			ActiveFlow int64  `json:"active_flows"`
			TotalConns uint64 `json:"total_clients"`
			TotalHomes uint64 `json:"total_home_connects"`
			Version    int    `json:"protocol"`
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot{
			Home:       homeUp,
			HomeGen:    gen,
			HomeSince:  since.Unix(),
			Clients:    nClients,
			ActiveFlow: r.activeFlow.Load(),
			TotalConns: r.totalConn.Load(),
			TotalHomes: r.totalHome.Load(),
			Version:    internal.ProtocolVersion,
		})
	})
	go func() {
		srv := &http.Server{Addr: statusAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("[relay] 状态端点启动失败: %v", err)
		}
	}()
	log.Printf("[relay] 状态端点 http://%s/status", statusAddr)
}

func listenAddr(port int) string {
	return net.JoinHostPort("", strconv.Itoa(port))
}

func main() {
	flag.Parse()
	if key == "" {
		log.Fatal("[relay] 必须通过 -key 指定预共享密钥")
	}
	log.Printf("[relay] 协议 v%d 启动 (home=:%d client=:%d)", internal.ProtocolVersion, homePort, clientPort)
	rl.serveStatus()
	go rl.serveHome()
	rl.serveClient()
}
