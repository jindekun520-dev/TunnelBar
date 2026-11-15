// 状态接口：给菜单栏/监控工具提供一个只读的本地观测点。
//
// 只监听 127.0.0.1，且只暴露计数与连接数，不泄露密钥。
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"tunnel/internal"
)

// statusPayload 是对外暴露的字段集合（JSON，snake_case 便于跨语言读取）。
type statusPayload struct {
	Protocol  int      `json:"protocol"`
	Relay     string   `json:"relay"`
	Socks     string   `json:"socks"`
	Ready     bool     `json:"ready"`
	PoolAlive int      `json:"pool_alive"`
	PoolTotal int      `json:"pool_total"`
	Active    int64    `json:"active"`
	Opened    uint64   `json:"opened"`
	TxBytes   uint64   `json:"tx_bytes"`
	RxBytes   uint64   `json:"rx_bytes"`
	Resets    uint64   `json:"resets"`
	Stalled   uint64   `json:"stalled"`
	Forwards  []string `json:"forwards"`
	UptimeSec int64    `json:"uptime_s"`
	PID       int      `json:"pid"`
	// 连接诊断：ready=false 时用这几项说明"为什么连不上"
	LastError    string `json:"last_error,omitempty"`
	LastErrorAge int64  `json:"last_error_age_s,omitempty"`
	FailCount    uint64 `json:"fail_count"`
	OKCount      uint64 `json:"ok_count"`

	// TUN 全局直连模式的状态；未启用时省略。
	Tun *tunPayload `json:"tun,omitempty"`

	// 池内每一条连接的明细，供菜单栏「连接池」子菜单展示。
	// 顺序与池内顺序一致，i 从 1 开始（人看的编号）。
	Pool []poolConn `json:"pool,omitempty"`
}

// poolConn 是单条池连接的运行快照。
type poolConn struct {
	Index   int  `json:"i"`
	Alive   bool `json:"alive"`
	Suspect bool `json:"suspect,omitempty"`
	// SuspectS 已隔离秒数（仅 suspect=true 时有意义）
	SuspectS int64 `json:"suspect_s,omitempty"`
	// AgeS 这条连接建立至今的秒数
	AgeS int64 `json:"age_s"`
	// IdleMs 距最近一次收到对端帧的毫秒数（越小越"新鲜"）
	IdleMs int64 `json:"idle_ms"`
	// RTTMs 心跳往返（client ↔ relay）毫秒；RttAgeMs 是这次测量的年龄。
	// 测不到（还没有心跳回包）时两者省略。
	RTTMs    float64 `json:"rtt_ms,omitempty"`
	RTTAgeMs int64   `json:"rtt_age_ms,omitempty"`

	Active  int64  `json:"active"`   // 当前承载的流数
	Opened  uint64 `json:"opened"`   // 累计开过的流数
	TxBytes uint64 `json:"tx_bytes"` // 本连接发送字节
	RxBytes uint64 `json:"rx_bytes"` // 本连接接收字节
	Resets  uint64 `json:"resets"`
	Stalled uint64 `json:"stalled"`
	Err     string `json:"err,omitempty"` // 已断开时的终止原因
}

// poolDetail 逐条汇总池连接，供状态接口输出。
// 顺序与 t.muxes 一致：菜单里看到的下标和这里能对得上。
func (t *tunnel) poolDetail() []poolConn {
	t.mu.RLock()
	muxes := make([]*internal.Mux, len(t.muxes))
	copy(muxes, t.muxes)
	suspect := make(map[*internal.Mux]time.Time, len(t.suspect))
	for m, at := range t.suspect {
		suspect[m] = at
	}
	t.mu.RUnlock()

	now := time.Now()
	out := make([]poolConn, 0, len(muxes))
	for i, m := range muxes {
		pc := poolConn{
			Index:   i + 1,
			Alive:   !m.Closed(),
			AgeS:    int64(now.Sub(m.BornAt()).Seconds()),
			IdleMs:  m.IdleSince().Milliseconds(),
			Active:  m.Stats.Active.Load(),
			Opened:  m.Stats.Opened.Load(),
			TxBytes: m.Stats.TxBytes.Load(),
			RxBytes: m.Stats.RxBytes.Load(),
			Resets:  m.Stats.Resets.Load(),
			Stalled: m.Stats.Stalled.Load(),
		}
		if at, ok := suspect[m]; ok {
			pc.Suspect = true
			pc.SuspectS = int64(now.Sub(at).Seconds())
		}
		if rtt, at, ok := m.RTT(); ok {
			pc.RTTMs = float64(rtt.Microseconds()) / 1000
			pc.RTTAgeMs = now.Sub(at).Milliseconds()
		}
		if err := m.Err(); err != nil {
			pc.Err = err.Error()
		}
		out = append(out, pc)
	}
	return out
}

// tunPayload 描述 TUN 模式（全局直连）的运行状态。
type tunPayload struct {
	Enabled    bool     `json:"enabled"`
	Device     string   `json:"device,omitempty"`
	MTU        int      `json:"mtu,omitempty"`
	Routes     []string `json:"routes,omitempty"`
	TCPTotal   int64    `json:"tcp_total"`
	UDPTotal   int64    `json:"udp_total"`
	TCPActive  int64    `json:"tcp_active"`
	UDPActive  int64    `json:"udp_active"`
	ICMPEchoes int64    `json:"icmp_replies"`
	OutDrops   uint64   `json:"outbound_drops"`
	Error      string   `json:"error,omitempty"`
}

// tunSnapshot 由 TUN 模式在启动时注入；未启用 TUN 时为 nil。
var tunSnapshot func() *tunPayload

// lastErrorMessage 返回最近一次连接失败的原因（没有则空串）。
func (t *tunnel) lastErrorMessage() string {
	v := t.lastErr.Load()
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// lastErrorAge 返回距最近一次连接失败的秒数，-1 表示从未失败。
func (t *tunnel) lastErrorAge() int64 {
	ns := t.lastErrAt.Load()
	if ns == 0 {
		return -1
	}
	return int64(time.Since(time.Unix(0, ns)).Seconds())
}

// snapshot 汇总池内所有连接的计数。
func (t *tunnel) snapshot() (alive, total int, active int64, opened, tx, rx, resets, stalled uint64) {
	t.mu.RLock()
	muxes := make([]*internal.Mux, len(t.muxes))
	copy(muxes, t.muxes)
	t.mu.RUnlock()

	total = len(muxes)
	for _, m := range muxes {
		if m.Closed() {
			continue
		}
		alive++
		active += m.Stats.Active.Load()
		opened += m.Stats.Opened.Load()
		tx += m.Stats.TxBytes.Load()
		rx += m.Stats.RxBytes.Load()
		resets += m.Stats.Resets.Load()
		stalled += m.Stats.Stalled.Load()
	}
	return
}

// serveStatus 在 addr 上提供 /status 与 /healthz。
// 绑定失败时只记日志，不影响隧道本身。
func serveStatus(t *tunnel, addr string, started time.Time, fwds []string) {
	if addr == "" {
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[client] 状态接口监听失败（不影响隧道）: %v", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		alive, total, active, opened, tx, rx, resets, stalled := t.snapshot()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(statusPayload{
			Protocol:  internal.ProtocolVersion,
			Relay:     relayAddr,
			Socks:     net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)),
			Ready:     alive > 0,
			PoolAlive: alive,
			PoolTotal: total,
			Active:    active,
			Opened:    opened,
			TxBytes:   tx,
			RxBytes:   rx,
			Resets:    resets,
			Stalled:   stalled,
			Forwards:  fwds,
			UptimeSec: int64(time.Since(started).Seconds()),
			PID:       os.Getpid(),

			LastError:    t.lastErrorMessage(),
			LastErrorAge: t.lastErrorAge(),
			FailCount:    t.failCount.Load(),
			OKCount:      t.okCount.Load(),
			Tun:          currentTun(),
			Pool:         t.poolDetail(),
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		alive, _, _, _, _, _, _, _ := t.snapshot()
		if alive == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("no tunnel\n"))
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("[client] 状态接口退出: %v", err)
		}
	}()
	log.Printf("[client] 状态接口就绪 http://%s/status", addr)
}

// currentTun 返回当前 TUN 状态；未启用 TUN 模式时返回 nil（JSON 中省略该字段）。
func currentTun() *tunPayload {
	if tunSnapshot == nil {
		return nil
	}
	return tunSnapshot()
}
