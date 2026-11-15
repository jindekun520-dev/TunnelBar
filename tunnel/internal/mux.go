package internal

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrStreamReset 对端异常终止了流。
	ErrStreamReset = errors.New("tunnel: 流被重置")
	// ErrDialFailed 目标不可达。
	ErrDialFailed = errors.New("tunnel: 目标连接失败")
	// ErrStreamClosed 流已关闭。
	ErrStreamClosed = errors.New("tunnel: 流已关闭")
	// ErrMuxClosed 底层连接已断开。
	ErrMuxClosed = errors.New("tunnel: 隧道已断开")
	// ErrStreamStalled 流消费过慢，触发保护性重置。
	ErrStreamStalled = errors.New("tunnel: 流阻塞超时")
)

const (
	// streamQueueBytes 单流待投递字节上限。
	//
	// 投递必须是「非阻塞入队 + 上限断流」。早先是「有界阻塞投递」：
	// 一条没人读的流（例如客户端已放弃的下载）会把 recv channel 塞满，
	// 而 deliver 在唯一的读循环里最多阻塞 30 秒，于是整条隧道上
	// 所有新流都拿不到 OPEN_OK，表现为「隧道时不时整体卡死几十秒」。
	// 现在读循环永不阻塞，缓冲超限只重置这一条流。
	streamQueueBytes = 4 << 20
	// streamQueueFrames 单流待投递帧数上限（防止大量小帧只占内存）。
	streamQueueFrames = 1024
)

// Stats 是复用层的运行计数。
type Stats struct {
	Opened  atomic.Uint64
	Active  atomic.Int64
	RxBytes atomic.Uint64
	TxBytes atomic.Uint64
	Resets  atomic.Uint64
	Stalled atomic.Uint64
}

// OpenHandler 在收到对端发起的新流时被调用（responder 角色）。
type OpenHandler func(st *Stream, target Target)

// Stream 是一条复用流，实现 io.ReadWriteCloser 与半关闭语义。
type Stream struct {
	ID  uint32
	mux *Mux

	// 接收侧是「非阻塞队列 + 通知」，读循环只入队，不会被慢流拖住。
	qmu    sync.Mutex
	queue  []Frame
	qBytes int
	notify chan struct{}
	done   chan struct{}

	closeOnce sync.Once
	counted   atomic.Bool
	finSent   atomic.Bool
	remoteFIN atomic.Bool
	isClosed  atomic.Bool

	errMu  sync.Mutex
	errVal error

	pending []byte // 仅由 Read 方访问
}

// Mux 在单条 SecureConn 上复用多条 Stream。
type Mux struct {
	sec     *SecureConn
	onOpen  OpenHandler
	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	closed  chan struct{}
	closeMu sync.RWMutex
	termErr error
	Stats   Stats
	// LastRecv 最近一次收到任何帧的 unix nano 时间，供上层看门狗判断存活。
	LastRecv atomic.Int64
	// bornAt 是会话建立时间，用于「还没收到过任何帧」的新连接做存活判断。
	bornAt time.Time

	// 心跳往返测量：PingSentAt 是最近一次心跳发出时刻（0=无在途），
	// LastRTT/LastRTTAt 是上一轮测到的往返时间与测量时刻。
	// 只做观测，不参与任何调度决策。
	PingSentAt atomic.Int64
	LastRTT    atomic.Int64
	LastRTTAt  atomic.Int64
}

// NoteRTT 记录一次心跳往返时间（由读循环在收到 PONG 时调用）。
func (m *Mux) NoteRTT(d time.Duration) {
	m.LastRTT.Store(int64(d))
	m.LastRTTAt.Store(time.Now().UnixNano())
}

// RTT 返回上一轮心跳往返时间、测量时刻与是否测过。
func (m *Mux) RTT() (time.Duration, time.Time, bool) {
	ns := m.LastRTT.Load()
	if ns <= 0 {
		return 0, time.Time{}, false
	}
	at := m.LastRTTAt.Load()
	return time.Duration(ns), time.Unix(0, at), true
}

// BornAt 返回会话建立时间。
func (m *Mux) BornAt() time.Time { return m.bornAt }

// IdleSince 返回「多久没有任何入向帧」。新连接用建立时间兜底，
// 避免 LastRecv 还是 0 时被误判成万年无响应。
func (m *Mux) IdleSince() time.Duration {
	last := m.LastRecv.Load()
	if last == 0 {
		if m.bornAt.IsZero() {
			return 0
		}
		return time.Since(m.bornAt)
	}
	return time.Since(time.Unix(0, last))
}

// NewMux 构造复用器并在后台启动读循环。onOpen 可为 nil（纯 initiator 场景）。
func NewMux(sec *SecureConn, onOpen OpenHandler) *Mux {
	m := &Mux{
		sec:     sec,
		onOpen:  onOpen,
		streams: make(map[uint32]*Stream),
		closed:  make(chan struct{}),
		bornAt:  time.Now(),
	}
	go m.readLoop()
	return m
}

// Sec 返回底层加密连接。
func (m *Mux) Sec() *SecureConn { return m.sec }

// Done 在底层连接断开时关闭。
func (m *Mux) Done() <-chan struct{} { return m.closed }

// Err 返回会话终止原因。
func (m *Mux) Err() error {
	m.closeMu.RLock()
	defer m.closeMu.RUnlock()
	return m.termErr
}

// Closed 报告会话是否已终止。
func (m *Mux) Closed() bool {
	select {
	case <-m.closed:
		return true
	default:
		return false
	}
}

// Close 终止整个复用会话并唤醒所有等待中的流。
func (m *Mux) Close(err error) {
	m.closeMu.Lock()
	first := m.termErr == nil
	if first {
		if err == nil {
			err = ErrMuxClosed
		}
		m.termErr = err
		close(m.closed)
	}
	m.closeMu.Unlock()
	if !first {
		return
	}

	m.sec.Close()

	m.mu.Lock()
	victims := make([]*Stream, 0, len(m.streams))
	for _, st := range m.streams {
		victims = append(victims, st)
	}
	m.streams = make(map[uint32]*Stream)
	m.mu.Unlock()

	for _, st := range victims {
		st.terminate(ErrMuxClosed)
	}
}

// allocIDLocked 分配一个未占用的流 ID。调用方必须持有 m.mu。
//
// 这里刻意「不复用刚释放的 ID」。曾经用 free 列表做 LIFO 复用，
// 结果是新 OPEN 常常落到对端还没清理完的旧流 ID 上：
// 对端会把 OPEN 当成旧流的帧投递进旧接收队列，然后随旧流一起丢掉，
// 发起方就一直等不到 OPEN_OK，只能超时重试——这就是「时不时卡几秒」的来源。
// uint32 的 ID 空间够用很久，单调递增最省心。
func (m *Mux) allocIDLocked() uint32 {
	for {
		m.nextID++
		if m.nextID == CtrlStreamID || m.nextID == 0 {
			m.nextID = 1
		}
		if _, used := m.streams[m.nextID]; !used {
			return m.nextID
		}
	}
}

func (m *Mux) releaseLocked(id uint32) {
	delete(m.streams, id)
}

func (m *Mux) get(id uint32) (*Stream, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.streams[id]
	return st, ok
}

func (m *Mux) newStreamLocked(id uint32) *Stream {
	return &Stream{
		ID:     id,
		mux:    m,
		notify: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

// enqueue 非阻塞地把帧放入接收队列。返回 false 表示该流积压过多，应当断流。
func (st *Stream) enqueue(f Frame) bool {
	st.qmu.Lock()
	if st.qBytes+len(f.Payload) > streamQueueBytes || len(st.queue) >= streamQueueFrames {
		st.qmu.Unlock()
		return false
	}
	st.queue = append(st.queue, f)
	st.qBytes += len(f.Payload)
	st.qmu.Unlock()

	select {
	case st.notify <- struct{}{}:
	default:
	}
	return true
}

// pushFront 把帧放回队首（用于 OPEN 应答前意外收到的数据帧）。
func (st *Stream) pushFront(f Frame) {
	st.qmu.Lock()
	st.queue = append([]Frame{f}, st.queue...)
	st.qBytes += len(f.Payload)
	st.qmu.Unlock()

	select {
	case st.notify <- struct{}{}:
	default:
	}
}

func (st *Stream) pop() (Frame, bool) {
	st.qmu.Lock()
	defer st.qmu.Unlock()
	if len(st.queue) == 0 {
		return Frame{}, false
	}
	f := st.queue[0]
	st.queue[0] = Frame{}
	st.queue = st.queue[1:]
	st.qBytes -= len(f.Payload)
	return f, true
}

// Open 主动开一条 TCP 流到 target，等待对端 OPEN_OK / OPEN_ERR。
func (m *Mux) Open(host string, port uint16, timeout time.Duration) (*Stream, error) {
	return m.OpenTarget(Target{Host: host, Port: port, Proto: ProtoTCP}, timeout)
}

// OpenTarget 按目标协议（TCP/UDP）开一条流。
func (m *Mux) OpenTarget(t Target, timeout time.Duration) (*Stream, error) {
	m.mu.Lock()
	id := m.allocIDLocked()
	st := m.newStreamLocked(id)
	m.streams[id] = st
	m.mu.Unlock()
	return m.finishOpen(st, t, timeout)
}

// OpenWithID 以指定流 ID 开流，供 relay 做 sid 重映射时使用。
func (m *Mux) OpenWithID(id uint32, t Target, timeout time.Duration) (*Stream, error) {
	if id == CtrlStreamID {
		return nil, ErrBadFrame
	}
	m.mu.Lock()
	if _, used := m.streams[id]; used {
		m.mu.Unlock()
		return nil, ErrBadFrame
	}
	st := m.newStreamLocked(id)
	m.streams[id] = st
	m.mu.Unlock()
	return m.finishOpen(st, t, timeout)
}

func (m *Mux) finishOpen(st *Stream, target Target, timeout time.Duration) (*Stream, error) {
	payload, err := EncodeTargetProto(target)
	if err != nil {
		m.dropStream(st)
		return nil, err
	}
	if m.Closed() {
		m.dropStream(st)
		return nil, ErrMuxClosed
	}
	if err := m.sec.WriteFrame(Frame{StreamID: st.ID, Flags: FlagOpen, Payload: payload}); err != nil {
		m.dropStream(st)
		return nil, err
	}

	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		if f, ok := st.pop(); ok {
			switch {
			case f.Flags&FlagOpenOK != 0:
				m.Stats.Opened.Add(1)
				m.Stats.Active.Add(1)
				st.counted.Store(true)
				return st, nil
			case f.Flags&FlagOpenErr != 0:
				m.dropStream(st)
				return nil, ErrDialFailed
			default:
				// 理论上对端先回 OPEN_OK 才发数据；真提前到了就放回队首，
				// 免得把数据吞掉。
				st.pushFront(f)
				select {
				case <-t.C:
					m.resetRaw(st.ID)
					m.dropStream(st)
					return nil, ErrStreamStalled
				case <-st.notify:
					continue
				}
			}
		}
		select {
		case <-st.notify:
		case <-t.C:
			// OPEN 应答超时属于隧道侧问题，与「目标不可达」区分开，
			// 让 client 能换一条池内连接重试。
			m.resetRaw(st.ID)
			m.dropStream(st)
			return nil, ErrStreamStalled
		case <-m.closed:
			m.dropStream(st)
			return nil, ErrMuxClosed
		case <-st.done:
			err := st.terminalErr()
			m.dropStream(st)
			return nil, err
		}
	}
}

// dropStream 从表中移除并唤醒该流（不再回发 RST）。
func (m *Mux) dropStream(st *Stream) {
	st.terminate(ErrStreamClosed)
	m.mu.Lock()
	m.releaseLocked(st.ID)
	m.mu.Unlock()
	if st.counted.CompareAndSwap(true, false) {
		m.Stats.Active.Add(-1)
	}
}

func (m *Mux) resetRaw(id uint32) {
	if err := m.sec.WriteFrame(Frame{StreamID: id, Flags: FlagRST}); err == nil {
		m.Stats.Resets.Add(1)
	}
}

// readLoop 是唯一的读帧 goroutine，按 StreamID 分发到各流。
func (m *Mux) readLoop() {
	for {
		f, err := m.sec.ReadFrame()
		if err != nil {
			m.Close(err)
			return
		}
		m.LastRecv.Store(time.Now().UnixNano())

		if f.StreamID == CtrlStreamID {
			if f.Flags&FlagPing != 0 {
				_ = m.sec.WriteFrame(Frame{StreamID: CtrlStreamID, Flags: FlagPong})
			} else if f.Flags&FlagPong != 0 {
				// 心跳回包：算出这条连接的真实往返，供状态接口展示。
				if sent := m.PingSentAt.Load(); sent != 0 {
					m.NoteRTT(time.Duration(time.Now().UnixNano() - sent))
					m.PingSentAt.Store(0)
				}
			}
			continue
		}

		if f.Flags&FlagData != 0 {
			m.Stats.RxBytes.Add(uint64(len(f.Payload)))
		}

		st, ok := m.get(f.StreamID)
		if ok && f.Flags&FlagOpen != 0 {
			// 对端在复用一个本端仍然存在的流 ID：这一定是对端发起的
			// 新连接，而本端旧流还没收尾。必须先把旧流清掉再接，
			// 否则这个 OPEN 会被当成旧流的帧投进旧队列，然后静默丢弃，
			// 对端只能干等超时。
			m.Stats.Resets.Add(1)
			st.terminate(ErrStreamReset)
			m.dropStream(st)
			ok = false
		}
		if !ok {
			switch {
			case f.Flags&FlagOpen != 0:
				m.acceptOpen(f)
			case f.Flags&FlagRST != 0:
				// 对端在重置一条本端已不存在的流：静默忽略，避免 RST 互相回击形成风暴。
			default:
				// 未知流：明确回 RST，而不是静默丢弃（v1 直接扔掉会让对端永久等待）。
				m.resetRaw(f.StreamID)
			}
			continue
		}

		if f.Flags&FlagRST != 0 {
			st.terminate(ErrStreamReset)
			m.dropStream(st)
			continue
		}
		if f.Flags&FlagFIN != 0 {
			st.remoteFIN.Store(true)
		}
		m.deliver(st, f)
	}
}

// acceptOpen 处理对端发起的新流。
func (m *Mux) acceptOpen(f Frame) {
	target, err := DecodeTargetProto(f.Payload)
	if err != nil {
		_ = m.sec.WriteFrame(Frame{StreamID: f.StreamID, Flags: FlagOpenErr, Payload: []byte{ErrCodeBad}})
		return
	}
	m.mu.Lock()
	if _, used := m.streams[f.StreamID]; used {
		m.mu.Unlock()
		m.resetRaw(f.StreamID)
		return
	}
	st := m.newStreamLocked(f.StreamID)
	m.streams[f.StreamID] = st
	m.mu.Unlock()

	if m.onOpen == nil {
		m.dropStream(st)
		_ = m.sec.WriteFrame(Frame{StreamID: st.ID, Flags: FlagOpenErr, Payload: []byte{ErrCodeRefuse}})
		return
	}
	go m.onOpen(st, target)
}

// deliver 把帧投递给目标流。只入队，绝不阻塞读循环：
// 一条积压过多的流只会被单独重置，不会连累同隧道上的其它流。
func (m *Mux) deliver(st *Stream, f Frame) {
	frame := Frame{StreamID: f.StreamID, Flags: f.Flags, Payload: f.Payload}
	if !st.enqueue(frame) {
		m.Stats.Stalled.Add(1)
		m.resetRaw(st.ID)
		m.dropStream(st)
	}
}

func (st *Stream) terminate(err error) {
	st.errMu.Lock()
	if st.errVal == nil {
		st.errVal = err
	}
	st.errMu.Unlock()
	st.closeOnce.Do(func() {
		st.isClosed.Store(true)
		close(st.done)
	})
}

func (st *Stream) terminalErr() error {
	st.errMu.Lock()
	defer st.errMu.Unlock()
	if st.errVal != nil {
		return st.errVal
	}
	return ErrStreamClosed
}

// ─── Stream: io.Reader / io.Writer ───────────────────────────────

// Read 从流中读数据，遇到对端 FIN 返回 io.EOF。
func (st *Stream) Read(p []byte) (int, error) {
	for {
		if len(st.pending) > 0 {
			n := copy(p, st.pending)
			st.pending = st.pending[n:]
			return n, nil
		}

		if f, ok := st.pop(); ok {
			switch {
			case f.Flags&FlagRST != 0:
				return 0, ErrStreamReset
			case f.Flags&FlagOpenErr != 0:
				return 0, ErrDialFailed
			case f.Flags&FlagData != 0 && len(f.Payload) > 0:
				st.pending = f.Payload
				continue
			case f.Flags&FlagFIN != 0:
				return 0, io.EOF
			default:
				continue
			}
		}

		select {
		case <-st.notify:
		case <-st.done:
			// 关闭前可能还有残留帧没读完，先取干净再报错。
			if _, ok := st.pop(); !ok {
				return 0, st.terminalErr()
			}
		}
	}
}

// Write 把数据切片后发送。并发安全（底层 WriteFrame 持写锁）。
func (st *Stream) Write(p []byte) (int, error) {
	if st.finSent.Load() {
		return 0, ErrStreamClosed
	}
	select {
	case <-st.done:
		return 0, st.terminalErr()
	default:
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxPayload {
			n = MaxPayload
		}
		if err := st.mux.sec.WriteFrame(Frame{StreamID: st.ID, Flags: FlagData, Payload: p[:n]}); err != nil {
			st.mux.dropStream(st)
			return total, err
		}
		st.mux.Stats.TxBytes.Add(uint64(n))
		total += n
		p = p[n:]
	}
	return total, nil
}

// CloseWrite 发送半关闭（FIN），表示本端不再发送数据。
func (st *Stream) CloseWrite() error {
	if st.finSent.Swap(true) {
		return nil
	}
	if err := st.mux.sec.WriteFrame(Frame{StreamID: st.ID, Flags: FlagFIN}); err != nil {
		st.mux.dropStream(st)
		return err
	}
	return nil
}

// RemoteFIN 报告对端是否已半关闭。
func (st *Stream) RemoteFIN() bool { return st.remoteFIN.Load() }

// Done 在流被终止时关闭。
func (st *Stream) Done() <-chan struct{} { return st.done }

// Reset 异常终止该流并通知对端。
// TunnelStream 是桥接与转发所需的流能力集合。
//
// 生产环境由 *Stream 实现；测试可以注入假实现，不必搭一套真实的 mux。
type TunnelStream interface {
	io.ReadWriteCloser
	// CloseWrite 关闭发送方向，对端读到 EOF。
	CloseWrite() error
	// Reset 以错误终止整条流。
	Reset(err error)
}

func (st *Stream) Reset(err error) {
	if st.isClosed.Load() {
		return
	}
	st.mux.resetRaw(st.ID)
	st.terminate(err)
	st.dropFromMux()
}

func (st *Stream) dropFromMux() {
	st.mux.mu.Lock()
	st.mux.releaseLocked(st.ID)
	st.mux.mu.Unlock()
	if st.counted.CompareAndSwap(true, false) {
		st.mux.Stats.Active.Add(-1)
	}
	st.terminate(ErrStreamClosed)
}

// Close 关闭流。若本端尚未发 FIN，则视为异常终止并通知对端 RST。
func (st *Stream) Close() error {
	if st.isClosed.Load() {
		return nil
	}
	if !st.finSent.Load() {
		st.Reset(ErrStreamClosed)
		return nil
	}
	st.dropFromMux()
	return nil
}

// AcceptOK 回应 OPEN_OK，表示本端到目标的连接已建立。
func (st *Stream) AcceptOK() error {
	if err := st.mux.sec.WriteFrame(Frame{StreamID: st.ID, Flags: FlagOpenOK}); err != nil {
		st.dropFromMux()
		return err
	}
	if st.counted.CompareAndSwap(false, true) {
		st.mux.Stats.Opened.Add(1)
		st.mux.Stats.Active.Add(1)
	}
	return nil
}

// Reject 回应 OPEN_ERR 并移除该流。code 取 ErrCode* 常量。
func (st *Stream) Reject(code byte) {
	_ = st.mux.sec.WriteFrame(Frame{StreamID: st.ID, Flags: FlagOpenErr, Payload: []byte{code}})
	st.dropFromMux()
}

// SetDeadline 设置底层连接读写超时（影响整条隧道，谨慎使用）。
func (m *Mux) SetDeadline(t time.Time) error { return m.sec.SetDeadline(t) }

var _ io.ReadWriteCloser = (*Stream)(nil)
