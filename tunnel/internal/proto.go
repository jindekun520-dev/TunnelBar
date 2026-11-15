// Package internal 实现隧道 v2 协议。
//
// 与 v1 的关键区别：
//   - 每条连接握手交换随机 salt，用 HKDF 派生出该连接独有的会话密钥，
//     彻底消除「同一 PSK 跨连接复用 AES-GCM nonce」这一致命缺陷。
//   - nonce 由 [方向位 4B][单调计数 8B] 构成，接收端严格校验方向与计数递增，
//     同时提供防重放与防反射（把收到的帧原样打回去）能力。
//   - 帧头带显式 flags（OPEN/OK/ERR/DATA/FIN/RST/PING/PONG），
//     v1 用「1 字节 payload」兼作建连结果判断、会误伤正常数据的问题不复存在。
//   - streamID 扩到 uint32。
package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// ProtocolVersion 协议版本，三端必须一致。
	ProtocolVersion = 2
	magicByte       = 0x54 // 'T'
	saltSize        = 16
	nonceSize       = 12
	headerSize      = 4 + nonceSize // ctLen(4) + nonce(12)

	// MaxPayload 单帧明文 payload 上限（不含 5 字节流头）。
	MaxPayload = 32 * 1024
	// maxCipherLen 允许接收的最大密文长度，用于快速拒绝畸形帧。
	maxCipherLen = MaxPayload + 64

	// writeFrameTimeout 单帧写入的兜底超时。超过它说明这条 TCP 已经
	// 无法把数据交给对端（发送窗口长时间为 0），继续等只会让所有流一起挂死。
	writeFrameTimeout = 10 * time.Second

	// dirInitiator / dirResponder 写入 nonce 前 4 字节，用于区分双工方向。
	dirInitiator = 0x01000000
	dirResponder = 0x02000000

	// CtrlStreamID 保留给控制帧的流 ID。
	CtrlStreamID = uint32(0)

	handshakeTimeout = 10 * time.Second
)

// 帧标志位。
const (
	FlagOpen    uint8 = 0x01 // 建连请求，payload = 目标地址编码
	FlagOpenOK  uint8 = 0x02 // 建连成功
	FlagOpenErr uint8 = 0x04 // 建连失败，payload[0] = 错误码
	FlagData    uint8 = 0x08 // 数据
	FlagFIN     uint8 = 0x10 // 半关闭：发送方不再发送数据
	FlagRST     uint8 = 0x20 // 异常终止整条流
	FlagPing    uint8 = 0x40 // 心跳请求（仅 sid=0）
	FlagPong    uint8 = 0x80 // 心跳响应（仅 sid=0）
)

// 建连失败错误码。
const (
	ErrCodeDial   = 1 // 目标不可达
	ErrCodeRefuse = 2 // 对端拒绝（无 home 在线等）
	ErrCodeBad    = 3 // 请求格式非法
)

var (
	ErrFrameTooLarge = errors.New("tunnel: 帧过大")
	ErrBadFrame      = errors.New("tunnel: 帧格式非法")
	ErrBadNonce      = errors.New("tunnel: nonce 非法（重放或乱序）")
	ErrDecrypt       = errors.New("tunnel: 解密失败（密钥不一致）")
	ErrVersion       = errors.New("tunnel: 协议版本不匹配")
	ErrHandshake     = errors.New("tunnel: 握手失败")
)

// Frame 是一条复用帧。
type Frame struct {
	StreamID uint32
	Flags    uint8
	Payload  []byte
}

// SecureConn 是在 net.Conn 之上的一层认证加密帧通道。
type SecureConn struct {
	conn net.Conn
	aead cipher.AEAD

	// keyHash 是本连接会话密钥的指纹（前 8 字节），仅用于自检与排查
	// 「两端 PSK 不一致」，不需要暴露密钥本身。
	keyHash [8]byte
	sendDir uint32
	recvDir uint32
	sendCtr uint64
	recvCtr uint64
	wmu     sync.Mutex
	ptBuf   []byte
	outBuf  []byte
	ctBuf   []byte
	hdrBuf  [headerSize]byte
}

// KeyFingerprint 返回本连接会话密钥指纹，用于两端比对排查密钥不一致。
func (s *SecureConn) KeyFingerprint() [8]byte { return s.keyHash }

// Conn 返回底层连接，供上层设置 deadline。
func (s *SecureConn) Conn() net.Conn { return s.conn }

// Close 关闭底层连接。
func (s *SecureConn) Close() error { return s.conn.Close() }

// sockBufSize 是隧道底层 TCP 的收发缓冲。
//
// 隧道是典型的「长肥管道」：本机到中继常有 50ms 以上 RTT，且中间经过移动网络
// 或家用 NAT。系统默认缓冲（几十 KB）会把单条 TCP 的带宽延迟积压死，
// 实测单流只能跑到 300KB/s 上下。放大到 4MB 后接收窗口足够让发送方把
// 拥塞窗口涨起来，单流吞吐随之提升。
const sockBufSize = 4 << 20

// SetNoDelay 调整底层 TCP：关闭 Nagle、开启保活、放大收发缓冲。
func (s *SecureConn) SetNoDelay() {
	if tc, ok := s.conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		// 保活周期压到 10s：热点/NAT 把连接悄悄丢掉时，内核能更快发现。
		_ = tc.SetKeepAlivePeriod(10 * time.Second)
		_ = tc.SetReadBuffer(sockBufSize)
		_ = tc.SetWriteBuffer(sockBufSize)
	}
}

// SetDeadline 透传读写超时。
func (s *SecureConn) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }

// hkdfSHA256 用 HMAC-SHA256 实现 HKDF-Extract + Expand（单块 32 字节输出），
// 避免引入外部依赖。
func hkdfSHA256(secret, salt []byte, info string) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	prk := mac.Sum(nil)

	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte(info))
	mac.Write([]byte{0x01})
	return mac.Sum(nil) // 32 字节
}

// handshakeFull 完成 salt 交换并构造会话密钥。
// 明文交换 18 字节 hello（magic + version + salt），salt 公开无碍；
// 之后所有帧均以派生出的会话密钥加密。
func handshakeFull(c net.Conn, psk []byte, initiator bool) (*SecureConn, error) {
	if err := c.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	defer c.SetDeadline(time.Time{})

	mySalt := make([]byte, saltSize)
	if _, err := rand.Read(mySalt); err != nil {
		return nil, err
	}
	hello := make([]byte, 2+saltSize)
	hello[0] = magicByte
	hello[1] = ProtocolVersion
	copy(hello[2:], mySalt)

	peer := make([]byte, 2+saltSize)
	if initiator {
		if _, err := c.Write(hello); err != nil {
			return nil, fmt.Errorf("%w: 发送 hello: %v", ErrHandshake, err)
		}
		if _, err := io.ReadFull(c, peer); err != nil {
			return nil, fmt.Errorf("%w: 读取 hello: %v", ErrHandshake, err)
		}
	} else {
		if _, err := io.ReadFull(c, peer); err != nil {
			return nil, fmt.Errorf("%w: 读取 hello: %v", ErrHandshake, err)
		}
		if _, err := c.Write(hello); err != nil {
			return nil, fmt.Errorf("%w: 发送 hello: %v", ErrHandshake, err)
		}
	}

	if peer[0] != magicByte {
		return nil, fmt.Errorf("%w: magic 不匹配", ErrHandshake)
	}
	if peer[1] != ProtocolVersion {
		return nil, fmt.Errorf("%w: 对端 v%d, 本端 v%d", ErrVersion, peer[1], ProtocolVersion)
	}
	peerSalt := peer[2:]

	// salt 顺序固定为「发起方 salt || 响应方 salt」，两端一致。
	var salt []byte
	if initiator {
		salt = append(append([]byte{}, mySalt...), peerSalt...)
	} else {
		salt = append(append([]byte{}, peerSalt...), mySalt...)
	}
	key := hkdfSHA256(psk, salt, fmt.Sprintf("tunnel/v%d/psk", ProtocolVersion))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key)
	s := &SecureConn{conn: c, aead: gcm}
	copy(s.keyHash[:], sum[:8])
	if initiator {
		s.sendDir, s.recvDir = dirInitiator, dirResponder
	} else {
		s.sendDir, s.recvDir = dirResponder, dirInitiator
	}
	return s, nil
}

// DialSecure 作为发起方连接到 addr 并完成握手。
func DialSecure(addr string, psk []byte, timeout time.Duration) (*SecureConn, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	s, err := handshakeFull(c, psk, true)
	if err != nil {
		c.Close()
		return nil, err
	}
	s.SetNoDelay()
	return s, nil
}

// ServerSecure 在已接受的连接上作为响应方完成握手。
func ServerSecure(c net.Conn, psk []byte) (*SecureConn, error) {
	s, err := handshakeFull(c, psk, false)
	if err != nil {
		c.Close()
		return nil, err
	}
	s.SetNoDelay()
	return s, nil
}

// WriteFrame 加密并发送一帧。并发安全。
func (s *SecureConn) WriteFrame(f Frame) error {
	if len(f.Payload) > MaxPayload {
		return ErrFrameTooLarge
	}
	ptLen := 5 + len(f.Payload)

	s.wmu.Lock()
	defer s.wmu.Unlock()

	if cap(s.ptBuf) < ptLen {
		s.ptBuf = make([]byte, ptLen)
	}
	pt := s.ptBuf[:ptLen]
	binary.BigEndian.PutUint32(pt[0:4], f.StreamID)
	pt[4] = f.Flags
	copy(pt[5:], f.Payload)

	s.sendCtr++
	var nonce [nonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], s.sendDir)
	binary.BigEndian.PutUint64(nonce[4:12], s.sendCtr)

	ctLen := ptLen + s.aead.Overhead()
	need := headerSize + ctLen
	if cap(s.outBuf) < need {
		s.outBuf = make([]byte, need)
	}
	out := s.outBuf[:need]
	binary.BigEndian.PutUint32(out[0:4], uint32(ctLen))
	copy(out[4:headerSize], nonce[:])
	s.aead.Seal(out[headerSize:headerSize], nonce[:], pt, nil)

	// 单次 Write，避免 TCP 小包。
	//
	// 必须带写超时：对端读循环被某条慢流卡住时，这条 TCP 的发送窗口会被填满，
	// 阻塞的 Write 会让该连接上所有流一起挂死——浏览器里就是「页面一直白着」，
	// 既不报错也不重试。写入超时就当这条连接已失效，直接关掉交给上层重建。
	if dl, ok := s.conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(writeFrameTimeout))
	}
	n, err := s.conn.Write(out)
	if err == nil && n < len(out) {
		err = io.ErrShortWrite
	}
	if err != nil {
		// 帧可能只写了一半，后续字节流已经对不齐，这条连接不能再复用。
		_ = s.conn.Close()
	}
	return err
}

// ReadFrame 读取并解密一帧。必须由单个 goroutine 调用。
func (s *SecureConn) ReadFrame() (Frame, error) {
	var f Frame

	hdr := s.hdrBuf[:]
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return f, err
	}
	ctLen := binary.BigEndian.Uint32(hdr[0:4])
	if ctLen == 0 || ctLen > maxCipherLen {
		return f, ErrBadFrame
	}

	if cap(s.ctBuf) < int(ctLen) {
		s.ctBuf = make([]byte, ctLen)
	}
	ct := s.ctBuf[:ctLen]
	if _, err := io.ReadFull(s.conn, ct); err != nil {
		return f, err
	}

	// 校验 nonce 的方向位与单调计数，拒绝重放/乱序/反射帧。
	var nonce [nonceSize]byte
	copy(nonce[:], hdr[4:headerSize])
	if binary.BigEndian.Uint32(nonce[0:4]) != s.recvDir {
		return f, ErrBadNonce
	}
	ctr := binary.BigEndian.Uint64(nonce[4:12])
	if ctr != s.recvCtr+1 {
		return f, ErrBadNonce
	}

	pt, err := s.aead.Open(nil, nonce[:], ct, nil)
	if err != nil {
		return f, ErrDecrypt
	}
	s.recvCtr = ctr

	if len(pt) < 5 {
		return f, ErrBadFrame
	}
	f.StreamID = binary.BigEndian.Uint32(pt[0:4])
	f.Flags = pt[4]
	f.Payload = pt[5:]
	return f, nil
}

// ─── 目标地址编码 ────────────────────────────────────────────────
//
//	[1B type][len/addr][2B port]
//	type: 1=IPv4(4B) 3=域名(1B len + n) 4=IPv6(16B)

const (
	addrIPv4   = 1
	addrDomain = 3
	addrIPv6   = 4
	// addrUDP 后面跟一个完整的 target 编码，表示这条流承载 UDP 数据报。
	//
	// 之所以在外层再包一层而不是改原有布局：老的 home 读到未知类型会回
	// OPEN_ERR，行为明确（而不是把 UDP 请求误当 TCP 拨号），升级后即恢复。
	addrUDP = 5
	// addrICMP 表示这条流只用来做一次 ICMP 可达性探测（ping）。
	// 隧道只承载 TCP/UDP，ICMP 无法直接穿过去，所以由家里那侧
	// 代发一次 echo，把「通/不通」回传给本机。
	addrICMP = 6
)

// 流承载的传输层协议。
const (
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoICMP = "icmp"
)

// Target 描述一条流的建连目标。
type Target struct {
	Host  string
	Port  uint16
	Proto string
}

// Network 返回给 net.Dialer 用的网络名。
func (t Target) Network() string {
	if t.Proto == ProtoUDP {
		return "udp"
	}
	return "tcp"
}

// EncodeTargetProto 按 target 的协议编码 OPEN 帧 payload。
// TCP 目标保持 v2 原格式不变，因此对老版本完全兼容。
func EncodeTargetProto(t Target) ([]byte, error) {
	inner, err := EncodeTarget(t.Host, t.Port)
	if err != nil {
		return nil, err
	}
	switch t.Proto {
	case ProtoUDP, ProtoICMP:
		// 带上协议前缀；TCP 保持原格式，对老版本完全兼容。
		prefix := byte(addrUDP)
		if t.Proto == ProtoICMP {
			prefix = addrICMP
		}
		buf := make([]byte, 0, 1+len(inner))
		buf = append(buf, prefix)
		buf = append(buf, inner...)
		return buf, nil
	default:
		return inner, nil
	}
}

// DecodeTargetProto 解析 OPEN 帧 payload，得到带协议标识的目标。
func DecodeTargetProto(b []byte) (Target, error) {
	if len(b) > 0 && (b[0] == addrUDP || b[0] == addrICMP) {
		host, port, err := DecodeTarget(b[1:])
		if err != nil {
			return Target{}, err
		}
		proto := ProtoUDP
		if b[0] == addrICMP {
			proto = ProtoICMP
		}
		return Target{Host: host, Port: port, Proto: proto}, nil
	}
	host, port, err := DecodeTarget(b)
	if err != nil {
		return Target{}, err
	}
	return Target{Host: host, Port: port, Proto: ProtoTCP}, nil
}

// EncodeTarget 把 host:port 编码进 OPEN 帧 payload。
func EncodeTarget(host string, port uint16) ([]byte, error) {
	buf := make([]byte, 0, 1+1+len(host)+2)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, addrIPv4)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, addrIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("tunnel: 目标主机名非法")
		}
		buf = append(buf, addrDomain, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, port)
	return buf, nil
}

// DecodeTarget 解析 OPEN 帧 payload。
func DecodeTarget(b []byte) (string, uint16, error) {
	if len(b) < 1 {
		return "", 0, errors.New("tunnel: 目标地址为空")
	}
	var host string
	var off int
	switch b[0] {
	case addrIPv4:
		if len(b) < 1+4+2 {
			return "", 0, errors.New("tunnel: IPv4 目标截断")
		}
		host = net.IP(b[1:5]).String()
		off = 5
	case addrIPv6:
		if len(b) < 1+16+2 {
			return "", 0, errors.New("tunnel: IPv6 目标截断")
		}
		host = net.IP(b[1:17]).String()
		off = 17
	case addrDomain:
		if len(b) < 2 {
			return "", 0, errors.New("tunnel: 域名目标截断")
		}
		n := int(b[1])
		if len(b) < 2+n+2 {
			return "", 0, errors.New("tunnel: 域名目标截断")
		}
		host = string(b[2 : 2+n])
		off = 2 + n
	default:
		return "", 0, errors.New("tunnel: 未知地址类型")
	}
	port := binary.BigEndian.Uint16(b[off : off+2])
	return host, port, nil
}
