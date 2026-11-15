package internal

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func pipePair(t *testing.T, psk []byte) (*SecureConn, *SecureConn) {
	t.Helper()
	c1, c2 := net.Pipe()
	type res struct {
		s   *SecureConn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := handshakeFull(c1, psk, true)
		ch <- res{s, err}
	}()
	s2, err := handshakeFull(c2, psk, false)
	if err != nil {
		t.Fatalf("responder 握手失败: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("initiator 握手失败: %v", r.err)
	}
	t.Cleanup(func() { c1.Close(); c2.Close() })
	return r.s, s2
}

func TestHandshakeDerivesDistinctKeys(t *testing.T) {
	// 关键安全属性：同一 PSK 下，每条连接必须派生各自的会话密钥。
	// 否则 nonce 计数会跨连接重复，AES-GCM 的 nonce 重用会让加密彻底失效。
	a1, b1 := pipePair(t, []byte("psk"))
	a2, b2 := pipePair(t, []byte("psk"))
	defer b1.Close()
	defer b2.Close()

	if a1.KeyFingerprint() != b1.KeyFingerprint() {
		t.Fatal("同一连接两端应导出相同密钥")
	}
	if a1.KeyFingerprint() == a2.KeyFingerprint() {
		t.Fatal("两条连接派生了相同密钥（salt 未生效，存在 nonce 重用风险）")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	a, b := pipePair(t, []byte("shared-secret"))
	want := []byte("hello-隧道")
	go func() {
		_ = a.WriteFrame(Frame{StreamID: 42, Flags: FlagData, Payload: want})
	}()
	f, err := b.ReadFrame()
	if err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	if f.StreamID != 42 || f.Flags != FlagData || !bytes.Equal(f.Payload, want) {
		t.Fatalf("帧内容不符: %+v", f)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ch := make(chan *SecureConn, 1)
	go func() {
		s, _ := handshakeFull(c1, []byte("key-AAA"), true)
		ch <- s
	}()
	s2, err := handshakeFull(c2, []byte("key-BBB"), false)
	if err != nil {
		t.Fatalf("握手本身不应失败（密钥在派生阶段才分叉）: %v", err)
	}
	s1 := <-ch
	if s1 == nil || s2 == nil {
		t.Fatal("握手返回空连接")
	}
	if s1.KeyFingerprint() == s2.KeyFingerprint() {
		t.Fatal("不同 PSK 派生出相同密钥")
	}

	go func() { _ = s1.WriteFrame(Frame{StreamID: 1, Flags: FlagData, Payload: []byte("x")}) }()
	if _, err := s2.ReadFrame(); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("密钥不一致时应解密失败，实际: %v", err)
	}
}

func TestReplayRejected(t *testing.T) {
	a, b := pipePair(t, []byte("psk"))
	f := Frame{StreamID: 7, Flags: FlagData, Payload: []byte("once")}

	go func() {
		_ = a.WriteFrame(f)
	}()
	if _, err := b.ReadFrame(); err != nil {
		t.Fatalf("首帧应成功: %v", err)
	}

	// 让发送方回退计数器，重放同一 nonce：接收端必须拒绝。
	a.sendCtr = 0
	go func() {
		_ = a.WriteFrame(f)
	}()
	_, err := b.ReadFrame()
	if !errors.Is(err, ErrBadNonce) {
		t.Fatalf("重放帧应被拒绝，实际 err=%v", err)
	}
}

func TestVersionMismatch(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	// 由 c1 手工发一个 v99 的 hello，c2 作为响应方读取后应直接拒绝。
	go func() {
		_, _ = c1.Write([]byte{magicByte, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 18)
		_, _ = c1.Read(buf)
	}()
	if _, err := handshakeFull(c2, []byte("psk"), false); !errors.Is(err, ErrVersion) {
		t.Fatalf("版本不匹配应报 ErrVersion，实际: %v", err)
	}
}

func TestTargetCodec(t *testing.T) {
	cases := []struct {
		host string
		port uint16
	}{
		{"10.0.0.201", 22},
		{"nas.home.lan", 8080},
		{"::1", 443},
	}
	for _, c := range cases {
		b, err := EncodeTarget(c.host, c.port)
		if err != nil {
			t.Fatalf("编码 %s 失败: %v", c.host, err)
		}
		h, p, err := DecodeTarget(b)
		if err != nil {
			t.Fatalf("解码 %s 失败: %v", c.host, err)
		}
		if h != c.host || p != c.port {
			t.Fatalf("往返不一致: want %s:%d got %s:%d", c.host, c.port, h, p)
		}
	}
}

func TestMuxOpenEcho(t *testing.T) {
	a, b := pipePair(t, []byte("psk"))

	var handled sync.WaitGroup
	handled.Add(1)
	muxB := NewMux(b, func(st *Stream, target Target) {
		defer handled.Done()
		if target.Host != "10.0.0.201" || target.Port != 22 {
			st.Reject(ErrCodeBad)
			return
		}
		if err := st.AcceptOK(); err != nil {
			return
		}
		buf := make([]byte, 64)
		n, err := st.Read(buf)
		if err != nil {
			return
		}
		_, _ = st.Write(append([]byte("echo:"), buf[:n]...))
		_ = st.CloseWrite()
	})
	muxA := NewMux(a, nil)
	defer muxA.Close(nil)
	defer muxB.Close(nil)

	st, err := muxA.Open("10.0.0.201", 22, 3*time.Second)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite 失败: %v", err)
	}
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(got) != "echo:ping" {
		t.Fatalf("回显不符: %q", string(got))
	}
	handled.Wait()
}

func TestMuxOpenRejected(t *testing.T) {
	a, b := pipePair(t, []byte("psk"))
	muxB := NewMux(b, func(st *Stream, target Target) {
		st.Reject(ErrCodeDial)
	})
	muxA := NewMux(a, nil)
	defer muxA.Close(nil)
	defer muxB.Close(nil)

	if _, err := muxA.Open("10.0.0.9", 9, 3*time.Second); !errors.Is(err, ErrDialFailed) {
		t.Fatalf("应返回 ErrDialFailed，实际: %v", err)
	}
}

func TestMuxOpenTimeout(t *testing.T) {
	a, b := pipePair(t, []byte("psk"))
	// 对端收到 OPEN 但永不回应，应超时而不是永久挂起。
	muxB := NewMux(b, func(st *Stream, target Target) {})
	muxA := NewMux(a, nil)
	defer muxA.Close(nil)
	defer muxB.Close(nil)

	start := time.Now()
	if _, err := muxA.Open("10.0.0.9", 9, 300*time.Millisecond); !errors.Is(err, ErrStreamStalled) {
		t.Fatalf("应返回 ErrStreamStalled，实际: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("超时保护失效，耗时 %v", d)
	}
}

func TestStreamIDReuse(t *testing.T) {
	a, b := pipePair(t, []byte("psk"))
	muxB := NewMux(b, func(st *Stream, target Target) {
		_ = st.AcceptOK()
		_ = st.CloseWrite()
	})
	muxA := NewMux(a, nil)
	defer muxA.Close(nil)
	defer muxB.Close(nil)

	// 同时保持 50 条流活跃：活跃期间 ID 必须唯一。
	// （流关闭后 ID 被回收复用是正确行为，不算冲突。）
	seen := map[uint32]bool{}
	live := make([]*Stream, 0, 50)
	defer func() {
		for _, st := range live {
			st.Reset(ErrStreamClosed)
		}
	}()
	for i := 0; i < 50; i++ {
		st, err := muxA.Open("x", 1, 2*time.Second)
		if err != nil {
			t.Fatalf("第 %d 次 Open 失败: %v", i, err)
		}
		if seen[st.ID] {
			t.Fatalf("流 ID %d 在并发活跃期间被重复分配", st.ID)
		}
		seen[st.ID] = true
		live = append(live, st)
	}
}

func TestEncodeTargetProtoCompat(t *testing.T) {
	// TCP 目标必须与 v2 原格式逐字节一致，否则老对端无法解析。
	plain, err := EncodeTarget("10.0.0.201", 22)
	if err != nil {
		t.Fatal(err)
	}
	coded, err := EncodeTargetProto(Target{Host: "10.0.0.201", Port: 22, Proto: ProtoTCP})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, coded) {
		t.Fatalf("TCP 编码与旧格式不一致: %x vs %x", plain, coded)
	}

	// UDP 目标多一个类型字节，解码后协议应回 udp。
	udp, err := EncodeTargetProto(Target{Host: "10.0.0.254", Port: 53, Proto: ProtoUDP})
	if err != nil {
		t.Fatal(err)
	}
	if len(udp) != len(plain)+1 || udp[0] != addrUDP {
		t.Fatalf("UDP 编码格式不对: %x", udp)
	}
	got, err := DecodeTargetProto(udp)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "10.0.0.254" || got.Port != 53 || got.Proto != ProtoUDP {
		t.Fatalf("UDP 往返不一致: %+v", got)
	}
	if got.Network() != "udp" {
		t.Fatalf("Network 应为 udp，实际 %s", got.Network())
	}

	// 老格式（无前缀）解出来的协议必须是 tcp。
	rt, err := DecodeTargetProto(plain)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Proto != ProtoTCP {
		t.Fatalf("旧格式应解出 tcp，实际 %s", rt.Proto)
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payloads := [][]byte{
		[]byte("hello"),
		{},
		bytes.Repeat([]byte{0xAB}, 1400),
	}
	for _, p := range payloads {
		if err := WriteDatagram(&buf, p); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
	}
	for i, want := range payloads {
		got, err := ReadDatagram(&buf)
		if err != nil {
			t.Fatalf("第 %d 个读取失败: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("第 %d 个内容不一致: %d vs %d 字节", i, len(got), len(want))
		}
	}
	if _, err := ReadDatagram(&buf); err == nil {
		t.Fatal("期望在流末尾读到 EOF")
	}

	// 超长数据报必须被拒绝，而不是悄悄截断。
	tooBig := make([]byte, MaxDatagram+1)
	if err := WriteDatagram(&bytes.Buffer{}, tooBig); err != ErrDatagramTooLarge {
		t.Fatalf("超长数据报应返回 ErrDatagramTooLarge，实际 %v", err)
	}
}
