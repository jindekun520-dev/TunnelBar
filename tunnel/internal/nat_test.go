package internal

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"tunnel/third_party/gvisor/pkg/tcpip"
	"tunnel/third_party/gvisor/pkg/tcpip/header"
)

// fakeStream 实现 TunnelStream，用来在测试里模拟对端行为。
type fakeStream struct {
	r io.Reader
}

func (f *fakeStream) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *fakeStream) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeStream) Close() error                { return nil }
func (f *fakeStream) CloseWrite() error           { return nil }
func (f *fakeStream) Reset(error)                 {}

// buildIPv4 构造一个 IPv4 头 + payload 的包，并算好 IP 校验和。
func buildIPv4(t *testing.T, src, dst [4]byte, proto tcpip.TransportProtocolNumber, payload []byte) []byte {
	t.Helper()
	b := make([]byte, header.IPv4MinimumSize+len(payload))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(proto),
		SrcAddr:     tcpip.AddrFrom4(src),
		DstAddr:     tcpip.AddrFrom4(dst),
	})
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	copy(ip.Payload(), payload)
	return b
}

// buildTCP 构造一个完整 TCP 段（IP 头 + TCP 头，校验和已算好）。
func buildTCP(t *testing.T, src, dst [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags header.TCPFlags) []byte {
	t.Helper()
	tcpH := make([]byte, header.TCPMinimumSize)
	header.TCP(tcpH).Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	pkt := buildIPv4(t, src, dst, header.TCPProtocolNumber, tcpH)

	ip := header.IPv4(pkt)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcpH)))
	seg := header.TCP(ip.Payload())
	seg.SetChecksum(0)
	seg.SetChecksum(^seg.CalculateChecksum(xsum))
	return pkt
}

// TestNATSynTriggersDial 走完一次完整三次握手，验证协议栈会把 TUN 上的
// 连接翻译成一次隧道拨号，且目标地址/端口/协议都正确。
func TestNATSynTriggersDial(t *testing.T) {
	dialed := make(chan Target, 1)
	nat, err := NewNAT(func(tg Target, _ time.Duration) (TunnelStream, error) {
		select {
		case dialed <- tg:
		default:
		}
		return nil, errors.New("test: 拒绝")
	}, 1400, time.Second, time.Second)
	if err != nil {
		t.Fatalf("初始化协议栈失败: %v", err)
	}
	defer nat.Close()

	clientIP := [4]byte{198, 18, 0, 1}
	serverIP := [4]byte{10, 0, 0, 201}
	const (
		clientPort = 51234
		serverPort = 22
		seq0       = 1000
	)

	// 1. 客户端 SYN
	nat.InjectInbound(buildTCP(t, clientIP, serverIP, clientPort, serverPort, seq0, 0, header.TCPFlagSyn))

	// 2. 等协议栈回 SYN-ACK
	var synack []byte
	deadline := time.After(3 * time.Second)
	for synack == nil {
		select {
		case p := <-nat.Outbound():
			ip := header.IPv4(p)
			if ip.Protocol() != uint8(header.TCPProtocolNumber) {
				continue
			}
			seg := header.TCP(ip.Payload())
			if seg.Flags().Contains(header.TCPFlagSyn) && seg.Flags().Contains(header.TCPFlagAck) {
				synack = p
			}
		case <-deadline:
			t.Fatal("没有收到 SYN-ACK")
		}
	}
	sip := header.IPv4(synack)
	sseg := header.TCP(sip.Payload())
	if got := sip.SourceAddress().String(); got != "10.0.0.201" {
		t.Fatalf("SYN-ACK 源地址应为 10.0.0.201，实际 %s", got)
	}

	// 3. 客户端 ACK，完成握手（方向是客户端 -> 服务端）
	nat.InjectInbound(buildTCP(t, clientIP, serverIP, clientPort, serverPort,
		seq0+1, sseg.SequenceNumber()+1, header.TCPFlagAck))

	// 4. 握手完成后应触发隧道拨号
	select {
	case tg := <-dialed:
		if tg.Host != "10.0.0.201" || tg.Port != 22 {
			t.Fatalf("拨号目标不对: %+v", tg)
		}
		if tg.Proto != ProtoTCP || tg.Network() != "tcp" {
			t.Fatalf("协议应为 tcp，实际 %+v", tg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("握手完成后未触发隧道拨号")
	}
}

// TestNATICMPEchoReply 验证：家里那侧确认可达后，本层才回 echo reply。
func TestNATICMPEchoReply(t *testing.T) {
	nat, err := NewNAT(func(tg Target, _ time.Duration) (TunnelStream, error) {
		if tg.Proto != ProtoICMP {
			return nil, errors.New("test: ICMP 探测不该走其它协议")
		}
		return &fakeStream{r: bytes.NewReader([]byte{1})}, nil
	}, 1400, time.Second, time.Second)
	if err != nil {
		t.Fatalf("初始化协议栈失败: %v", err)
	}
	defer nat.Close()

	icmp := make([]byte, header.ICMPv4MinimumSize+8)
	header.ICMPv4(icmp).SetType(header.ICMPv4Echo)
	header.ICMPv4(icmp).SetCode(0)
	header.ICMPv4(icmp).SetIdent(0x1234)
	header.ICMPv4(icmp).SetSequence(7)
	copy(icmp[header.ICMPv4MinimumSize:], []byte("pingdata"))
	header.ICMPv4(icmp).SetChecksum(0)
	header.ICMPv4(icmp).SetChecksum(header.ICMPv4Checksum(header.ICMPv4(icmp), 0))

	pkt := buildIPv4(t, [4]byte{198, 18, 0, 1}, [4]byte{10, 0, 0, 10}, header.ICMPv4ProtocolNumber, icmp)
	nat.InjectInbound(pkt)

	select {
	case reply := <-nat.Outbound():
		ip := header.IPv4(reply)
		if !ip.IsValid(len(reply)) {
			t.Fatalf("回包不是合法 IPv4: %s", tcpip.AddrFrom4Slice(reply[12:16]))
		}
		// 源/目的应互换
		if got := ip.SourceAddress().String(); got != "10.0.0.10" {
			t.Fatalf("回包源地址应为 10.0.0.10，实际 %s", got)
		}
		if got := ip.DestinationAddress().String(); got != "198.18.0.1" {
			t.Fatalf("回包目的地址应为 198.18.0.1，实际 %s", got)
		}
		ric := header.ICMPv4(ip.Payload())
		if ric.Type() != header.ICMPv4EchoReply {
			t.Fatalf("回包类型应为 echo reply，实际 %d", ric.Type())
		}
		if ric.Checksum() != 0 && ric.Checksum() != header.ICMPv4Checksum(ric, 0) {
			t.Fatalf("ICMP 校验和错误: %#x", ric.Checksum())
		}
		if nat.Stats().ICMPEchoes != 1 {
			t.Fatalf("应记录 1 次 echo 应答，实际 %d", nat.Stats().ICMPEchoes)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("echo request 没有得到应答")
	}
}

// TestNATICMPUnreachableSilent 验证：家里那侧说不可达时，本层不回包，
// 让 ping 自然超时——绝不能无条件回包，否则 ping 什么地址都"通"。
func TestNATICMPUnreachableSilent(t *testing.T) {
	nat, err := NewNAT(func(Target, time.Duration) (TunnelStream, error) {
		return nil, errors.New("test: 目标不可达")
	}, 1400, time.Second, time.Second)
	if err != nil {
		t.Fatalf("初始化协议栈失败: %v", err)
	}
	defer nat.Close()

	icmpPkt := make([]byte, header.ICMPv4MinimumSize)
	header.ICMPv4(icmpPkt).SetType(header.ICMPv4Echo)
	header.ICMPv4(icmpPkt).SetIdent(1)
	header.ICMPv4(icmpPkt).SetSequence(1)
	header.ICMPv4(icmpPkt).SetChecksum(0)
	header.ICMPv4(icmpPkt).SetChecksum(header.ICMPv4Checksum(header.ICMPv4(icmpPkt), 0))

	pkt := buildIPv4(t, [4]byte{198, 18, 0, 1}, [4]byte{10, 0, 0, 77}, header.ICMPv4ProtocolNumber, icmpPkt)
	nat.InjectInbound(pkt)

	select {
	case <-nat.Outbound():
		t.Fatal("目标不可达时不应回包")
	case <-time.After(700 * time.Millisecond):
	}
	if got := nat.Stats().ICMPEchoes; got != 0 {
		t.Fatalf("不应记录 echo 应答，实际 %d", got)
	}
}
