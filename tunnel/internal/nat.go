// 本文件把 TUN 设备上的 TCP/UDP 流量接进 gvisor 用户态协议栈，
// 再逐条转成隧道流发给对端。协议栈取自 gvisor 的 netstack（见 third_party/gvisor）。
package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"tunnel/third_party/gvisor/pkg/buffer"
	"tunnel/third_party/gvisor/pkg/tcpip"
	"tunnel/third_party/gvisor/pkg/tcpip/adapters/gonet"
	"tunnel/third_party/gvisor/pkg/tcpip/header"
	"tunnel/third_party/gvisor/pkg/tcpip/link/channel"
	"tunnel/third_party/gvisor/pkg/tcpip/network/ipv4"
	"tunnel/third_party/gvisor/pkg/tcpip/stack"
	"tunnel/third_party/gvisor/pkg/tcpip/transport/tcp"
	"tunnel/third_party/gvisor/pkg/tcpip/transport/udp"
	"tunnel/third_party/gvisor/pkg/waiter"
)

const (
	nicID = tcpip.NICID(1)

	// TUN 接口自身的地址。198.18.0.0/15 是 RFC 2544 留给基准测试的保留段，
	// 与家庭、公司网段都不重叠，因此不会和真实内网抢路由。
	tunIPv4       = "198.18.0.1"
	tunIPv4Prefix = 15

	// outboundQueue 是协议栈交给 TUN 的包队列长度。
	outboundQueue = 512
	// tcpInFlight 单条 TUN 上允许同时在建的 TCP 连接数上限。
	tcpInFlight = 2048
	// udpIdle UDP 会话的空闲回收时间。UDP 没有关闭语义，只能靠闲置判断。
	udpIdle = 90 * time.Second
)

// DialFunc 由上层提供：按目标建一条隧道流。
type DialFunc func(t Target, timeout time.Duration) (TunnelStream, error)

// NATStats 是 TUN 转发侧的计数快照。
type NATStats struct {
	TCPTotal   int64  `json:"tcp_total"`
	UDPTotal   int64  `json:"udp_total"`
	TCPActive  int64  `json:"tcp_active"`
	UDPActive  int64  `json:"udp_active"`
	ICMPEchoes int64  `json:"icmp_echo_replies"`
	OutDrops   uint64 `json:"outbound_drops"`
}

// NAT 把 TUN 上的流量翻译成隧道流。
// DefaultFinGuard 关闭流之前多等的时间。见 pipe.Bridge 里的说明。
const DefaultFinGuard = 700 * time.Millisecond

// icmpFailTTL 「不可达」结果的缓存时长。只用于抑制探测流堆积，
// ping 间隔通常 1s，取 2s 既能压住堆积，又不会太迟钝。
const icmpFailTTL = 2 * time.Second

type NAT struct {
	s    *stack.Stack
	ep   *channel.Endpoint
	dial DialFunc
	mtu  int

	openTimeout time.Duration
	linger      time.Duration
	// finGuard 收尾前多压一会儿再发 FIN，规避 relay 侧路由 ID 复用导致的串包。
	finGuard time.Duration

	out    chan []byte
	once   sync.Once
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc

	tcpTotal   atomic.Int64
	udpTotal   atomic.Int64
	tcpActive  atomic.Int64
	udpActive  atomic.Int64
	icmpEchoes atomic.Int64
	// icmpFail 只缓存「最近确认不可达」的目标，值为过期时间。
	//
	// 可达的目标**不缓存**：一旦缓存，缓存命中的 echo reply 是本地合成的，
	// 用时 0.3ms，跟真实链路（80~110ms）差两个数量级。表现出来就是
	// 「每隔 3 个包出现一个慢包」——慢的才是真的，快的全是假的，
	// 排障时会得出完全错误的结论。宁可多开一条探测流，也要让每个
	// ping 包都反映真实往返。
	//
	// 不可达则短暂缓存，避免目标关机时每个 ping 包都开一条探测流。
	icmpFail sync.Map
	outDrops atomic.Uint64
}

// NewNAT 初始化用户态协议栈。
func NewNAT(dial DialFunc, mtu int, openTimeout, linger time.Duration) (*NAT, error) {
	if mtu <= 0 {
		mtu = 1400
	}
	ep := channel.New(outboundQueue, uint32(mtu), "")

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	ctx, cancel := context.WithCancel(context.Background())
	n := &NAT{
		s:           s,
		ep:          ep,
		dial:        dial,
		mtu:         mtu,
		openTimeout: openTimeout,
		linger:      linger,
		finGuard:    DefaultFinGuard,
		out:         make(chan []byte, outboundQueue),
		done:        make(chan struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}

	if err := s.CreateNIC(nicID, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("创建 TUN 网卡失败: %v", err)
	}
	// 混杂 + 欺骗：TUN 上的目标地址都不是本机地址，必须让协议栈
	// 接受「发往任意地址」的包，并以原目标地址作为回包的源地址。
	_ = s.SetPromiscuousMode(nicID, true)
	_ = s.SetSpoofing(nicID, true)

	addr := tcpip.AddrFrom4Slice([]byte{198, 18, 0, 1})
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: tunIPv4Prefix},
	}, stack.AddressProperties{}); err != nil {
		s.Close()
		return nil, fmt.Errorf("配置 TUN 地址失败: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	tcpFwd := tcp.NewForwarder(s, 0, tcpInFlight, n.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, n.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	go n.pumpOutbound()
	return n, nil
}

// MTU 返回协议栈侧的 MTU。
func (n *NAT) MTU() int { return n.mtu }

// Outbound 返回「要写进 TUN 的 IP 包」通道。
func (n *NAT) Outbound() <-chan []byte { return n.out }

// pumpOutbound 把协议栈要发出的包搬到通道里，交给 TUN 写出。
func (n *NAT) pumpOutbound() {
	for {
		// 必须用阻塞读：Read() 是非阻塞的，读到空即返回 nil，
		// 用它会把「暂时没有包」误当成「链路结束」，随后所有出站包都会丢失。
		pkt := n.ep.ReadContext(n.ctx)
		if pkt == nil {
			return
		}
		buf := pkt.ToBuffer()
		raw := buf.Flatten()
		out := make([]byte, len(raw))
		copy(out, raw)
		pkt.DecRef()

		select {
		case n.out <- out:
		case <-n.done:
			return
		default:
			// 上层写不出去时丢包而不是阻塞协议栈（TCP 会靠重传自愈）。
			n.outDrops.Add(1)
		}
	}
}

// InjectInbound 把一个从 TUN 读到的 IP 包送进协议栈。
// ICMP echo 由本层处理，不进协议栈（stack 不带 ICMP 转发器）。
func (n *NAT) InjectInbound(p []byte) {
	if len(p) == 0 {
		return
	}
	if p[0]>>4 != 4 {
		return // 目前只处理 IPv4
	}
	if n.handleICMPv4(p) {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(p),
	})
	// utun 上的包来自本机内核，校验和必然已由内核算好。不标记的话
	// 协议栈会再校验一次，任何差异（例如测试构造的包）都会被当作无效段丢弃。
	pkt.RXChecksumValidated = true
	n.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

// handleICMPv4 处理 echo request。
//
// 隧道只承载 TCP/UDP，ICMP 本身过不去，所以这里让家里那侧代发一次探测：
// 只有目标真的回包，才给本机回一个 echo reply。这样「ping 通」才代表主机在线；
// 早先是本地无条件回包，ping 任何地址都通，排障时会被彻底误导。
//
// 注意：**不缓存「可达」结果**。reply 必须等真实探测返回后才合成，
// 这样 macOS 量到的 RTT 就是真实端到端往返（约 80~110ms），
// 而不是本地合成的 0.3ms。缓存只会制造「偶尔一个慢包」的假象。
func (n *NAT) handleICMPv4(p []byte) bool {
	reply, dst, ok := buildICMPEchoReply(p)
	if !ok {
		return false
	}
	// 刚刚确认过不可达：直接不回包，让 ping 自然超时，避免探测流堆积。
	if v, ok := n.icmpFail.Load(dst); ok {
		if until, _ := v.(time.Time); time.Now().Before(until) {
			return true
		}
	}

	go func() {
		st, err := n.dial(Target{Host: dst, Proto: ProtoICMP}, n.openTimeout)
		if err != nil {
			n.icmpFail.Store(dst, time.Now().Add(icmpFailTTL))
			return // 目标不可达：不回包，让 ping 自然超时
		}
		defer st.Close()

		res := make(chan byte, 1)
		go func() {
			buf := make([]byte, 1)
			if _, err := io.ReadFull(st, buf); err != nil {
				res <- 0
				return
			}
			res <- buf[0]
		}()
		select {
		case v := <-res:
			if v != 1 {
				n.icmpFail.Store(dst, time.Now().Add(icmpFailTTL))
				return
			}
		case <-time.After(3 * time.Second):
			n.icmpFail.Store(dst, time.Now().Add(icmpFailTTL))
			return
		}

		n.sendICMPReply(reply)
	}()
	return true
}

// sendICMPReply 把 echo reply 交给上层写回 TUN。
func (n *NAT) sendICMPReply(reply []byte) {
	select {
	case n.out <- reply:
		n.icmpEchoes.Add(1)
	default:
		n.outDrops.Add(1)
	}
}

// buildICMPEchoReply 从 echo request 构造 echo reply，并返回目标地址。
func buildICMPEchoReply(p []byte) ([]byte, string, bool) {
	if len(p) < header.IPv4MinimumSize {
		return nil, "", false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < header.IPv4MinimumSize || len(p) < ihl {
		return nil, "", false
	}
	if p[9] != byte(header.ICMPv4ProtocolNumber) {
		return nil, "", false
	}
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if total < ihl+header.ICMPv4MinimumSize || total > len(p) {
		return nil, "", false
	}

	req := header.IPv4(p[:total])
	ic := header.ICMPv4(req.Payload())
	if ic.Type() != header.ICMPv4Echo {
		return nil, "", false
	}
	dst := req.DestinationAddress().String()

	reply := make([]byte, total)
	copy(reply, p[:total])
	r := header.IPv4(reply)
	src := r.SourceAddress()
	r.SetSourceAddressWithChecksumUpdate(r.DestinationAddress())
	r.SetDestinationAddressWithChecksumUpdate(src)

	ric := header.ICMPv4(r.Payload())
	ric.SetType(header.ICMPv4EchoReply)
	ric.SetChecksum(0)
	ric.SetChecksum(header.ICMPv4Checksum(ric, 0))
	return reply, dst, true
}

func (n *NAT) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	target := Target{Host: id.LocalAddress.String(), Port: id.LocalPort, Proto: ProtoTCP}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true) // 建端点失败，回 RST
		return
	}
	r.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	go n.serveTCP(conn, target)
}

func (n *NAT) serveTCP(conn *gonet.TCPConn, target Target) {
	n.tcpTotal.Add(1)
	n.tcpActive.Add(1)
	defer n.tcpActive.Add(-1)
	defer conn.Close()

	st, err := n.dial(target, n.openTimeout)
	if err != nil {
		return
	}
	Bridge(st, conn, n.linger, n.finGuard)
	st.Close()
}

// handleUDP 处理一条新的 UDP 会话（按四元组）。
func (n *NAT) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	target := Target{Host: id.LocalAddress.String(), Port: id.LocalPort, Proto: ProtoUDP}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return false
	}
	conn := gonet.NewUDPConn(&wq, ep)
	go n.serveUDP(conn, target)
	return true
}

func (n *NAT) serveUDP(conn *gonet.UDPConn, target Target) {
	n.udpTotal.Add(1)
	n.udpActive.Add(1)
	defer n.udpActive.Add(-1)
	defer conn.Close()

	st, err := n.dial(target, n.openTimeout)
	if err != nil {
		return
	}
	defer st.Close()

	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())
	touch := func() { lastActive.Store(time.Now().UnixNano()) }

	done := make(chan struct{}, 2)

	// 隧道 -> 本地 UDP 端点
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			b, err := ReadDatagram(st)
			if err != nil {
				return
			}
			touch()
			if _, err := conn.Write(b); err != nil {
				return
			}
		}
	}()

	// 本地 UDP 端点 -> 隧道
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, MaxDatagram)
		for {
			nr, err := conn.Read(buf)
			if err != nil {
				return
			}
			touch()
			if err := WriteDatagram(st, buf[:nr]); err != nil {
				return
			}
		}
	}()

	// 空闲回收：UDP 没有关闭握手，只能靠一段时间没流量来判定结束。
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-n.done:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, lastActive.Load())) > udpIdle {
				return
			}
		}
	}
}

// Stats 返回当前计数。
func (n *NAT) Stats() NATStats {
	return NATStats{
		TCPTotal:   n.tcpTotal.Load(),
		UDPTotal:   n.udpTotal.Load(),
		TCPActive:  n.tcpActive.Load(),
		UDPActive:  n.udpActive.Load(),
		ICMPEchoes: n.icmpEchoes.Load(),
		OutDrops:   n.outDrops.Load(),
	}
}

// Close 关闭协议栈。
func (n *NAT) Close() {
	n.once.Do(func() {
		close(n.done)
		n.cancel()
		n.ep.Close()
		go func() {
			// 排空剩余出站包，避免 pumpOutbound 卡在发送上。
			for {
				select {
				case <-n.out:
				default:
					return
				}
			}
		}()
		n.s.Close()
		log.Printf("[tun] 协议栈已关闭")
	})
}
