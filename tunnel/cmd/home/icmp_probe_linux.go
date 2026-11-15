//go:build linux

package main

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"tunnel/third_party/gvisor/pkg/tcpip/header"
)

// icmpSeq 递增的序列号，用来把本进程发出的探测与其它 ICMP 流量区分开。
var icmpSeq atomic.Uint32

// probeICMPHost 用原始套接字直接向 host 发一个 ICMP echo 并等应答。
//
// 为什么不用 exec ping：每包 fork 一次进程要 5~20ms，遇到首包重试还会拖到
// 1 秒以上，client 侧就会冒出 600~1000ms 的尖刺，看着像链路抖动，
// 其实是本地进程开销。原始套接字是微秒级的，且不受 shell/环境干扰。
//
// 需要 root（home 由 systemd 以 root 运行）或 CAP_NET_RAW；
// 拿不到权限时返回 error，由调用方退化到 exec ping。
func probeICMPHost(host string, timeout time.Duration) (bool, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Errorf("非法地址: %s", host)
	}
	v4 := ip.To4()
	if v4 == nil {
		return false, fmt.Errorf("仅支持 IPv4: %s", host)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return false, err
	}

	id := uint16(syscall.Getpid())
	seq := uint16(icmpSeq.Add(1))

	payload := []byte("tunnelbar-probe")
	msg := make([]byte, header.ICMPv4MinimumSize+len(payload))
	ic := header.ICMPv4(msg)
	ic.SetType(header.ICMPv4Echo)
	ic.SetCode(0)
	ic.SetIdent(id)
	ic.SetSequence(seq)
	copy(ic.Payload(), payload)
	ic.SetChecksum(header.ICMPv4Checksum(ic, 0))

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], v4)
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return false, err
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			// 接收超时：目标没回包，按不可达处理。
			return false, nil
		}
		fa, ok := from.(*syscall.SockaddrInet4)
		if !ok || fa.Addr != sa.Addr {
			continue // 其它主机发来的 ICMP，忽略
		}
		// Linux 的原始套接字会带上 IP 头，需要自己跳过。
		if n < 20 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || n < ihl+header.ICMPv4MinimumSize {
			continue
		}
		if buf[9] != byte(header.ICMPv4ProtocolNumber) {
			continue
		}
		rc := header.ICMPv4(buf[ihl:n])
		if rc.Type() != header.ICMPv4EchoReply {
			continue
		}
		if rc.Ident() != id || rc.Sequence() != seq {
			continue
		}
		return true, nil
	}
	return false, nil
}
