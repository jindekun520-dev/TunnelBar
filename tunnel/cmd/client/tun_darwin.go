//go:build darwin

// TUN 全局直连模式（macOS）。
//
// 打开一个 utun 设备，把指定网段的路由指进去，再用内嵌的用户态协议栈
// （gvisor netstack）解析其中的 TCP/UDP 流量，逐条转成隧道流。
// 这样所有程序都不需要配代理，也不需要端口转发，直接访问内网 IP。
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"tunnel/internal"
)

// hostTunAddr 是分配给 utun 接口的本端地址，与协议栈内的地址保持一致。
const hostTunAddr = "198.18.0.1"

// tunManager 持有 utun 设备与协议栈的生命周期。
type tunManager struct {
	tun    *internal.TUN
	nat    *internal.NAT
	dev    string
	mtu    int
	routes []string

	mu     sync.Mutex
	closed bool
	errMsg string
}

// startTUN 建立 utun 设备、配置路由，并启动收发循环。需要 root。
func startTUN(t *tunnel, routeSpec string, mtu int) (*tunManager, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("TUN 模式需要 root 权限（当前 euid=%d）", os.Geteuid())
	}

	tun, err := internal.OpenTUN(0)
	if err != nil {
		return nil, err
	}
	dev := tun.Name()

	if err := internal.ConfigureIface(dev, mtu); err != nil {
		tun.Close()
		return nil, err
	}
	// 必须给接口配个本端地址，否则后面的 route add 会被内核以
	// "Network is unreachable" 拒绝（而 route 的退出码仍是 0）。
	if err := internal.AssignIPv4(dev, hostTunAddr); err != nil {
		tun.Close()
		return nil, err
	}
	log.Printf("[tun] 设备 %s 已就绪（MTU %d）", dev, mtu)

	nat, err := internal.NewNAT(func(target internal.Target, timeout time.Duration) (internal.TunnelStream, error) {
		return t.openTarget(target)
	}, mtu, openTO, lingerTO)
	if err != nil {
		tun.Close()
		return nil, err
	}

	m := &tunManager{tun: tun, nat: nat, dev: dev, mtu: mtu}

	for _, r := range strings.Split(routeSpec, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if err := internal.AddRoute(r, dev); err != nil {
			log.Printf("[tun] 路由 %s 添加失败: %v", r, err)
			continue
		}
		m.routes = append(m.routes, r)
		log.Printf("[tun] 路由 %s -> %s", r, dev)
	}
	if len(m.routes) == 0 {
		log.Printf("[tun] 警告：没有任何路由被接管，TUN 实际上不会承载流量")
	}

	// 状态接口的 TUN 快照
	tunSnapshot = func() *tunPayload {
		m.mu.Lock()
		defer m.mu.Unlock()
		st := m.nat.Stats()
		return &tunPayload{
			Enabled:    !m.closed,
			Device:     m.dev,
			MTU:        m.mtu,
			Routes:     m.routes,
			TCPTotal:   st.TCPTotal,
			UDPTotal:   st.UDPTotal,
			TCPActive:  st.TCPActive,
			UDPActive:  st.UDPActive,
			ICMPEchoes: st.ICMPEchoes,
			OutDrops:   st.OutDrops,
			Error:      m.errMsg,
		}
	}

	go m.pumpInbound()
	go m.pumpOutbound()
	return m, nil
}

// pumpInbound 从 utun 读 IP 包送进协议栈。
func (m *tunManager) pumpInbound() {
	fd := m.tun.Fd()
	buf := make([]byte, 65536)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EBADF || err == unix.EINVAL {
				return // 设备已关闭，正常退出
			}
			m.setError(fmt.Sprintf("读 utun 失败: %v", err))
			return
		}
		// utun 读出的每个包前 4 字节是地址族（AF_INET / AF_INET6），不是 IP 内容。
		if n <= 4 {
			continue
		}
		m.nat.InjectInbound(buf[4:n])
	}
}

// pumpOutbound 把协议栈产出的 IP 包写回 utun。
func (m *tunManager) pumpOutbound() {
	for pkt := range m.nat.Outbound() {
		out := make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(out[0:4], uint32(unix.AF_INET))
		copy(out[4:], pkt)
		if _, err := unix.Write(m.tun.Fd(), out); err != nil {
			if err == unix.EBADF || err == unix.EINVAL {
				return
			}
			// 单个包写失败（如缓冲区满）不致命，丢包由上层协议自愈。
			continue
		}
	}
}

func (m *tunManager) setError(s string) {
	m.mu.Lock()
	m.errMsg = s
	m.mu.Unlock()
	log.Printf("[tun] %s", s)
}

// Close 关闭协议栈、删除路由并关闭设备。
func (m *tunManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.mu.Unlock()

	m.nat.Close()
	m.tun.Close()
	for _, r := range m.routes {
		if err := internal.DelRoute(r); err != nil {
			log.Printf("[tun] 删除路由 %s 失败: %v", r, err)
		}
	}
	log.Printf("[tun] 已关闭，路由已清理")
}
