package internal

// Wake-on-LAN：构造魔术包并在二层广播域里发出去。
//
// 为什么必须由「内网那台机器」来发：魔术包是**链路层广播**，
// 目标网卡在关机状态下只认自己所在广播域里的帧。从公网服务器发到
// 10.0.0.255 只会被路由丢掉（定向广播默认关闭），就算侥幸放行，
// 也跨不过 NAT——所以触发点必须在同一网段里。本项目的 home 端正好在那儿。

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// 魔术包：6 字节 0xFF + 目标 MAC 重复 16 次，共 102 字节。
// 这个格式从 1995 年 AMD 的 Magic Packet 规范起就没变过，NIC 在
// 断电待机时由辅电源供电的接收逻辑按比特匹配，格式错一个字节就不醒。
const (
	magicSyncBytes = 6
	magicRepeats   = 16
	MagicPacketLen = magicSyncBytes + magicRepeats*6 // 102
	// 默认端口。历史上 0/7/9 都有人用，9（discard）最常见；
	// 少数老网卡只监听 7，所以 Wake 允许显式指定。
	DefaultWOLPort = 9

	// 每个广播地址连发几份。网卡在深度省电（D3cold / 现代待机）状态下会漏掉
	// 单个包，连发几份是各家 WOL 工具的常规做法；3 份 × 两个广播地址一共 6 个
	// 102 字节的包，代价可以忽略。
	DefaultWOLRepeats = 3
	// 每份之间的间隔
	wolRepeatGap = 120 * time.Millisecond
)

// ErrBadMAC 表示 MAC 字面量无法解析。
var ErrBadMAC = errors.New("MAC 地址格式不对")

// ParseMAC 接受几种常见的 MAC 写法：
//
//	AA:BB:CC:DD:EE:FF   aa-bb-cc-dd-ee-ff   aabb.ccdd.eeff   aabbccddeeff
//
// 故意不用 net.ParseMAC：它不接受 12 位裸十六进制（`ip link` 之外的
// 大多数设备管理页面导出的就是裸十六进制），而用户粘过来的往往是那种。
func ParseMAC(s string) (net.HardwareAddr, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)

	if len(clean) != 12 {
		return nil, fmt.Errorf("%w：%q 去掉分隔符后是 %d 位，应为 12 位十六进制",
			ErrBadMAC, s, len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%w：%q 含非十六进制字符", ErrBadMAC, s)
	}
	mac := net.HardwareAddr(b)
	if mac.String() == "00:00:00:00:00:00" {
		return nil, fmt.Errorf("%w：全 0 的 MAC 不是有效目标", ErrBadMAC)
	}
	// 组播位（第一字节最低位）为 1 的是组播/广播地址，不能作为单机唤醒目标。
	// 常见误填是把 IPv4 组播 MAC 01:00:5e:xx 当设备 MAC。
	if b[0]&0x01 != 0 {
		return nil, fmt.Errorf("%w：%s 是组播地址（第一字节最低位为 1）", ErrBadMAC, mac)
	}
	return mac, nil
}

// MagicPacket 按规范拼出 102 字节的魔术包。
func MagicPacket(mac net.HardwareAddr) []byte {
	p := make([]byte, 0, MagicPacketLen)
	for i := 0; i < magicSyncBytes; i++ {
		p = append(p, 0xFF)
	}
	for i := 0; i < magicRepeats; i++ {
		p = append(p, mac...)
	}
	return p
}

// BroadcastAddrs 枚举本机所有「up 且支持广播」的 IPv4 网卡的定向广播地址，
// 例如 10.0.0.1/24 → 10.0.0.255。
//
// 为什么要逐网卡算：只往 255.255.255.255 发，在多网卡（docker0、虚拟网卡、
// VPN）的机器上经常从错误的接口出去，包压根没到目标网段。定向广播按接口算
// 出来，每一块网卡都能覆盖到。
func BroadcastAddrs() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 ||
			ifi.Flags&net.FlagLoopback != 0 ||
			ifi.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil {
				continue // 跳过 IPv6
			}
			mask := ipn.Mask
			if len(mask) == net.IPv6len {
				mask = mask[12:] // IPv4-in-IPv6 掩码
			}
			if len(mask) != net.IPv4len {
				continue
			}
			b := make(net.IP, net.IPv4len)
			for i := 0; i < net.IPv4len; i++ {
				b[i] = ip4[i] | ^mask[i]
			}
			s := b.String()
			if s == "255.255.255.255" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Wake 把魔术包发到每个广播地址；broadcast 为空时自动探测本机网卡。
// 端口 0 或负数用 DefaultWOLPort。
//
// 返回成功发出的份数与**实际使用的广播地址**（去重）。只要有一份发成功
// 就不返回错误——多网卡机器上某块网卡发不出去是常态（比如未插网线的
// docker 网桥），不该让整次唤醒失败。
func Wake(mac net.HardwareAddr, broadcast []string, port int) (int, []string, error) {
	if len(mac) != 6 {
		return 0, nil, fmt.Errorf("%w：长度 %d", ErrBadMAC, len(mac))
	}
	if port <= 0 {
		port = DefaultWOLPort
	}
	targets := broadcast
	if len(targets) == 0 {
		targets = BroadcastAddrs()
		// 兜底：一块网卡都算不出来（极少见，比如只有回环）时仍试全局广播
		targets = append(targets, "255.255.255.255")
	}

	packet := MagicPacket(mac)
	var (
		sent  int
		used  []string
		errs  []string
		dedup = map[string]bool{}
	)
	for _, host := range targets {
		addr := net.JoinHostPort(host, fmt.Sprint(port))
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
		if err != nil {
			errs = append(errs, addr+": "+err.Error())
			continue
		}
		enableBroadcast(c) // 显式开 SO_BROADCAST，不依赖运行时默认行为
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		written := 0
		var werr error
		for i := 0; i < DefaultWOLRepeats; i++ {
			if _, err := c.Write(packet); err != nil {
				werr = err
				break
			}
			written++
			if i+1 < DefaultWOLRepeats {
				time.Sleep(wolRepeatGap)
			}
		}
		_ = c.Close()
		if written == 0 {
			errs = append(errs, addr+": "+werr.Error())
			continue
		}
		sent += written
		if !dedup[host] {
			dedup[host] = true
			used = append(used, host)
		}
	}
	if sent == 0 {
		if len(errs) == 0 {
			return 0, nil, errors.New("没有可用的广播地址")
		}
		return 0, nil, errors.New(strings.Join(errs, "；"))
	}
	return sent, used, nil
}

// enableBroadcast 给 UDP socket 打开 SO_BROADCAST。
//
// Go 的 net 包在多数平台已经替我们开了，但这是**实现细节**，不是契约；
// 万一哪天没开，sendto 会直接 EACCES，现象是「静默失败」——所以这里自己来。
func enableBroadcast(c *net.UDPConn) {
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
}
