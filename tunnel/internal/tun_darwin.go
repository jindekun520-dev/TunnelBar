//go:build darwin

// Package internal: macOS utun 设备封装。
//
// 只负责把 utun 设备打开并把 fd 交给上层的 netstack；包的读取/写入由
// netstack 的 link endpoint 直接持 fd 完成，避免多一次用户态拷贝。
package internal

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"
	// SYSPROTO_CONTROL 是 PF_SYSTEM 域下的控制协议号。
	sysprotoControl = 2
	// UTUN_OPT_IFNAME 取回内核分配的接口名（utunN）。
	utunIfnameOpt = 2
)

// TUN 是一个已打开的 utun 设备。
type TUN struct {
	fd   int
	name string
}

// OpenTUN 打开一个新的 utun 设备。unit 为 0 时由内核自动分配编号。
// 需要 root 权限。
func OpenTUN(unit int) (*TUN, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("打开 utun 套接字失败（需要 root）：%w", err)
	}

	ctl := unix.CtlInfo{}
	copy(ctl.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, &ctl); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("获取 utun 控制信息失败: %w", err)
	}

	sa := &unix.SockaddrCtl{ID: ctl.Id, Unit: uint32(unit)}
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("连接 utun 控制单元失败（unit=%d）: %w", unit, err)
	}

	name, err := unix.GetsockoptString(fd, sysprotoControl, utunIfnameOpt)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("获取 utun 接口名失败: %w", err)
	}
	if name == "" {
		unix.Close(fd)
		return nil, errors.New("内核返回了空的 utun 接口名")
	}

	return &TUN{fd: fd, name: name}, nil
}

// Fd 返回底层文件描述符，交给 netstack 的 link endpoint 使用。
func (t *TUN) Fd() int { return t.fd }

// Name 返回内核分配的接口名，如 utun7。
func (t *TUN) Name() string { return t.name }

// Close 关闭设备。接口随之消失，内核会自动回收其上的路由。
func (t *TUN) Close() error {
	if t.fd < 0 {
		return nil
	}
	err := unix.Close(t.fd)
	t.fd = -1
	return err
}

// ConfigureIface 给接口配上 MTU 并启用。等价于 ifconfig <name> mtu <mtu> up。
func ConfigureIface(name string, mtu int) error {
	if name == "" {
		return errors.New("接口名为空")
	}
	out, err := exec.Command("/sbin/ifconfig", name, "mtu", fmt.Sprint(mtu), "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s 失败: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// AssignIPv4 给点对点接口配一个本端地址。
//
// 这一步不能省：接口上没有任何 inet 地址时，`route add -net ... -interface utunN`
// 会以退出码 0 返回、但内核实际拒绝并返回 "Network is unreachable"，
// 表现就是日志显示加成功、路由表里却查不到。地址取协议栈那侧的同一个地址，
// 这样回包的目的地址在本机被认为「就是我自己」，能被正常收下。
func AssignIPv4(name, addr string) error {
	out, err := exec.Command("/sbin/ifconfig", name, "inet", addr, addr, "netmask", "255.255.255.255", "up").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "File exists") {
			return nil
		}
		return fmt.Errorf("配置 %s 的 IPv4 地址 %s 失败: %v: %s", name, addr, err, msg)
	}
	return nil
}

// AddRoute 增加一条走指定接口的路由。dst 形如 10.0.0.0/24。
//
// route(8) 退出码为 0 不代表路由一定生效（例如接口没有地址时内核可能不收），
// 所以这里加完立刻用 `route get` 复核一次，没生效就换一种写法再试。
func AddRoute(dst, iface string) error {
	addr, mask, err := splitCIDR(dst)
	if err != nil {
		return err
	}

	try := func(args ...string) (string, error) {
		out, err := exec.Command("/sbin/route", args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}

	first := []string{"-n", "add", "-net", dst, "-interface", iface}
	out, err := try(first...)
	if err != nil && !strings.Contains(out, "File exists") {
		return fmt.Errorf("添加路由 %s 失败: %v: %s", dst, err, out)
	}
	if out != "" {
		log.Printf("[tun] route add 输出: %s", out)
	}
	if RouteInterface(addr) == iface {
		return nil
	}

	// 退一步：显式给出掩码，有些 macOS 版本对 CIDR 形式处理不一致。
	second := []string{"-n", "add", "-net", addr, "-netmask", mask, "-interface", iface}
	out, err = try(second...)
	if err != nil && !strings.Contains(out, "File exists") {
		return fmt.Errorf("添加路由 %s 失败(重试): %v: %s", dst, err, out)
	}
	if out != "" {
		log.Printf("[tun] route add 输出(重试): %s", out)
	}
	if got := RouteInterface(addr); got == iface {
		return nil
	} else if got != "" {
		return fmt.Errorf("路由 %s 指向了 %s，不是 %s", dst, got, iface)
	}
	return fmt.Errorf("路由 %s 添加后未出现在路由表中", dst)
}

// RouteInterface 返回内核中到 addr 实际使用的出口接口，空串表示没查到。
// 用它来判断路由是否真的生效，比只看 route(8) 的退出码可靠。
func RouteInterface(addr string) string {
	out, err := exec.Command("/sbin/route", "-n", "get", addr).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	return ""
}

// splitCIDR 把 10.0.0.0/24 拆成 10.0.0.0 与 255.255.255.0。
func splitCIDR(dst string) (string, string, error) {
	parts := strings.SplitN(dst, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("路由格式应为 网段/前缀，实际 %q", dst)
	}
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil {
		return "", "", fmt.Errorf("解析路由 %q 失败: %v", dst, err)
	}
	mask := fmt.Sprintf("%d.%d.%d.%d", ipnet.Mask[0], ipnet.Mask[1], ipnet.Mask[2], ipnet.Mask[3])
	return parts[0], mask, nil
}

// DelRoute 删除一条路由，忽略不存在的错误。
func DelRoute(dst string) error {
	out, err := exec.Command("/sbin/route", "-n", "delete", "-net", dst).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "not in table") || strings.Contains(msg, "No such process") {
			return nil
		}
		return fmt.Errorf("删除路由 %s 失败: %v: %s", dst, err, msg)
	}
	return nil
}

// HasRoute 判断某条路由当前是否指向指定接口。
func HasRoute(dst, iface string) bool {
	out, err := exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return false
	}
	prefix := strings.SplitN(dst, "/", 2)[0]
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[0] == prefix && (f[len(f)-1] == iface || (len(f) > 3 && f[3] == iface)) {
			return true
		}
	}
	return false
}
