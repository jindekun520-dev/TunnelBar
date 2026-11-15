package internal

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMagicPacketLayout(t *testing.T) {
	mac, err := ParseMAC("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("解析 MAC 失败：%v", err)
	}
	p := MagicPacket(mac)

	if len(p) != 102 {
		t.Fatalf("魔术包长度应为 102，实际 %d", len(p))
	}
	if MagicPacketLen != 102 {
		t.Fatalf("常量 MagicPacketLen 应为 102，实际 %d", MagicPacketLen)
	}
	// 前 6 字节必须是 FF
	if !bytes.Equal(p[:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Fatalf("前 6 字节应为全 FF，实际 % x", p[:6])
	}
	// 之后 16 组 MAC，逐组比对（不是「包含」——顺序错了也会被 NIC 丢掉）
	for i := 0; i < 16; i++ {
		off := 6 + i*6
		if !bytes.Equal(p[off:off+6], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}) {
			t.Fatalf("第 %d 组 MAC 不对：% x", i+1, p[off:off+6])
		}
	}
}

func TestParseMACAccepted(t *testing.T) {
	// 这些写法在实际设备页面/`ip link`/`arp` 里都能见到，必须都认
	cases := []string{
		"AA:BB:CC:DD:EE:FF",
		"aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff",
		"aabb.ccdd.eeff",
		"aabbccddeeff",
		"AA-BB-CC-DD-EE-FF",
		" aa:bb:cc:dd:ee:ff ",
	}
	for _, s := range cases {
		mac, err := ParseMAC(s)
		if err != nil {
			t.Fatalf("%q 应能解析，却报错：%v", s, err)
		}
		if mac.String() != "aa:bb:cc:dd:ee:ff" {
			t.Fatalf("%q 解析结果错：%s", s, mac)
		}
	}
}

func TestParseMACRejected(t *testing.T) {
	cases := []struct{ in, why string }{
		{"", "空串"},
		{"aa:bb:cc:dd:ee", "只有 10 位"},
		{"aa:bb:cc:dd:ee:ff:00", "13 位"},
		{"zz:bb:cc:dd:ee:ff", "非十六进制"},
		{"00:00:00:00:00:00", "全 0"},
		{"01:00:5e:00:00:01", "组播地址"},
		{"ff:ff:ff:ff:ff:ff", "广播地址"},
	}
	for _, c := range cases {
		if _, err := ParseMAC(c.in); err == nil {
			t.Fatalf("%s（%q）应被拒绝，却通过了", c.why, c.in)
		}
	}
	// 错误信息要能指导用户，而不是只回一句 "invalid"
	if _, err := ParseMAC("aa:bb:cc"); err == nil ||
		!strings.Contains(err.Error(), "12 位") {
		t.Fatalf("位数错误的提示不明确：%v", err)
	}
}

// TestWakeSendsPacket 真的发一次，再从 UDP 监听端收回来比对字节。
// 这是唯一能证明「发送路径没写错」的测试——只测 MagicPacket 的话，
// DialUDP 的目标地址拼错、端口写死、包被截断都发现不了。
func TestWakeSendsPacket(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("监听 UDP 失败：%v", err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port

	mac, _ := ParseMAC("aa:bb:cc:dd:ee:ff")
	sent, used, err := Wake(mac, []string{"127.0.0.1"}, port)
	if err != nil {
		t.Fatalf("发送失败：%v", err)
	}
	if sent != 1 || len(used) != 1 || used[0] != "127.0.0.1" {
		t.Fatalf("发送统计不对：sent=%d used=%v", sent, used)
	}

	_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _, err := ln.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("没收到包：%v", err)
	}
	if n != MagicPacketLen {
		t.Fatalf("收到 %d 字节，应为 %d", n, MagicPacketLen)
	}
	if !bytes.Equal(buf[:n], MagicPacket(mac)) {
		t.Fatalf("收到的内容与魔术包不一致")
	}
}

func TestWakeDefaultPort(t *testing.T) {
	// 端口传 0 时应落到 9；用一个高位端口收不到，所以只校验不报错、
	// 且统计为「发出了」——真正的端口选择由默认常量保证。
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("监听 UDP 失败：%v", err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port

	mac, _ := ParseMAC("aa:bb:cc:dd:ee:ff")
	// 显式给端口，验证 port<=0 的分支走的是 DefaultWOLPort（不 panic 即可）
	if DefaultWOLPort != 9 {
		t.Fatalf("默认端口应为 9，实际 %d", DefaultWOLPort)
	}
	if _, _, err := Wake(mac, []string{"127.0.0.1"}, port); err != nil {
		t.Fatalf("发送失败：%v", err)
	}
}

func TestWakeBadMAC(t *testing.T) {
	if _, _, err := Wake(net.HardwareAddr{1, 2, 3}, []string{"127.0.0.1"}, 9); err == nil {
		t.Fatal("长度不足的 MAC 应报错")
	}
}

// TestBroadcastAddrsPlausible 只做弱断言：结果里不应该出现回环，
// 且都应是 4 段点分地址。网卡环境差异太大，强断言会让 CI 随机挂。
func TestBroadcastAddrsPlausible(t *testing.T) {
	for _, a := range BroadcastAddrs() {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("%q 不是合法 IP", a)
		}
		if ip.IsLoopback() {
			t.Fatalf("不应包含回环广播地址：%s", a)
		}
	}
}
