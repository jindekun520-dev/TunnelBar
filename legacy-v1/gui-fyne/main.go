package main

import (
	"fmt"
	"image/color"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const (
	relayAddr = "203.0.113.10:7100"
	socksPort = "1080"
	psk       = "" // 存档版：运行时填入，别在这里写死
)

var (
	mu        sync.Mutex
	clientCmd *exec.Cmd
	startTime time.Time
	pacSrv    *http.Server // 托管 PAC 文件的本地 HTTP 服务
)

const pacListen = "127.0.0.1:1088" // 托管 tunnel.pac 的本地端口（与 SOCKS5 1080 区分）
const pacURLHost = "127.0.0.1:1088"

// customTheme 加载系统中文字体以解决 fyne 默认字体中文显示为 ???? 的问题
type customTheme struct {
	defaultTheme fyne.Theme
	cjkFont      fyne.Resource
}

func (t *customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	return t.defaultTheme.Color(name, variant)
}

func (t *customTheme) Font(style fyne.TextStyle) fyne.Resource {
	return t.cjkFont
}

func (t *customTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.defaultTheme.Icon(name)
}

func (t *customTheme) Size(name fyne.ThemeSizeName) float32 {
	return t.defaultTheme.Size(name)
}

func resourcesDir() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "..", "Resources")
}

func loadCJKFont() fyne.Theme {
	// 优先使用应用包内拆好的单字体 ttf，避免 .ttc 集合解析失败导致中文乱码
	candidates := []string{
		filepath.Join(resourcesDir(), "cjkfont.ttf"),
		"/Library/Fonts/Arial Unicode.ttf",
		"/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
	}
	for _, p := range candidates {
		if r, err := fyne.LoadResourceFromPath(p); err == nil {
			return &customTheme{defaultTheme: theme.DefaultTheme(), cjkFont: r}
		}
	}
	return theme.DefaultTheme()
}

func clientBin() string {
	exe, _ := os.Executable()
	binDir := filepath.Dir(exe)
	cand := filepath.Join(binDir, "..", "Resources", "client")
	if _, err := os.Stat(cand); err == nil {
		return cand
	}
	return filepath.Join(filepath.Dir(exe), "..", "..", "..", "bin", "client")
}

func logPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Logs", "tunnel-client.log")
}

func isChromeRunning() bool {
	out, err := exec.Command("pgrep", "-x", "Google Chrome").Output()
	return err == nil && len(out) > 0
}

func isRunning() bool {
	out, err := exec.Command("pgrep", "-f", "Resources/client").Output()
	if err != nil {
		out, err = exec.Command("pgrep", "-f", "bin/client").Output()
		if err != nil {
			return false
		}
	}
	return strings.TrimSpace(string(out)) != ""
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// homeTargets 家里内网需要自动检测的地址（IP:端口 / 用途说明）
var homeTargets = []struct {
	addr  string
	desc  string
}{
	{"10.0.0.199:5666", "家庭服务 HTTP"},
	{"10.0.0.204:22", "NAS SSH"},
	{"10.0.0.200:22", "家里主机 SSH"},
}

// checkSocks5Local 检查本地 SOCKS5 监听是否就绪
func checkSocks5Local() bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+socksPort, 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// checkRelayReachable 直接探测 relay 的 client 端口是否可 TCP 连接
func checkRelayReachable() bool {
	c, err := net.DialTimeout("tcp", relayAddr, 3*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// checkHome 通过本地 SOCKS5 走隧道探测家里地址连通性，返回 addr->ok
func checkHome() map[string]bool {
	res := make(map[string]bool)
	if !checkSocks5Local() {
		return res
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	for _, t := range homeTargets {
		c, err := d.Dial("tcp", "127.0.0.1:"+socksPort)
		if err != nil {
			break
		}
		conn, err := socks5Connect(c, t.addr)
		if err != nil {
			res[t.addr] = false
			c.Close()
			continue
		}
		res[t.addr] = true
		conn.Close()
		c.Close()
	}
	return res
}

// socks5Connect 在已建立的 SOCKS5 连接 c 上完成 CONNECT 到 target
func socks5Connect(c net.Conn, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	// 协商：无认证
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return nil, err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return nil, fmt.Errorf("socks5 协商失败")
	}
	// CONNECT
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	// 跳过绑定地址
	var n int
	switch hdr[3] {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		n = int(l[0])
	default:
		return nil, fmt.Errorf("socks5 地址类型异常")
	}
	skip := make([]byte, n+2)
	io.ReadFull(c, skip)
	if hdr[1] != 0x00 {
		return nil, fmt.Errorf("socks5 CONNECT 失败 code=%d", hdr[1])
	}
	return c, nil
}

// primaryServices 返回所有启用的网络服务名（Wi-Fi / 以太网等）
func primaryServices() []string {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var svc []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		svc = append(svc, line)
	}
	return svc
}

// writePAC 生成仅让家里 10.0.0.0/24 走 SOCKS5 的 PAC 文件，返回路径
func writePAC() (string, error) {
	dir := filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "TunnelClient")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	pac := filepath.Join(dir, "tunnel.pac")
	content := fmt.Sprintf(
		"function FindProxyForURL(url, host) {\n"+
			"  if (isInNet(host, \"10.0.0.0\", \"255.255.255.0\") || shExpMatch(host, \"10.0.0.*\")) {\n"+
			"    return \"SOCKS5 127.0.0.1:%s; SOCKS 127.0.0.1:%s\";\n"+
			"  }\n"+
			"  return \"DIRECT\";\n"+
			"}\n", socksPort, socksPort)
	if err := os.WriteFile(pac, []byte(content), 0644); err != nil {
		return "", err
	}
	return pac, nil
}

// enableSystemProxy 自动开启系统代理（PAC），仅家里网段走隧道
// 用本地 HTTP 服务托管 PAC（浏览器对 file:// 的 PAC 有安全限制，常拒绝加载）
func enableSystemProxy() error {
	if _, err := writePAC(); err != nil {
		return err
	}
	// 先停掉已有的 PAC 服务，避免重复监听
	stopPACServer()

	pacPath := filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "TunnelClient", "tunnel.pac")
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel.pac", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(pacPath)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Write(data)
	})
	srv := &http.Server{Addr: pacListen, Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	pacSrv = srv

	// PAC URL 每次带时间戳，强制 Chrome/Safari 重新获取 PAC，避免缓存旧规则
	url := fmt.Sprintf("http://%s/tunnel.pac?t=%d", pacURLHost, time.Now().Unix())
	// 把所有服务的 networksetup 命令拼成一条脚本，只提权执行一次，避免反复弹密码框
	var b strings.Builder
	for _, s := range primaryServices() {
		b.WriteString("/usr/sbin/networksetup -setautoproxyurl ")
		b.WriteString(shellQuoteArgs([]string{s, url}))
		b.WriteString(" ; ")
		b.WriteString("/usr/sbin/networksetup -setautoproxystate ")
		b.WriteString(shellQuoteArgs([]string{s, "on"}))
		b.WriteString(" ; ")
	}
	if err := runNetworksetupPrivileged(b.String()); err != nil {
		return err
	}
	return nil
}

// runNetworksetupPrivileged 优先用 sudo -n 免密执行；失败（未授权）才弹密码框
func runNetworksetupPrivileged(scriptBody string) error {
	// 先尝试免密（sudo 时间戳缓存或 sudoers 免密）
	if out, err := exec.Command("/usr/bin/sudo", "-n", "/bin/sh", "-c", scriptBody).CombinedOutput(); err == nil {
		return nil
	} else if strings.TrimSpace(string(out)) == "" {
		// sudo -n 失败但无输出（通常是需要密码），走提权
	}
	// 弹密码框提权，整段脚本只弹一次
	script := fmt.Sprintf(`do shell script "%s" with administrator privileges`, strings.ReplaceAll(scriptBody, `"`, `\"`))
	out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// shellQuoteArgs 把参数拼接成单条命令的安全形式
func shellQuoteArgs(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("'")
		b.WriteString(strings.ReplaceAll(a, "'", "'\\''"))
		b.WriteString("'")
	}
	return b.String()
}

// stopPACServer 关闭本地 PAC 托管服务
func stopPACServer() {
	mu.Lock()
	srv := pacSrv
	pacSrv = nil
	mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// ensureSSHConfig 自动写入 ~/.ssh/config，使 10.0.0.x 的 SSH 直接走 SOCKS5
func ensureSSHConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}
	cfg := filepath.Join(sshDir, "config")
	marker := "# TunnelClient 自动代理配置"
	block := marker + "\nHost 10.0.0.*\n    ProxyCommand nc -X 5 -x 127.0.0.1:" + socksPort + " %h %p\n" + marker + " 结束\n"

	existing, _ := os.ReadFile(cfg)
	if strings.Contains(string(existing), marker) {
		return nil
	}

	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		f.WriteString("\n")
	}
	if _, err := f.WriteString("\n" + block); err != nil {
		return err
	}
	return nil
}

// disableSystemProxy 关闭系统代理
func disableSystemProxy() {
	var b strings.Builder
	for _, s := range primaryServices() {
		b.WriteString("/usr/sbin/networksetup -setautoproxystate ")
		b.WriteString(shellQuoteArgs([]string{s, "off"}))
		b.WriteString(" ; ")
	}
	_ = runNetworksetupPrivileged(b.String())
	stopPACServer()
}

// systemProxyEnabled 查询系统自动代理是否已开启
func systemProxyEnabled() bool {
	for _, s := range primaryServices() {
		out, _ := exec.Command("/usr/sbin/networksetup", "-getautoproxyurl", s).Output()
		if strings.Contains(string(out), "Enabled: Yes") {
			return true
		}
	}
	return false
}

func main() {
	a := app.New()
	a.Settings().SetTheme(loadCJKFont())
	w := a.NewWindow("本地隧道客户端")
	w.Resize(fyne.NewSize(520, 720))

	statusLabel := widget.NewLabel("状态：未连接")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	infoLabel := widget.NewLabel("")
	usageLabel := widget.NewLabel("")
	usageLabel.Wrapping = fyne.TextWrapWord

	// 家里内网连通性检测结果
	probeLabel := widget.NewLabel("")
	probeLabel.Wrapping = fyne.TextWrapWord
	probeBtn := widget.NewButtonWithIcon("检测家里连通性", theme.ViewRefreshIcon(), nil)
	probeBtn.Disable()

	startBtn := widget.NewButtonWithIcon("开始连接", theme.MediaPlayIcon(), nil)
	stopBtn := widget.NewButtonWithIcon("断开连接", theme.MediaStopIcon(), nil)
	stopBtn.Disable()
	copyLogBtn := widget.NewButtonWithIcon("复制日志", theme.ContentCopyIcon(), nil)
	copyLogBtn.Disable()

	// 暗黑终端风格日志：深色背景 + 等宽绿字
	logBG := canvas.NewRectangle(color.NRGBA{R: 16, G: 18, B: 22, A: 255})
	logRich := widget.NewRichText()
	logRich.Wrapping = fyne.TextWrapWord
	logRich.Scroll = container.ScrollNone
	logBox := container.NewStack(logBG, container.NewPadded(logRich))
	logBox.Resize(fyne.NewSize(0, 200))
	logScroll := container.NewScroll(logBox)
	logScroll.SetMinSize(fyne.NewSize(0, 200))

	logLines := []string{}
	appendLog := func(s string) {
		mu.Lock()
		ts := time.Now().Format("15:04:05")
		line := "[" + ts + "] " + s
		logLines = append(logLines, line)
		if len(logLines) > 500 {
			logLines = logLines[len(logLines)-500:]
		}
		segs := logRich.Segments
		segs = append(segs, &widget.TextSegment{
			Text: line + "\n",
			Style: widget.RichTextStyle{
				TextStyle: fyne.TextStyle{Monospace: true},
				ColorName: theme.ColorNamePrimary,
				SizeName:  theme.SizeNameText,
			},
		})
		if len(segs) > 500 {
			segs = segs[len(segs)-500:]
		}
		logRich.Segments = segs
		mu.Unlock()
		logRich.Refresh()
		logScroll.ScrollToBottom()
	}

	copyLogBtn.OnTapped = func() {
		mu.Lock()
		txt := strings.Join(logLines, "\n")
		mu.Unlock()
		w.Clipboard().SetContent(txt)
		appendLog("日志已复制到剪贴板")
	}

	var probeRunning bool
	var probeMu sync.Mutex

	runProbe := func() {
		probeMu.Lock()
		if probeRunning {
			probeMu.Unlock()
			appendLog("检测已在运行中")
			return
		}
		probeRunning = true
		probeMu.Unlock()

		probeBtn.Disable()
		probeLabel.SetText("正在检测 ...")
		probeLabel.Refresh()
		go func() {
			defer func() {
				probeMu.Lock()
				probeRunning = false
				probeMu.Unlock()
			}()
			res := checkHome()
			var b strings.Builder
			if len(res) == 0 {
				msg := "未检测到本地 SOCKS5 代理，请先「开始连接」。"
				b.WriteString(msg + "\n")
				appendLog(msg)
			} else {
				appendLog("开始诊断网络 ...")
				socksOK := checkSocks5Local()
				relayOK := checkRelayReachable()
				if !socksOK {
					appendLog("❌ 本地 SOCKS5 代理未监听（client 可能未启动或 1080 被占用）")
				} else {
					appendLog("✅ 本地 SOCKS5 代理 127.0.0.1:" + socksPort + " 正常")
				}
				if !relayOK {
					appendLog("❌ 无法连接中继 " + relayAddr + "（当前网络可能限制该端口）")
				} else {
					appendLog("✅ 中继 " + relayAddr + " TCP 可达")
				}
				if !socksOK {
					appendLog("因本地代理未就绪，跳过家里内网检测")
					b.WriteString("诊断结果：本地 SOCKS5 代理未就绪\n")
					b.WriteString("建议：点击「断开连接」后重新「开始连接」；若仍失败，检查 127.0.0.1:1080 是否被其他程序占用。\n")
				} else if !relayOK {
					appendLog("因无法连接中继，跳过家里内网检测")
					b.WriteString("诊断结果：当前网络无法连接中继 " + relayAddr + "\n")
					b.WriteString("建议：检查当前网络是否允许访问 203.0.113.10:7100，或家中 relay/home 是否在线。\n")
				} else {
					b.WriteString("家里内网连通性：\n")
					for _, t := range homeTargets {
						ok := res[t.addr]
						mark := "✅ 可达"
						if !ok {
							mark = "❌ 不可达"
						}
						line := fmt.Sprintf("  %s  %s（%s）", mark, t.addr, t.desc)
						b.WriteString(line + "\n")
						appendLog(line)
					}
					if len(res) == 0 || !res[homeTargets[0].addr] {
						b.WriteString("\n提示：中继可达但家里设备不可达，通常是家中 tunnel-home 未运行或家中网络中断。\n")
					}
				}
				appendLog("诊断完成")
			}
			mu.Lock()
			probeLabel.SetText(b.String())
			probeLabel.Refresh()
			mu.Unlock()
			probeBtn.Enable()
		}()
	}

	refresh := func() {
		running := isRunning()
		if running {
			statusLabel.SetText("状态：已连接")
			dur := time.Since(startTime)
			proxyState := "未开启"
			if systemProxyEnabled() {
				proxyState = "已开启（仅 10.0.0.x 走隧道）"
			}
			infoLabel.SetText(fmt.Sprintf(
				"中继服务器：%s\n本地 SOCKS5：127.0.0.1:%s\n已连接时长：%s\n系统代理：%s\n日志：%s",
				relayAddr, socksPort, formatDuration(dur), proxyState, logPath()))
			usageLabel.SetText("隧道已建立，并已自动配置代理。\n" +
				"• 浏览器：直接打开 http://10.0.0.199:5666/（系统 PAC 自动生效）\n" +
				"• SSH：ssh root@10.0.0.200（~/.ssh/config 已自动写入）\n" +
				"• 其他公网流量仍正常直连，不受影响。\n\n" +
				"注意：若浏览器已打开但未生效，重启浏览器即可。")
			probeBtn.Enable()
			copyLogBtn.Enable()
			startBtn.Disable()
			stopBtn.Enable()
		} else {
			statusLabel.SetText("状态：未连接")
			infoLabel.SetText(fmt.Sprintf(
				"中继服务器：%s\n本地 SOCKS5：127.0.0.1:%s\n系统代理：未开启\n日志：%s",
				relayAddr, socksPort, logPath()))
			usageLabel.SetText("点击「开始连接」建立隧道。\n\n连接成功后会自动：\n" +
				"• 写入系统 PAC 代理，浏览器直接访问 10.0.0.x；\n" +
				"• 写入 ~/.ssh/config，SSH 直接访问 10.0.0.x；\n" +
				"无需任何手动配置。")
			probeLabel.SetText("")
			probeBtn.Disable()
			copyLogBtn.Enable()
			startBtn.Enable()
			stopBtn.Disable()
		}
	}

	startBtn.OnTapped = func() {
		if isRunning() {
			appendLog("已经在运行中")
			mu.Lock()
			if startTime.IsZero() {
				startTime = time.Now()
			}
			mu.Unlock()
			refresh()
			return
		}
		bin := clientBin()
		cmd := exec.Command(bin, "-relay", relayAddr, "-socks", "1080", "-key", psk)
		f, err := os.OpenFile(logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			cmd.Stdout = f
			cmd.Stderr = f
		}
		if err := cmd.Start(); err != nil {
			appendLog("启动失败: " + err.Error())
			return
		}
		mu.Lock()
		clientCmd = cmd
		startTime = time.Now()
		mu.Unlock()
		appendLog("正在连接中继 " + relayAddr + " ...")
		if !checkRelayReachable() {
			appendLog("⚠️ 当前网络无法直接连接中继 " + relayAddr + "，请检查网络或端口限制")
		} else {
			appendLog("✅ 当前网络到中继 TCP 端口可达")
		}
		go func() {
			time.Sleep(1500 * time.Millisecond)
			if isRunning() {
				appendLog("已连接，SOCKS5 监听 127.0.0.1:" + socksPort)
				if err := enableSystemProxy(); err == nil {
					appendLog("已自动开启系统代理（仅 10.0.0.x 走隧道），浏览器可直接访问家里地址")
					if isChromeRunning() {
						appendLog("检测到 Chrome 正在运行，请完全退出（Cmd+Q）再重新打开，或访问 chrome://net-internals/#proxy 刷新代理")
					}
				} else {
					appendLog("自动开启系统代理失败，请手动在系统设置里配置 SOCKS5 127.0.0.1:" + socksPort)
				}
				if err := ensureSSHConfig(); err == nil {
					appendLog("已自动配置 ~/.ssh/config，SSH 可直接访问 10.0.0.x")
				} else {
					appendLog("自动配置 SSH 失败: " + err.Error())
				}
				runProbe()
			}
			refresh()
		}()
		refresh()
	}

	stopBtn.OnTapped = func() {
		exec.Command("pkill", "-f", "Resources/client").Run()
		exec.Command("pkill", "-f", "bin/client").Run()
		disableSystemProxy()
		mu.Lock()
		if clientCmd != nil && clientCmd.Process != nil {
			clientCmd.Process.Kill()
		}
		clientCmd = nil
		startTime = time.Time{}
		mu.Unlock()
		appendLog("已断开连接，并关闭系统代理")
		time.Sleep(500 * time.Millisecond)
		refresh()
	}

	// 顶部栏
	top := container.NewHBox(statusLabel, layout.NewSpacer())

	btnRow := container.NewHBox(startBtn, stopBtn)
	probeRow := container.NewHBox(probeBtn, layout.NewSpacer())

	infoCard := container.NewVBox(
		widget.NewLabelWithStyle("连接信息", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		infoLabel,
	)

	probeCard := container.NewVBox(
		widget.NewLabelWithStyle("家里内网连通性", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		probeRow,
		probeLabel,
	)

	usageCard := container.NewVBox(
		widget.NewLabelWithStyle("使用说明", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		usageLabel,
	)

	logCard := container.NewVBox(
		container.NewHBox(
			widget.NewLabelWithStyle("运行日志（终端）", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			layout.NewSpacer(),
			copyLogBtn,
		),
		logScroll,
	)

	content := container.NewVBox(
		top,
		widget.NewSeparator(),
		btnRow,
		widget.NewSeparator(),
		infoCard,
		widget.NewSeparator(),
		probeCard,
		widget.NewSeparator(),
		usageCard,
		widget.NewSeparator(),
		logCard,
	)

	w.SetContent(container.NewPadded(container.NewVScroll(content)))
	refresh()

	// 已连接时每秒刷新一次连接时长
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if isRunning() {
				mu.Lock()
				st := startTime
				mu.Unlock()
				if st.IsZero() {
					continue
				}
				dur := time.Since(st)
				infoLabel.SetText(fmt.Sprintf(
					"中继服务器：%s\n本地 SOCKS5：127.0.0.1:%s\n已连接时长：%s\n日志：%s",
					relayAddr, socksPort, formatDuration(dur), logPath()))
				infoLabel.Refresh()
			}
		}
	}()

	w.ShowAndRun()
}
