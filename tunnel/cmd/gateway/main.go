// gateway 给「只能用浏览器」的设备（车机、借来的电脑、临时设备）提供一个内网入口。
//
// 它做三件事：
//  1. 按 Host 头把请求分给不同内网资产——子域名方式，一台资产一个域名；
//  2. 所有出站连接都经本地 SOCKS5（也就是隧道 client）拨到内网，本身不碰隧道协议；
//  3. 一道登录门，避免把内网管理界面裸奔在公网上。
//
// 为什么是子域名而不是 /path 前缀：ESXi、TrueNAS 这类前端全部按绝对路径取资源、
// 还带 WebSocket，挂在 /g/esxi/ 下面会碎得很干净。子域名下它们以为自己就在根路径，
// 一个字节都不需要改。
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- 配置

// Asset 是一台内网服务在网关里的呈现。
//
// 两种暴露方式，二选一或都开：
//   - Port > 0：占用一个独立的公网端口，整个端口的所有路径都归这台资产。
//     只需要一张「单域名」证书就能用，且每台资产都在自己 URL 的根路径上，
//     ESXi / 飞牛这类绝对路径 + WebSocket 的前端完全不用改。
//   - Sub 非空：走子域名（esxi.example.com），一台端口都不用多开，
//     但需要泛域名证书（*.example.com）或每台各签一张。
type Asset struct {
	Sub    string `json:"sub"`    // 子域名前缀，如 esxi → esxi.example.com
	Port   int    `json:"port"`   // 独立监听端口；0 表示只走子域名
	Name   string `json:"name"`   // 门户上显示的名字
	Target string `json:"target"` // 内网地址 host:port
	Scheme string `json:"scheme"` // 后端协议 http / https
	Note   string `json:"note"`   // 门户上的一行说明
	Icon   string `json:"icon"`   // 门户上的字符图标（避免用图片，老浏览器也能显示）
	// 防火墙把外部端口映射成别的号时（比如外 9444 → 内 8444），
	// 填这里，门户链接与 Location 重写才会用对外的号。留空 = 与 Port 相同。
	PubPort int `json:"public_port"`
	// MAC 填了之后，门户上这台资产会多一个「唤醒」按钮（网络唤醒 / WOL）。
	// 魔术包由 home 端在内网广播出去——网关在公网上发不到目标网段。
	MAC string `json:"mac"`
	// 唤醒后用来判断「起来了没有」的地址，默认取 Target。
	// 一台机器常常有多个身份（3389 的 PC 和 ssh 的同一台），填这个可以指定探哪个。
	Check string `json:"check"`
}

type Config struct {
	Listen string `json:"listen"`
	// 资产端口绑定的地址。留空则沿用 listen 的主机部分（一般是 0.0.0.0）
	Bind   string `json:"bind"`
	Socks  string `json:"socks"`
	Domain string `json:"domain"`
	User   string `json:"user"`
	// Password 只是**初始**密码。一旦 passwd_file 存在，就以文件里的哈希为准，
	// 这里的明文会被忽略（改过一次密码之后它就是死字段了，留着只为首次部署方便）。
	Password string `json:"password"`
	Secret   string `json:"secret"`
	// 密码哈希文件。留空则用配置文件同目录下的 passwd。
	// 门户里改密码写这个文件，不进 gateway.json——配置文件是明文、还常被备份传阅。
	PassFile string `json:"passwd_file"`
	// 证书路径。都填了才启 HTTPS；留空则跑明文（只适合本机调试）
	TLSCert string  `json:"tls_cert"`
	TLSKey  string  `json:"tls_key"`
	Assets  []Asset `json:"assets"`
	// 额外入口：把某个子域名转到本机某个端口（比如 Guacamole），不经 SOCKS
	Extra map[string]string `json:"extra"`
	// 路径入口：把某个路径前缀转到本机某个端口，挂在门户那个端口上。
	// 例如 "/guacamole/" → "http://127.0.0.1:8089"，省一个端口映射。
	Paths map[string]string `json:"paths"`
	// 门户所在的子域名前缀，默认 portal。
	// 用泛域名证书（*.example.com）时，证书**不覆盖裸域名** example.com，
	// 所以门户必须挂在一个子域上，否则浏览器会在握手阶段就报证书错误。
	PortalSub string `json:"portal_sub"`
	// 对外端口。防火墙把外部号映射成别的号时填这里（如外 6443 → 内 8843），
	// 门户链接才会带上正确的端口号。443 / 80 或留 0 时链接里不写端口。
	PubPort int `json:"public_port"`
	// Guacamole 代登录（可选）。填了之后从门户点进 guacamole 就不需要再输一次
	// Guacamole 自己的账号密码，网关会拿这里的账号先去换 token。
	Guac *GuacSSO `json:"guacamole"`
	// 网络唤醒（可选）。填了之后，配了 mac 的资产在门户上会出现「唤醒」按钮。
	// 请求会经 SOCKS 转给 home 端的 WOL 接口，由它在家里的广播域真正发魔术包。
	WOL *WOLConfig `json:"wol"`
}

// certReloader 按证书文件的 mtime 判断是否需要重读。
// certbot renew 之后再也不会因为没重启网关而继续用旧证书（那是最常见的「证书过期」
// 事故来源）。读失败时退回上一次成功的证书，避免续期瞬间握手全挂。
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	mod               time.Time
}

func (c *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, err := os.Stat(c.certFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	if c.cert != nil && !st.ModTime().After(c.mod) {
		return c.cert, nil
	}
	crt, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			log.Printf("重载证书失败（继续用旧的）：%v", err)
			return c.cert, nil
		}
		return nil, err
	}
	c.cert = &crt
	c.mod = st.ModTime()
	log.Printf("已加载证书 %s", c.certFile)
	return c.cert, nil
}

func loadConfig(p string) (*Config, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	c.normalize()
	if c.Secret == "" {
		return nil, errors.New("配置缺少 secret（用它签名登录 Cookie）")
	}
	if c.PassFile == "" {
		// 默认放在配置文件旁边，跟着备份/迁移一起走
		c.PassFile = filepath.Join(filepath.Dir(p), "passwd")
	}
	return &c, nil
}

// ---------------------------------------------------------------- SOCKS5 客户端
//
// 只实现 CONNECT，够用。不引第三方库，编译不会因为模块版本出岔子。

type socksDialer struct {
	addr string
}

func (d *socksDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("不支持的协议 %s", network)
	}
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	// 握手有时限，别让一条坏连接吊死整个请求
	deadline := time.Now().Add(10 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		c.Close()
		return nil, err
	}

	// 1) 打招呼：仅「无认证」
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		c.Close()
		return nil, err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("SOCKS 不支持无认证（版本 %d 方法 %d）", reply[0], reply[1])
	}

	// 2) CONNECT，地址能当 IP 就发 IP，否则发域名（让 SOCKS 端自己解析）
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			c.Close()
			return nil, errors.New("域名过长")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}

	// 3) 读应答：VER REP RSV ATYP + BND.ADDR + BND.PORT
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("SOCKS 拒绝连接（状态码 %d）", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(l[0])
	default:
		c.Close()
		return nil, fmt.Errorf("未知的地址类型 %d", head[3])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		c.Close()
		return nil, err
	}

	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// ---------------------------------------------------------------- 网关

type Gateway struct {
	cfg     *Config
	dialer  *socksDialer
	proxies map[string]*httputil.ReverseProxy
	// 后端是 https 且多为自签，统一跳过校验；这些是内网服务，TLS 只是传输层
	insecureTLS *tls.Config
	mu          sync.RWMutex
	// 密码相关。passTag 是当前密码哈希的指纹，混进登录 Cookie 的签名里——
	// 改密码之后所有旧 Cookie 自动失效，不然「改了密码但别人还能用」等于没改。
	passMu   sync.RWMutex
	passHash string
	passTag  string
}

func NewGateway(cfg *Config) *Gateway {
	return &Gateway{
		cfg:         cfg,
		dialer:      &socksDialer{addr: cfg.Socks},
		proxies:     make(map[string]*httputil.ReverseProxy),
		insecureTLS: &tls.Config{InsecureSkipVerify: true},
	}
}

// withPort 给 Host 补上对外端口号。443/80 不写（浏览器默认就是它）。
func (g *Gateway) withPort(host string) string {
	p := g.cfg.PubPort
	if p <= 0 || p == 443 || p == 80 {
		return host
	}
	return host + ":" + strconv.Itoa(p)
}

// portalHost 是门户所在的 Host，如 portal.example.com。
func (g *Gateway) portalHost() string {
	return g.cfg.PortalSub + "." + g.cfg.Domain
}

// pubHost 是这台资产对外的 Host[:port]。Location 重写、门户链接都用它。
func (g *Gateway) pubHost(a *Asset) string {
	port := a.Port
	if a.PubPort > 0 {
		port = a.PubPort
	}
	if port > 0 {
		if port == 443 || port == 80 {
			return g.cfg.Domain
		}
		return g.cfg.Domain + ":" + strconv.Itoa(port)
	}
	return g.withPort(a.Sub + "." + g.cfg.Domain)
}

// pubURL 是门户上点进去的地址。
func (g *Gateway) pubURL(a *Asset) string {
	if a.Port <= 0 && a.Sub == "" {
		return "#"
	}
	return "https://" + g.pubHost(a) + "/"
}

func (g *Gateway) findAssetBySub(sub string) *Asset {
	for i := range g.cfg.Assets {
		if g.cfg.Assets[i].Sub == sub {
			return &g.cfg.Assets[i]
		}
	}
	return nil
}

// proxyFor 为某台资产建（并缓存）一条反向代理。key 区分「子域名入口」和「端口入口」，
// 同一个后端从两个入口进来时共用一条代理也没问题，但分开更好排查日志。
func (g *Gateway) proxyFor(key string, a *Asset) *httputil.ReverseProxy {
	g.mu.RLock()
	p := g.proxies[key]
	g.mu.RUnlock()
	if p != nil {
		return p
	}

	scheme := a.Scheme
	if scheme == "" {
		scheme = "https"
	}
	target := a.Target
	pub := g.pubHost(a)
	name := a.Name
	sub := key

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// 先把公网 Host 记下来，改完就取不到了
			origHost := req.Host
			req.URL.Scheme = scheme
			req.URL.Host = target
			// Host 必须改成后端真实地址：ESXi/TNAS 会按 Host 做校验
			req.Host = target
			// 让后端能看出请求是从公网网关进来的
			req.Header.Set("X-Forwarded-Host", origHost)
			if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				req.Header.Set("X-Forwarded-For", ip)
			}
			req.Header.Set("X-Forwarded-Proto", "https")
		},
		Transport: &http.Transport{
			DialContext:           g.dialer.DialContext,
			TLSClientConfig:       g.insecureTLS,
			MaxIdleConns:          32,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// 内网设备普遍只支持 HTTP/1.1，开 h2 反而容易出怪问题
			ForceAttemptHTTP2: false,
			// WebSocket / SSE 需要长连接，不要设 ResponseHeaderTimeout
		},
		ModifyResponse: func(resp *http.Response) error {
			// 后端有时会把自己的内网地址写进 Location，换成公网地址，
			// 否则车机会被指到 10.0.0.x 上去（那里它连不到）
			if loc := resp.Header.Get("Location"); loc != "" {
				if u, err := url.Parse(loc); err == nil && u.Host != "" {
					u.Host = pub
					resp.Header.Set("Location", u.String())
				}
			}
			// 允许被嵌到门户里（部分设备会拒绝）
			resp.Header.Del("X-Frame-Options")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[%s] 反代失败 %s %s: %v", sub, r.Method, r.URL.Path, err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			// 用 WriteString 而不是 Fprintf：页面里有 % 号，会被当成格式占位符
			io.WriteString(w, pageTpl("连不上 · "+name,
				`<p class="err">`+html.EscapeString(err.Error())+`</p>`+
					`<p class="note">`+html.EscapeString(name)+` 没有响应。可能是内网机器关机，或者隧道断开。</p>`))
		},
	}

	g.mu.Lock()
	g.proxies[key] = rp
	g.mu.Unlock()
	return rp
}

// assetHandler 是「一个端口一台资产」的入口：进了这个端口，所有路径都归它。
func (g *Gateway) assetHandler(a *Asset) http.Handler {
	rp := g.proxyFor("port:"+strconv.Itoa(a.Port), a)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__health" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, "ok\n")
			return
		}
		if !g.authed(r) {
			g.showLogin(w, r, "", http.StatusUnauthorized)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- 登录

func (g *Gateway) token() string {
	// 值里带签发日期，过期就不认，避免配置泄露后永久可用
	day := time.Now().UTC().Format("2006-01-02")
	return g.sign(day) + "." + day
}

// sign 把「用户 + 日期 + 当前密码指纹」一起签，密码一改指纹就变，旧 Cookie 全废。
func (g *Gateway) sign(day string) string {
	g.passMu.RLock()
	tag := g.passTag
	g.passMu.RUnlock()
	mac := hmac.New(sha256.New, []byte(g.cfg.Secret))
	mac.Write([]byte("carweb|" + g.cfg.User + "|" + day + "|" + tag))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func (g *Gateway) checkToken(v string) bool {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return false
	}
	day, err := time.Parse("2006-01-02", parts[1])
	if err != nil {
		return false
	}
	// Cookie 有效期 14 天
	if time.Since(day) > 14*24*time.Hour {
		return false
	}
	// 当天和前一天都认，跨零点不会把人踢出去
	for _, d := range []time.Time{day, day.AddDate(0, 0, -1)} {
		want := g.sign(d.UTC().Format("2006-01-02")) + "." + d.UTC().Format("2006-01-02")
		if hmac.Equal([]byte(v), []byte(want)) {
			return true
		}
	}
	return false
}

func (g *Gateway) authed(r *http.Request) bool {
	c, err := r.Cookie("carweb")
	if err != nil {
		return false
	}
	return g.checkToken(c.Value)
}

// ---------------------------------------------------------------- 路由

func hostOnly(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	path := r.URL.Path

	// 健康检查不设门，方便运维探活
	if path == "/__health" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
		return
	}

	if path == "/__login" {
		g.handleLogin(w, r)
		return
	}

	if !g.authed(r) {
		g.showLogin(w, r, "", http.StatusUnauthorized)
		return
	}

	// 改密码：必须已经登录，且还要再验一次旧密码
	if path == "/__passwd" {
		g.handlePasswd(w, r)
		return
	}

	// 网络唤醒：门户上的「唤醒」按钮打这两个接口
	if path == "/__wake" {
		g.handleWake(w, r)
		return
	}
	if path == "/__wolstatus" {
		g.handleWOLStatus(w, r)
		return
	}

	// 自动登录脚本向这里取 Guacamole 的账号密码（同样在登录门之后）
	if path == "/__guaccred" {
		g.handleGuacCred(w, r)
		return
	}

	// Guacamole 代登录：必须在把请求交给反代之前拦一次
	if g.guacSSO(w, r) {
		return
	}

	// 路径入口：挂在门户端口上，省一个端口映射（Guacamole 这类）。
	// 必须排在门户前面——否则 /guacamole/ 会被门户的「根域名」分支吃掉。
	for prefix, target := range g.cfg.Paths {
		if strings.HasPrefix(path, prefix) {
			g.pathProxy(w, r, target)
			return
		}
	}

	// 门户：默认挂在 portal.<domain>；裸域名兼容（泛域名证书不覆盖裸域名，
	// 所以裸域名只在证书额外带了它的时候才有用）
	if host == g.portalHost() || host == g.cfg.Domain || host == "www."+g.cfg.Domain {
		g.portal(w, r)
		return
	}

	// 额外入口：整个子域名转给本机某端口（Guacamole 这类），不经 SOCKS
	if target, ok := g.cfg.Extra[host]; ok {
		g.extraProxy(w, r, target)
		return
	}

	// 资产子域名
	if sub, ok := g.matchSub(host); ok {
		if a := g.findAssetBySub(sub); a != nil {
			g.proxyFor("sub:"+sub, a).ServeHTTP(w, r)
			return
		}
	}

	http.NotFound(w, r)
}

func (g *Gateway) matchSub(host string) (string, bool) {
	suffix := "." + g.cfg.Domain
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	sub := strings.TrimSuffix(host, suffix)
	if sub == "" || strings.Contains(sub, ".") {
		// 只认一级子域，避免 esxi.a.b.example.com 这种绕法
		return "", false
	}
	return sub, true
}

func (g *Gateway) extraProxy(w http.ResponseWriter, r *http.Request, target string) {
	tu, err := url.Parse(target)
	if err != nil {
		http.Error(w, "extra 目标无效", http.StatusInternalServerError)
		return
	}
	p := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(tu)
			pr.Out.Host = tu.Host
		},
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			ForceAttemptHTTP2:   false,
			MaxIdleConnsPerHost: 8,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[extra] %s 失败: %v", target, err)
			http.Error(w, "后端没有响应", http.StatusBadGateway)
		},
	}
	p.ServeHTTP(w, r)
}

// pathProxy 把一个路径前缀原样转给本机端口。路径不改写——
// Guacamole 本来就跑在 /guacamole/ 这个 context 下，前缀留着正好。
func (g *Gateway) pathProxy(w http.ResponseWriter, r *http.Request, target string) {
	tu, err := url.Parse(target)
	if err != nil {
		http.Error(w, "paths 目标无效", http.StatusInternalServerError)
		return
	}
	p := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = tu.Scheme
			req.URL.Host = tu.Host
			req.Host = tu.Host
		},
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			ForceAttemptHTTP2:   false,
			MaxIdleConnsPerHost: 8,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[paths] %s 失败: %v", target, err)
			http.Error(w, "后端没有响应", http.StatusBadGateway)
		},
	}
	p.ServeHTTP(w, r)
}

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		g.showLogin(w, r, "", 0)
		return
	}
	if err := r.ParseForm(); err != nil {
		g.showLogin(w, r, "请求格式不对", http.StatusBadRequest)
		return
	}
	u := r.PostFormValue("u")
	p := r.PostFormValue("p")
	// 恒定时间比较，别让响应时间泄露密码信息
	uOK := hmac.Equal([]byte(u), []byte(g.cfg.User))
	if !uOK || !g.verifyPassword(p) {
		log.Printf("登录失败：来自 %s，用户名 %q", r.RemoteAddr, u)
		time.Sleep(800 * time.Millisecond) // 拖慢暴力破解
		g.showLogin(w, r, "账号或密码不对", http.StatusUnauthorized)
		return
	}
	g.setLoginCookie(w, r)
	log.Printf("登录成功：来自 %s", r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// setLoginCookie 在门户和各资产子域之间共用：Domain 放到父域，一次登录全站通用。
func (g *Gateway) setLoginCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:  "carweb",
		Value: g.token(),
		Path:  "/",
		// 子域名模式下门户和各资产是不同 Host，Cookie 不带 Domain 就只能在
		// 登录过的那一个子域上用，点进 esxi 又要再登一次。整个域都是自家的，
		// 干脆放到父域上，一次登录全站通用。
		Domain:   "." + g.cfg.Domain,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   14 * 24 * 3600,
	})
}

func (g *Gateway) clearLoginCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "carweb",
		Value:    "",
		Path:     "/",
		Domain:   "." + g.cfg.Domain,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// ---------------------------------------------------------------- 页面

const styleTpl = `<style>
*{box-sizing:border-box}
body{margin:0;padding:20px;font:16px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
     background:#f5f6f8;color:#1a1a1a;-webkit-text-size-adjust:100%}
h1{font-size:20px;margin:0 0 4px;font-weight:600}
.sub{color:#777;font-size:14px;margin-bottom:18px}
.card{display:flex;flex-wrap:wrap;align-items:center;gap:10px;background:#fff;border:1px solid #e2e4e8;
      border-radius:12px;padding:16px 18px;margin-bottom:12px;text-decoration:none;color:inherit}
.card:active{background:#eef2f8}
.card>a.row{text-decoration:none;color:inherit}
.row{display:flex;align-items:center;gap:12px;flex:1;min-width:0}
.tx{min-width:0}
.ico{width:40px;height:40px;flex:0 0 40px;border-radius:10px;background:#e8f0fb;color:#185fa5;
     display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:600}
.nm{font-size:17px;font-weight:500}
.nt{color:#888;font-size:13px;margin-top:2px}
/* 唤醒按钮：尺寸必须压过下面那条通用 button 规则（登录按钮要整宽，这个不要） */
.wk{width:auto;flex:0 0 auto;padding:9px 14px;font-size:14px;font-weight:500;color:#fff;
    background:#185fa5;border:0;border-radius:8px}
.wk:active{background:#124a80}
.wk:disabled{background:#9db4cd}
/* 唤醒结果行：平时不占位，有内容才出现 */
.wst{display:none;flex:1 0 100%;font-size:13px;margin-top:8px;color:#666;word-break:break-word}
.wst.on{display:block}
.wst.ok{color:#0a7d33}
.wst.warn{color:#9a6700}
.wst.bad{color:#b42318}
.err{color:#b42318;background:#fdecea;border:1px solid #f5c2bd;border-radius:8px;
     padding:10px 12px;margin:0 0 14px}
.note{color:#777;font-size:14px}
input{width:100%;padding:12px;font-size:16px;border:1px solid #ccd0d6;border-radius:8px;
      margin-bottom:12px;background:#fff}
button{width:100%;padding:14px;font-size:17px;font-weight:500;color:#fff;background:#185fa5;
       border:0;border-radius:8px}
button:active{background:#124a80}
form{max-width:360px;margin:8vh auto 0}
.foot{color:#aaa;font-size:12px;text-align:center;margin-top:24px}
</style>`

func pageTpl(title, body string) string {
	return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">` +
		`<title>` + html.EscapeString(title) + `</title>` + styleTpl +
		`</head><body>` + body + `</body></html>`
}

func (g *Gateway) showLogin(w http.ResponseWriter, r *http.Request, errMsg string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 401 但不带 WWW-Authenticate，浏览器只会显示这段 HTML，不会弹 Basic Auth 框
	if status != 0 {
		w.WriteHeader(status)
	}
	body := `<form method="post" action="/__login">`
	if errMsg != "" {
		body += `<p class="err">` + html.EscapeString(errMsg) + `</p>`
	}
	body += `<h1>内网入口</h1><p class="sub">输入账号密码后继续</p>` +
		`<input name="u" placeholder="账号" autocomplete="username" autocapitalize="off">` +
		`<input name="p" type="password" placeholder="密码" autocomplete="current-password">` +
		`<button type="submit">登录</button></form>` +
		`<p class="foot">TunnelBar 网关</p>`
	io.WriteString(w, pageTpl("登录 · 内网入口", body))
}

func (g *Gateway) portal(w http.ResponseWriter, r *http.Request) {
	list := make([]Asset, len(g.cfg.Assets))
	copy(list, g.cfg.Assets)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })

	var b strings.Builder
	b.WriteString(`<h1>内网入口</h1><p class="sub">点一下直接打开</p>`)
	wakeReady := g.cfg.WOL != nil
	wakeUsed := false
	for _, a := range list {
		icon := a.Icon
		if icon == "" {
			icon = "·"
		}
		openable := a.Port > 0 || a.Sub != ""
		canWake := wakeReady && a.MAC != ""
		// 既打不开也唤不醒的资产不进门户（比如只配了名字的占位项）
		if !openable && !canWake {
			continue
		}
		key := assetKey(&a)

		b.WriteString(`<div class="card">`)
		inner := `<div class="ico">` + html.EscapeString(icon) + `</div><div class="tx">`
		inner += `<div class="nm">` + html.EscapeString(a.Name) + `</div>`
		if a.Note != "" {
			inner += `<div class="nt">` + html.EscapeString(a.Note) + `</div>`
		}
		inner += `</div>`
		if openable {
			b.WriteString(`<a class="row" href="` + html.EscapeString(g.pubURL(&a)) + `">` + inner + `</a>`)
		} else {
			// 只有 MAC 没有 Web 入口的设备（如开机后才连得上的 PC）：
			// 整张卡就是唤醒入口
			b.WriteString(`<div class="row">` + inner + `</div>`)
		}
		if canWake {
			wakeUsed = true
			b.WriteString(`<button class="wk" data-wake="` + html.EscapeString(key) + `">唤醒</button>`)
			b.WriteString(`<div class="wst" data-k="` + html.EscapeString(key) + `"></div>`)
		}
		b.WriteString(`</div>`)
	}
	// 路径入口（Guacamole 之类）也列出来
	pk := make([]string, 0, len(g.cfg.Paths))
	for k := range g.cfg.Paths {
		pk = append(pk, k)
	}
	sort.Strings(pk)
	for _, k := range pk {
		label := strings.Trim(k, "/")
		if label == "" {
			label = "根路径"
		}
		b.WriteString(`<a class="card" href="` + html.EscapeString(k) + `"><div class="row">`)
		b.WriteString(`<div class="ico">⌘</div><div><div class="nm">` + html.EscapeString(label) + `</div>`)
		b.WriteString(`<div class="nt">远程桌面 / 终端</div></div></div></a>`)
	}
	// 额外入口（子域名直连本机端口）也列出来
	keys := make([]string, 0, len(g.cfg.Extra))
	for k := range g.cfg.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(`<a class="card" href="https://` + html.EscapeString(k) + `/"><div class="row">`)
		b.WriteString(`<div class="ico">⌘</div><div><div class="nm">` + html.EscapeString(strings.TrimSuffix(k, "."+g.cfg.Domain)) + `</div>`)
		b.WriteString(`<div class="nt">远程桌面 / 终端</div></div></div></a>`)
	}

	// 账号维护入口，放最后一行
	b.WriteString(`<a class="card" href="/__passwd"><div class="row">`)
	b.WriteString(`<div class="ico">K</div><div><div class="nm">修改密码</div>`)
	b.WriteString(`<div class="nt">当前账号 ` + html.EscapeString(g.cfg.User) + `</div></div></div></a>`)

	// 唤醒交互只在页面上确实有按钮时才注入，没配 WOL 的网关
	// （或一台都没填 mac）连这段 JS 都不需要下载
	if wakeUsed && g.cfg.WOL != nil {
		b.WriteString(`<div id="wolcfg" data-wait="` + strconv.Itoa(g.cfg.WOL.WaitSeconds) + `" hidden></div>`)
		b.WriteString(portalWOLJS)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, pageTpl("内网入口", b.String()))
}

func main() {
	var (
		cfgPath = flag.String("config", "/home/carweb/etc/gateway.json", "配置文件路径")
		listen  = flag.String("listen", "", "覆盖监听地址，如 0.0.0.0:8443")
	)
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("读配置失败：%v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	// 资产端口默认绑在 listen 的同一个地址上（一般是 0.0.0.0），
	// 否则 listen 写 127.0.0.1 时资产端口也会跟着只监听回环，映射出去也没用。
	bindHost := cfg.Bind
	if bindHost == "" {
		h, _, err := net.SplitHostPort(cfg.Listen)
		if err != nil {
			log.Fatalf("listen 地址不对：%v", err)
		}
		bindHost = h
	}

	gw := NewGateway(cfg)
	if err := gw.loadPassword(); err != nil {
		log.Fatalf("密码初始化失败：%v", err)
	}

	var tlsCfg *tls.Config
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		rl := &certReloader{certFile: cfg.TLSCert, keyFile: cfg.TLSKey}
		if _, err := rl.getCertificate(nil); err != nil {
			log.Fatalf("证书加载失败（%s）：%v", cfg.TLSCert, err)
		}
		tlsCfg = &tls.Config{
			GetCertificate: rl.getCertificate,
			MinVersion:     tls.VersionTLS12,
		}
	}

	// 先把要监听的端口全部列出来，任何一个绑不上就直接退出，
	// 免得“一半起来了”这种最难查的状态。
	type endpoint struct {
		addr string
		h    http.Handler
		tag  string
	}
	var eps []endpoint
	eps = append(eps, endpoint{cfg.Listen, gw, "门户"})
	used := map[int]bool{}
	for i := range cfg.Assets {
		a := &cfg.Assets[i]
		if a.Port <= 0 {
			continue
		}
		if used[a.Port] {
			log.Fatalf("资产 %q 的端口 %d 重复了", a.Name, a.Port)
		}
		used[a.Port] = true
		addr := net.JoinHostPort(bindHost, strconv.Itoa(a.Port))
		eps = append(eps, endpoint{addr, gw.assetHandler(a), a.Name})
	}

	log.Printf("网关启动，域名 %s，%d 个资产，SOCKS %s，HTTPS=%v",
		cfg.Domain, len(cfg.Assets), cfg.Socks, tlsCfg != nil)
	for i := range cfg.Assets {
		a := &cfg.Assets[i]
		log.Printf("  %-32s %s://%s  (%s)", gw.endpointOf(a), a.Scheme, a.Target, a.Name)
	}
	for _, k := range sortedKeys(cfg.Paths) {
		log.Printf("  %-32s %s  (本机路径)", cfg.Listen+k, cfg.Paths[k])
	}
	for _, k := range sortedKeys(cfg.Extra) {
		log.Printf("  %-32s %s  (本机直连)", k, cfg.Extra[k])
	}
	if cfg.Guac != nil {
		log.Printf("Guacamole 代登录：%s 用账号 %q 自动登录（%s）",
			cfg.Guac.Path, cfg.Guac.User, cfg.Guac.Target)
	}
	if cfg.WOL != nil {
		n := 0
		for i := range cfg.Assets {
			if cfg.Assets[i].MAC != "" {
				n++
			}
		}
		log.Printf("网络唤醒：转给 home 的 %s，%d 台资产配了 MAC，等待上线 %ds",
			cfg.WOL.Endpoint, n, cfg.WOL.WaitSeconds)
	}

	for _, ep := range eps {
		ln, err := net.Listen("tcp", ep.addr)
		if err != nil {
			log.Fatalf("[%s] 监听 %s 失败：%v", ep.tag, ep.addr, err)
		}
		log.Printf("[%s] 已监听 %s", ep.tag, ep.addr)
		srv := &http.Server{
			Addr:              ep.addr,
			Handler:           ep.h,
			ReadHeaderTimeout: 15 * time.Second,
			// 不设 WriteTimeout：WebSocket 和长下载会被砍断
			IdleTimeout: 120 * time.Second,
			TLSConfig:   tlsCfg,
		}
		go func(ep endpoint, ln net.Listener, srv *http.Server) {
			var err error
			if tlsCfg != nil {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			log.Printf("[%s] %s 退出：%v", ep.tag, ep.addr, err)
		}(ep, ln, srv)
	}

	if tlsCfg == nil {
		log.Printf("注意：未配置证书，当前是明文 HTTP")
	}
	select {} // 等信号，systemd 停服务时进程直接被杀
}

func (g *Gateway) endpointOf(a *Asset) string {
	if a.Port > 0 {
		return g.cfg.Domain + ":" + strconv.Itoa(a.Port)
	}
	if a.Sub != "" {
		return a.Sub + "." + g.cfg.Domain
	}
	return "-"
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ---------------------------------------------------------------- 配置默认值

func (c *Config) normalize() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8090"
	}
	if c.Socks == "" {
		c.Socks = "127.0.0.1:1080"
	}
	if c.PortalSub == "" {
		c.PortalSub = "portal"
	}
	if c.WOL != nil {
		c.WOL.normalize()
	}
}
