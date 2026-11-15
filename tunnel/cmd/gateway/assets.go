// 网关的资产管理：在浏览器里新增 / 修改 / 删除内网入口，保存后立刻生效。
//
// 为什么需要它：资产原本只写在 gateway.json 里，加一台机器得改配置文件再
// systemctl restart。可这个网关存在的意义就是「人不在家」，那台跑网关的
// 机器通常也不在手边——于是加一台 NAS、换一个端口，反倒要等回家才能做。
//
// 两类资产的生效方式不一样，页面里必须说清楚：
//   - 子域名资产（sub）：复用现有 HTTPS 端口，靠 Host 分流。保存即生效，
//     不需要任何端口映射，也不需要重启；
//   - 独立端口资产（port）：必须真去 listen 一个新端口，所以这里是运行时
//     起监听（删除时关掉）。但**防火墙上的端口映射在网关之外**，界面会提示
//     这一点——不提示的话，用户会以为「保存了就能从外面访问」。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"tunnel/internal"
)

// ---------------------------------------------------------------- 运行时资产表

// assetList 取当前资产表的一份拷贝。
//
// 拷贝而不是返回切片本身：调用方（门户渲染、反代构造）会持有它一段时间，
// 这期间另一个人可能在另一个浏览器里删了资产，直接共享底层数组会读到半更新状态。
func (g *Gateway) assetList() []Asset {
	g.assetsMu.RLock()
	defer g.assetsMu.RUnlock()
	out := make([]Asset, len(g.assets))
	copy(out, g.assets)
	return out
}

func (g *Gateway) findAssetBySub(sub string) *Asset {
	g.assetsMu.RLock()
	defer g.assetsMu.RUnlock()
	for i := range g.assets {
		if g.assets[i].Sub == sub {
			a := g.assets[i]
			return &a
		}
	}
	return nil
}

func (g *Gateway) assetByPort(port int) *Asset {
	g.assetsMu.RLock()
	defer g.assetsMu.RUnlock()
	for i := range g.assets {
		if g.assets[i].Port == port {
			a := g.assets[i]
			return &a
		}
	}
	return nil
}

// assetByKey 按门户回传的标识找资产：优先子域名，其次名字。
func (g *Gateway) assetByKey(k string) *Asset {
	if k == "" {
		return nil
	}
	g.assetsMu.RLock()
	defer g.assetsMu.RUnlock()
	for i := range g.assets {
		a := g.assets[i]
		if a.Sub != "" && a.Sub == k {
			return &a
		}
		if a.Name == k {
			return &a
		}
	}
	return nil
}

// assetKey 是门户按钮 / 编辑链接回传的资产标识：优先子域名，其次名字。
func assetKey(a *Asset) string {
	if a.Sub != "" {
		return a.Sub
	}
	return a.Name
}

func portInUse(list []Asset, p int) bool {
	for i := range list {
		if list[i].Port == p {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- 动态端口

// startPort 在运行时给一台「独立端口资产」起监听。
//
// 资产端口和门户端口走同一个 TLS 配置：证书是同一个泛域名证书，
// 少一套配置就少一处会忘掉的地方。
func (g *Gateway) startPort(p int) error {
	if p <= 0 {
		return errors.New("端口必须大于 0")
	}
	g.portMu.Lock()
	defer g.portMu.Unlock()
	if _, ok := g.ports[p]; ok {
		return nil // 已经在监听，重复保存不该报错
	}
	host := g.bindHost
	if host == "" {
		host = "0.0.0.0"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(p))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           g.assetHandlerByPort(p),
		ReadHeaderTimeout: 15 * time.Second,
		// 不设 WriteTimeout：WebSocket 和长下载会被砍断
		IdleTimeout: 120 * time.Second,
		TLSConfig:   g.tlsCfg,
	}
	g.ports[p] = srv
	go func() {
		var serr error
		if g.tlsCfg != nil {
			serr = srv.ServeTLS(ln, "", "")
		} else {
			serr = srv.Serve(ln)
		}
		log.Printf("[资产:%d] 监听结束：%v", p, serr)
	}()
	log.Printf("[资产:%d] 已监听 %s", p, addr)
	return nil
}

// stopPort 关掉一台资产的端口。用 Shutdown 而不是 Close：
// 正在看 ESXi 控制台的那个人不该因为别人删了一台不相关的资产被直接掐断。
func (g *Gateway) stopPort(p int) {
	g.portMu.Lock()
	srv := g.ports[p]
	delete(g.ports, p)
	g.portMu.Unlock()
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[资产:%d] 关闭监听：%v", p, err)
		return
	}
	log.Printf("[资产:%d] 已停止监听", p)
}

// invalidateProxies 丢掉所有已建的反向代理。
//
// 代理里缓存了 target / 对外 Host，改完资产不重建的话，改的地址不会生效——
// 会出现「配置改了、日志也改了，但访问还是老机器」这种最难查的错。
// 重建代价只有一次 map 分配，全清比按 key 精准失效更不容易漏。
func (g *Gateway) invalidateProxies() {
	g.mu.Lock()
	g.proxies = make(map[string]*httputil.ReverseProxy)
	g.mu.Unlock()
}

// assetHandlerByPort 是「一个端口一台资产」的入口。每次请求现查资产表，
// 这样改完 target 不需要重建 handler 也能落到新地址。
func (g *Gateway) assetHandlerByPort(p int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__health" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		if !g.authed(r) {
			g.showLogin(w, r, "", false, http.StatusUnauthorized)
			return
		}
		a := g.assetByPort(p)
		if a == nil {
			// 资产刚被删、监听还没关掉的那几毫秒
			http.NotFound(w, r)
			return
		}
		g.proxyFor("port:"+strconv.Itoa(p), a).ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- 校验

var subRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// normalizeTarget 把用户填写的东西整成 host:port。
// 顺手容忍粘贴整个 URL 的情况（从浏览器地址栏复制是最常见的操作）。
func normalizeTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("「目标地址」必填：内网那台机器的 host:port")
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("目标地址看不懂：%s", s)
		}
		s = u.Host
	}
	s = strings.TrimSuffix(s, "/")
	if _, _, err := net.SplitHostPort(s); err != nil {
		return "", fmt.Errorf("目标地址要写成 host:port，例如 10.0.0.10:443（现在是 %q）", s)
	}
	host, portStr, _ := net.SplitHostPort(s)
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("目标端口不对：%q", portStr)
	}
	if host == "" {
		return "", errors.New("目标地址缺少主机名")
	}
	return net.JoinHostPort(host, strconv.Itoa(p)), nil
}

func parsePortField(v, label string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	p, err := strconv.Atoi(v)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("%s要是 1-65535 之间的数字（现在是 %q）", label, v)
	}
	return p, nil
}

// assetFromForm 把表单读成一台资产，所有校验都在这里做完。
func assetFromForm(r *http.Request) (Asset, error) {
	var a Asset
	a.Name = strings.TrimSpace(r.PostFormValue("name"))
	rawSub := strings.TrimSpace(r.PostFormValue("sub"))
	a.Sub = strings.ToLower(rawSub)
	a.Scheme = strings.ToLower(strings.TrimSpace(r.PostFormValue("scheme")))
	a.Icon = strings.TrimSpace(r.PostFormValue("icon"))
	a.Note = strings.TrimSpace(r.PostFormValue("note"))

	if a.Name == "" {
		return a, errors.New("「名称」必填：门户上显示的就是它")
	}
	if len([]rune(a.Name)) > 40 {
		return a, errors.New("名称太长了，40 个字以内")
	}
	if a.Scheme != "http" {
		a.Scheme = "https"
	}

	t, err := normalizeTarget(r.PostFormValue("target"))
	if err != nil {
		return a, err
	}
	a.Target = t

	if a.Port, err = parsePortField(r.PostFormValue("port"), "独立端口"); err != nil {
		return a, err
	}
	if a.PubPort, err = parsePortField(r.PostFormValue("public_port"), "对外端口"); err != nil {
		return a, err
	}

	if a.Sub != "" && !subRe.MatchString(a.Sub) {
		return a, fmt.Errorf("子域名只能用小写字母、数字和连字符，且不能以连字符开头或结尾（现在是 %q）", rawSub)
	}

	// 图标只取一个字符。门户上那一格是 40×40，放多字符会被裁掉，
	// 不如在这里截断，让人立刻看到实际效果。
	if r := []rune(a.Icon); len(r) > 1 {
		a.Icon = string(r[0])
	}

	if mac := strings.TrimSpace(r.PostFormValue("mac")); mac != "" {
		hw, err := internal.ParseMAC(mac)
		if err != nil {
			return a, fmt.Errorf("MAC 写法不对（%s）：应形如 AA:BB:CC:DD:EE:FF", mac)
		}
		a.MAC = hw.String()
	}

	if a.Sub == "" && a.Port == 0 && a.MAC == "" {
		return a, errors.New("「子域名」和「独立端口」至少填一个；只想做唤醒入口的话，把 MAC 填上")
	}
	if a.Sub == "" && a.Port == 0 && a.MAC != "" {
		// 纯唤醒设备（比如开机后才连得上的工作站）：合法，门户上只显示唤醒按钮
		a.Note = strings.TrimSpace(a.Note)
	}
	return a, nil
}

func listenPortOf(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// ---------------------------------------------------------------- 保存 / 删除

// saveAsset 处理「新增或修改一台资产」。返回给用户看的结果文案。
//
// 顺序很重要：先把新端口真的监听起来，再写配置文件，最后才替换内存表。
// 这样任何一步失败都不会留下「配置里有一台机器、实际却连不上」的状态。
func (g *Gateway) saveAsset(r *http.Request) (string, error) {
	orig := strings.TrimSpace(r.PostFormValue("orig"))
	form, err := assetFromForm(r)
	if err != nil {
		return "", err
	}

	g.assetsMu.Lock()
	defer g.assetsMu.Unlock()

	old := make([]Asset, len(g.assets))
	copy(old, g.assets)

	idx := -1
	if orig != "" {
		for i := range old {
			if assetKey(&old[i]) == orig {
				idx = i
				break
			}
		}
		if idx < 0 {
			return "", errors.New("要改的那台资产已经不在了，刷新页面再试")
		}
	}

	// 冲突检查（跳过自己，否则「只改说明」也会被判重复）
	for i := range old {
		if i == idx {
			continue
		}
		o := &old[i]
		if form.Sub != "" && o.Sub == form.Sub {
			return "", fmt.Errorf("子域名 %q 已被「%s」占用", form.Sub, o.Name)
		}
		if form.Port > 0 && o.Port == form.Port {
			return "", fmt.Errorf("端口 %d 已被「%s」占用", form.Port, o.Name)
		}
		if form.Name == o.Name && form.Sub == o.Sub && form.Port == o.Port {
			return "", fmt.Errorf("已经有一个「%s」了，换个名称或子域名", o.Name)
		}
	}
	if form.Sub != "" {
		if form.Sub == g.cfg.PortalSub {
			return "", fmt.Errorf("子域名 %q 是门户自己在用的", form.Sub)
		}
		if _, ok := g.cfg.Extra[form.Sub+"."+g.cfg.Domain]; ok {
			return "", fmt.Errorf("子域名 %q 已经配在 extra 里了", form.Sub)
		}
	}
	if form.Port > 0 && form.Port == listenPortOf(g.cfg.Listen) {
		return "", fmt.Errorf("端口 %d 是门户自己在用的", form.Port)
	}

	next := make([]Asset, len(old))
	copy(next, old)
	if idx >= 0 {
		next[idx] = form
	} else {
		next = append(next, form)
	}

	// ① 先开新端口
	var opened []int
	for _, na := range next {
		if na.Port > 0 && !portInUse(old, na.Port) {
			if err := g.startPort(na.Port); err != nil {
				for _, p := range opened {
					g.stopPort(p)
				}
				if isAddrInUse(err) {
					return "", fmt.Errorf("端口 %d 已被别的程序占用（不是本网关的资产）", na.Port)
				}
				return "", fmt.Errorf("监听端口 %d 失败：%v", na.Port, err)
			}
			opened = append(opened, na.Port)
		}
	}

	// ② 写配置
	if err := g.persistAssets(next); err != nil {
		for _, p := range opened {
			g.stopPort(p)
		}
		return "", fmt.Errorf("写配置文件失败：%v（内存里的资产没有改动）", err)
	}

	// ③ 提交内存
	g.assets = next
	g.cfg.Assets = append([]Asset(nil), next...)
	g.invalidateProxies()

	// ④ 关掉不再需要的旧端口
	for i := range old {
		if old[i].Port > 0 && !portInUse(next, old[i].Port) {
			g.stopPort(old[i].Port)
		}
	}

	if idx >= 0 {
		return fmt.Sprintf("已保存「%s」的修改", form.Name), nil
	}
	return fmt.Sprintf("已新增「%s」", form.Name), nil
}

// deleteAsset 删掉一台资产。
func (g *Gateway) deleteAsset(key string) (string, error) {
	if key == "" {
		return "", errors.New("没说要删哪一台")
	}
	g.assetsMu.Lock()
	defer g.assetsMu.Unlock()

	old := make([]Asset, len(g.assets))
	copy(old, g.assets)

	idx := -1
	for i := range old {
		if assetKey(&old[i]) == key {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", errors.New("找不到这台资产，可能已经被删了")
	}
	removed := old[idx]

	next := make([]Asset, 0, len(old)-1)
	next = append(next, old[:idx]...)
	next = append(next, old[idx+1:]...)

	if err := g.persistAssets(next); err != nil {
		return "", fmt.Errorf("写配置文件失败：%v（没有删除）", err)
	}
	g.assets = next
	g.cfg.Assets = append([]Asset(nil), next...)
	g.invalidateProxies()
	if removed.Port > 0 {
		g.stopPort(removed.Port)
	}
	return fmt.Sprintf("已删除「%s」", removed.Name), nil
}

// persistAssets 把资产表写回 gateway.json。
//
// 只替换 assets 这一个键，其余键原样保留：配置文件里还有 wol / guacamole /
// paths 这些手写过的东西，用结构体整体回写会把不认识的字段（以及以后新增的
// 字段）静默吃掉——那种损失在下次重启时才暴露。
//
// 写之前先备份一份 .bak-时间戳，写完是「临时文件 → fsync → rename」，
// 中途断电也只会留下旧文件或新文件，不会出现半截 JSON 让网关起不来。
func (g *Gateway) persistAssets(next []Asset) error {
	path := g.cfgPath
	if path == "" {
		return errors.New("网关不知道配置文件在哪（启动时没给 -config），只能手工改配置")
	}

	raw := map[string]json.RawMessage{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("现有配置文件不是合法 JSON：%v", err)
		}
	}

	ab, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	raw["assets"] = ab

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')

	perm := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}
	if b, err := os.ReadFile(path); err == nil {
		// 同一秒连着改两次会生成同一个名字，后一次把前一次的备份覆盖掉——
		// 那正好是「改错了想退回去」最需要它的时刻。撞名就加序号。
		base := path + ".bak-" + time.Now().Format("20060102-150405")
		bak := base
		for i := 1; i < 100; i++ {
			if _, err := os.Stat(bak); os.IsNotExist(err) {
				break
			}
			bak = base + "-" + strconv.Itoa(i)
		}
		if err := os.WriteFile(bak, b, perm); err != nil {
			// 备份失败就不写了：网关配置被写坏比改不动更麻烦
			return fmt.Errorf("备份原配置失败：%v", err)
		}
		log.Printf("[资产] 配置已备份到 %s", bak)
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(out); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	log.Printf("[资产] 已写入 %s（%d 台）", path, len(next))
	return nil
}

func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "address already in use") ||
		strings.Contains(err.Error(), "address in use")
}

// ---------------------------------------------------------------- 页面

const assetMgrCSS = `<style>
form.mgr{max-width:none;margin:0}
.mgr input[type=hidden]{display:none}
.mgr label{display:block;margin:0 0 14px}
.mgr .lb{display:block;font-size:13px;color:#555;margin-bottom:6px}
.mgr input,.mgr select{width:100%;margin:0;padding:10px 12px;font-size:16px;border:1px solid #ccd0d6;
  border-radius:8px;background:#fff;color:#1a1a1a}
.mgr .hint{display:block;color:#999;font-size:12px;margin-top:5px;line-height:1.5}
/* 占位符要明显浅于真实内容，否则一眼看过去像「已经填好了」 */
.mgr input::placeholder{color:#c2c6cc}
.mgr input::-webkit-input-placeholder{color:#c2c6cc}
.mgr .grid{display:flex;flex-wrap:wrap;gap:0 14px}
.mgr .grid>label{flex:1 1 200px;min-width:0}
.mgr .acts{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:6px}
.mgr button,.mgr a.sec{width:auto;flex:0 0 auto;padding:12px 22px;font-size:16px;border-radius:8px;
  text-decoration:none;display:inline-block;text-align:center;line-height:1.2}
.mgr a.sec{background:#eef2f8;color:#185fa5}
.mgr a.sec.danger{background:#fdecea;color:#b42318}
h2{font-size:15px;margin:26px 0 10px;color:#444;font-weight:600}
.it{background:#fff;border:1px solid #e2e4e8;border-radius:12px;padding:14px 16px;margin-bottom:10px}
.it .top{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.it .nm2{font-size:16px;font-weight:500;flex:1 1 140px;min-width:0;overflow-wrap:break-word}
.it .meta{color:#777;font-size:13px;margin-top:6px;overflow-wrap:break-word;word-break:break-all}
.it .ops{display:flex;gap:8px;flex:0 0 auto}
a.lnk{color:#185fa5;text-decoration:none;font-size:14px;padding:7px 12px;border-radius:7px;background:#eef2f8}
a.lnk.del{color:#b42318;background:#fdecea}
.tagk{display:inline-block;background:#e8f0fb;color:#185fa5;border-radius:6px;padding:1px 7px;
  font-size:12px;margin-left:6px;vertical-align:middle}
.tagm{display:inline-block;background:#eaf7ee;color:#0a7d33;border-radius:6px;padding:1px 7px;
  font-size:12px;margin-left:6px;vertical-align:middle}
.ok{color:#0a7d33;background:#eaf7ee;border:1px solid #b7e3c6;border-radius:8px;padding:10px 12px;margin:0 0 14px}
.warnbox{color:#9a6700;background:#fff8e6;border:1px solid #f0dda0;border-radius:8px;
  padding:10px 12px;margin:0 0 14px;font-size:14px;line-height:1.6}
</style>`

func esc(s string) string { return html.EscapeString(s) }

func (g *Gateway) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		g.handleAssetPost(w, r)
		return
	}
	g.renderAssets(w, r)
}

func (g *Gateway) handleAssetPost(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "跨站请求被拒绝", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		g.redirectAssets(w, r, "", "表单读不出来："+err.Error())
		return
	}
	var (
		msg string
		err error
	)
	switch r.PostFormValue("action") {
	case "delete":
		msg, err = g.deleteAsset(strings.TrimSpace(r.PostFormValue("orig")))
	default:
		msg, err = g.saveAsset(r)
	}
	if err != nil {
		g.redirectAssets(w, r, "", err.Error())
		return
	}
	g.redirectAssets(w, r, msg, "")
}

// redirectAssets 用 303 回到管理页：这样刷新不会重复提交，
// 也不用把「保存成功」这件事塞进页面状态里。
func (g *Gateway) redirectAssets(w http.ResponseWriter, r *http.Request, ok, errMsg string) {
	q := url.Values{}
	if ok != "" {
		q.Set("ok", ok)
	}
	if errMsg != "" {
		q.Set("err", errMsg)
	}
	// 错误时把原表单字段带回去，避免用户重填一遍
	if errMsg != "" && r.Method == http.MethodPost {
		for _, k := range []string{"orig", "name", "target", "scheme", "sub", "port",
			"public_port", "icon", "note", "mac"} {
			if v := r.PostFormValue(k); v != "" {
				q.Set("f_"+k, v)
			}
		}
	}
	loc := "/__assets"
	if s := q.Encode(); s != "" {
		loc += "?" + s
	}
	http.Redirect(w, r, loc, http.StatusSeeOther)
}

// sameOrigin 挡一下跨站提交。
//
// Cookie 是 SameSite=Lax，跨站 POST 本来就不带 Cookie，但老浏览器不一定
// 认这个属性；带 Origin 头时必须同源，不带 Origin 的（很老的浏览器、部分
// 车机）只能靠 Cookie 那道门，属于已知的折中。
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (g *Gateway) renderAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list := g.assetList()
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })

	// 编辑态：?k=<标识>
	var draft Asset
	orig := ""
	if k := q.Get("k"); k != "" {
		for i := range list {
			if assetKey(&list[i]) == k {
				draft = list[i]
				orig = k
				break
			}
		}
	}
	// 保存失败回填：带着刚填的内容回到表单，而不是留一张空白表
	if q.Get("err") != "" {
		draft = Asset{
			Name:    q.Get("f_name"),
			Target:  q.Get("f_target"),
			Scheme:  q.Get("f_scheme"),
			Sub:     q.Get("f_sub"),
			Icon:    q.Get("f_icon"),
			Note:    q.Get("f_note"),
			MAC:     q.Get("f_mac"),
			Port:    atoiOr0(q.Get("f_port")),
			PubPort: atoiOr0(q.Get("f_public_port")),
		}
		orig = q.Get("f_orig")
		if draft.Scheme == "" {
			draft.Scheme = "https"
		}
	}
	if draft.Scheme == "" {
		draft.Scheme = "https"
	}

	isDel := q.Get("del") != ""

	var b strings.Builder
	b.WriteString(`<p style="margin:0 0 14px"><a class="lnk" href="/">← 返回门户</a></p>`)
	b.WriteString(`<h1>`)
	switch {
	case isDel:
		b.WriteString(`删除资产`)
	case orig != "":
		b.WriteString(`修改资产`)
	default:
		b.WriteString(`新增资产`)
	}
	b.WriteString(`</h1><p class="sub">`)
	if isDel {
		b.WriteString(`删掉之后，这个入口立刻不可用`)
	} else {
		b.WriteString(`保存后立即生效，不用重启网关`)
	}
	b.WriteString(`</p>`)

	if e := q.Get("err"); e != "" {
		b.WriteString(`<p class="err">` + esc(e) + `</p>`)
	}
	if o := q.Get("ok"); o != "" {
		b.WriteString(`<p class="ok">` + esc(o) + `</p>`)
	}

	// ---- 删除确认 ----
	if del := q.Get("del"); del != "" {
		b.WriteString(g.renderDeleteConfirm(del, list))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, pageWith("删除资产 · 内网入口", assetMgrCSS, b.String()))
		return
	}

	// ---- 现有资产列表 ----
	b.WriteString(`<h2>现有资产（` + strconv.Itoa(len(list)) + ` 台）</h2>`)
	if len(list) == 0 {
		b.WriteString(`<p class="note">还没有资产，用下面的表单加一台。</p>`)
	}
	for i := range list {
		a := &list[i]
		key := assetKey(a)
		b.WriteString(`<div class="it"><div class="top">`)
		b.WriteString(`<div class="nm2">` + esc(a.Name))
		if a.Port > 0 {
			b.WriteString(`<span class="tagk">端口 ` + strconv.Itoa(a.Port) + `</span>`)
		}
		if a.Sub != "" {
			b.WriteString(`<span class="tagk">` + esc(a.Sub) + `.` + esc(g.cfg.Domain) + `</span>`)
		}
		if a.MAC != "" {
			b.WriteString(`<span class="tagm">可唤醒</span>`)
		}
		b.WriteString(`</div><div class="ops">`)
		b.WriteString(`<a class="lnk" href="/__assets?k=` + url.QueryEscape(key) + `">编辑</a>`)
		b.WriteString(`<a class="lnk del" href="/__assets?del=` + url.QueryEscape(key) + `">删除</a>`)
		b.WriteString(`</div></div>`)
		if a.Port > 0 || a.Sub != "" {
			b.WriteString(`<div class="meta">入口 ` + esc(g.pubURL(a)) + `</div>`)
		}
		b.WriteString(`<div class="meta">后端 ` + esc(a.Scheme) + `://` + esc(a.Target) + `</div>`)
		if a.Note != "" {
			b.WriteString(`<div class="meta">` + esc(a.Note) + `</div>`)
		}
		if a.MAC != "" {
			b.WriteString(`<div class="meta">MAC ` + esc(a.MAC) + `</div>`)
		}
		b.WriteString(`</div>`)
	}

	// ---- 表单 ----
	b.WriteString(`<h2>`)
	if orig != "" {
		b.WriteString(`修改「` + esc(draft.Name) + `」`)
	} else {
		b.WriteString(`新增一台`)
	}
	b.WriteString(`</h2>`)

	b.WriteString(`<p class="warnbox">两种暴露方式，选一种就够：<br>`)
	b.WriteString(`<b>子域名</b>（推荐）——复用现有的 HTTPS 端口，靠域名分流，不用改防火墙；<br>`)
	b.WriteString(`<b>独立端口</b>——单独占一个端口，需要你在防火墙上把这个端口映射到本机，否则只有局域网能访问。</p>`)

	b.WriteString(`<form method="post" action="/__assets" class="mgr">`)
	b.WriteString(`<input type="hidden" name="action" value="save">`)
	b.WriteString(`<input type="hidden" name="orig" value="` + esc(orig) + `">`)

	b.WriteString(`<label><span class="lb">名称</span>`)
	b.WriteString(`<input name="name" value="` + esc(draft.Name) + `" placeholder="ESXi 宿主机" autocomplete="off">`)
	b.WriteString(`<span class="hint">门户卡片上显示的名字</span></label>`)

	b.WriteString(`<label><span class="lb">目标地址</span>`)
	b.WriteString(`<input name="target" value="` + esc(draft.Target) + `" placeholder="10.0.0.10:443" autocapitalize="off" autocomplete="off">`)
	b.WriteString(`<span class="hint">内网那台机器的 host:port。可以整段粘贴 https://10.0.0.10:443/，会自动拆</span></label>`)

	b.WriteString(`<div class="grid">`)
	b.WriteString(`<label><span class="lb">协议</span><select name="scheme">`)
	for _, s := range []struct{ v, label string }{
		{"https", "https（多数管理界面）"},
		{"http", "http（内网明文服务）"},
	} {
		sel := ""
		if draft.Scheme == s.v {
			sel = " selected"
		}
		b.WriteString(`<option value="` + s.v + `"` + sel + `>` + s.label + `</option>`)
	}
	b.WriteString(`</select></label>`)

	b.WriteString(`<label><span class="lb">图标</span>`)
	b.WriteString(`<input name="icon" value="` + esc(draft.Icon) + `" placeholder="▣" maxlength="2" autocomplete="off">`)
	b.WriteString(`<span class="hint">一个字符，留空显示「·」</span></label>`)
	b.WriteString(`</div>`)

	b.WriteString(`<div class="grid">`)
	b.WriteString(`<label><span class="lb">子域名（推荐）</span>`)
	b.WriteString(`<input name="sub" value="` + esc(draft.Sub) + `" placeholder="esxi" autocapitalize="off" autocomplete="off">`)
	b.WriteString(`<span class="hint">填 esxi 就是 esxi.` + esc(g.cfg.Domain) + `；小写字母/数字/连字符</span></label>`)

	b.WriteString(`<label><span class="lb">独立端口（可选）</span>`)
	portVal := ""
	if draft.Port > 0 {
		portVal = strconv.Itoa(draft.Port)
	}
	b.WriteString(`<input name="port" value="` + portVal + `" placeholder="留空" inputmode="numeric" autocomplete="off">`)
	b.WriteString(`<span class="hint">保存后立刻监听；需要防火墙映射才能从公网访问</span></label>`)
	b.WriteString(`</div>`)

	b.WriteString(`<label><span class="lb">说明（可选）</span>`)
	b.WriteString(`<input name="note" value="` + esc(draft.Note) + `" placeholder="10.0.0.10 · 虚拟化" autocomplete="off"></label>`)

	b.WriteString(`<div class="grid">`)
	b.WriteString(`<label><span class="lb">MAC（可选）</span>`)
	b.WriteString(`<input name="mac" value="` + esc(draft.MAC) + `" placeholder="AA:BB:CC:DD:EE:FF" autocapitalize="off" autocomplete="off">`)
	b.WriteString(`<span class="hint">填了才有「唤醒」按钮；只填 MAC 不填以上两项 = 纯唤醒入口</span></label>`)

	pubVal := ""
	if draft.PubPort > 0 {
		pubVal = strconv.Itoa(draft.PubPort)
	}
	b.WriteString(`<label><span class="lb">对外端口（可选）</span>`)
	b.WriteString(`<input name="public_port" value="` + pubVal + `" placeholder="留空" inputmode="numeric" autocomplete="off">`)
	b.WriteString(`<span class="hint">防火墙把外部号映射成别的号时填，如外 9444 → 内 8444</span></label>`)
	b.WriteString(`</div>`)

	b.WriteString(`<div class="acts"><button type="submit">`)
	if orig != "" {
		b.WriteString(`保存修改`)
	} else {
		b.WriteString(`新增`)
	}
	b.WriteString(`</button>`)
	if orig != "" {
		b.WriteString(`<a class="sec" href="/__assets">取消修改</a>`)
	}
	b.WriteString(`</div></form>`)

	b.WriteString(`<p class="foot"><a class="lnk" href="/">返回门户</a></p>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, pageWith("资产管理 · 内网入口", assetMgrCSS, b.String()))
}

func (g *Gateway) renderDeleteConfirm(key string, list []Asset) string {
	var target *Asset
	for i := range list {
		if assetKey(&list[i]) == key {
			target = &list[i]
			break
		}
	}
	if target == nil {
		return `<p class="err">这台资产已经不在了</p><p class="foot"><a class="lnk" href="/__assets">返回</a></p>`
	}

	var b strings.Builder
	b.WriteString(`<h2 style="margin-top:0">确认删除？</h2>`)
	b.WriteString(`<div class="it"><div class="top"><div class="nm2">` + esc(target.Name) + `</div></div>`)
	b.WriteString(`<div class="meta">后端 ` + esc(target.Scheme) + `://` + esc(target.Target) + `</div>`)
	if target.Sub != "" {
		b.WriteString(`<div class="meta">子域名 ` + esc(target.Sub) + `.` + esc(g.cfg.Domain) + `</div>`)
	}
	if target.Port > 0 {
		b.WriteString(`<div class="meta">独立端口 ` + strconv.Itoa(target.Port) + `（会立刻停止监听）</div>`)
	}
	b.WriteString(`</div>`)
	b.WriteString(`<p class="warnbox">删除后：门户上这张卡片消失、对应的域名/端口立刻不可用、`)
	b.WriteString(`gateway.json 会被改写（改之前自动备份一份 .bak）。原配置里的机器本身不受影响。</p>`)
	b.WriteString(`<form method="post" action="/__assets" class="mgr">`)
	b.WriteString(`<input type="hidden" name="action" value="delete">`)
	b.WriteString(`<input type="hidden" name="orig" value="` + esc(key) + `">`)
	b.WriteString(`<div class="acts"><button type="submit" style="background:#b42318">确认删除</button>`)
	b.WriteString(`<a class="sec" href="/__assets">不删了</a></div></form>`)
	return b.String()
}

func atoiOr0(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
