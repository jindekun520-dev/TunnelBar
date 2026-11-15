// 密码：存哈希、能在线改、改完踢掉所有旧登录。
//
// 为什么不把密码写在 gateway.json 里就完事：配置文件是明文，而且会被备份、
// 截图、发给别人看。一旦上过一次线，密码就该只以哈希形式存在独立文件里。
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	pwAlgo = "pbkdf2-sha256"
	// 迭代次数：202 这种小机器上大约 80~120ms，登录感知不到，
	// 但把离线爆破的成本抬高了几个数量级。车机慢一点也无所谓。
	pwIter = 120000
	pwLen  = 32
	// 太短的密码不如不设
	pwMinLen = 8
)

// hashPassword 生成 "pbkdf2-sha256$迭代$盐$哈希"，盐每次随机。
func hashPassword(plain string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(plain), salt, pwIter, pwLen)
	return fmt.Sprintf("%s$%d$%s$%s", pwAlgo, pwIter,
		hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// verifyHash 按存储的算法/迭代次数重算，这样以后调高 pwIter 也不影响老记录。
func verifyHash(plain, stored string) bool {
	f := strings.Split(stored, "$")
	if len(f) != 4 || f[0] != pwAlgo {
		return false
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1000 || iter > 5000000 {
		return false
	}
	salt, err := hex.DecodeString(f[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(f[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got := pbkdf2SHA256([]byte(plain), salt, iter, len(want))
	return hmac.Equal(got, want)
}

// pbkdf2SHA256 是 PBKDF2-HMAC-SHA256（RFC 8018）。标准库没有，为了不引
// golang.org/x/crypto（网关一直是零依赖），这里手写一份，二十来行。
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	if iter < 1 {
		iter = 1
	}
	hLen := sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	var idx [4]byte

	for b := 1; b <= blocks; b++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		binary.BigEndian.PutUint32(idx[:], uint32(b))
		mac.Write(idx[:])
		u := mac.Sum(nil)

		t := make([]byte, hLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// passTag 是密码哈希的短指纹，混进登录 Cookie 的签名。
// 改密码 → 指纹变 → 所有旧 Cookie 校验失败。
func passTag(stored string) string {
	sum := sha256.Sum256([]byte(stored))
	return hex.EncodeToString(sum[:])[:16]
}

// setPassword 更新内存里的哈希，并原子写盘（先写临时文件再 rename，
// 避免断电/被杀时留下一个半截文件，下次启动直接进不去）。
func (g *Gateway) setPassword(plain string) error {
	stored, err := hashPassword(plain)
	if err != nil {
		return err
	}
	if err := writeSecret(g.cfg.PassFile, stored); err != nil {
		return err
	}
	g.passMu.Lock()
	g.passHash = stored
	g.passTag = passTag(stored)
	g.passMu.Unlock()
	return nil
}

func (g *Gateway) verifyPassword(plain string) bool {
	g.passMu.RLock()
	stored := g.passHash
	g.passMu.RUnlock()
	if stored == "" {
		return false
	}
	return verifyHash(plain, stored)
}

// loadPassword 在启动时调用一次。
// 文件存在就以它为准；不存在才用配置里的明文初始化，并立刻落盘——
// 之后就再也不用管配置里那个字段了。
func (g *Gateway) loadPassword() error {
	b, err := os.ReadFile(g.cfg.PassFile)
	if err == nil {
		stored := strings.TrimSpace(string(b))
		if !strings.HasPrefix(stored, pwAlgo+"$") || len(strings.Split(stored, "$")) != 4 {
			return fmt.Errorf("密码文件 %s 格式不对（应为 %s$迭代$盐$哈希）", g.cfg.PassFile, pwAlgo)
		}
		g.passMu.Lock()
		g.passHash = stored
		g.passTag = passTag(stored)
		g.passMu.Unlock()
		log.Printf("密码：取自 %s", g.cfg.PassFile)
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("读密码文件失败：%w", err)
	}

	if g.cfg.Password == "" {
		return fmt.Errorf("没有密码文件，配置里也没写 password，无法登录")
	}
	if err := g.setPassword(g.cfg.Password); err != nil {
		return fmt.Errorf("初始化密码文件失败：%w", err)
	}
	log.Printf("密码：用配置里的 password 初始化，已写入 %s", g.cfg.PassFile)
	return nil
}

// writeSecret 原子写一个只有属主能读的文件。
func writeSecret(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".passwd-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // rename 成功后这里就是空操作

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content + "\n"); err != nil {
		tmp.Close()
		return err
	}
	// 先落盘再 rename，断电后不会出现「文件在但内容是空的」
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ---------------------------------------------------------------- 改密码页面

func (g *Gateway) showPasswd(w http.ResponseWriter, errMsg string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != 0 {
		w.WriteHeader(status)
	}
	var b strings.Builder
	b.WriteString(`<form method="post" action="/__passwd"><h1>修改密码</h1>`)
	b.WriteString(`<p class="sub">账号 ` + html.EscapeString(g.cfg.User) + ` · 改完要重新登录</p>`)
	if errMsg != "" {
		b.WriteString(`<p class="err">` + html.EscapeString(errMsg) + `</p>`)
	}
	b.WriteString(`<input name="old" type="password" placeholder="当前密码" autocomplete="current-password">`)
	b.WriteString(`<input name="n1" type="password" placeholder="新密码（至少 8 位）" autocomplete="new-password">`)
	b.WriteString(`<input name="n2" type="password" placeholder="再输一次新密码" autocomplete="new-password">`)
	b.WriteString(`<button type="submit">保存</button>`)
	b.WriteString(`<p class="foot"><a href="/">返回门户</a></p></form>`)
	io.WriteString(w, pageTpl("修改密码", b.String()))
}

func (g *Gateway) handlePasswd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		g.showPasswd(w, "", 0)
		return
	}
	if err := r.ParseForm(); err != nil {
		g.showPasswd(w, "请求格式不对", http.StatusBadRequest)
		return
	}
	old := r.PostFormValue("old")
	n1 := r.PostFormValue("n1")
	n2 := r.PostFormValue("n2")

	if !g.verifyPassword(old) {
		log.Printf("改密码失败（旧密码不对）：来自 %s", r.RemoteAddr)
		time.Sleep(800 * time.Millisecond)
		g.showPasswd(w, "当前密码不对", http.StatusUnauthorized)
		return
	}
	if len([]rune(n1)) < pwMinLen {
		g.showPasswd(w, fmt.Sprintf("新密码至少 %d 位", pwMinLen), http.StatusBadRequest)
		return
	}
	if len(n1) > 128 {
		g.showPasswd(w, "新密码太长了（上限 128 字符）", http.StatusBadRequest)
		return
	}
	if n1 != n2 {
		g.showPasswd(w, "两次输入的新密码不一样", http.StatusBadRequest)
		return
	}
	if n1 == old {
		g.showPasswd(w, "新密码和旧密码一样，没改成", http.StatusBadRequest)
		return
	}
	if err := g.setPassword(n1); err != nil {
		log.Printf("写密码文件失败：%v", err)
		g.showPasswd(w, "保存失败："+err.Error(), http.StatusInternalServerError)
		return
	}

	// 密码一变，签名指纹跟着变，所有设备上的旧 Cookie 立刻失效
	g.clearLoginCookie(w, r)
	log.Printf("密码已修改：来自 %s", r.RemoteAddr)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, pageTpl("密码已修改",
		`<h1>密码已修改</h1><p class="sub">所有设备上的登录状态都已失效，请用新密码重新登录。</p>`+
			`<a class="card" href="/__login"><div class="row"><div class="ico">→</div><div>`+
			`<div class="nm">去登录</div><div class="nt">账号 `+html.EscapeString(g.cfg.User)+`</div>`+
			`</div></div></a>`))
}
