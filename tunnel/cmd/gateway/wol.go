// 网关侧 WOL：门户上那个「唤醒」按钮背后的两件事——
//  1. 把唤醒请求转给真正能发魔术包的那台机器（家里主机的 home 端）；
//  2. 唤醒之后盯着目标端口，等它真的起来再告诉用户「已上线」。
//
// 第 2 点不是装饰：按下按钮到能连上要 30~90 秒（BIOS POST + 系统启动 +
// 服务起来），期间如果页面什么反应都没有，用户只会反复点，怀疑没生效。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"tunnel/internal"
)

// WOLConfig 是网关的唤醒配置。
type WOLConfig struct {
	// Endpoint 是 home 端 WOL 接口的地址，**经 SOCKS 拨号**，所以填的是
	// 从 home 的角度看的地址：默认 127.0.0.1:9912（落到 home 自己的回环）。
	// 如果 home 把接口绑在局域网地址上，也可以填 10.0.0.12:9912。
	Endpoint string `json:"endpoint"`
	// Token 与 home 的 -wol-token 一致；home 没配令牌就留空。
	Token string `json:"token"`
	// Port 是魔术包的 UDP 端口，留空用 9。
	Port int `json:"port"`
	// Broadcast 指定广播地址（如 10.0.0.255）。留空由 home 自动探测各网卡，
	// 这是推荐做法——网关并不知道家里有几块网卡。
	Broadcast []string `json:"broadcast"`
	// WaitSeconds 是门户等待「上线」的最长秒数，默认 90。
	WaitSeconds int `json:"wait_seconds"`
}

// wolDefaults 补齐缺省值，并且容忍 endpoint 写成 http://host:port 的形式。
func (c *WOLConfig) normalize() {
	if c.Endpoint == "" {
		c.Endpoint = "127.0.0.1:9912"
	}
	c.Endpoint = strings.TrimPrefix(strings.TrimPrefix(c.Endpoint, "http://"), "https://")
	c.Endpoint = strings.TrimSuffix(c.Endpoint, "/")
	if c.Port <= 0 {
		c.Port = internal.DefaultWOLPort
	}
	if c.WaitSeconds <= 0 {
		c.WaitSeconds = 90
	}
}

// assetKey / assetByKey 在 assets.go：资产表现在是运行时可变的，
// 查表要过那把读写锁，放在资产那堆逻辑里更不容易被绕过。

// wolClient 返回一个走 SOCKS 的短超时 HTTP 客户端。
func (g *Gateway) wolClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           g.dialer.DialContext,
			ForceAttemptHTTP2:     false,
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConns:          2,
			IdleConnTimeout:       30 * time.Second,
		},
		// 整个请求（含握手）不超过 15s：这是个「按一下就要有回音」的操作，
		// 吊太久不如直接告诉用户隧道可能断了。
		Timeout: 15 * time.Second,
	}
}

type wolReply struct {
	OK        bool     `json:"ok"`
	Sent      int      `json:"sent"`
	Broadcast []string `json:"broadcast,omitempty"`
	Port      int      `json:"port,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// handleWake 收到门户的唤醒请求 → 转给 home → 回执。
func (g *Gateway) handleWake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, wolReply{Error: "只支持 POST"})
		return
	}
	key := r.URL.Query().Get("k")
	if key == "" {
		_ = r.ParseForm()
		key = r.PostFormValue("k")
	}
	a := g.assetByKey(key)
	if a == nil {
		writeJSON(w, http.StatusNotFound, wolReply{Error: "没找到这台资产"})
		return
	}
	if a.MAC == "" {
		writeJSON(w, http.StatusBadRequest, wolReply{Error: "这台资产没有配置 mac"})
		return
	}
	if g.cfg.WOL == nil {
		writeJSON(w, http.StatusServiceUnavailable, wolReply{Error: "网关没有配置 wol 段"})
		return
	}
	mac, err := internal.ParseMAC(a.MAC)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wolReply{Error: err.Error()})
		return
	}

	body, _ := json.Marshal(map[string]any{
		"mac":       mac.String(),
		"port":      g.cfg.WOL.Port,
		"broadcast": g.cfg.WOL.Broadcast,
	})
	url := "http://" + g.cfg.WOL.Endpoint + "/wake"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, wolReply{Error: err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if g.cfg.WOL.Token != "" {
		req.Header.Set("X-Wol-Token", g.cfg.WOL.Token)
	}

	resp, err := g.wolClient().Do(req)
	if err != nil {
		log.Printf("[wol] 唤醒 %s（%s）失败：%v", a.Name, mac, err)
		writeJSON(w, http.StatusBadGateway, wolReply{
			Error: "连不上家里主机的唤醒接口（" + g.cfg.WOL.Endpoint + "）：" + err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	var hr wolReply
	_ = json.Unmarshal(raw, &hr)
	if resp.StatusCode != http.StatusOK || !hr.OK {
		msg := strings.TrimSpace(hr.Error)
		if msg == "" {
			msg = fmt.Sprintf("唤醒接口返回 %d：%s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		log.Printf("[wol] 唤醒 %s（%s）被拒绝：%s", a.Name, mac, msg)
		writeJSON(w, http.StatusBadGateway, wolReply{Error: msg})
		return
	}

	log.Printf("[wol] 已唤醒 %s（%s），%d 个广播地址 %v", a.Name, mac, hr.Sent, hr.Broadcast)
	writeJSON(w, http.StatusOK, wolReply{
		OK:        true,
		Sent:      hr.Sent,
		Broadcast: hr.Broadcast,
		Port:      hr.Port,
	})
}

// handleWOLStatus 探一下这台资产是否已经起来了。门户在唤醒后轮询它。
func (g *Gateway) handleWOLStatus(w http.ResponseWriter, r *http.Request) {
	a := g.assetByKey(r.URL.Query().Get("k"))
	if a == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "没找到这台资产"})
		return
	}
	target := a.Check
	if target == "" {
		target = a.Target
	}
	if target == "" {
		writeJSON(w, http.StatusOK, map[string]any{"up": false, "note": "这台资产没有可探测的地址"})
		return
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	c, err := g.dialer.DialContext(ctx, "tcp", target)
	ms := int(time.Since(start).Milliseconds())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"up": false, "ms": ms, "target": target})
		return
	}
	_ = c.Close()
	writeJSON(w, http.StatusOK, map[string]any{"up": true, "ms": ms, "target": target})
}

// portalWOLJS 是门户的唤醒交互，纯 ES5 + XHR。
//
// 车机和借来的旧电脑上不一定有 fetch / Promise / 箭头函数，之前 Guacamole
// 代登录就栽在这上面，所以这里一律用最老的写法。
const portalWOLJS = `<script>
(function () {
  function xhr(method, url, body, cb) {
    var x = new XMLHttpRequest();
    x.open(method, url, true);
    if (body) { x.setRequestHeader('Content-Type', 'application/json'); }
    x.onreadystatechange = function () {
      if (x.readyState !== 4) return;
      var d = null;
      try { d = JSON.parse(x.responseText); } catch (e) { d = null; }
      cb(x.status, d);
    };
    x.send(body || null);
  }

  function find(el, attr) {
    while (el && el.getAttribute) {
      if (el.getAttribute(attr)) return el;
      el = el.parentNode;
    }
    return null;
  }

  function statusOf(key) {
    var nodes = document.querySelectorAll('.wst');
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].getAttribute('data-k') === key) return nodes[i];
    }
    return null;
  }

  // 等服务端配置的秒数（门户渲染时写在 #wolcfg 上），默认 90
  function maxWait() {
    var el = document.getElementById('wolcfg');
    var n = el ? parseInt(el.getAttribute('data-wait'), 10) : 90;
    return (n > 0 ? n : 90);
  }

  function say(el, text, kind) {
    if (!el) return;
    el.innerHTML = text;
    // 必须带 on 才会显示：.wst 默认 display:none，空着时不该占一行
    el.className = 'wst on' + (kind ? ' ' + kind : '');
  }

  // 唤醒后每 3 秒探一次目标端口，直到上线或超时
  function wait(key, el, left) {
    if (left <= 0) {
      say(el, '还没等到上线。机器可能不支持网络唤醒，或需要更长时间。', 'warn');
      // 选择器必须用 data-wake：按钮上挂的是 data-wake，data-k 在状态行上
      var b = document.querySelector('.wk[data-wake="' + key + '"]');
      if (b) { b.disabled = false; b.innerHTML = '再试一次'; }
      return;
    }
    setTimeout(function () {
      xhr('GET', '/__wolstatus?k=' + encodeURIComponent(key), null, function (code, d) {
        if (code === 200 && d && d.up) {
          say(el, '已上线（' + d.ms + ' ms）——点卡片打开', 'ok');
          var b = document.querySelector('.wk[data-wake="' + key + '"]');
          // 已经开机了，再点一次没意义：置灰并改成「已开机」
          if (b) { b.disabled = true; b.innerHTML = '已开机'; }
          return;
        }
        wait(key, el, left - 3);
      });
    }, 3000);
  }

  document.addEventListener('click', function (ev) {
    var btn = find(ev.target, 'data-wake');
    if (!btn) return;
    if (btn.disabled) return;
    ev.preventDefault();
    var key = btn.getAttribute('data-wake');
    var el = statusOf(key);
    btn.disabled = true;
    btn.innerHTML = '发送中…';
    say(el, '正在发送唤醒包…', '');
    xhr('POST', '/__wake?k=' + encodeURIComponent(key), '{}', function (code, d) {
      if (code !== 200 || !d || !d.ok) {
        btn.disabled = false;
        btn.innerHTML = '唤醒';
        say(el, (d && d.error) ? d.error : ('唤醒失败（HTTP ' + code + '）'), 'bad');
        return;
      }
      btn.innerHTML = '等待开机…';
      var where = (d.broadcast && d.broadcast.length) ? ('（' + d.broadcast.join(' / ') + '）') : '';
      say(el, '唤醒包已发出' + where + ' · 等目标上线…', '');
      wait(key, el, maxWait());
    });
  }, false);
})();
</script>`

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// 门户与接口同源，不需要 CORS；但缓存一定不能留，否则状态会是旧的
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
