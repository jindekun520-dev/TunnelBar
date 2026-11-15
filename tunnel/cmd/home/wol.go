// home 端的 WOL 接口：把「发一个魔术包」这件事暴露给隧道另一端。
//
// 为什么由 home 来发：魔术包是链路层广播，只有和目标处在同一广播域的
// 机器发出去才有效。home 就装在家里那台机器上，位置正好；公网服务器
// （relay/gateway）发出来的包跨不过 NAT，也进不了那个广播域。
//
// 只监听回环有个讲究：远端经隧道访问时，是 home 自己去 dial 目标地址，
// 所以 gateway 把目标写成 127.0.0.1:9912，落到 home 上就是它的回环。
// 好处是同一 LAN 里的其他机器**根本连不上**这个接口，不需要额外 ACL。
package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tunnel/internal"
)

// wolRequest 是 /wake 的入参。mac 允许逗号分隔多个（一台机器双网卡、
// 或者一次点醒一串设备），逐个发。
type wolRequest struct {
	MAC       string   `json:"mac"`
	Port      int      `json:"port"`
	Broadcast []string `json:"broadcast"`
}

type wolResponse struct {
	OK        bool     `json:"ok"`
	MAC       []string `json:"mac,omitempty"`
	Port      int      `json:"port,omitempty"`
	Sent      int      `json:"sent"`
	Broadcast []string `json:"broadcast,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// serveWOL 起一个只做唤醒的极小 HTTP 服务。
func serveWOL(addr, token string, defaultPort int) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})

	mux.HandleFunc("/wake", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, wolResponse{Error: "只支持 GET / POST"})
			return
		}
		if token != "" && !wolTokenOK(r, token) {
			log.Printf("[home] WOL 请求被拒：令牌不匹配（来自 %s）", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, wolResponse{Error: "令牌不对"})
			return
		}

		req := wolRequest{}
		if r.Method == http.MethodPost && r.Body != nil {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			if len(strings.TrimSpace(string(body))) > 0 {
				// 也接受纯文本 body：把 MAC 直接贴在请求体里（curl 用起来最省事）
				if json.Unmarshal(body, &req) != nil {
					req.MAC = strings.TrimSpace(string(body))
				}
			}
		}
		if v := r.URL.Query().Get("mac"); v != "" {
			req.MAC = v
		}
		if v := r.URL.Query().Get("port"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				req.Port = n
			}
		}
		if v := r.URL.Query().Get("broadcast"); v != "" {
			for _, s := range strings.Split(v, ",") {
				if s = strings.TrimSpace(s); s != "" {
					req.Broadcast = append(req.Broadcast, s)
				}
			}
		}
		if strings.TrimSpace(req.MAC) == "" {
			writeJSON(w, http.StatusBadRequest, wolResponse{Error: "缺 mac 参数"})
			return
		}

		port := req.Port
		if port <= 0 {
			port = defaultPort
		}
		if port <= 0 {
			port = internal.DefaultWOLPort
		}

		resp := wolResponse{Port: port}
		var lastErr error
		for _, raw := range strings.Split(req.MAC, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			mac, err := internal.ParseMAC(raw)
			if err != nil {
				lastErr = err
				continue
			}
			sent, used, err := internal.Wake(mac, req.Broadcast, port)
			if err != nil {
				lastErr = err
				log.Printf("[home] 唤醒 %s 失败：%v", mac, err)
				continue
			}
			resp.MAC = append(resp.MAC, mac.String())
			resp.Sent += sent
			for _, u := range used {
				resp.Broadcast = appendUnique(resp.Broadcast, u)
			}
			log.Printf("[home] 已发送唤醒包 → %s，%d 个广播地址 %s:%d",
				mac, sent, strings.Join(used, ","), port)
		}

		if len(resp.MAC) == 0 {
			msg := "没有可发送的目标"
			if lastErr != nil {
				msg = lastErr.Error()
			}
			resp.Error = msg
			writeJSON(w, http.StatusBadRequest, resp)
			return
		}
		resp.OK = true
		writeJSON(w, http.StatusOK, resp)
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[home] WOL 接口监听 %s 失败：%v（唤醒功能不可用）", addr, err)
		return
	}
	host, _, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsLoopback() && token == "" {
		log.Printf("[home] 注意：WOL 接口监听在 %s 且没有令牌，局域网内任何人都能唤醒设备", addr)
	}
	log.Printf("[home] WOL 接口就绪 %s（令牌校验=%v，默认端口 %d）", addr, token != "", defaultPort)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if err := srv.Serve(ln); err != nil {
		log.Printf("[home] WOL 接口退出：%v", err)
	}
}

// wolTokenOK 接受两种常见写法，方便 curl 和网关各用各的。
func wolTokenOK(r *http.Request, token string) bool {
	if v := r.Header.Get("X-Wol-Token"); v != "" {
		return v == token
	}
	auth := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
		return strings.TrimSpace(after) == token
	}
	return r.URL.Query().Get("token") == token
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func appendUnique(list []string, v string) []string {
	for _, s := range list {
		if s == v {
			return list
		}
	}
	return append(list, v)
}
