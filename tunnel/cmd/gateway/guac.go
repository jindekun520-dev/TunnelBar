// Guacamole 免二次登录。
//
// Guacamole 是独立应用，有自己的账号体系和登录页，所以从网关点进去还要再输一次
// 密码。这里的做法是：网关把 Guacamole 首页抓下来，往 <head> 最前面注入一小段
// 脚本，由脚本向网关取凭据、自动填表并提交。用户只需要过网关那道门。
//
// 为什么不是「注入 token」：试过，走不通。Guacamole 1.6 前端把登录态放在内存对象
// 里（p），localStorage 里那个 GUAC_AUTH_TOKEN 只是裸 token 字符串，页面刷新后
// 没有接口能把裸 token 换回登录态（GET /api/tokens/{token} 在 1.6 上返回 405），
// 所以塞 token 进去后前端仍然停/弹登录页。而「自动提交登录表单」走的是它自己的
// 登录流程，版本无关，密码错了也只是提示错误，不会把页面搞坏。
//
// 凭据没有写进 HTML：页面里只有逻辑，密码通过 /__guaccred 现取（要已登录的
// Cookie 才给），避免源码/截图里出现明文密码。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// GuacSSO 是一段可选配置：填了就由网关代填登录表单。
type GuacSSO struct {
	// 门户上的路径前缀，要和 paths 里的键一致，比如 "/guacamole/"
	Path string `json:"path"`
	// Guacamole 本机地址。留空则取 paths[path] 对应的那个 target。
	Target string `json:"target"`
	// Guacamole 自己的账号密码（user-mapping.xml 里那对）。
	User     string `json:"user"`
	Password string `json:"password"`
}

// handleGuacCred 把 Guacamole 的账号密码交给自动登录脚本。
// 只在已经通过网关门之后才可能被调用——凭据不比门户本身更敏感。
func (g *Gateway) handleGuacCred(w http.ResponseWriter, r *http.Request) {
	cfg := g.cfg.Guac
	if cfg == nil || cfg.User == "" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	_ = json.NewEncoder(w).Encode(map[string]string{"u": cfg.User, "p": cfg.Password})
}

// guacSSO 处理「进 Guacamole 首页」这一次请求。返回 true 表示已经接管。
func (g *Gateway) guacSSO(w http.ResponseWriter, r *http.Request) bool {
	cfg := g.cfg.Guac
	if cfg == nil || r.Method != http.MethodGet {
		return false
	}
	base := strings.TrimRight(cfg.Path, "/") // "/guacamole"
	p := r.URL.Path
	if p != cfg.Path && p != base && p != base+"/index.html" {
		return false
	}
	// 想用原生登录页（比如换别的账号）：加 ?manual=1
	if r.URL.Query().Get("manual") == "1" {
		return false
	}
	if cfg.Target == "" {
		cfg.Target = g.cfg.Paths[cfg.Path]
	}
	if cfg.Target == "" {
		return false
	}

	page, err := g.guacFrontend(cfg)
	if err != nil {
		// 取不到首页就别硬来，交回给普通反代（用户会看到原生登录页）
		log.Printf("[guac] 取首页失败，走原生登录页：%v", err)
		return false
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 页面里带着自动登录逻辑，绝不能被缓存下来
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	io.WriteString(w, injectGuacLogin(page, base))
	return true
}

// guacFrontend 取 Guacamole 首页 HTML（注入脚本用）。
//
// 走本机直连，显式要 identity 编码：上游若回 gzip，注入就会把压缩流写坏。
func (g *Gateway) guacFrontend(cfg *GuacSSO) ([]byte, error) {
	u := strings.TrimRight(cfg.Target, "/") + strings.TrimRight(cfg.Path, "/") + "/"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("上游返回 " + resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	// 上游给的不是 HTML（比如 302 到别处）就别硬注入
	if !bytes.Contains(bytes.ToLower(body), []byte("<html")) {
		return nil, errors.New("上游响应不是 HTML 页面")
	}
	return body, nil
}

// injectGuacLogin 把自动登录脚本塞进页面 head 最前面。
// 放最前是为了它注册的 DOMContentLoaded 一定先于页面自身脚本。
func injectGuacLogin(page []byte, base string) string {
	snippet := []byte(strings.ReplaceAll(guacAutoLoginJS, "__GUAC_BASE__", base))

	low := bytes.ToLower(page)
	if i := bytes.Index(low, []byte("</head>")); i >= 0 {
		var b bytes.Buffer
		b.Grow(len(page) + len(snippet))
		b.Write(page[:i])
		b.Write(snippet)
		b.Write(page[i:])
		return b.String()
	}
	// 没有 head 的残页：放最前面也能生效
	return string(snippet) + string(page)
}

// guacAutoLoginJS 是注入到 Guacamole 首页的自动登录脚本。
//
// 两条路都试，哪条成算哪条：
//  1. 直接调 Angular 登录 controller 的 scope（enteredValues + login()），最贴近它
//     自己的流程；
//  2. 万一字段名对不上，退回 DOM：填输入框 + 派发 input 事件 + 点提交按钮。
//
// 只在登录页（存在 .login-ui / form.login-form）动作，已登录时静默退出；
// 最多试 12 秒，失败就停手，绝不反复提交（避免把人家的账号刷锁）。
const guacAutoLoginJS = `<script>(function(){
var BASE="__GUAC_BASE__",tries=0,MAX=60,done=false;
function cred(cb){
  try{
    var x=new XMLHttpRequest();
    x.open("GET","/__guaccred",true);
    x.onload=function(){ if(x.status===200){ try{cb(JSON.parse(x.responseText));}catch(e){} } };
    x.send();
  }catch(e){}
}
function visible(el){
  // 老内核里 offsetParent 在 fixed 布局下为 null，别拿它当可见性判断，
  // 只排除 hidden 就够了
  var t=(el.getAttribute("type")||"text").toLowerCase();
  return t!=="hidden";
}
function fire(el,type){
  try{
    el.dispatchEvent(new Event(type,{bubbles:true}));
  }catch(e){
    try{
      var ev=document.createEvent("HTMLEvents");
      ev.initEvent(type,true,true);
      el.dispatchEvent(ev);
    }catch(e2){}
  }
}
function domFill(c){
  var pw=document.querySelector("form.login-form input[type=password], .login-ui input[type=password]");
  if(!pw) return false;
  var inputs=document.querySelectorAll("form.login-form input, .login-ui input"),u=null;
  for(var i=0;i<inputs.length;i++){
    if(inputs[i]===pw) break;
    if(visible(inputs[i]) && inputs[i].type!=="password") u=inputs[i];
  }
  function set(el,v){
    if(!el) return;
    el.value=v;
    fire(el,"input");
    fire(el,"change");
  }
  set(u,c.u); set(pw,c.p);
  return true;
}
// 只派发一次 submit 事件，交给 Angular 的 ng-submit 处理。
// 不要点按钮：点 input[type=submit] 可能同时触发原生提交，导致发两次
// api/tokens——第二次往往带空值，既失败又会计入封禁次数。
function submitForm(){
  var form=document.querySelector("form.login-form");
  if(!form) return false;
  try{
    form.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}));
    return true;
  }catch(e){
    try{
      var ev=document.createEvent("HTMLEvents");
      ev.initEvent("submit",true,true);
      form.dispatchEvent(ev);
      return true;
    }catch(e2){}
  }
  return false;
}
function scopeFill(c){
  if(!window.angular) return false;
  var el=document.querySelector(".login-ui")||document.querySelector("form.login-form");
  if(!el) return false;
  var sc;
  try{ sc=angular.element(el).scope(); }catch(e){ return false; }
  if(!sc||!sc.enteredValues) return false;
  var filled=false;
  try{
    sc.$apply(function(){
      var ev=sc.enteredValues;
      for(var k in ev){
        if(/USER/i.test(k)){ ev[k]=c.u; filled=true; }
        else if(/PASS/i.test(k)){ ev[k]=c.p; filled=true; }
      }
    });
  }catch(e){ return false; }
  return filled;
}
var submitting=false;
function attempt(c){
  if(done||submitting) return;
  // 只有登录页才动手；已经进去了就安静退出
  if(!document.querySelector(".login-ui, form.login-form")) return;
  // 密码框还没出现就别提交：Guacamole 是分阶段登录（先用户名、再密码），
  // 提前提交会发一次空密码，既白失败一次，还会累计暴力破解封禁的次数
  if(!document.querySelector("form.login-form input[type=password]")) return;
  // 两条填值路都走一遍：Angular model 和 DOM 值各管一边，谁生效都算
  var a=scopeFill(c);
  var b=domFill(c);
  if(!a&&!b) return;
  // 填完别立刻提交：等一轮 digest 把值同步进 Angular 模型，
  // 否则可能提交一份空表单（服务端会回 403）
  submitting=true;
  setTimeout(function(){
    submitting=false;
    done=submitForm();
  },350);
}
function start(){
  cred(function(c){
    if(!c||!c.u) return;
    var timer=setInterval(function(){
      if(done||tries++>MAX){ clearInterval(timer); return; }
      attempt(c);
    },200);
    attempt(c);
  });
}
if(document.readyState==="loading"){
  document.addEventListener("DOMContentLoaded",start);
}else{
  start();
}
})();</script>`
