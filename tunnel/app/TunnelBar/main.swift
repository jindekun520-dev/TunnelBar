// TunnelBar —— 本地隧道菜单栏管理工具
//
// 职责：
//   - 管理 client 进程的启动/停止/异常自动重启
//   - 从 client 的本地状态接口读取实时统计，展示在菜单里
//   - 通过 SOCKS5 探测真实连通性与延迟
//   - 「本机自测」模式：一键起 relay + home + 本地站点，验证全链路后再去改服务器
//
// 编译：swiftc -O -swift-version 5 main.swift -o TunnelBar
import AppKit
import Foundation
import Security

// MARK: - 路径与配置

enum Paths {
    static let support: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Tunnel", isDirectory: true)
    }()

    static let config = support.appendingPathComponent("config.json")

    static let logs: URL = {
        let lib = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
        return lib.appendingPathComponent("Logs/TunnelBar", isDirectory: true)
    }()

    static let resources = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources")

    /// 临时文件放这儿（askpass 脚本），路径里没有空格
    static let caches: URL = {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("TunnelBar", isDirectory: true)
    }()

    static func ensureDirs() {
        for d in [support, logs] {
            try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        }
    }
}

/// 一条「资源」：菜单里点一下就能直接打开的目标（内网 Web 界面、SSH、文件共享等）。
/// 老模型，只用于迁移到 Asset，新代码不再读它。
struct Resource: Codable {
    var name: String
    /// 打开目标的 URL。支持 https:// / http:// / smb:// / ssh://
    var url: String
    /// 右侧说明文字，一般填内网地址
    var note: String = ""
    /// 是否在菜单里显示（临时隐藏用，不必删）
    var enabled: Bool = true
}

/// 一个资产：内网里一台能直接连的机器或服务。
///
/// 这是原来「资源」+「端口转发」合并后的统一模型——一条资产回答三件事：
/// 去哪（host:port）、用什么连（scheme）、用谁的身份连（user + 钥匙串密码）。
/// 浏览器不认 SOCKS 的场景才需要本地端口，填了 localPort 就自动派生出
/// client 的 `-forward` 规则，不再单独维护一份转发列表。
struct Asset: Codable {
    var id: String = UUID().uuidString
    var name: String
    /// 内网真实地址（不是 127.0.0.1）
    var host: String
    var port: Int
    /// https / http / ssh / smb / rdp / vnc
    var scheme: String
    /// 登录账号（ssh 必填，其余可空）
    var user: String = ""
    /// 本地转发端口；nil = 直连（走 TUN 或 SOCKS）
    var localPort: Int?
    var note: String = ""
    var enabled: Bool = true
    /// 网络唤醒用的 MAC（AA:BB:CC:DD:EE:FF / aa-bb-... / 裸 12 位都认）。
    ///
    /// 这里必须是 Optional，不能用「非可选 + 默认空串」：合成的解码器对
    /// 非可选属性要求 JSON 里**必须有这个键**，老配置文件就会整份解码失败，
    /// Config.load() 会退回默认配置并写盘——用户的资产全没了。
    var mac: String?

    /// 去掉空白后的 MAC；没配就是空串
    var macText: String { (mac ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
    var canWake: Bool { !macText.isEmpty }

    /// 派生成 client 的 -forward 规则；直连资产返回 nil
    var forwardRule: String? {
        guard let lp = localPort else { return nil }
        return "\(lp):\(host):\(port)"
    }

    /// 菜单里显示的地址
    var addr: String { "\(host):\(port)" }
}

/// 资产在菜单里的图标，按协议区分（取不到符号会退化成纯文字，不会留白）
func assetIcon(_ scheme: String) -> String {
    switch scheme.lowercased() {
    case "https", "http": return "globe"
    case "ssh": return "terminal"
    case "smb": return "folder"
    case "rdp", "vnc": return "display"
    default: return "network"
    }
}

/// 各协议的默认端口，迁移和补全时用
func defaultPort(_ scheme: String) -> Int {
    switch scheme.lowercased() {
    case "https": return 443
    case "http": return 80
    case "ssh": return 22
    case "smb": return 445
    case "rdp": return 3389
    case "vnc": return 5900
    default: return 0
    }
}

/// 一条转发规则的附加信息。规则本体仍以 `local:host:port` 存在 `forwards` 里，
/// 因为 client 的 `-forward` 只认这个格式；打开方式、账号这些只跟 App 有关的
/// 元数据放这里，避免动到协议。
struct ForwardMeta: Codable {
    /// 点开时用的协议；nil = 按目标端口自动判断
    var scheme: String?
    /// SSH / RDP 这类需要账号的协议用的用户名
    var user: String?
}

/// 钥匙串读写。只存转发规则对应的登录密码，用通用密码条目。
///
/// 权限说明：App 是 ad-hoc 签名的，每次重签身份都会变，所以系统可能弹一次
/// 「xxx 想要使用钥匙串中的机密信息」，点「始终允许」后同一签名内不再问。
enum Keychain {
    static let service = "TunnelBar"

    static func save(_ secret: String, account: String) {
        let data = Data(secret.utf8)
        // 先删再写，避免 duplicate item
        delete(account: account)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrLabel as String: "TunnelBar 转发密码",
        ]
        SecItemAdd(q as CFDictionary, nil)
    }

    static func load(account: String) -> String? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data,
              let s = String(data: data, encoding: .utf8), !s.isEmpty
        else { return nil }
        return s
    }

    static func delete(account: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(q as CFDictionary)
    }
}

struct Config: Codable {
    var relay: String = "relay.example.com:7100"
    var key: String = ""
    var socksPort: Int = 1080
    var statusPort: Int = 9908
    var pool: Int = 4
    var forwards: [String] = []
    /// 每条转发的附加信息（协议、账号、是否存了密码）：规则串 → ForwardMeta。
    /// 不在表里的规则按目标端口自动判断协议。
    var forwardMeta: [String: ForwardMeta] = [:]
    /// 旧版存法（规则串 → 协议），只用于把老配置迁移到 forwardMeta；
    /// 迁移完会清空，之后保存时恒为空。
    var forwardSchemes: [String: String] = [:]

    /// 一条规则当前生效的协议
    func scheme(of rule: String) -> String {
        if let s = forwardMeta[rule]?.scheme, !s.isEmpty { return s }
        guard let f = parseForward(rule) else { return "http" }
        return guessScheme(remotePort: f.remote)
    }
    /// 已废弃：老的「单独配置一个探测目标」。
    ///
    /// 这个字段要求手工维护一个和资产列表重复的地址，家里机器 DHCP 一换 IP
    /// 就变成永久失败的靶子。现在菜单栏延迟直接取资产探测里最快的那台
    /// （见 `probeAssets`），这里只为读旧配置时能解码，不再参与探测。
    var probe: String = ""
    /// 启动 App 时自动连接（服务端还是 v1 时先关掉，避免一开机就空转重连）
    var autoConnect: Bool = false
    /// 状态项固定在哪个屏幕：main=含 (0,0) 的主屏（默认）、cursor=鼠标所在屏、none=交给系统。
    /// 默认不用 cursor：那样图标会跟着鼠标在多块屏之间来回搬家，反而更难找。
    var pinToScreen: String = "main"
    /// 菜单栏图标旁边的文字。留空则只显示图标；文字能让图标在各种菜单栏背景/隐藏状态下都更容易被找到
    var menuBarTitle: String = "隧道"
    /// 资源清单：菜单「资源」子菜单的内容（老模型，迁移完成后不再使用，保留仅为回滚）
    var resources: [Resource] = Config.seedResources
    /// 资产：合并「资源」与「端口转发」后的统一列表，菜单主入口
    var assets: [Asset] = []
    /// 老配置是否已经转成资产（true 后不再迁移）
    var assetsMigrated: Bool = false
    /// 全局直连（TUN）：把内网网段直接路由进隧道，程序不必再配代理
    var tunEnabled: Bool = false
    /// TUN 接管的路由段
    var tunRoutes: [String] = ["10.0.0.0/24"]
    /// TUN 接口 MTU，隧道再套一层 TCP，留出余量避免二次分片
    var tunMTU: Int = 1400

    // 网络唤醒（Wake-on-LAN）
    /// 魔术包 UDP 端口。9 最常见；少数老网卡只认 7
    var wolPort: Int = 9
    /// 指定广播地址（如 10.0.0.255）。留空 = 按本机每块网卡自动算，推荐留空
    var wolBroadcast: [String] = []
    /// 经隧道让家里主机代发时，home 端 WOL 接口的地址（home 视角，通常是回环）
    var wolEndpoint: String = "127.0.0.1:9912"
    /// 是否同时走隧道。本机不在内网时这是唯一能真正唤醒的路径
    var wolViaTunnel: Bool = true

    // 本机自测模式使用的端口，避开生产端口以免互相干扰
    var labRelayHome: Int = 17000
    var labRelayClient: Int = 17100
    var labSocksPort: Int = 11080
    var labStatusPort: Int = 19908
    var labSitePort: Int = 18080

    init() {}

    /// 首次运行时的资源清单，与本地转发端口一一对应
    static var seedResources: [Resource] {
        [
            Resource(name: "ESXi 宿主机", url: "https://127.0.0.1:18443", note: "10.0.0.10"),
            Resource(name: "NAS 管理", url: "https://127.0.0.1:15667", note: "10.0.0.11"),
            Resource(name: "路由器", url: "https://127.0.0.1:14443", note: "10.0.0.1"),
            Resource(name: "NAS 文件共享", url: "smb://127.0.0.1:10445", note: "10.0.0.11"),
            Resource(name: "Linux 主机", url: "ssh://root@10.0.0.12", note: "10.0.0.12"),
        ]
    }

    // 手写解码：新增字段（如 resources）时，老配置文件缺这个 key 也能正常读，
    // 不会因为一处缺失导致整份配置被重置成默认值。
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Config()
        relay = try c.decodeIfPresent(String.self, forKey: .relay) ?? d.relay
        key = try c.decodeIfPresent(String.self, forKey: .key) ?? d.key
        socksPort = try c.decodeIfPresent(Int.self, forKey: .socksPort) ?? d.socksPort
        statusPort = try c.decodeIfPresent(Int.self, forKey: .statusPort) ?? d.statusPort
        pool = try c.decodeIfPresent(Int.self, forKey: .pool) ?? d.pool
        forwards = try c.decodeIfPresent([String].self, forKey: .forwards) ?? d.forwards
        forwardSchemes = try c.decodeIfPresent([String: String].self, forKey: .forwardSchemes) ?? d.forwardSchemes
        forwardMeta = try c.decodeIfPresent([String: ForwardMeta].self, forKey: .forwardMeta) ?? d.forwardMeta
        // 老配置只有 forwardSchemes：并进 forwardMeta 后清掉，之后只认 forwardMeta
        for (rule, scheme) in forwardSchemes where forwardMeta[rule] == nil {
            forwardMeta[rule] = ForwardMeta(scheme: scheme)
        }
        forwardSchemes = [:]
        probe = try c.decodeIfPresent(String.self, forKey: .probe) ?? d.probe
        autoConnect = try c.decodeIfPresent(Bool.self, forKey: .autoConnect) ?? d.autoConnect
        pinToScreen = try c.decodeIfPresent(String.self, forKey: .pinToScreen) ?? d.pinToScreen
        menuBarTitle = try c.decodeIfPresent(String.self, forKey: .menuBarTitle) ?? d.menuBarTitle
        resources = try c.decodeIfPresent([Resource].self, forKey: .resources) ?? d.resources
        assets = try c.decodeIfPresent([Asset].self, forKey: .assets) ?? d.assets
        assetsMigrated = try c.decodeIfPresent(Bool.self, forKey: .assetsMigrated) ?? d.assetsMigrated
        tunEnabled = try c.decodeIfPresent(Bool.self, forKey: .tunEnabled) ?? d.tunEnabled
        tunRoutes = try c.decodeIfPresent([String].self, forKey: .tunRoutes) ?? d.tunRoutes
        tunMTU = try c.decodeIfPresent(Int.self, forKey: .tunMTU) ?? d.tunMTU
        wolPort = try c.decodeIfPresent(Int.self, forKey: .wolPort) ?? d.wolPort
        wolBroadcast = try c.decodeIfPresent([String].self, forKey: .wolBroadcast) ?? d.wolBroadcast
        wolEndpoint = try c.decodeIfPresent(String.self, forKey: .wolEndpoint) ?? d.wolEndpoint
        wolViaTunnel = try c.decodeIfPresent(Bool.self, forKey: .wolViaTunnel) ?? d.wolViaTunnel
        labRelayHome = try c.decodeIfPresent(Int.self, forKey: .labRelayHome) ?? d.labRelayHome
        labRelayClient = try c.decodeIfPresent(Int.self, forKey: .labRelayClient) ?? d.labRelayClient
        labSocksPort = try c.decodeIfPresent(Int.self, forKey: .labSocksPort) ?? d.labSocksPort
        labStatusPort = try c.decodeIfPresent(Int.self, forKey: .labStatusPort) ?? d.labStatusPort
        labSitePort = try c.decodeIfPresent(Int.self, forKey: .labSitePort) ?? d.labSitePort
    }

    static func load() -> Config {
        guard var cfg = try? JSONDecoder().decode(Config.self, from: Data(contentsOf: Paths.config))
        else {
            let cfg = Config()
            cfg.save()
            return cfg
        }
        if !cfg.assetsMigrated {
            cfg.migrateToAssets()
            cfg.save()
        }
        return cfg
    }

    /// 实际传给 client 的 `-forward`：资产派生 + 手工临时规则。
    /// 迁移后 `forwards` 是空的，只有用户另外手工加的临时转发才会出现在后半段。
    var effectiveForwards: [String] {
        var out: [String] = []
        for a in assets where a.enabled {
            if let rule = a.forwardRule, !out.contains(rule) { out.append(rule) }
        }
        for rule in forwards where !out.contains(rule) { out.append(rule) }
        return out
    }

    /// 把老的 `resources` + `forwards` 合并成 `assets`。幂等，只在第一次跑。
    ///
    /// 配对规则：URL 指向 127.0.0.1:端口 的资源，按这个端口去 forwards 里反查
    /// 真实内网目标，于是"资源 + 转发"合成一条资产；没被任何资源认领的转发
    /// 也单独变成一条资产，一条都不丢。
    mutating func migrateToAssets() {
        guard !assetsMigrated else { return }

        // 动结构前留一份原样配置，出问题能直接换回来
        if let data = try? Data(contentsOf: Paths.config) {
            let stamp = ISO8601DateFormatter().string(from: Date())
                .replacingOccurrences(of: ":", with: "")
            try? data.write(to: Paths.support.appendingPathComponent("config.before-assets-\(stamp).json"))
        }

        var made: [Asset] = []
        var claimed = Set<Int>()

        // 1) 资源 → 资产
        for r in resources {
            guard let u = URL(string: r.url),
                  let scheme = u.scheme?.lowercased(), !scheme.isEmpty else { continue }
            var host = u.host ?? ""
            var port = u.port ?? defaultPort(scheme)
            var localPort: Int?
            if host == "127.0.0.1" || host == "localhost" {
                if let lp = u.port,
                   let i = forwards.firstIndex(where: { parseForward($0)?.local == lp }),
                   let f = parseForward(forwards[i]) {
                    host = f.host
                    port = f.remote
                    localPort = lp
                    claimed.insert(i)
                }
            }
            guard !host.isEmpty else { continue }
            made.append(Asset(
                name: r.name.isEmpty ? "\(host):\(port)" : r.name,
                host: host, port: port, scheme: scheme,
                user: u.user ?? "", localPort: localPort,
                note: r.note, enabled: r.enabled
            ))
        }

        // 2) 剩下的转发也变成资产
        for (i, rule) in forwards.enumerated() where !claimed.contains(i) {
            guard let f = parseForward(rule) else { continue }
            let meta = forwardMeta[rule]
            made.append(Asset(
                name: "\(f.host):\(f.remote)",
                host: f.host, port: f.remote,
                scheme: meta?.scheme ?? guessScheme(remotePort: f.remote),
                user: meta?.user ?? "", localPort: f.local
            ))
        }

        assets = made
        assetsMigrated = true
        // 旧字段清空，免得两处都能改；原始配置已另存为 config.before-assets-*.json
        resources = []
        forwards = []
        forwardMeta = [:]
    }

    func save() {
        Paths.ensureDirs()
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? enc.encode(self) {
            try? data.write(to: Paths.config)
        }
    }
}

// MARK: - 转发与资源工具

/// 解析一条转发规则 "本地端口:目标主机:目标端口"
func parseForward(_ s: String) -> (local: Int, host: String, remote: Int)? {
    let p = s.split(separator: ":")
    guard p.count == 3,
          let lp = Int(p[0]), let rp = Int(p[2]),
          (1...65535).contains(lp), (1...65535).contains(rp),
          !p[1].isEmpty
    else { return nil }
    return (lp, String(p[1]), rp)
}

/// 从资源 URL 里取本地转发端口：https://127.0.0.1:18443/x → 18443
func localForwardPort(of urlString: String) -> Int? {
    guard let u = URL(string: urlString), let port = u.port else { return nil }
    let h = u.host ?? ""
    guard h == "127.0.0.1" || h == "localhost" else { return nil }
    return port
}

/// 目标端口 → 适合用什么协议打开
func guessScheme(remotePort: Int) -> String {
    switch remotePort {
    case 443, 8443, 4443: return "https"
    case 445: return "smb"
    case 22: return "ssh"
    default: return "http"
    }
}

/// 编辑弹窗里可选的打开方式。nil 表示「自动」，即按目标端口猜。
let forwardSchemeChoices: [String?] = [nil, "https", "http", "ssh", "smb"]

func forwardSchemeTitle(_ scheme: String?) -> String {
    guard let s = scheme else { return "自动（按目标端口判断）" }
    return s
}

/// 把 URL 里指向 127.0.0.1 的旧转发端口换成新端口（资源清单跟随转发规则用）。
/// 必须连主机一起判断：只比端口的话，`https://10.0.0.10:443` 这种直连地址会被误改。
func replacingLocalPort(_ urlString: String, from old: Int, to new: Int) -> String {
    guard localForwardPort(of: urlString) == old,
          var c = URLComponents(string: urlString) else { return urlString }
    c.port = new
    return c.url?.absoluteString ?? urlString
}

/// 单引号包裹一个 shell 参数。用户名/主机一般很干净，但 host 万一带特殊字符
/// 也不能把命令拆坏。
func shellQuote(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// 把命令安全地塞进 AppleScript 的双引号字符串里
func appleScriptEscape(_ s: String) -> String {
    s.replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
}

/// 写一个「只回答密码」的 askpass 脚本，权限 0700。
///
/// 为什么用文件：ssh 在终端里有 tty 时不会调 askpass，除非 `SSH_ASKPASS_REQUIRE=force`；
/// 而 askpass 必须是可执行程序，没法把密码直接递进去。脚本内容只有密码的 base64，
/// 会话结束由命令里的 `rm -f` 删掉，存活期就是这一次连接。
/// 真不想让密码落盘的话，就不填密码、手动输一次，或者改用公钥登录。
func writeAskpass(_ password: String) -> URL? {
    let dir = Paths.caches.appendingPathComponent("askpass", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let f = dir.appendingPathComponent("askpass-\(UUID().uuidString).sh")
    let b64 = Data(password.utf8).base64EncodedString()
    let body = "#!/bin/sh\nprintf '%s' '\(b64)' | /usr/bin/base64 -D\n"
    do {
        try body.write(to: f, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: f.path)
        return f
    } catch {
        return nil
    }
}

/// 在 Terminal 里开一个 SSH 会话。
///
/// 走本地转发时 host 是 127.0.0.1、端口是本地端口，所以必须写成 `ssh -p 端口 账号@主机`。
/// 不能写成 `ssh 127.0.0.1:2022`——OpenSSH 会把冒号后面整段当成主机名去做 DNS 解析，
/// 结果是 `Could not resolve hostname 127.0.0.1:2022`。
func startSSH(host: String, port: Int, user: String?, password: String?) {
    let target = (user?.isEmpty == false) ? "\(user!)@\(host)" : host
    var ssh = "ssh -p \(port)"
    // 首次连接自动接受主机密钥；之后密钥一变仍会报错，比 StrictHostKeyChecking=no 安全
    ssh += " -o StrictHostKeyChecking=accept-new"
    if password?.isEmpty == false {
        // 密码错时别反复重试，避免把账号锁了
        ssh += " -o NumberOfPasswordPrompts=1"
    }
    ssh += " " + shellQuote(target)

    var script: URL?
    if let pw = password, !pw.isEmpty, let f = writeAskpass(pw) {
        script = f
        ssh = "SSH_ASKPASS=\(shellQuote(f.path)) SSH_ASKPASS_REQUIRE=force " + ssh
    }
    var cmd = ssh
    if let f = script {
        // 用 ; 而不是 &&：Ctrl-C 中断 ssh 时也要把含密码的脚本删掉
        cmd += "; rm -f " + shellQuote(f.path)
    }

    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    p.arguments = ["-e",
                   "tell application \"Terminal\" to do script \"\(appleScriptEscape(cmd))\"\n"
                   + "tell application \"Terminal\" to activate"]
    try? p.run()
}

/// 取一条资产的登录密码。
/// 新条目按 asset.id 存；老版本按转发规则串存，读到就顺手搬到 id 下（只在这一条被
/// 真正用到时才去钥匙串，避免弹一堆授权框）。
func assetPassword(_ a: Asset) -> String? {
    if let pw = Keychain.load(account: a.id) { return pw }
    guard let rule = a.forwardRule, let pw = Keychain.load(account: rule) else { return nil }
    Keychain.save(pw, account: a.id)
    Keychain.delete(account: rule)
    return pw
}

/// 打开一个内网入口。ssh:// 交给 Terminal（会换算成 ssh -p），其余走系统默认处理程序。
func openTarget(_ urlString: String) {
    if let u = URL(string: urlString), u.scheme?.lowercased() == "ssh" {
        startSSH(host: u.host ?? "", port: u.port ?? 22, user: u.user, password: nil)
        return
    }
    guard let u = URL(string: urlString) else { return }
    NSWorkspace.shared.open(u)
}

// MARK: - RDP / VNC

/// Windows App（原 Microsoft Remote Desktop）的 bundle id。
let rdpBundleIDs = ["com.microsoft.rdc.macos", "com.microsoft.rdc.mac"]

/// 找到能处理 .rdp 的客户端；没装返回 nil。
func rdpClientApp() -> URL? {
    for id in rdpBundleIDs {
        if let u = NSWorkspace.shared.urlForApplication(withBundleIdentifier: id) { return u }
    }
    return nil
}

/// 用 RDP 客户端连一台机器。
///
/// 为什么不用 `rdp://host:port`：Windows App 只接受**旧版 RDP URI**语法
/// （`rdp://full%20address=s:host:port&username=s:...`），裸的 `rdp://host:port`
/// 会被它直接判成「URL 无效。请通知你的网络管理员」。而旧版语法里 `%20` 与 `&`
/// 的转义在不同客户端版本上行为不一，不如直接写一个 .rdp 文件——这是微软自己
/// 文档给的自动化方式，参数也更全（分辨率、多屏、剪贴板方向）。
///
/// 返回错误说明，成功返回 nil。
func startRDP(host: String, port: Int, user: String, assetID: String) -> String? {
    guard rdpClientApp() != nil else {
        return "没找到 RDP 客户端。请先安装「Windows App」（App Store 免费），再点一次。"
    }
    let dir = Paths.caches.appendingPathComponent("rdp", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    // 一个资产固定一个文件名，避免反复点产生一堆重复的「已保存设备」
    let safe = assetID.replacingOccurrences(of: "/", with: "-")
    let file = dir.appendingPathComponent("\(safe).rdp")

    var lines: [String] = [
        "full address:s:\(host):\(port)",
        "prompt for credentials:i:0",   // 凭据只问一次，不每轮重问
        "authentication level:i:2",     // 服务端证书不受信时提示，而不是直接连
        "screen mode id:i:2",           // 全屏
        "use multimon:i:0",
        "redirectclipboard:i:1",
        "audiomode:i:0",
        "autoreconnection enabled:i:1",
        "",
    ]
    // 账号写进文件，客户端打开时用户名已填好，只剩密码
    if !user.isEmpty {
        lines.insert("username:s:\(user)", at: 1)
    }
    // .rdp 是 Windows 风格文本文件，用 CRLF 兼容性最好
    let body = lines.joined(separator: "\r\n")
    do {
        try body.write(to: file, atomically: true, encoding: .utf8)
    } catch {
        return "写 .rdp 文件失败：\(error.localizedDescription)"
    }
    appLog("RDP 会话文件：\(file.path)（\(host):\(port)，账号 \(user.isEmpty ? "未填" : user)）")
    NSWorkspace.shared.open(file)
    return nil
}

// MARK: - client 状态

struct ClientStatus: Decodable {
    let protocolVersion: Int
    let relay: String
    let socks: String
    let ready: Bool
    let poolAlive: Int
    let poolTotal: Int
    let active: Int64
    let opened: UInt64
    let txBytes: UInt64
    let rxBytes: UInt64
    let resets: UInt64
    let stalled: UInt64
    let uptimeSec: Int64
    let pid: Int
    let lastError: String?
    let lastErrorAge: Int64?
    let failCount: UInt64?
    let okCount: UInt64?
    let tun: TunStatus?
    let pool: [PoolConn]?

    /// 单条池连接的运行快照（对应 client /status 里的 pool 数组）
    struct PoolConn: Decodable {
        let i: Int
        let alive: Bool
        let suspect: Bool?
        let suspectS: Int64?
        let ageS: Int64
        let idleMs: Int64
        let rttMs: Double?
        let rttAgeMs: Int64?
        let active: Int64
        let opened: UInt64
        let txBytes: UInt64
        let rxBytes: UInt64
        let resets: UInt64
        let stalled: UInt64
        let err: String?

        enum CodingKeys: String, CodingKey {
            case i, alive, suspect, active, opened, resets, stalled, err
            case suspectS = "suspect_s"
            case ageS = "age_s"
            case idleMs = "idle_ms"
            case rttMs = "rtt_ms"
            case rttAgeMs = "rtt_age_ms"
            case txBytes = "tx_bytes"
            case rxBytes = "rx_bytes"
        }
    }

    /// TUN 全局直连模式的运行状态
    struct TunStatus: Decodable {
        let enabled: Bool
        let device: String?
        let mtu: Int?
        let routes: [String]?
        let tcpTotal: Int?
        let udpTotal: Int?
        let tcpActive: Int?
        let udpActive: Int?
        let icmpReplies: Int?
        let outboundDrops: UInt64?
        let error: String?

        enum CodingKeys: String, CodingKey {
            case enabled, device, mtu, routes, error
            case tcpTotal = "tcp_total"
            case udpTotal = "udp_total"
            case tcpActive = "tcp_active"
            case udpActive = "udp_active"
            case icmpReplies = "icmp_replies"
            case outboundDrops = "outbound_drops"
        }
    }

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol"
        case relay, socks, ready, active, opened, resets, stalled, pid
        case poolAlive = "pool_alive"
        case poolTotal = "pool_total"
        case txBytes = "tx_bytes"
        case rxBytes = "rx_bytes"
        case uptimeSec = "uptime_s"
        case lastError = "last_error"
        case lastErrorAge = "last_error_age_s"
        case failCount = "fail_count"
        case okCount = "ok_count"
        case tun
        case pool
    }
}

func fetchStatus(port: Int, timeout: TimeInterval = 1.2) -> ClientStatus? {
    guard let url = URL(string: "http://127.0.0.1:\(port)/status") else { return nil }
    var req = URLRequest(url: url)
    req.timeoutInterval = timeout
    req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData

    let sem = DispatchSemaphore(value: 0)
    var result: ClientStatus?
    URLSession.shared.dataTask(with: req) { data, _, _ in
        if let data, let st = try? JSONDecoder().decode(ClientStatus.self, from: data) {
            result = st
        }
        sem.signal()
    }.resume()
    _ = sem.wait(timeout: .now() + timeout + 0.5)
    return result
}

// MARK: - 网络唤醒（Wake-on-LAN）
//
// 两条路同时走，谁也不挡谁：
//   1. 本机 UDP 广播——人在家里、Mac 就在同一网段时，直接就唤醒了；
//   2. 经隧道让家里主机代发——人在外面时，本机广播只是发到当前网络（
//      多半是酒店 WiFi），只有这条才真正落到家里的广播域。
// 两条都发没有副作用：魔术包是幂等的，重复发不会把机器搞乱。

enum WOL {
    /// 魔术包：6 字节 FF + MAC 重复 16 次，共 102 字节
    static let packetLen = 102

    /// 解析 MAC，写法太杂（设备页面多是裸 12 位、`ip link` 带冒号、
    /// Windows 的 getmac 带横杠），这里全认。
    static func parseMAC(_ s: String) -> [UInt8]? {
        let cleaned = s.filter { $0 != ":" && $0 != "-" && $0 != "." && $0 != " " && $0 != "\t" }
        guard cleaned.count == 12 else { return nil }
        var out: [UInt8] = []
        var idx = cleaned.startIndex
        for _ in 0..<6 {
            let next = cleaned.index(idx, offsetBy: 2)
            guard let b = UInt8(cleaned[idx..<next], radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        if out.allSatisfy({ $0 == 0 }) { return nil }   // 全 0 不是有效目标
        if out[0] & 0x01 != 0 { return nil }           // 组播/广播地址
        return out
    }

    static func macString(_ b: [UInt8]) -> String {
        b.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    static func packet(_ mac: [UInt8]) -> [UInt8] {
        var p = [UInt8](repeating: 0xFF, count: 6)
        for _ in 0..<16 { p.append(contentsOf: mac) }
        return p
    }

    /// 本机各网卡的定向广播地址（10.0.0.1/24 → 10.0.0.255）。
    /// 只发 255.255.255.255 在多网卡（含 VPN、虚拟网卡）的 Mac 上经常从
    /// 错的接口出去，包压根到不了目标网段。
    static func localBroadcasts() -> [String] {
        var out: [String] = []
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return out }
        defer { freeifaddrs(ifap) }

        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cur {
            cur = p.pointee.ifa_next
            let flags = Int32(p.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0, (flags & IFF_BROADCAST) != 0 else { continue }
            guard let sa = p.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            guard let ms = p.pointee.ifa_netmask, ms.pointee.sa_family == UInt8(AF_INET) else { continue }

            let ip = UInt32(bigEndian: sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr })
            let mask = UInt32(bigEndian: ms.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr })
            let b = ip | ~mask
            let str = "\((b >> 24) & 0xff).\((b >> 16) & 0xff).\((b >> 8) & 0xff).\(b & 0xff)"
            if str != "255.255.255.255" && !out.contains(str) { out.append(str) }
        }
        return out
    }

    /// 往每个广播地址各发一个魔术包。多网卡机器上某块网卡发不出去很正常
    /// （例如没插网线的 USB 网卡），只要有一份成功就算成功。
    static func send(_ mac: [UInt8], hosts: [String], port: Int) -> (sent: Int, used: [String], errors: [String]) {
        let pkt = packet(mac)
        var sent = 0
        var used: [String] = []
        var errors: [String] = []
        for host in hosts {
            let fd = socket(AF_INET, SOCK_DGRAM, 0)
            if fd < 0 { errors.append("\(host)：建 socket 失败"); continue }
            var yes: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, socklen_t(MemoryLayout<Int32>.size))

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = in_port_t(UInt16(port).bigEndian)
            addr.sin_addr.s_addr = inet_addr(host)

            let n = pkt.withUnsafeBytes { raw -> Int in
                withUnsafePointer(to: &addr) { ap -> Int in
                    ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(fd, raw.baseAddress, pkt.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            close(fd)
            if n == pkt.count {
                sent += 1
                if !used.contains(host) { used.append(host) }
            } else {
                errors.append("\(host)：sendto 返回 \(n)")
            }
        }
        return (sent, used, errors)
    }

    /// 经隧道请家里主机代发。返回 nil 表示成功，否则是给人看的错误原因。
    static func wakeViaTunnel(endpoint: String, socksPort: Int, mac: [UInt8], port: Int) -> String? {
        let parts = endpoint.split(separator: ":")
        guard parts.count >= 2, let eport = UInt16(parts[1]) else {
            return "接口地址写法不对（应形如 127.0.0.1:9912）"
        }
        guard let fd = socksConnect(socksPort: socksPort, host: String(parts[0]), port: eport, timeout: 8) else {
            return "隧道没通（client 的 SOCKS \(socksPort) 没起来？）"
        }
        defer { close(fd) }

        let body = "{\"mac\":\"\(macString(mac))\",\"port\":\(port)}"
        let req = "POST /wake HTTP/1.1\r\n"
            + "Host: \(endpoint)\r\n"
            + "Content-Type: application/json\r\n"
            + "Content-Length: \(body.utf8.count)\r\n"
            + "Connection: close\r\n\r\n"
            + body
        guard writeAll(fd, Array(req.utf8)) else { return "请求写不出去，隧道可能断了" }

        var got: [UInt8] = []
        var buf = [UInt8](repeating: 0, count: 1024)
        var guard_ = 0
        while got.count < 8192 && guard_ < 16 {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { break }
            got.append(contentsOf: buf[0..<n])
            guard_ += 1
        }
        let text = String(decoding: got, as: UTF8.self)
        guard let first = text.split(separator: "\r\n").first else { return "没有收到应答" }
        if !first.contains(" 200 ") {
            return "家里主机回了 " + first.replacingOccurrences(of: "HTTP/1.1 ", with: "")
                + (text.contains("error") ? "（\(text.suffix(120))）" : "")
        }
        return nil
    }
}

// MARK: - 端口/连通性工具

func isPortOpen(_ port: Int, host: String = "127.0.0.1") -> Bool {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    if fd < 0 { return false }
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = in_port_t(UInt16(port).bigEndian)
    addr.sin_addr.s_addr = inet_addr(host)
    let rc = withUnsafePointer(to: &addr) { p -> Int32 in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    return rc == 0
}

/// 走 SOCKS5 建连到 target，返回耗时（毫秒）；失败返回 nil。
/// 走本机 SOCKS5 建一条到 host:port 的 TCP 连接，返回已连好的 fd（调用方负责 close）。
///
/// 单独抽出来是因为「探测延迟」和「经隧道发唤醒请求」都要这一段握手，
/// 复制两份的话迟早会有一份忘记处理域名长度上限或者应答变长。
func socksConnect(socksPort: Int, host: String, port: UInt16, timeout: TimeInterval = 5) -> Int32? {
    guard let hostBytes = host.data(using: .utf8), hostBytes.count <= 255 else { return nil }

    let fd = socket(AF_INET, SOCK_STREAM, 0)
    if fd < 0 { return nil }

    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = in_port_t(UInt16(socksPort).bigEndian)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")

    var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

    let rc = withUnsafePointer(to: &addr) { p -> Int32 in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard rc == 0 else { close(fd); return nil }

    // 握手：版本 5，1 种方法，无认证
    guard writeAll(fd, [0x05, 0x01, 0x00]) else { close(fd); return nil }
    guard let hello = readExact(fd, 2), hello[0] == 0x05, hello[1] == 0x00 else { close(fd); return nil }

    // CONNECT，域名类型（IP 字面量也能被对端正常解析）
    var req: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8(hostBytes.count)]
    req.append(contentsOf: hostBytes)
    req.append(UInt8(port >> 8))
    req.append(UInt8(port & 0xff))
    guard writeAll(fd, req) else { close(fd); return nil }

    guard let head = readExact(fd, 4), head[0] == 0x05, head[1] == 0x00 else { close(fd); return nil }
    switch head[3] {
    case 0x01:
        guard readExact(fd, 4 + 2) != nil else { close(fd); return nil }
    case 0x04:
        guard readExact(fd, 16 + 2) != nil else { close(fd); return nil }
    case 0x03:
        guard let l = readExact(fd, 1), let first = l.first else { close(fd); return nil }
        guard readExact(fd, Int(first) + 2) != nil else { close(fd); return nil }
    default:
        close(fd); return nil
    }
    return fd
}

func socksProbe(socksPort: Int, target: String, timeout: TimeInterval = 5) -> Double? {
    let parts = target.split(separator: ":")
    guard parts.count == 2, let tport = UInt16(parts[1]) else { return nil }
    let start = Date()
    guard let fd = socksConnect(socksPort: socksPort, host: String(parts[0]), port: tport, timeout: timeout) else {
        return nil
    }
    close(fd)
    return Date().timeIntervalSince(start) * 1000
}

private func writeAll(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
    var off = 0
    while off < bytes.count {
        let n = bytes[off...].withUnsafeBytes { p -> Int in
            write(fd, p.baseAddress, bytes.count - off)
        }
        if n <= 0 { return false }
        off += n
    }
    return true
}

private func readExact(_ fd: Int32, _ n: Int) -> [UInt8]? {
    var buf = [UInt8](repeating: 0, count: n)
    var off = 0
    while off < n {
        let got = buf[off...].withUnsafeMutableBytes { p -> Int in
            read(fd, p.baseAddress, n - off)
        }
        if got <= 0 { return nil }
        off += got
    }
    return buf
}

func humanBytes(_ n: UInt64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var v = Double(n)
    var i = 0
    while v >= 1024, i < units.count - 1 {
        v /= 1024
        i += 1
    }
    if i == 0 { return "\(n) B" }
    return String(format: "%.1f %@", v, units[i])
}

func humanDuration(_ s: Int64) -> String {
    if s < 60 { return "\(s) 秒" }
    if s < 3600 { return "\(s / 60) 分" }
    let h = s / 3600
    let m = (s % 3600) / 60
    return "\(h) 时 \(m) 分"
}

// MARK: - 应用日志

func appLog(_ msg: String) {
    Paths.ensureDirs()
    let url = Paths.logs.appendingPathComponent("app.log")
    let fmt = DateFormatter()
    fmt.dateFormat = "MM-dd HH:mm:ss"
    let line = "[\(fmt.string(from: Date()))] \(msg)\n"
    if let data = line.data(using: .utf8) {
        if let h = try? FileHandle(forWritingTo: url) {
            _ = try? h.seekToEnd()
            _ = try? h.write(contentsOf: data)
            _ = try? h.close()
        } else {
            try? data.write(to: url)
        }
    }
}


/// 有上限地等待子进程退出。
/// 主线程上永远不要用 waitUntilExit()：子进程被外部信号结束、或由 sudo 派生时，
/// 它可能永久不返回，整个菜单栏就一起假死（2026-11-13 实际踩到）。
@discardableResult
func waitExit(_ p: Process, timeout: TimeInterval = 3) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while p.isRunning, Date() < deadline {
        Thread.sleep(forTimeInterval: 0.02)
    }
    if p.isRunning {
        kill(p.processIdentifier, SIGKILL)
        return false
    }
    return true
}

// MARK: - 生命周期辅助

/// 清理上次异常退出遗留的 client（父进程已变成 launchd 的那些）。
/// 否则它会一直占着 SOCKS 端口，导致新实例启动失败。
func reapStaleClients() {
    let exe = Paths.resources.appendingPathComponent("client").path
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/ps")
    p.arguments = ["-Ao", "pid=,ppid=,command="]
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    waitExit(p)

    guard let text = String(data: data, encoding: .utf8) else { return }
    for line in text.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count == 3,
              let pid = pid_t(parts[0]), let ppid = pid_t(parts[1]), ppid == 1,
              parts[2].contains(exe)
        else { continue }
        kill(pid, SIGTERM)
        appLog("清理残留 client 进程 pid=\(pid)")
    }
}

// MARK: - 进程管理

final class Runner {
    struct Spec {
        let name: String
        let exe: String
        let args: [String]
        let log: URL
        /// 是否需要 root 运行（TUN 模式要建虚拟网卡、改路由表）
        var sudo: Bool = false

        init(name: String, exe: String, args: [String], log: URL, sudo: Bool = false) {
            self.name = name
            self.exe = exe
            self.args = args
            self.log = log
            self.sudo = sudo
        }
    }

    private(set) var children: [(name: String, proc: Process)] = []
    private(set) var running = false
    private(set) var mode: String = "off"
    private(set) var lastError: String?

    private let queue = DispatchQueue(label: "tunnel.runner")

    func start(specs: [Spec], mode: String, stagger: TimeInterval) {
        stop()
        running = true
        self.mode = mode
        lastError = nil

        queue.async { [weak self] in
            guard let self else { return }
            Paths.ensureDirs()
            for (i, spec) in specs.enumerated() {
                if i > 0, stagger > 0 {
                    Thread.sleep(forTimeInterval: stagger)
                }
                guard FileManager.default.isExecutableFile(atPath: spec.exe) else {
                    self.lastError = "找不到可执行文件：\(spec.exe)"
                    self.running = false
                    return
                }
                let proc = Process()
                if spec.sudo {
                    // 用 -n：没配好免密规则时立即失败，而不是在后台弹一个看不见的密码框卡住
                    proc.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
                    proc.arguments = ["-n", spec.exe] + spec.args
                } else {
                    proc.executableURL = URL(fileURLWithPath: spec.exe)
                    proc.arguments = spec.args
                }

                var env = ProcessInfo.processInfo.environment
                env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"
                proc.environment = env

                if !FileManager.default.fileExists(atPath: spec.log.path) {
                    FileManager.default.createFile(atPath: spec.log.path, contents: nil)
                }
                rotateIfNeeded(spec.log)
                if let h = try? FileHandle(forWritingTo: spec.log) {
                    _ = try? h.seekToEnd()
                    proc.standardOutput = h
                    proc.standardError = h
                }

                do {
                    try proc.run()
                    self.children.append((spec.name, proc))
                } catch {
                    self.lastError = "启动 \(spec.name) 失败: \(error.localizedDescription)"
                    self.running = false
                    return
                }
            }
        }
    }

    func stop() {
        let list = children
        children = []
        running = false
        mode = "off"
        for (_, p) in list where p.isRunning {
            p.terminationHandler = nil
            p.terminate()
        }
        // 给它们 1.5 秒体面退出，再强制
        let deadline = Date().addingTimeInterval(1.5)
        for (_, p) in list where p.isRunning {
            while p.isRunning, Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if p.isRunning {
                kill(p.processIdentifier, SIGKILL)
            }
        }
        // 等子进程回收，避免僵尸。
        // 绝对不要用 waitUntilExit()：它在 main thread 上可能永久阻塞
        // （子进程已被外部信号/自身逻辑结束、或 sbin/sudo 派生时尤其明显），
        // 一旦卡住，整个菜单栏就没有任何反应，只能强杀 App。
        // 改用有上限的轮询，超时就放手——留个僵尸进程远好过 App 假死。
        let reapDeadline = Date().addingTimeInterval(2.0)
        while Date() < reapDeadline {
            if list.allSatisfy({ !$0.1.isRunning }) {
                break
            }
            Thread.sleep(forTimeInterval: 0.02)
        }
    }

    func onExit(_ handler: @escaping (String) -> Void) {
        for (name, p) in children {
            p.terminationHandler = { _ in handler(name) }
        }
    }

    private func rotateIfNeeded(_ url: URL) {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = attrs[.size] as? Int, size > 5 * 1024 * 1024
        else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

// MARK: - 开机自启

enum LoginItem {
    static let label = "com.jindekun.tunnelbar"

    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static var enabled: Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    static func appExecutablePath() -> String {
        Bundle.main.executableURL?.path ?? CommandLine.arguments[0]
    }

    static func enable() -> String? {
        let exe = appExecutablePath()
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(exe)</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <false/>
            <key>ProcessType</key>
            <string>Interactive</string>
        </dict>
        </plist>
        """
        try? FileManager.default.createDirectory(
            at: plistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        do {
            try plist.write(to: plistURL, atomically: true, encoding: .utf8)
        } catch {
            return "写入 \(plistURL.path) 失败：\(error.localizedDescription)"
        }
        _ = runLaunchctl(["bootout", "gui/\(getuid())/\(label)"])
        let out = runLaunchctl(["bootstrap", "gui/\(getuid())", plistURL.path])
        if let out, !out.isEmpty {
            return "launchctl bootstrap 失败：\(out)\n已写入 \(plistURL.path)，可在「系统设置 → 通用 → 登录项」里手动添加。"
        }
        return nil
    }

    static func disable() {
        _ = runLaunchctl(["bootout", "gui/\(getuid())/\(label)"])
        try? FileManager.default.removeItem(at: plistURL)
    }

    private static func runLaunchctl(_ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        let pipe = Pipe()
        p.standardError = pipe
        p.standardOutput = pipe
        do { try p.run() } catch { return error.localizedDescription }
        waitExit(p)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if p.terminationStatus == 0 { return nil }
        return text.isEmpty ? "退出码 \(p.terminationStatus)" : text
    }
}

// MARK: - 启动参数组装

func clientBinaryPath() -> String {
    Paths.resources.appendingPathComponent("client").path
}

func labBinaryPath(_ name: String) -> String {
    Paths.resources.appendingPathComponent(name).path
}

func makeProductionSpec(_ cfg: Config, tun: Bool) -> Runner.Spec {
    Runner.Spec(
        name: "client",
        // TUN 模式必须以 root 运行，而 sudoers 里配的是无空格包装脚本；
        // 普通模式直接跑 App 内的二进制，不需要任何授权。
        exe: tun ? "/usr/local/bin/tunnelbar-client" : clientBinaryPath(),
        args: [
            "-relay", cfg.relay,
            "-key", cfg.key,
            "-socks", "\(cfg.socksPort)",
            "-status", "127.0.0.1:\(cfg.statusPort)",
            "-pool", "\(cfg.pool)",
            "-forward", cfg.effectiveForwards.joined(separator: ","),
            "-v",
        ] + (tun
             ? ["-tun", "-tun-routes", cfg.tunRoutes.joined(separator: ","), "-tun-mtu", "\(cfg.tunMTU)"]
             : []),
        log: Paths.logs.appendingPathComponent("client.log"),
        sudo: tun
    )
}

func makeLabSpecs(_ cfg: Config) -> [Runner.Spec] {
    let key = cfg.key.isEmpty ? "lab-psk" : cfg.key
    let labLog = Paths.logs.appendingPathComponent("lab.log")
    return [
        .init(name: "relay", exe: labBinaryPath("relay.local"),
              args: ["-home", "\(cfg.labRelayHome)", "-client", "\(cfg.labRelayClient)",
                     "-key", key, "-status", "127.0.0.1:17911"],
              log: labLog),
        .init(name: "home", exe: labBinaryPath("home.local"),
              args: ["-relay", "127.0.0.1:\(cfg.labRelayHome)", "-key", key,
                     "-status", Paths.logs.appendingPathComponent("home.status").path, "-v"],
              log: labLog),
        .init(name: "site", exe: "/usr/bin/python3",
              args: [labBinaryPath("testsrv.py"), "\(cfg.labSitePort)"],
              log: labLog),
        .init(name: "client-lab", exe: clientBinaryPath(),
              args: ["-relay", "127.0.0.1:\(cfg.labRelayClient)", "-key", key,
                     "-socks", "\(cfg.labSocksPort)", "-status", "127.0.0.1:\(cfg.labStatusPort)",
                     "-pool", "2", "-forward", "", "-v"],
              log: Paths.logs.appendingPathComponent("client-lab.log")),
    ]
}

// MARK: - 菜单栏应用

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private let runner = Runner()
    private var cfg = Config.load()
    private var timer: Timer?
    private var status: ClientStatus?
    private var latency: Double?
    private var latencyAt: Date?
    private var restartCount = 0
    private var labMode = false
    private var signalSources: [DispatchSourceSignal] = []
    private var lastAssetSig = ""
    private var lastForwardSig = ""

    // MARK: 资产可达性

    /// 单台资产的探测结果。只在内存里，不写盘——重启就该重新探。
    private enum Reach {
        case probing
        case online(ms: Double)
        case offline
    }

    /// key = asset.id。没有条目 = 还没探过。
    ///
    /// 为什么不再用配置里的 `probe`：那个字段要单独维护一个「和资产列表重复」的地址，
    /// 家里机器 DHCP 一换 IP 就成了永久失败的靶子，还把日志刷满。现在延迟直接从
    /// 这轮探测结果里取最快的在线资产，地址只存在资产列表这一处。
    private var reach: [String: Reach] = [:]
    private var reachAt: Date?
    private var probingAssets = false
    /// 打开面板时强制刷新的最小间隔：连点几次菜单不该发三遍探测
    private let reachFreshWindow: TimeInterval = 5
    /// 后台自动探测周期
    private let reachInterval: TimeInterval = 60

    private static let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    // 菜单项
    private let headerItem = NSMenuItem(title: "未连接", action: nil, keyEquivalent: "")
    private let trafficItem = NSMenuItem(title: "流量 —", action: nil, keyEquivalent: "")
    private let streamItem = NSMenuItem(title: "活跃流 —", action: nil, keyEquivalent: "")
    private let latencyItem = NSMenuItem(title: "延迟 —", action: nil, keyEquivalent: "")
    private let errorItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let toggleItem = NSMenuItem(title: "连接", action: #selector(toggle), keyEquivalent: "")
    private let testItem = NSMenuItem(title: "测试连通性", action: #selector(runTest), keyEquivalent: "t")
    private let labItem = NSMenuItem(title: "启动本机自测", action: #selector(toggleLab), keyEquivalent: "")
    private let logItem = NSMenuItem(title: "打开日志", action: #selector(openLog), keyEquivalent: "l")
    private let configItem = NSMenuItem(title: "打开配置", action: #selector(openConfig), keyEquivalent: ",")
    private let reloadItem = NSMenuItem(title: "重新加载配置", action: #selector(reloadConfig), keyEquivalent: "r")
    private let loginItem = NSMenuItem(title: "开机自启", action: #selector(toggleLogin), keyEquivalent: "")
    private let copySocksItem = NSMenuItem(title: "复制 SOCKS 地址", action: #selector(copySocks), keyEquivalent: "c")
    private let resourcesItem = NSMenuItem(title: "资源", action: nil, keyEquivalent: "")
    private let forwardsItem = NSMenuItem(title: "端口转发", action: nil, keyEquivalent: "")
    private let poolItem = NSMenuItem(title: "连接池", action: nil, keyEquivalent: "")
    /// 「连接池」每行的完整明细，点行即复制（key 与菜单项 tag 对应）
    private var poolDetail: [Int: String] = [:]
    private let tunItem = NSMenuItem(title: "全局直连（TUN）", action: nil, keyEquivalent: "")
    private let tunInfoItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        Paths.ensureDirs()
        reapStaleClients()
        installSignalHandlers()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        buildMenu()
        updateIcon(state: .off)

        if cfg.key.isEmpty {
            alert("首次使用需要配置", "请在「打开配置」里填入预共享密钥（三端必须一致）。")
        }

        timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.tick()
        }
        RunLoop.main.add(timer!, forMode: .common)
        tick()
        appLog("TunnelBar 启动，资源目录=\(Paths.resources.path)")
        for delay in [1.0, 3.0, 8.0] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                self?.logPlacement(String(format: "%.0fs", delay))
                self?.pinStatusItemIfNeeded()
            }
        }

        if cfg.autoConnect {
            // 稍等一拍，让菜单先画出来
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
                self?.startProduction()
            }
        }
    }

    /// pkill / 注销时 App 收到的是 SIGTERM，默认行为会直接终止而不走
    /// applicationWillTerminate，导致子进程变孤儿继续占端口。这里拦下来收尾。
    private func installSignalHandlers() {
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { [weak self] in
                appLog("收到信号 \(sig)，收尾退出")
                self?.runner.stop()
                exit(0)
            }
            src.resume()
            signalSources.append(src)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
        runner.stop()
    }

    // MARK: 菜单构建

    /// 菜单项图标：SF Symbol → 14pt 模板图。
    ///
    /// 和菜单栏图标同一套规则——只用模板图、不设 tint，颜色随浅色/深色菜单自动反转，
    /// 看起来才和系统菜单一致。取不到符号时返回 nil，菜单项退化为纯文字，
    /// 绝不会留一个空白占位。
    private func menuIcon(_ symbol: String, size: CGFloat = 14) -> NSImage? {
        let conf = NSImage.SymbolConfiguration(pointSize: size, weight: .regular)
        guard let base = NSImage(systemSymbolName: symbol, accessibilityDescription: nil),
              let img = base.withSymbolConfiguration(conf) else { return nil }
        img.isTemplate = true
        return img
    }

    /// 开关型菜单项：用「实心勾/空心圈」两个图标表达状态，不再用 state 勾号——
    /// 两者同时存在时 AppKit 会把勾画在图标上，糊成一团。
    private func setToggle(_ item: NSMenuItem, on: Bool,
                           onSymbol: String = "checkmark.circle.fill",
                           offSymbol: String = "circle") {
        item.state = .off
        item.image = menuIcon(on ? onSymbol : offSymbol)
    }

    private func buildMenu() {
        let menu = NSMenu()
        menu.delegate = self
        // 关掉自动启用校验：带 submenu 的父项会被 AppKit 判成"无 action = 不可用"而显示成灰色，
        // 这里改为全部手动控制 isEnabled。
        menu.autoenablesItems = false

        errorItem.target = self
        errorItem.action = #selector(copyLastError)
        for item in [headerItem, trafficItem, streamItem, latencyItem, errorItem] {
            item.isEnabled = false
        }

        // 静态菜单项图标（纯装饰，取不到符号就留空）
        headerItem.image = menuIcon("shield.lefthalf.filled")
        trafficItem.image = menuIcon("arrow.up.arrow.down")
        streamItem.image = menuIcon("point.3.connected.trianglepath.dotted")
        latencyItem.image = menuIcon("stopwatch")
        errorItem.image = menuIcon("exclamationmark.triangle")
        toggleItem.image = menuIcon("power")
        testItem.image = menuIcon("antenna.radiowaves.left.and.right")
        labItem.image = menuIcon("flask")
        logItem.image = menuIcon("doc.text.magnifyingglass")
        configItem.image = menuIcon("slider.horizontal.3")
        copySocksItem.image = menuIcon("doc.on.doc")
        reloadItem.image = menuIcon("arrow.clockwise")
        resourcesItem.image = menuIcon("square.grid.2x2")
        forwardsItem.image = menuIcon("arrow.left.arrow.right")
        poolItem.image = menuIcon("square.stack.3d.up")
        tunInfoItem.image = menuIcon("info.circle")

        toggleItem.target = self
        testItem.target = self
        labItem.target = self
        logItem.target = self
        configItem.target = self
        reloadItem.target = self
        loginItem.target = self
        copySocksItem.target = self
        tunItem.target = self
        tunItem.action = #selector(toggleTun)
        tunInfoItem.isEnabled = false
        tunInfoItem.isHidden = true

        // 顶部：状态与诊断
        menu.addItem(headerItem)
        menu.addItem(errorItem)
        menu.addItem(.separator())

        // 连接控制
        menu.addItem(toggleItem)
        menu.addItem(testItem)
        menu.addItem(.separator())

        // 资源与转发：内容在 menuWillOpen 里动态生成
        resourcesItem.submenu = NSMenu()
        forwardsItem.submenu = NSMenu()
        poolItem.submenu = NSMenu()
        menu.addItem(resourcesItem)
        menu.addItem(forwardsItem)
        menu.addItem(poolItem)
        menu.addItem(.separator())

        // 全局直连（TUN）：勾选即把内网网段直接路由进隧道
        menu.addItem(tunItem)
        menu.addItem(tunInfoItem)
        menu.addItem(.separator())

        // 运行统计
        for item in [trafficItem, streamItem, latencyItem] {
            menu.addItem(item)
        }
        menu.addItem(.separator())

        // 工具
        menu.addItem(labItem)
        menu.addItem(.separator())
        menu.addItem(logItem)
        menu.addItem(configItem)
        menu.addItem(copySocksItem)
        menu.addItem(reloadItem)
        menu.addItem(loginItem)
        menu.addItem(.separator())

        let about = NSMenuItem(title: "关于 TunnelBar", action: #selector(about), keyEquivalent: "")
        about.target = self
        about.image = menuIcon("info.circle")
        menu.addItem(about)

        let quit = NSMenuItem(title: "退出（并断开隧道）", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        quit.image = menuIcon("power.circle")
        menu.addItem(quit)

        statusItem.menu = menu
        rebuildAssetMenu()
        rebuildForwardMenu()
        let n = menu.items.filter { !$0.isSeparatorItem }.count
        appLog("菜单构建完成，共 \(n) 项" + "；状态项长度=\(statusItem.button == nil ? -1 : statusItem.button!.bounds.width)")
    }

    // MARK: 菜单弹出时刷新动态子菜单

    func menuWillOpen(_ menu: NSMenu) {
        guard menu === statusItem.menu else { return }
        rebuildAssetMenu()
        rebuildForwardMenu()
        rebuildPoolMenu()
        refreshTunItem()

        // 打开面板就探一轮：用户看到的必须是新鲜结论，不是几十秒前的。
        // 5 秒内刚探过的不再重复探（连点菜单不该发三遍探测请求）。
        if !labMode, reachAt == nil || Date().timeIntervalSince(reachAt!) >= reachFreshWindow {
            probeAssets(reason: "打开面板")
        }
    }

    /// 「资产」子菜单：一个列表管所有内网入口。
    ///
    /// 这里是原来「资源」和「端口转发」合并后的结果——每条资产自带
    /// 名称 / 地址 / 协议 / 账号，需要本地端口的自动派生出转发规则。
    /// 前缀圆点表示它依赖的本地转发端口当前是否在监听（直连资产没有圆点）。
    private func rebuildAssetMenu() {
        guard let sub = resourcesItem.submenu else { return }
        sub.removeAllItems()
        sub.autoenablesItems = false
        resourcesItem.isEnabled = true

        let list = cfg.assets.filter { $0.enabled }
        resourcesItem.title = list.isEmpty ? "资产（未配置）" : "资产"

        // 顶部两行：这些圆点是什么时候的结论，以及手动刷新入口。
        // 不做这两行的话，用户看到「离线」会以为设备真挂了，其实是半小时前的旧结果。
        if !list.isEmpty {
            let stamp: String
            if !runner.running {
                stamp = "未连接"
            } else if let t = reachAt {
                stamp = "最后探测 " + AppDelegate.clock.string(from: t)
            } else {
                stamp = "正在探测…"
            }
            let head = NSMenuItem(title: "\(stamp) · 每 \(Int(reachInterval)) 秒自动刷新",
                                  action: nil, keyEquivalent: "")
            head.isEnabled = false
            sub.addItem(head)

            let refresh = NSMenuItem(title: "立即刷新状态", action: #selector(refreshAssetReach), keyEquivalent: "")
            refresh.target = self
            refresh.image = menuIcon("arrow.clockwise")
            sub.addItem(refresh)
            sub.addItem(.separator())
        }

        for (idx, a) in list.enumerated() {
            let item = NSMenuItem(title: a.name, action: #selector(openAsset), keyEquivalent: "")
            item.target = self
            item.tag = idx

            // 圆点优先级：本地转发没起来（一定打不开）> 探测结果 > 未知
            var prefix = "  "
            var stateText: String?
            switch reach[a.id] {
            case .some(.probing):
                prefix = "◌ "
                stateText = "探测中…"
            case .some(.online(let ms)):
                prefix = "● "
                stateText = String(format: "%.0f ms", ms)
            case .some(.offline):
                prefix = "○ "
                stateText = "离线"
            case .none:
                break
            }

            var detail: [String] = []
            if let lp = a.localPort {
                if isPortOpen(lp) {
                    detail.append("转发 \(lp)")
                } else {
                    // 转发端口没监听，走本地端口那条路必然失败，状态点也要跟着变
                    prefix = "○ "
                    stateText = "转发未就绪"
                    detail.append("转发 \(lp)")
                }
            }
            if let st = stateText { detail.append(st) }
            detail.append(a.addr)
            if !a.user.isEmpty { detail.append(a.user) }

            let attr = NSMutableAttributedString(
                string: prefix + a.name,
                attributes: [.font: NSFont.menuFont(ofSize: 0)]
            )
            attr.append(NSAttributedString(
                string: "   " + detail.joined(separator: " · "),
                attributes: [
                    .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize),
                    .foregroundColor: NSColor.secondaryLabelColor,
                ]
            ))
            item.attributedTitle = attr
            item.image = menuIcon(assetIcon(a.scheme))
            item.toolTip = a.localPort == nil
                ? "\(a.scheme)://\(a.addr)（直连）"
                : "\(a.scheme)://127.0.0.1:\(a.localPort!)（经本地转发到 \(a.addr)）"
            sub.addItem(item)
        }

        if !list.isEmpty { sub.addItem(.separator()) }

        let add = NSMenuItem(title: "添加资产…", action: #selector(addAsset), keyEquivalent: "")
        add.target = self
        add.image = menuIcon("plus.circle")
        sub.addItem(add)

        if !list.isEmpty {
            let editRoot = NSMenuItem(title: "编辑资产", action: nil, keyEquivalent: "")
            editRoot.image = menuIcon("square.and.pencil")
            let es = NSMenu()
            for (idx, a) in list.enumerated() {
                let it = NSMenuItem(title: a.name, action: #selector(editAsset), keyEquivalent: "")
                it.target = self
                it.tag = idx
                es.addItem(it)
            }
            editRoot.submenu = es
            sub.addItem(editRoot)

            let rmRoot = NSMenuItem(title: "移除资产", action: nil, keyEquivalent: "")
            rmRoot.image = menuIcon("minus.circle")
            let rs = NSMenu()
            for (idx, a) in list.enumerated() {
                let it = NSMenuItem(title: a.name, action: #selector(removeAsset), keyEquivalent: "")
                it.target = self
                it.tag = idx
                rs.addItem(it)
            }
            rmRoot.submenu = rs
            sub.addItem(rmRoot)
        }

        // 只列出配了 MAC 的资产；一台都没配就整块不显示，免得菜单里多一行空的
        let wakeIdxes = list.enumerated().filter { $0.element.canWake }.map { $0.offset }
        if !wakeIdxes.isEmpty {
            let wakeRoot = NSMenuItem(title: "唤醒设备", action: nil, keyEquivalent: "")
            wakeRoot.image = menuIcon("power")
            let ws = NSMenu()
            for idx in wakeIdxes {
                let a = list[idx]
                let it = NSMenuItem(title: a.name, action: #selector(wakeAsset), keyEquivalent: "")
                it.target = self
                it.tag = idx
                it.toolTip = "向 \(a.macText) 广播魔术包（端口 \(cfg.wolPort)）"
                it.image = menuIcon("power")
                ws.addItem(it)
            }
            ws.addItem(.separator())
            let all = NSMenuItem(title: "唤醒全部（\(wakeIdxes.count) 台）", action: #selector(wakeAll), keyEquivalent: "")
            all.target = self
            ws.addItem(all)
            wakeRoot.submenu = ws
            sub.addItem(wakeRoot)
        }

        let openCustom = NSMenuItem(title: "在浏览器打开地址…", action: #selector(openCustomURL), keyEquivalent: "")
        openCustom.target = self
        openCustom.image = menuIcon("link")
        sub.addItem(openCustom)

        let sig = list.map { "\($0.name)[\($0.localPort.map(String.init) ?? "-")]" }.joined(separator: " ")
        if sig != lastAssetSig {
            lastAssetSig = sig
            appLog("资产菜单重建：\(sig.isEmpty ? "（空）" : sig)")
        }
    }

    /// 「端口转发」子菜单：现在只是底层管道视图。
    ///
    /// 规则全部由资产派生，点一条等于打开对应资产的面板；改端口请去「编辑资产」，
    /// 这里不再单独维护一份，避免两处都能改导致对不上。
    /// 底部保留「添加临时转发」，给那种只想临时开个端口、不想建资产的场景。
    private func rebuildForwardMenu() {
        guard let sub = forwardsItem.submenu else { return }
        sub.removeAllItems()
        sub.autoenablesItems = false
        forwardsItem.isEnabled = true

        let rules = cfg.effectiveForwards
        forwardsItem.title = rules.isEmpty ? "端口转发（无）" : "端口转发"

        for (idx, rule) in rules.enumerated() {
            guard let f = parseForward(rule) else {
                let bad = NSMenuItem(title: "⚠ 格式错误：\(rule)", action: nil, keyEquivalent: "")
                bad.isEnabled = false
                bad.image = menuIcon("exclamationmark.triangle")
                sub.addItem(bad)
                continue
            }
            let listening = isPortOpen(f.local)
            let owner = cfg.assets.first { $0.forwardRule == rule }
            let who = owner?.name ?? "临时规则"

            let item = NSMenuItem(
                title: "\(listening ? "●" : "○") \(f.local) → \(f.host):\(f.remote)",
                action: #selector(openForward),
                keyEquivalent: ""
            )
            item.target = self
            item.tag = idx
            let attr = NSMutableAttributedString(
                string: item.title,
                attributes: [.font: NSFont.menuFont(ofSize: 0)]
            )
            attr.append(NSAttributedString(string: "   \(who)", attributes: [
                .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize),
                .foregroundColor: NSColor.secondaryLabelColor,
            ]))
            item.attributedTitle = attr
            item.toolTip = "点击打开「\(who)」"
                + (listening ? "" : "（这个端口没在监听，client 可能没起来）")
            item.image = menuIcon("arrow.left.arrow.right.circle")
            sub.addItem(item)
        }

        sub.addItem(.separator())
        let add = NSMenuItem(title: "添加临时转发…", action: #selector(addForward), keyEquivalent: "")
        add.target = self
        add.image = menuIcon("plus.circle")
        sub.addItem(add)

        if !cfg.forwards.isEmpty {
            let removeRoot = NSMenuItem(title: "移除临时转发", action: nil, keyEquivalent: "")
            removeRoot.image = menuIcon("minus.circle")
            let removeSub = NSMenu()
            for (idx, rule) in cfg.forwards.enumerated() {
                let item = NSMenuItem(title: rule, action: #selector(removeForward), keyEquivalent: "")
                item.target = self
                item.tag = idx
                removeSub.addItem(item)
            }
            removeRoot.submenu = removeSub
            sub.addItem(removeRoot)
        }

        let fsig = rules.joined(separator: " ")
        if fsig != lastForwardSig {
            lastForwardSig = fsig
            appLog("转发菜单重建：\(fsig.isEmpty ? "（空）" : fsig)")
        }
    }

    /// 「连接池」子菜单：逐条列出池里的连接，点一条即复制它的完整明细。
    ///
    /// 这里显示的是**到中继**的往返（心跳 PING 由 relay 直接回 PONG），不是端到端。
    /// 两个数配合着看才能定位问题在哪一跳：
    ///   全都很慢 → 本机网络/热点；
    ///   只有一条慢 → 这条通道拥塞，看看是不是被标成「隔离」；
    ///   到这里都正常、端到端却慢 → relay 与家里那一跳的事。
    private func rebuildPoolMenu() {
        guard let sub = poolItem.submenu else { return }
        sub.removeAllItems()
        sub.autoenablesItems = false
        poolDetail.removeAll()

        // 刻意不在这里同步拉状态：菜单弹出时阻塞主线程（哪怕 200ms）很显眼，
        // 而 tick 每 2 秒刷新一次，对"看拓扑"来说 2 秒内的数据完全够用；
        // 隧道挂了的时候也不会卡——status 为空直接走下面的兜底文案。

        let alive = status?.poolAlive ?? 0
        let total = status?.poolTotal ?? 0
        poolItem.title = total > 0 ? "连接池 \(alive)/\(total)" : "连接池"

        guard let st = status, let pool = st.pool, !pool.isEmpty else {
            let why = status == nil ? "状态接口未响应（看 client 是否在跑）" : "池为空：正在建立首批连接"
            let none = NSMenuItem(title: why, action: nil, keyEquivalent: "")
            none.isEnabled = false
            none.image = menuIcon("hourglass")
            sub.addItem(none)
            appendPoolActions(sub)
            return
        }

        // 汇总行：一眼看出"能不能用、有没有哪条明显慢"
        let rtts = pool.compactMap { $0.rttMs }
        let suspectN = pool.filter { $0.suspect == true && $0.alive }.count
        var parts = ["\(alive)/\(total) 就绪"]
        if let worst = rtts.max() { parts.append(String(format: "最慢 %.0f ms", worst)) }
        if suspectN > 0 { parts.append("\(suspectN) 条隔离中") }
        if let lat = latency { parts.append(String(format: "端到端 %.0f ms", lat)) }
        let head = NSMenuItem(title: parts.joined(separator: " · "), action: nil, keyEquivalent: "")
        head.isEnabled = false
        head.image = menuIcon("gauge.with.dots.needle.67percent")
        sub.addItem(head)
        sub.addItem(.separator())

        for c in pool {
            let item = NSMenuItem(title: poolRowTitle(c), action: #selector(copyPoolRow), keyEquivalent: "")
            item.target = self
            item.tag = c.i
            let detail = poolRowDetail(c)
            item.toolTip = detail + "\n（点击复制）"
            item.image = menuIcon(poolRowSymbol(c), size: 12)
            sub.addItem(item)
            poolDetail[c.i] = detail
        }

        appendPoolActions(sub)

        // 记一行，排障时能回看"当时池里到底几条、谁被隔离"
        let sig = pool.map { c in
            "#\(c.i)\(c.alive ? "" : "死")\(c.suspect == true ? "隔离" : "")"
            + (c.rttMs.map { String(format: " %.0fms", $0) } ?? " —")
        }.joined(separator: " ")
        appLog("池菜单重建：\(parts.joined(separator: " · "))；\(sig)")
    }

    /// 一行说清状态：正常看 RTT 与负载，隔离/断开要说清为什么。
    private func poolRowTitle(_ c: ClientStatus.PoolConn) -> String {
        if !c.alive {
            return "#\(c.i) 已断开 · 等待重建"
        }
        if c.suspect == true {
            return "#\(c.i) 隔离 \(c.suspectS ?? 0)s 内 · 暂不派新流"
        }
        var s = "#\(c.i)"
        if let rtt = c.rttMs {
            s += String(format: " %.0f ms", rtt)
        } else {
            s += " RTT —"
        }
        s += " · 流 \(c.active) · 空闲 " + String(format: "%.1fs", Double(c.idleMs) / 1000)
        return s
    }

    private func poolRowSymbol(_ c: ClientStatus.PoolConn) -> String {
        if !c.alive { return "xmark.circle" }
        if c.suspect == true { return "exclamationmark.circle" }
        return "circle.fill"
    }

    /// 复制到剪贴板/悬浮提示用的多行明细。
    private func poolRowDetail(_ c: ClientStatus.PoolConn) -> String {
        var lines: [String] = []
        lines.append("池连接 #\(c.i) · " + (c.alive ? (c.suspect == true ? "已隔离" : "正常") : "已断开"))
        lines.append("已建立 \(humanDuration(c.ageS)) · 最近收包 \(c.idleMs) ms 前")
        if let rtt = c.rttMs {
            let age = Double(c.rttAgeMs ?? 0) / 1000
            lines.append(String(format: "到中继 RTT %.1f ms（%.0f 秒前测）", rtt, age))
        } else {
            lines.append("到中继 RTT —（尚无心跳回包）")
        }
        lines.append("承载 \(c.active) 条流 · 累计开流 \(c.opened) 条")
        lines.append("收 \(humanBytes(c.rxBytes)) · 发 \(humanBytes(c.txBytes))")
        lines.append("RST \(c.resets) · 卡死重置 \(c.stalled)")
        if let e = c.err, !e.isEmpty { lines.append("断开原因：\(e)") }
        return lines.joined(separator: "\n")
    }

    private func appendPoolActions(_ sub: NSMenu) {
        sub.addItem(.separator())
        let copy = NSMenuItem(title: "复制池诊断", action: #selector(copyPoolDiag), keyEquivalent: "")
        copy.target = self
        copy.image = menuIcon("doc.on.doc")
        sub.addItem(copy)

        let rebuild = NSMenuItem(title: "重建连接池（重启 client）", action: #selector(rebuildPool), keyEquivalent: "")
        rebuild.target = self
        rebuild.image = menuIcon("arrow.triangle.2.circlepath")
        rebuild.isEnabled = runner.running
        sub.addItem(rebuild)
    }

    // MARK: 连接池动作

    @objc private func copyPoolRow(_ sender: NSMenuItem) {
        guard let text = poolDetail[sender.tag] else { return }
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        appLog("复制池连接明细：#\(sender.tag)")
    }

    @objc private func copyPoolDiag() {
        let port = labMode ? cfg.labStatusPort : cfg.statusPort
        var lines: [String] = []
        if let st = status {
            lines.append("TunnelBar 池诊断 · \(Date())")
            lines.append("relay=\(st.relay) ready=\(st.ready) pool=\(st.poolAlive)/\(st.poolTotal) uptime=\(humanDuration(st.uptimeSec))")
            lines.append("ok=\(st.okCount ?? 0) fail=\(st.failCount ?? 0) active=\(st.active) opened=\(st.opened)")
            if let e = st.lastError, !e.isEmpty { lines.append("last_error=\(e)（\(st.lastErrorAge ?? -1)s 前）") }
            lines.append("status_port=\(port)")
            lines.append("")
            for c in st.pool ?? [] { lines.append(poolRowDetail(c)); lines.append("") }
        } else {
            lines.append("TunnelBar 池诊断 · \(Date())\n状态接口 \(port) 无响应：client 未运行或端口被占用")
        }
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(lines.joined(separator: "\n"), forType: .string)
        appLog("复制池诊断（\(lines.count) 行）")
    }

    @objc private func rebuildPool() {
        guard runner.running else { return }
        appLog("按用户请求重建连接池")
        restartClient(reason: "手动重建连接池")
    }

    // MARK: 资产动作

    /// 手动刷新资产状态（菜单里的「立即刷新状态」）。
    ///
    /// 打开面板时也会自动探一轮，这个入口是给「刚从休眠回来、想立刻确认真实状态」用的。
    @objc private func refreshAssetReach() {
        probeAssets(reason: "手动刷新")
    }

    /// 点资产 → 先出一个小面板：连哪、用什么身份、能不能用，再决定打开还是别的。
    @objc private func openAsset(_ sender: NSMenuItem) {
        let list = cfg.assets.filter { $0.enabled }
        guard sender.tag >= 0, sender.tag < list.count else { return }
        assetPanel(list[sender.tag])
    }

    private func assetPanel(_ a: Asset) {
        let alert = NSAlert()
        alert.messageText = a.name

        var lines: [String] = []
        // 状态放第一行：点开一台资产，最想先知道的就是「现在到底通不通」
        switch reach[a.id] {
        case .some(.probing):
            lines.append("状态：探测中…")
        case .some(.online(let ms)):
            lines.append(String(format: "状态：● 在线 %.0f ms", ms))
        case .some(.offline):
            lines.append("状态：○ 离线")
        case .none:
            lines.append(runner.running ? "状态：未探测（打开菜单会自动探一轮）" : "状态：未连接")
        }
        lines.append("\(a.scheme)://\(a.addr)")
        if let lp = a.localPort {
            lines.append("经本地转发 127.0.0.1:\(lp)" + (isPortOpen(lp) ? "（就绪）" : "（未就绪）"))
        } else {
            lines.append("直连，不占用本地端口（走 TUN / SOCKS）")
        }
        lines.append("账号：" + (a.user.isEmpty ? "—" : a.user))
        let hasPass = assetPassword(a) != nil
        lines.append("密码：" + (hasPass ? "已存钥匙串" : "未保存"))
        if !a.note.isEmpty { lines.append(a.note) }
        alert.informativeText = lines.joined(separator: "\n")

        alert.addButton(withTitle: openButtonTitle(a.scheme))
        // 配了 MAC 才插「唤醒」；按钮顺序一变，下标就得跟着算，不能写死 case
        let wakeIdx: Int? = a.canWake ? 1 : nil
        if a.canWake { alert.addButton(withTitle: "唤醒") }
        alert.addButton(withTitle: "编辑…")
        let copyUser = alert.addButton(withTitle: "复制账号")
        let copyPass = alert.addButton(withTitle: "复制密码")
        copyUser.isEnabled = !a.user.isEmpty
        copyPass.isEnabled = hasPass

        let editIdx = a.canWake ? 2 : 1
        // NSAlert 第 4 个按钮以后没有命名常量，只能按 rawValue 判断（1000 起）
        let chosen = Int(alert.runModal().rawValue) - 1000
        switch chosen {
        case 0:
            openAssetNow(a)
        case editIdx:
            editAssetDialog(a)
        case editIdx + 1:
            copyToClipboard(a.user, what: "账号")
        case editIdx + 2:
            if let pw = assetPassword(a) { copyToClipboard(pw, what: "密码") }
        default:
            if let w = wakeIdx, chosen == w { wakeNow(a) }
        }
    }

    /// 菜单「唤醒设备」里的入口（tag 对应 cfg.assets 过滤后的下标）
    @objc private func wakeAsset(_ sender: NSMenuItem) {
        let list = cfg.assets.filter { $0.enabled }
        guard sender.tag >= 0, sender.tag < list.count else { return }
        wakeNow(list[sender.tag])
    }

    /// 一次把配了 MAC 的设备都唤醒（比如开机前把 NAS + Windows 一起叫起来）
    @objc private func wakeAll() {
        let targets = cfg.assets.filter { $0.enabled && $0.canWake }
        guard !targets.isEmpty else { return }
        var lines: [String] = []
        for a in targets {
            guard let macBytes = WOL.parseMAC(a.macText) else {
                lines.append("\(a.name)：MAC 不对（\(a.macText)），跳过")
                continue
            }
            var paths: [String] = []
            let hosts = cfg.wolBroadcast.isEmpty ? WOL.localBroadcasts() : cfg.wolBroadcast
            let local = WOL.send(macBytes, hosts: hosts, port: cfg.wolPort)
            if local.sent > 0 { paths.append("本机 \(local.sent) 包") }
            if cfg.wolViaTunnel {
                if let err = WOL.wakeViaTunnel(endpoint: cfg.wolEndpoint, socksPort: cfg.socksPort,
                                               mac: macBytes, port: cfg.wolPort) {
                    paths.append("隧道失败：\(err)")
                } else {
                    paths.append("隧道已代发")
                }
            }
            lines.append("\(a.name)：" + paths.joined(separator: " / "))
        }
        appLog("唤醒全部：" + lines.joined(separator: "；"))
        alert("唤醒全部（\(targets.count) 台）", lines.joined(separator: "\n") + "\n\n等 30–90 秒再逐个打开。")
    }

    /// 唤醒一台设备：本机广播 + 经隧道代发，两条路都试，最后如实报告结果。
    private func wakeNow(_ a: Asset) {
        guard let macBytes = WOL.parseMAC(a.macText) else {
            alertError("唤醒失败", "「\(a.name)」的 MAC 填得不对：\(a.macText.isEmpty ? "（空）" : a.macText)\n\n"
                      + "应形如 AA:BB:CC:DD:EE:FF，也认 aa-bb-cc-dd-ee-ff 和裸 12 位十六进制。")
            return
        }

        var lines: [String] = []
        var ok = false

        // ① 本机广播：人在家里时这条就够
        let hosts = cfg.wolBroadcast.isEmpty ? WOL.localBroadcasts() : cfg.wolBroadcast
        let local = WOL.send(macBytes, hosts: hosts, port: cfg.wolPort)
        if local.sent > 0 {
            ok = true
            lines.append("本机广播：已发出 \(local.sent) 个包 → " + local.used.joined(separator: "、"))
        } else {
            lines.append("本机广播：没发出去（" + (local.errors.first ?? "找不到可广播的网卡") + "）")
        }

        // ② 经隧道让家里主机代发：人在外面时这条才有效
        if cfg.wolViaTunnel {
            if let err = WOL.wakeViaTunnel(endpoint: cfg.wolEndpoint, socksPort: cfg.socksPort,
                                           mac: macBytes, port: cfg.wolPort) {
                lines.append("经隧道：\(err)")
            } else {
                ok = true
                lines.append("经隧道：家里主机已代发（\(cfg.wolEndpoint)）")
            }
        }

        appLog("唤醒 \(a.name)（\(WOL.macString(macBytes))）：" + lines.joined(separator: "；"))
        alert(ok ? "已发送唤醒包 · \(a.name)" : "唤醒包没发出去 · \(a.name)",
              lines.joined(separator: "\n")
              + "\n\n开机到能连上一般要 30–90 秒。等一会儿再点「\(openButtonTitle(a.scheme))」。")
    }

    private func openButtonTitle(_ scheme: String) -> String {
        switch scheme.lowercased() {
        case "ssh": return "在终端打开"
        case "smb": return "挂载"
        case "rdp", "vnc": return "连接"
        default: return "打开"
        }
    }

    private func copyToClipboard(_ text: String, what: String) {
        guard !text.isEmpty else { return }
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        // 日志里不记内容，只记长度
        appLog("已复制\(what)（\(text.count) 字符）")
    }

    /// 真正去连。SSH 走终端并代填密码，其余交给系统默认客户端。
    private func openAssetNow(_ a: Asset) {
        let host = a.localPort == nil ? a.host : "127.0.0.1"
        let port = a.localPort ?? a.port

        if a.scheme.lowercased() == "ssh" {
            let pw = assetPassword(a)
            appLog("打开资产 \(a.name)：ssh -p \(port) "
                   + (a.user.isEmpty ? host : "\(a.user)@\(host)")
                   + "（目标 \(a.addr)，\(pw == nil ? "手动输密码" : "钥匙串代填")）")
            startSSH(host: host, port: port,
                     user: a.user.isEmpty ? nil : a.user,
                     password: pw)
            return
        }

        if a.scheme.lowercased() == "rdp" {
            appLog("打开资产 \(a.name)：rdp \(host):\(port)（目标 \(a.addr)）")
            if let err = startRDP(host: host, port: port, user: a.user, assetID: a.id) {
                alertError("打不开 RDP", err)
            }
            return
        }

        // VNC 用系统自带「屏幕共享」，vnc://user@host:port 是它认的格式
        if a.scheme.lowercased() == "vnc" {
            let who = a.user.isEmpty ? host : "\(a.user)@\(host)"
            let url = "vnc://\(who):\(port)"
            appLog("打开资产 \(a.name)：\(url) → \(a.addr)")
            openTarget(url)
            return
        }

        let url = "\(a.scheme)://\(host):\(port)"
        appLog("打开资产 \(a.name)：\(url) → \(a.addr)")
        openTarget(url)
    }

    /// 资产弹窗草稿
    private struct AssetDraft {
        var name = ""
        var host = ""
        var port = ""
        var scheme = "https"
        var user = ""
        var localPort = ""
        var note = ""
        var mac = ""
        var password = ""
        var clearPassword = false
        var hasPassword = false
        var error: String?
    }

    private let assetSchemes = ["https", "http", "ssh", "smb", "rdp", "vnc"]

    /// 添加 / 编辑资产共用的弹窗。返回 nil 表示取消。
    private func promptAsset(title: String, okTitle: String, draft: AssetDraft) -> AssetDraft? {
        let alert = NSAlert()
        alert.messageText = title
        var info = "一条资产 = 去哪（主机:端口）+ 用什么连（协议）+ 用谁的身份（账号密码）。"
        info += "\n\n本地转发端口留空就是直连（走 TUN 或 SOCKS，不占本地端口）；"
        info += "只有浏览器这类不认代理的程序才需要填一个本地端口。"
        info += "\n账号和密码只在「协议 = ssh」时用于一键登录，密码存系统钥匙串。"
        info += "\nMAC 可选：填了这台资产就能在菜单里被「网络唤醒」，关机状态也能叫起来。"
        if let e = draft.error { info = "⚠︎ \(e)\n\n" + info }
        alert.informativeText = info
        alert.addButton(withTitle: okTitle)
        alert.addButton(withTitle: "取消")

        let box = NSView(frame: NSRect(x: 0, y: 0, width: 450, height: 196))
        let small = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        func caption(_ s: String, _ x: CGFloat, _ y: CGFloat, _ w: CGFloat) -> NSTextField {
            let f = NSTextField(labelWithString: s)
            f.frame = NSRect(x: x, y: y, width: w, height: 18)
            f.font = small
            return f
        }

        let nameCaption = caption("名称", 0, 170, 48)
        let nameField = NSTextField(frame: NSRect(x: 56, y: 166, width: 394, height: 24))
        nameField.placeholderString = "ESXi 宿主机"
        nameField.stringValue = draft.name

        let hostCaption = caption("地址", 0, 138, 48)
        let hostField = NSTextField(frame: NSRect(x: 56, y: 134, width: 186, height: 24))
        hostField.placeholderString = "10.0.0.10"
        hostField.stringValue = draft.host
        let portField = NSTextField(frame: NSRect(x: 250, y: 134, width: 70, height: 24))
        portField.placeholderString = "443"
        portField.stringValue = draft.port
        let schemePopup = NSPopUpButton(frame: NSRect(x: 330, y: 133, width: 120, height: 26), pullsDown: false)
        schemePopup.addItems(withTitles: assetSchemes)
        schemePopup.selectItem(withTitle: draft.scheme)
        if schemePopup.indexOfSelectedItem < 0 { schemePopup.selectItem(at: 0) }

        let userCaption = caption("账号", 0, 106, 48)
        let userField = NSTextField(frame: NSRect(x: 56, y: 102, width: 150, height: 24))
        userField.placeholderString = "root（ssh 用）"
        userField.stringValue = draft.user
        let passCaption = caption("密码", 214, 106, 40)
        let passField = NSSecureTextField(frame: NSRect(x: 256, y: 102, width: 120, height: 24))
        passField.placeholderString = draft.hasPassword ? "已存（留空不改）" : "可留空"
        passField.stringValue = draft.password
        let clearBox = NSButton(checkboxWithTitle: "清除", target: nil, action: nil)
        clearBox.frame = NSRect(x: 384, y: 103, width: 64, height: 20)
        clearBox.font = small
        clearBox.state = draft.clearPassword ? .on : .off
        clearBox.isEnabled = draft.hasPassword

        let localCaption = caption("本地转发", 0, 74, 56)
        let localField = NSTextField(frame: NSRect(x: 56, y: 70, width: 70, height: 24))
        localField.placeholderString = "留空"
        localField.stringValue = draft.localPort
        let localHint = caption("留空 = 直连，不占本地端口", 134, 72, 260)

        let noteCaption = caption("说明", 0, 42, 48)
        let noteField = NSTextField(frame: NSRect(x: 56, y: 38, width: 394, height: 24))
        noteField.placeholderString = "备注，可留空"
        noteField.stringValue = draft.note

        // MAC 放最后一行：留空的资产就只是一个普通入口，不影响原有用法
        let macCaption = caption("MAC", 0, 8, 48)
        let macField = NSTextField(frame: NSRect(x: 56, y: 4, width: 150, height: 24))
        macField.placeholderString = "AA:BB:CC:DD:EE:FF"
        macField.stringValue = draft.mac
        let macHint = caption("填了就能网络唤醒（关机状态也能开机）", 214, 8, 250)

        for v in [nameCaption, nameField, hostCaption, hostField, portField, schemePopup,
                  userCaption, userField, passCaption, passField, clearBox,
                  localCaption, localField, localHint, noteCaption, noteField,
                  macCaption, macField, macHint] {
            box.addSubview(v)
        }
        alert.accessoryView = box
        alert.window.initialFirstResponder = nameField

        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        return AssetDraft(
            name: nameField.stringValue,
            host: hostField.stringValue,
            port: portField.stringValue,
            scheme: assetSchemes[max(0, schemePopup.indexOfSelectedItem)],
            user: userField.stringValue,
            localPort: localField.stringValue,
            note: noteField.stringValue,
            mac: macField.stringValue,
            password: passField.stringValue,
            clearPassword: clearBox.state == .on,
            hasPassword: draft.hasPassword,
            error: nil
        )
    }

    /// 校验草稿并组装成 Asset。editingID 非空时表示在改已有的那条。
    private func buildAsset(_ d: AssetDraft, editingID: String?) -> (error: String?, asset: Asset?) {
        let host = d.host.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { return ("主机不能为空", nil) }
        guard let port = Int(d.port.trimmingCharacters(in: .whitespaces)), (1...65535).contains(port) else {
            return ("端口要填 1–65535 的数字，收到「\(d.port)」", nil)
        }

        var lp: Int?
        let lpText = d.localPort.trimmingCharacters(in: .whitespaces)
        if !lpText.isEmpty {
            guard let v = Int(lpText), (1...65535).contains(v) else {
                return ("本地转发端口要填 1–65535，或者留空表示直连", nil)
            }
            if let other = cfg.assets.first(where: { $0.id != editingID && $0.localPort == v }) {
                return ("本地端口 \(v) 已经被「\(other.name)」占用了", nil)
            }
            // 编辑时端口往往不变，而 client 正听着它——只在真的换成新端口时才查占用
            let oldLocal = editingID.flatMap { id in cfg.assets.first(where: { $0.id == id })?.localPort }
            if v != oldLocal, isPortOpen(v) {
                return ("127.0.0.1:\(v) 已经在监听，换一个本地端口", nil)
            }
            lp = v
        }

        // MAC 可以留空；填了就必须能解析，并统一成 aa:bb:cc:dd:ee:ff 再存
        var macOut: String?
        let macRaw = d.mac.trimmingCharacters(in: .whitespaces)
        if !macRaw.isEmpty {
            guard let b = WOL.parseMAC(macRaw) else {
                return ("MAC 写法不对：「\(macRaw)」，应形如 AA:BB:CC:DD:EE:FF", nil)
            }
            macOut = WOL.macString(b)
        }

        let name = d.name.trimmingCharacters(in: .whitespaces)
        var a = Asset(
            name: name.isEmpty ? "\(host):\(port)" : name,
            host: host, port: port, scheme: d.scheme,
            user: d.user.trimmingCharacters(in: .whitespaces),
            localPort: lp,
            note: d.note.trimmingCharacters(in: .whitespaces)
        )
        a.mac = macOut
        if let id = editingID { a.id = id }
        return (nil, a)
    }

    @objc private func addAsset() {
        var draft = AssetDraft()
        while true {
            guard var d = promptAsset(title: "添加资产", okTitle: "添加", draft: draft) else { return }
            let (err, built) = buildAsset(d, editingID: nil)
            if let e = err {
                d.error = e
                draft = d
                continue
            }
            guard let a = built else { return }
            cfg.assets.append(a)
            if !d.password.isEmpty { Keychain.save(d.password, account: a.id) }
            cfg.save()
            appLog("新增资产 \(a.name)：\(a.scheme)://\(a.addr)"
                   + (a.localPort.map { " 经转发 \($0)" } ?? " 直连")
                   + (a.user.isEmpty ? "" : "，账号 \(a.user)"))
            if a.localPort != nil {
                restartClient(reason: "新增了带本地转发的资产")
            } else {
                refreshMenu()
            }
            return
        }
    }

    @objc private func editAsset(_ sender: NSMenuItem) {
        let list = cfg.assets.filter { $0.enabled }
        guard sender.tag >= 0, sender.tag < list.count else { return }
        editAssetDialog(list[sender.tag])
    }

    private func editAssetDialog(_ a: Asset) {
        let hasPass = assetPassword(a) != nil
        var draft = AssetDraft(
            name: a.name, host: a.host, port: "\(a.port)", scheme: a.scheme,
            user: a.user, localPort: a.localPort.map(String.init) ?? "",
            note: a.note, mac: a.macText, hasPassword: hasPass
        )
        let oldLocal = a.localPort

        while true {
            guard var d = promptAsset(title: "编辑资产", okTitle: "保存", draft: draft) else { return }
            let (err, built) = buildAsset(d, editingID: a.id)
            if let e = err {
                d.error = e
                draft = d
                continue
            }
            guard let na = built else { return }

            if let i = cfg.assets.firstIndex(where: { $0.id == a.id }) {
                cfg.assets[i] = na
            } else {
                cfg.assets.append(na)
            }
            if d.clearPassword {
                Keychain.delete(account: na.id)
            } else if !d.password.isEmpty {
                Keychain.save(d.password, account: na.id)
            }
            cfg.save()
            appLog("编辑资产 \(na.name)：\(na.scheme)://\(na.addr)"
                   + (na.localPort.map { " 经转发 \($0)" } ?? " 直连")
                   + (d.clearPassword ? "，已清除密码" : d.password.isEmpty ? "" : "，密码已更新"))

            if na.localPort != oldLocal {
                restartClient(reason: "资产的本地转发端口变了")
            } else {
                refreshMenu()
            }
            return
        }
    }

    @objc private func removeAsset(_ sender: NSMenuItem) {
        let list = cfg.assets.filter { $0.enabled }
        guard sender.tag >= 0, sender.tag < list.count else { return }
        let a = list[sender.tag]

        let confirm = NSAlert()
        confirm.messageText = "移除资产「\(a.name)」？"
        var info = "\(a.scheme)://\(a.addr)"
        if let lp = a.localPort { info += "\n本地转发 \(lp) 会一起删掉" }
        info += "\n\n钥匙串里这一条保存的密码也会删除。"
        confirm.informativeText = info
        confirm.addButton(withTitle: "移除")
        confirm.addButton(withTitle: "取消")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        let hadForward = a.localPort != nil
        cfg.assets.removeAll { $0.id == a.id }
        Keychain.delete(account: a.id)
        cfg.save()
        appLog("移除资产 \(a.name)")
        if hadForward {
            restartClient(reason: "资产已移除")
        } else {
            refreshMenu()
        }
    }

    @objc private func openForward(_ sender: NSMenuItem) {
        let rules = cfg.effectiveForwards
        guard sender.tag >= 0, sender.tag < rules.count,
              let f = parseForward(rules[sender.tag]) else { return }
        let rule = rules[sender.tag]

        // 资产派生的规则：点它等于点那条资产
        if let owner = cfg.assets.first(where: { $0.forwardRule == rule }) {
            assetPanel(owner)
            return
        }

        // 临时规则：沿用原来的打开方式
        let scheme = cfg.scheme(of: rule)
        let meta = cfg.forwardMeta[rule]
        if scheme == "ssh" {
            let pw = Keychain.load(account: rule)
            let user = meta?.user?.isEmpty == false ? meta!.user! : nil
            appLog("打开临时规则 SSH：\(user ?? "-")@127.0.0.1 -p \(f.local)")
            startSSH(host: "127.0.0.1", port: f.local, user: user, password: pw)
            return
        }
        let url = "\(scheme)://127.0.0.1:\(f.local)"
        appLog("打开临时转发：\(url) → \(f.host):\(f.remote)")
        openTarget(url)
    }

    // MARK: 转发规则的附加信息

    /// 写入/更新一条规则的元数据。scheme 传 nil 表示回到「自动」。
    private func setMeta(_ rule: String, scheme: String?, user: String?) {
        let hasScheme = !(scheme?.isEmpty ?? true)
        let hasUser = !(user?.isEmpty ?? true)
        if !hasScheme && !hasUser {
            cfg.forwardMeta.removeValue(forKey: rule)
            return
        }
        cfg.forwardMeta[rule] = ForwardMeta(
            scheme: hasScheme ? scheme : nil,
            user: hasUser ? user : nil
        )
    }

    @objc private func openCustomURL() {
        let alert = NSAlert()
        alert.messageText = "打开地址"
        alert.informativeText = "填写要走隧道的地址，例如 https://10.0.0.199:5667 或 ssh://root@10.0.0.201"
        alert.addButton(withTitle: "打开")
        alert.addButton(withTitle: "取消")
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 24))
        field.placeholderString = "https://127.0.0.1:18443"
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let text = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, URL(string: text) != nil else {
            alertError("地址无效", "无法解析：\(text)")
            return
        }
        openTarget(text)
    }

    /// 转发弹窗里的草稿。添加和编辑共用一套控件，只有标题与初始值不同。
    private struct ForwardDraft {
        var local: String = ""
        var target: String = ""
        var scheme: String?          // nil = 自动（按目标端口判断）
        var user: String = ""        // SSH 等协议用的账号
        var password: String = ""    // 空 = 不改动已存的密码
        var clearPassword: Bool = false
        var hasPassword: Bool = false  // 钥匙串里已有密码（只用于提示文案）
        var error: String?           // 上一轮的校验错误，带到下一轮弹窗顶部
    }

    /// 校验结果：error 非空表示不通过，否则 rule/local/host/remote 可用。
    private struct ForwardCheck {
        var error: String?
        var rule: String = ""
        var local: Int = 0
        var host: String = ""
        var remote: Int = 0
    }

    /// 添加 / 编辑共用的输入弹窗。返回 nil 表示用户取消。
    private func promptForward(title: String, okTitle: String, draft: ForwardDraft) -> ForwardDraft? {
        let alert = NSAlert()
        alert.messageText = title
        var info = "本地端口 → 目标主机:目标端口，保存后自动重启 client 生效。"
        info += "\n\nhttps 建议本地端口与目标端口保持一致——证书通常绑端口，"
        info += "端口换掉浏览器会报证书错误。"
        info += "\n账号 / 密码只用于「打开方式 = ssh」：点击后终端里直接执行 "
        info += "ssh -p 本地端口 账号@127.0.0.1，密码从钥匙串取、不写进配置文件。"
        if let e = draft.error { info = "⚠︎ \(e)\n\n" + info }
        alert.informativeText = info
        alert.addButton(withTitle: okTitle)
        alert.addButton(withTitle: "取消")

        let box = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 96))
        let small = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)

        let localCaption = NSTextField(labelWithString: "本地端口")
        localCaption.frame = NSRect(x: 0, y: 72, width: 64, height: 18)
        localCaption.font = small
        let localField = NSTextField(frame: NSRect(x: 68, y: 68, width: 104, height: 24))
        localField.placeholderString = "18443"
        localField.stringValue = draft.local

        let schemeCaption = NSTextField(labelWithString: "打开方式")
        schemeCaption.frame = NSRect(x: 186, y: 72, width: 64, height: 18)
        schemeCaption.font = small
        let popup = NSPopUpButton(frame: NSRect(x: 252, y: 67, width: 166, height: 26), pullsDown: false)
        popup.addItems(withTitles: forwardSchemeChoices.map { forwardSchemeTitle($0) })
        popup.selectItem(at: forwardSchemeChoices.firstIndex(where: { $0 == draft.scheme }) ?? 0)

        let targetCaption = NSTextField(labelWithString: "目标")
        targetCaption.frame = NSRect(x: 0, y: 42, width: 64, height: 18)
        targetCaption.font = small
        let targetField = NSTextField(frame: NSRect(x: 68, y: 38, width: 350, height: 24))
        targetField.placeholderString = "10.0.0.10:443"
        targetField.stringValue = draft.target

        let userCaption = NSTextField(labelWithString: "账号")
        userCaption.frame = NSRect(x: 0, y: 12, width: 64, height: 18)
        userCaption.font = small
        let userField = NSTextField(frame: NSRect(x: 68, y: 8, width: 104, height: 24))
        userField.placeholderString = "root"
        userField.stringValue = draft.user

        let passCaption = NSTextField(labelWithString: "密码")
        passCaption.frame = NSRect(x: 186, y: 12, width: 64, height: 18)
        passCaption.font = small
        let passField = NSSecureTextField(frame: NSRect(x: 252, y: 8, width: 104, height: 24))
        passField.placeholderString = draft.hasPassword ? "已存（留空不改）" : "可留空"
        passField.stringValue = draft.password

        let clearBox = NSButton(checkboxWithTitle: "清除", target: nil, action: nil)
        clearBox.frame = NSRect(x: 362, y: 9, width: 56, height: 20)
        clearBox.font = small
        clearBox.state = draft.clearPassword ? .on : .off
        clearBox.isEnabled = draft.hasPassword

        for v in [localCaption, localField, schemeCaption, popup,
                  targetCaption, targetField,
                  userCaption, userField, passCaption, passField, clearBox] {
            box.addSubview(v)
        }
        alert.accessoryView = box
        alert.window.initialFirstResponder = localField

        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        return ForwardDraft(
            local: localField.stringValue,
            target: targetField.stringValue,
            scheme: forwardSchemeChoices[max(0, popup.indexOfSelectedItem)],
            user: userField.stringValue,
            password: passField.stringValue,
            clearPassword: clearBox.state == .on,
            hasPassword: draft.hasPassword,
            error: nil
        )
    }

    private func checkForward(_ d: ForwardDraft, replacingIndex: Int?) -> ForwardCheck {
        var r = ForwardCheck()
        let localText = d.local.trimmingCharacters(in: .whitespaces)
        guard let localPort = Int(localText), (1...65535).contains(localPort) else {
            r.error = "本地端口要填 1–65535 的数字，收到「\(localText)」"
            return r
        }
        let parts = d.target.trimmingCharacters(in: .whitespaces).split(separator: ":")
        guard parts.count == 2, let remotePort = Int(parts[1]),
              (1...65535).contains(remotePort), !parts[0].isEmpty else {
            r.error = "目标应为「主机:端口」，例如 10.0.0.10:443，收到「\(d.target)」"
            return r
        }

        // 编辑时本地端口往往不变，而 client 正在监听它——不能当成"被占用"，
        // 所以只在端口真的换了的时候才检查。
        let oldLocal = replacingIndex.flatMap { parseForward(cfg.forwards[$0])?.local }
        if localPort != oldLocal, isPortOpen(localPort) {
            r.error = "127.0.0.1:\(localPort) 已经在监听，换一个本地端口。"
            return r
        }

        let rule = "\(localPort):\(parts[0]):\(remotePort)"
        let skip = replacingIndex ?? -1
        if cfg.forwards.enumerated().contains(where: { $0.offset != skip && $0.element == rule }) {
            r.error = "这条规则已经存在了：\(rule)"
            return r
        }

        r.rule = rule
        r.local = localPort
        r.host = String(parts[0])
        r.remote = remotePort
        return r
    }

    @objc private func addForward() {
        var draft = ForwardDraft()
        while true {
            guard var d = promptForward(title: "添加端口转发", okTitle: "添加", draft: draft) else { return }
            let chk = checkForward(d, replacingIndex: nil)
            if let e = chk.error {
                d.error = e
                draft = d
                continue
            }
            cfg.forwards.append(chk.rule)
            setMeta(chk.rule, scheme: d.scheme, user: d.user)
            if !d.password.isEmpty { Keychain.save(d.password, account: chk.rule) }
            cfg.save()
            appLog("新增转发 \(chk.rule)（打开方式 \(d.scheme ?? "自动")"
                   + (d.user.isEmpty ? "" : "，账号 \(d.user)")
                   + (d.password.isEmpty ? "" : "，密码已存钥匙串") + "）")
            restartClient(reason: "转发规则已变更")
            return
        }
    }

    // 编辑转发已合并进「编辑资产」：端口、目标、协议、账号密码都在资产弹窗里改，
    // 避免两处都能改同一件事而对不上。

    @objc private func removeForward(_ sender: NSMenuItem) {
        guard sender.tag >= 0, sender.tag < cfg.forwards.count else { return }
        let rule = cfg.forwards[sender.tag]

        let confirm = NSAlert()
        confirm.messageText = "移除这条转发？"
        confirm.informativeText = rule
        confirm.addButton(withTitle: "移除")
        confirm.addButton(withTitle: "取消")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        cfg.forwards.remove(at: sender.tag)
        cfg.forwardMeta.removeValue(forKey: rule)
        Keychain.delete(account: rule)
        cfg.save()
        appLog("移除转发 \(rule)（含钥匙串密码）")
        restartClient(reason: "转发规则已变更")
    }

    /// 转发规则改动后必须重启 client 才会重新建立监听。App 本身不退出。
    private func restartClient(reason: String) {
        guard runner.running else {
            refreshMenu()
            appLog("\(reason)；当前未连接，规则将在下次连接时生效")
            return
        }
        appLog("\(reason)，重启 client")
        let wasLab = labMode
        runner.stop()
        // 重启多半意味着资产地址/端口刚改过，旧的探测结论一律作废，等新一轮
        reach = [:]
        reachAt = nil
        if wasLab {
            startLab()
        } else {
            startProduction()
        }
    }

    // MARK: 启停

    private func startProduction() {
        guard !cfg.key.isEmpty else {
            alert("缺少预共享密钥", "请先在配置里填写 key。")
            return
        }
        var useTun = cfg.tunEnabled
        if useTun && !sudoRuleInstalled(client: "/usr/local/bin/tunnelbar-client") {
            // 规则被删掉或换机器时，宁可先以普通模式连上，也不要让 client 直接起不来
            appLog("TUN 已开启但缺少 sudo 规则，本次以普通模式启动")
            useTun = false
        }
        labMode = false
        runner.start(specs: [makeProductionSpec(cfg, tun: useTun)], mode: "prod", stagger: 0)
        appLog("启动生产模式：relay=\(cfg.relay) socks=\(cfg.socksPort) status=\(cfg.statusPort)")
        status = nil
        restartCount = 0
        updateIcon(state: .connecting)
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.tick()
        }
    }

    private func startLab() {
        labMode = true
        latency = nil
        runner.start(specs: makeLabSpecs(cfg), mode: "lab", stagger: 0.7)
        appLog("启动本机自测模式")
        status = nil
        updateIcon(state: .connecting)
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) { [weak self] in
            self?.tick()
        }
    }

    private func stopAll() {
        appLog("停止全部进程")
        runner.stop()
        status = nil
        latency = nil
        // 隧道断了，资产状态全部作废——留着会显示成一片过期的「在线」
        reach = [:]
        reachAt = nil
        probingAssets = false
        labMode = false
        updateIcon(state: .off)
        refreshMenu()
    }

    // MARK: 状态刷新

    private enum VisualState { case off, connecting, on, degraded }

    private func tick() {
        guard runner.running else {
            status = nil
            updateIcon(state: .off)
            refreshMenu()
            return
        }
        let port = labMode ? cfg.labStatusPort : cfg.statusPort
        let st = fetchStatus(port: port)
        status = st

        if let st {
            if st.ready {
                updateIcon(state: st.poolAlive >= st.poolTotal ? .on : .degraded)
                if labMode {
                    if latency == nil || latencyAt == nil || Date().timeIntervalSince(latencyAt!) > 15 {
                        refreshLatency()
                    }
                } else if reachAt == nil || Date().timeIntervalSince(reachAt!) >= reachInterval {
                    // 后台兜底：60 秒一轮，只在隧道就绪时探，省得没连上也去刷失败
                    probeAssets(reason: "定时")
                }
            } else if (st.failCount ?? 0) > 0 && (st.okCount ?? 0) == 0 {
                updateIcon(state: .degraded)
            } else {
                updateIcon(state: .connecting)
            }
        } else {
            // 状态接口打不开：进程可能刚起或已崩
            updateIcon(state: .connecting)
        }
        refreshMenu()
    }

    /// 把 client 的原始报错翻译成能直接照着做的结论。
    private func diagnose(_ st: ClientStatus) -> String {
        if st.ready { return "" }
        let raw = (st.lastError ?? "").lowercased()
        if raw.isEmpty { return "" }
        let age = st.lastErrorAge ?? -1
        let when = age >= 0 ? "（\(age)s 前）" : ""

        if raw.contains("hello") || raw.contains("i/o timeout") {
            return "中继无 v2 握手响应\(when)：服务端大概率仍是 v1，需先升级 relay"
        }
        if raw.contains("decrypt") || raw.contains("密钥") {
            return "握手解密失败\(when)：三端预共享密钥不一致"
        }
        if raw.contains("version") || raw.contains("协议") {
            return "协议版本不匹配\(when)：三端需统一升级到 v2"
        }
        if raw.contains("connection refused") {
            return "中继端口拒绝连接\(when)：检查端口与 systemd 状态"
        }
        if raw.contains("no such host") || raw.contains("lookup") {
            return "中继地址解析失败\(when)：检查配置里的 relay 地址"
        }
        let brief = String((st.lastError ?? "").prefix(80))
        return "最近错误\(when)：\(brief)"
    }

    /// 记录状态项落在哪块屏、是否在屏幕可见区域内。
    private func logPlacement(_ tag: String) {
        guard let w = statusItem.button?.window else { return }
        let f = w.frame
        let idx = NSScreen.screens.firstIndex { $0.frame.intersects(f) }
        let name = idx.map { "屏#\($0)" } ?? "屏幕外"
        appLog("状态项位置[\(tag)]：\(NSStringFromRect(f)) → \(name)")
    }

    /// 把状态项摆到用户指定的屏幕上（默认交给系统，仅在 config.pinToScreen 设置时才干预）。
    private func pinStatusItemIfNeeded() {
        guard cfg.pinToScreen != "none", let w = statusItem.button?.window else { return }
        let target: NSScreen?
        switch cfg.pinToScreen {
        case "none":
            return
        case "cursor":
            target = NSScreen.screens.first { $0.frame.contains(NSEvent.mouseLocation) }
                ?? NSScreen.screens.first
        default:
            // NSScreen.main 是「当前活跃屏」，会随鼠标/焦点变化；
            // 这里取包含坐标原点的屏，才是稳定不变的那块。
            target = NSScreen.screens.first { $0.frame.origin == .zero } ?? NSScreen.screens.first
        }
        guard let scr = target else { return }
        var f = w.frame
        if scr.frame.intersects(f) { return }   // 已经在目标屏上，不动
        let oldX = f.origin.x
        // 只纠正纵向：落到目标屏的菜单栏条带里（25pt 高，留 2pt 余量）
        f.origin.y = scr.frame.maxY - f.height - 2
        // 横向若跑出了目标屏，放到状态区左侧，别去和 WiFi/电池/时钟挤在一起
        if f.origin.x < scr.frame.minX || f.origin.x > scr.frame.maxX - f.width {
            f.origin.x = scr.frame.minX + 480
        }
        w.setFrame(f, display: true, animate: false)
        appLog("已把状态项从 x=\(oldX) 移到 \(NSStringFromRect(scr.frame)) 的菜单栏：\(NSStringFromRect(f))")
    }

    /// 一次性诊断：确认状态项真的被插入到菜单栏窗口里。
    private func dumpStatusItemDiag() {
        guard let button = statusItem.button else {
            appLog("诊断：statusItem.button 为 nil")
            return
        }
        for (i, scr) in NSScreen.screens.enumerated() {
            let bar = scr.frame.height - scr.visibleFrame.height
            appLog("屏#\(i)：frame=\(NSStringFromRect(scr.frame)) visible=\(NSStringFromRect(scr.visibleFrame)) 菜单栏高度=\(bar)")
        }
        let win = button.window
        appLog("诊断：window frame=\(win?.frame.debugDescription ?? "nil") "
            + "winVisible=\(win?.isVisible.description ?? "nil") "
            + "screen=\(NSScreen.main?.frame.debugDescription ?? "nil") "
            + "screens=\(NSScreen.screens.count)")
        appLog("诊断：isVisible=\(statusItem.isVisible) len=\(statusItem.length) "
            + "frame=\(button.frame) window=\(button.window == nil ? "nil" : "ok") "
            + "image=\(button.image == nil ? "nil" : "\(button.image!.size)") "
            + "title=\(button.title) hidden=\(button.isHidden) alpha=\(button.alphaValue)")
    }

    /// 菜单栏那个「延迟」数字：直接取本轮探测里最快的在线资产。
    ///
    /// 不再自己发探测——探测统一由 `probeAssets()` 负责，这里只读结果。
    /// 老实现每 2 秒探一次配置里写死的 `probe` 地址，那台机器 DHCP 换 IP 之后
    /// 就变成永久失败的靶子，一天往日志里灌 8 万多条。
    private func refreshLatency() {
        if labMode {
            // 自测模式探的是本机站点，与资产列表无关，保持原逻辑
            let socks = cfg.labSocksPort
            guard isPortOpen(socks) else {
                latency = nil
                return
            }
            let target = "127.0.0.1:\(cfg.labSitePort)"
            DispatchQueue.global(qos: .utility).async { [weak self] in
                let ms = socksProbe(socksPort: socks, target: target)
                DispatchQueue.main.async {
                    self?.latency = ms
                    self?.latencyAt = Date()
                    self?.refreshMenu()
                }
            }
            return
        }

        let best = reach.values.compactMap { r -> Double? in
            if case .online(let ms) = r { return ms }
            return nil
        }.min()
        latency = best
        latencyAt = best == nil ? nil : reachAt
    }

    /// 探测所有启用的资产，结果写进 `reach`。
    ///
    /// 三个约束：
    /// 1. **并发 3** —— 池连接总共 6 条，一次全占满会把正在用的隧道拖慢；
    /// 2. **单台超时 1.5 秒** —— 内网设备要么秒回要么不在，等 5 秒没意义；
    /// 3. **同一时刻只跑一轮** —— `probingAssets` 挡住重入，菜单连点不会叠加。
    private func probeAssets(reason: String) {
        guard runner.running, !probingAssets else { return }
        let socks = labMode ? cfg.labSocksPort : cfg.socksPort
        guard isPortOpen(socks) else { return }

        let targets = cfg.assets.filter { $0.enabled && $0.port > 0 }
        guard !targets.isEmpty else {
            reach = [:]
            reachAt = Date()
            refreshLatency()
            return
        }

        probingAssets = true
        for a in targets { reach[a.id] = .probing }
        refreshMenu()

        let sem = DispatchSemaphore(value: 3)
        let group = DispatchGroup()
        let lock = NSLock()
        var results: [String: Reach] = [:]

        for a in targets {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                sem.wait()
                defer { sem.signal(); group.leave() }
                let ms = socksProbe(socksPort: socks, target: "\(a.host):\(a.port)", timeout: 1.5)
                lock.lock()
                results[a.id] = ms.map { .online(ms: $0) } ?? .offline
                lock.unlock()
            }
        }

        group.notify(queue: .main) { [weak self] in
            guard let self else { return }
            self.reach = results
            self.reachAt = Date()
            self.probingAssets = false
            self.refreshLatency()
            self.refreshMenu()
            let online = results.values.filter {
                if case .online = $0 { return true }
                return false
            }.count
            appLog("资产探测（\(reason)）：\(online)/\(targets.count) 在线")
        }
    }

    private func refreshMenu() {
        let st = status
        if runner.running {
            if let st {
                if st.ready {
                    headerItem.title = "已连接 · 池 \(st.poolAlive)/\(st.poolTotal)"
                } else if (st.failCount ?? 0) > 0 && (st.okCount ?? 0) == 0 {
                    // 一次都没成功过：不是"连接中"，是根本连不上中继
                    headerItem.title = "连不上中继 · 已重试 \(st.failCount ?? 0) 次"
                } else if st.uptimeSec < 5 {
                    headerItem.title = "启动中…"
                } else {
                    headerItem.title = "连接中… 池 \(st.poolAlive)/\(st.poolTotal)"
                }
                let tip = diagnose(st)
                errorItem.title = tip
                errorItem.isHidden = tip.isEmpty
                trafficItem.title = "↑ \(humanBytes(st.txBytes))   ↓ \(humanBytes(st.rxBytes))"
                streamItem.title = "活跃流 \(st.active) · 累计 \(st.opened) · 重置 \(st.resets) · \(humanDuration(st.uptimeSec))"
                toggleItem.title = "断开连接"
            } else {
                headerItem.title = "进程已起，状态接口未响应"
                trafficItem.title = "流量 —"
                streamItem.title = "状态接口 127.0.0.1:\(labMode ? cfg.labStatusPort : cfg.statusPort) 打不开"
                errorItem.title = ""
                errorItem.isHidden = true
                toggleItem.title = "断开连接"
            }
        } else {
            headerItem.title = "未连接"
            trafficItem.title = "流量 —"
            streamItem.title = "活跃流 —"
            errorItem.title = ""
            errorItem.isHidden = true
            toggleItem.title = "连接"
        }

        if let ms = latency {
            latencyItem.title = String(format: "延迟 %.0f ms（在线资产里最快的一台）", ms)
        } else {
            latencyItem.title = runner.running ? "延迟 —（没有在线资产）" : "延迟 —"
        }

        refreshTunItem()
        labItem.title = labMode ? "停止本机自测" : "启动本机自测（本机起 relay+home+站点）"
        setToggle(loginItem, on: LoginItem.enabled, onSymbol: "arrow.right.to.line.circle.fill", offSymbol: "arrow.right.to.line.circle")
    }

    /// 菜单栏图标。
    ///
    /// 两个关键约束，决定它看起来是否"和系统图标一样"：
    /// 1. 只用**描边**符号（shield.fill 这类实心块面积大，在菜单栏里显得又黑又重）；
    /// 2. **不设 contentTintColor**，全部交给模板图自动着色——浅色菜单栏取深色、
    ///    深色菜单栏取白色，和 WiFi/电池等图标完全同步。
    /// 状态改由图标形状区分，另外菜单首行有文字说明。
    private func updateIcon(state: VisualState) {
        guard let button = statusItem.button else { return }
        let name: String
        switch state {
        case .on:
            name = "checkmark.shield"
        case .degraded:
            name = "exclamationmark.shield"
        case .connecting:
            name = "shield"
        case .off:
            name = "shield.slash"
        }
        // 13pt / regular 与系统菜单栏图标的笔画粗细最接近
        let conf = NSImage.SymbolConfiguration(pointSize: 13, weight: .regular)
        if let base = NSImage(systemSymbolName: name, accessibilityDescription: "TunnelBar"),
           let img = base.withSymbolConfiguration(conf) {
            img.isTemplate = true   // 模板图：颜色完全由系统菜单栏决定
            button.image = img
            button.title = cfg.menuBarTitle
            button.imagePosition = .imageLeading
        } else {
            // 系统取不到该符号时退化为文字，绝不让菜单栏出现空白项
            button.image = nil
            button.title = cfg.menuBarTitle.isEmpty ? (state == .on ? "T" : "t") : cfg.menuBarTitle
        }
        // 必须显式清空：之前设置过就会一直沿用，导致图标被染成绿/橙/灰
        button.contentTintColor = nil
        button.toolTip = state == .on ? "隧道已连接" : (state == .off ? "隧道未连接" : "隧道连接中")
    }

    // MARK: 动作

    @objc private func toggle() {
        if runner.running {
            stopAll()
        } else {
            startProduction()
        }
    }


    // MARK: 全局直连（TUN）

    /// 切换 TUN 模式。开启前先确保有免密规则，否则 client 拿不到 root 会直接失败。
    @objc private func toggleTun() {
        let turningOn = !cfg.tunEnabled
        if turningOn && !ensureSudoersRule() { return }
        cfg.tunEnabled = turningOn
        cfg.save()
        appLog("TUN 模式 -> \(turningOn ? "开启" : "关闭")，路由段=\(cfg.tunRoutes.joined(separator: ","))")
        refreshTunItem()
        if runner.running {
            // 参数变化只能靠重启 client 生效；App 本身不退出
            startProduction()
        }
    }

    /// 刷新「全局直连」这一行及其下方的统计行。
    private func refreshTunItem() {
        setToggle(tunItem, on: cfg.tunEnabled)
        if let t = status?.tun, let dev = t.device {
            tunItem.title = "全局直连（TUN）· \(dev)"
        } else {
            tunItem.title = "全局直连（TUN）"
        }

        guard cfg.tunEnabled else {
            tunInfoItem.isHidden = true
            return
        }
        guard let t = status?.tun, t.enabled else {
            // 配置已开启但 client 还没以 root 起起来（多半是缺授权或正在重启）
            tunInfoItem.isHidden = false
            tunInfoItem.title = "TUN 未启用 · 等待以 root 重启 client"
            return
        }
        tunInfoItem.isHidden = false
        let routes = (t.routes ?? []).joined(separator: " ")
        let tcp = "TCP \(t.tcpActive ?? 0)/\(t.tcpTotal ?? 0)"
        let udp = "UDP \(t.udpActive ?? 0)/\(t.udpTotal ?? 0)"
        tunInfoItem.title = "接管 \(routes.isEmpty ? "—" : routes) · \(tcp) · \(udp)"
        if let err = t.error, !err.isEmpty {
            tunInfoItem.title = "TUN 异常：\(err)"
        }
    }

    /// 免密包装脚本路径。
    ///
    /// 为什么不直接把 App 里的 client 写进 sudoers：本次安装路径含空格
    /// （`2-开发项目/20-本地隧道穿透/…`），而 sudoers 的命令字段按空白分词，
    /// 带空格路径无法可靠匹配。用一个无空格的固定路径转发执行就绕开了这个问题，
    /// App 挪位置、改名之后也不用重新授权。
    private func sudoWrapperShellPath() -> String {
        "/usr/local/bin/tunnelbar-client"
    }

    /// 确保包装脚本与 /etc/sudoers.d/tunnelbar 都存在且有效。
    /// 返回 false 表示用户取消了授权，或写入后仍不生效。
    private func ensureSudoersRule() -> Bool {
        let wrapper = sudoWrapperShellPath()
        if sudoRuleInstalled(client: wrapper) { return true }

        // 写成独立脚本再交给 osascript 执行，避免多层引号转义出错。
        let script = """
        #!/bin/sh
        set -e
        mkdir -p /usr/local/bin /etc/sudoers.d
        cat > \(wrapper) <<'WRAPPER'
        #!/bin/sh
        exec "\(clientBinaryPath())" "$@"
        WRAPPER
        chown root:wheel \(wrapper)
        chmod 755 \(wrapper)
        printf 'ALL ALL=(root) NOPASSWD: \(wrapper)\\n' > /etc/sudoers.d/tunnelbar
        chown root:wheel /etc/sudoers.d/tunnelbar
        chmod 440 /etc/sudoers.d/tunnelbar
        /usr/sbin/visudo -cf /etc/sudoers.d/tunnelbar
        """
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tunnelbar-sudo-setup.sh")
        guard (try? script.write(to: tmp, atomically: true, encoding: .utf8)) != nil else {
            alert("无法开启全局直连", "写入临时脚本失败，请检查磁盘空间。")
            return false
        }
        let ok = runAppleScriptAdmin("sh \(tmp.path)")
        try? FileManager.default.removeItem(at: tmp)

        guard ok else {
            alert("无法开启全局直连", """
            需要一次管理员授权，用来写入一条 sudo 规则。

            建虚拟网卡和修改路由表必须有 root 权限。这条规则只允许 \(wrapper) 以 root 运行，
            而这个脚本只转发执行本 App 内嵌的 client，不授权其它任何程序；
            不想保留时可以删掉 /etc/sudoers.d/tunnelbar 和 \(wrapper)。
            """)
            return false
        }
        guard sudoRuleInstalled(client: wrapper) else {
            alert("授权未生效", """
            规则已写入但仍无法以 root 执行：
            \(wrapper)

            可以手动检查 /etc/sudoers.d/tunnelbar 是否被其它规则覆盖。
            """)
            return false
        }
        return true
    }

    /// 用 `sudo -n -l <client>` 探测规则是否已生效（不会真的执行 client）。
    private func sudoRuleInstalled(client: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["-n", "-l", client]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
        } catch {
            return false
        }
        // 有上限地等，别在主线程上无限等一个可能永远不退的子进程。
        let deadline = Date().addingTimeInterval(3)
        while p.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        if p.isRunning {
            kill(p.processIdentifier, SIGKILL)
            return false
        }
        return p.terminationStatus == 0
    }

    /// 以管理员权限执行一段 shell，会弹出系统授权框。
    @discardableResult
    private func runAppleScriptAdmin(_ shell: String) -> Bool {
        let escaped = shell
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let src = "do shell script \"\(escaped)\" with administrator privileges"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", src]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
        } catch {
            return false
        }
        // 授权框最多等 180 秒：超时就当用户取消，绝不把菜单栏一起卡死。
        let deadline = Date().addingTimeInterval(180)
        while p.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if p.isRunning {
            kill(p.processIdentifier, SIGKILL)
            appLog("管理员授权超时，已放弃本次提权")
            return false
        }
        return p.terminationStatus == 0
    }

    @objc private func toggleLab() {
        if labMode {
            stopAll()
        } else {
            startLab()
        }
    }

    @objc private func runTest() {
        let socks = labMode ? cfg.labSocksPort : cfg.socksPort

        // 探测目标不再单独配置：优先取本轮探测里最快的在线资产，
        // 没探过就退到第一台启用资产，一台都没有才提示去添加。
        // 这样地址只在资产列表里存一份，DHCP 换了 IP 也不会两处打架。
        var target = labMode ? "127.0.0.1:\(cfg.labSitePort)" : ""
        if !labMode {
            let usable = cfg.assets.filter { $0.enabled && $0.port > 0 }
            let fastest = usable.compactMap { a -> (String, Double)? in
                if case .online(let ms) = reach[a.id] ?? .offline {
                    return ("\(a.host):\(a.port)", ms)
                }
                return nil
            }.min { $0.1 < $1.1 }
            if let f = fastest {
                target = f.0
            } else if let first = usable.first {
                target = "\(first.host):\(first.port)"
            }
        }

        guard !target.isEmpty else {
            alert("还没有可用资产", "先在「资产」→「添加资产…」里加一台内网设备，再来测连通性。")
            return
        }

        guard isPortOpen(socks) else {
            alert("测试失败", "本地 SOCKS5 端口 \(socks) 没有监听，隧道未启动。")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let start = Date()
            let ms = socksProbe(socksPort: socks, target: target)
            let text: String
            if let ms {
                text = String(format: "通过隧道访问 %@ 成功，耗时 %.0f ms。", target, ms)
            } else {
                text = """
                通过隧道访问 \(target) 失败。

                可能原因：
                · 隧道未就绪（等待 2~3 秒再试）
                · 对端 home 未启动，或目标机该端口未开放
                · 远端 relay 仍是旧协议版本（v1），与本地 v2 不兼容
                """
            }
            let elapsed = Date().timeIntervalSince(start)
            DispatchQueue.main.async {
                self.latency = ms
                self.latencyAt = Date()
                self.refreshMenu()
                self.alert(ms == nil ? "测试失败" : "测试通过",
                           text + String(format: "\n\n总耗时 %.1f 秒。", elapsed))
            }
        }
    }

    @objc private func openLog() {
        let log = labMode
            ? Paths.logs.appendingPathComponent("client-lab.log")
            : Paths.logs.appendingPathComponent("client.log")
        if !FileManager.default.fileExists(atPath: log.path) {
            alert("暂无日志", "日志会写入：\(log.path)")
            return
        }
        NSWorkspace.shared.open(log)
    }

    @objc private func openConfig() {
        cfg.save()
        NSWorkspace.shared.open(Paths.config)
    }

    @objc private func reloadConfig() {
        cfg = Config.load()
        alert("配置已重新加载", "relay = \(cfg.relay)\nSOCKS 端口 = \(cfg.socksPort)\n\n若正在连接，请断开后重连使其生效。")
    }

    @objc private func toggleLogin() {
        if LoginItem.enabled {
            LoginItem.disable()
            refreshMenu()
            return
        }
        if let err = LoginItem.enable() {
            alert("开机自启设置失败", err)
        } else {
            alert("已开启开机自启", "已写入 \(LoginItem.plistURL.path)\n下次登录会自动启动菜单栏。")
        }
        refreshMenu()
    }

    /// 点诊断行：把完整报错复制到剪贴板，排查时直接甩给日志。
    @objc private func copyLastError() {
        guard let raw = status?.lastError, !raw.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(raw, forType: .string)
        appLog("已复制连接错误：\(raw)")
    }

    @objc private func copySocks() {
        let socks = labMode ? cfg.labSocksPort : cfg.socksPort
        let text = "socks5h://127.0.0.1:\(socks)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        appLog("已复制 \(text)")
    }

    @objc private func about() {
        alert("TunnelBar", """
        本地隧道菜单栏管理工具

        client 状态接口：127.0.0.1:\(labMode ? cfg.labStatusPort : cfg.statusPort)
        SOCKS5：127.0.0.1:\(labMode ? cfg.labSocksPort : cfg.socksPort)
        日志目录：\(Paths.logs.path)
        """)
    }

    /// 已在运行时用户又从访达/启动台双击 App：直接把菜单弹出来，
    /// 这样即使状态项被系统摆到了看不见的位置，也能操作。
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        statusItem.button?.performClick(nil)
        appLog("二次启动：弹出菜单")
        return true
    }

    @objc private func quit() {
        runner.stop()
        NSApp.terminate(nil)
    }

    private func alert(_ title: String, _ body: String) {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = body
        a.alertStyle = .informational
        a.addButton(withTitle: "好")
        NSApp.activate(ignoringOtherApps: true)
        a.runModal()
    }

    /// 输入校验失败用：加个警告样式，和一般提示区分开
    private func alertError(_ title: String, _ body: String) {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = body
        a.alertStyle = .warning
        a.addButton(withTitle: "好")
        NSApp.activate(ignoringOtherApps: true)
        a.runModal()
    }
}

// MARK: - 无界面自检（--selftest）

enum SelfTest {
    static func run() -> Never {
        Paths.ensureDirs()
        let cfg = Config.load()
        let runner = Runner()

        print("▸ 拉起本机自测三端（relay / home / 站点 / client）...")
        runner.start(specs: makeLabSpecs(cfg), mode: "lab", stagger: 0.7)
        appLog("启动本机自测模式")

        var ok = true

        var st: ClientStatus?
        for _ in 0..<30 {
            Thread.sleep(forTimeInterval: 0.5)
            if let s = fetchStatus(port: cfg.labStatusPort), s.ready {
                st = s
                break
            }
        }
        if let st {
            print("✓ 状态接口就绪：协议 v\(st.protocolVersion)，池 \(st.poolAlive)/\(st.poolTotal)")
        } else {
            print("✗ 状态接口未就绪（127.0.0.1:\(cfg.labStatusPort)）")
            ok = false
        }

        if let ms = socksProbe(socksPort: cfg.labSocksPort, target: "127.0.0.1:\(cfg.labSitePort)") {
            print(String(format: "✓ SOCKS 探测通过：%.0f ms", ms))
        } else {
            print("✗ SOCKS 探测失败")
            ok = false
        }

        if let (code, size) = curlBig(port: cfg.labSocksPort, site: cfg.labSitePort) {
            if code == "200", size == "20971520" {
                print("✓ 20MB 传输完整（\(size) 字节）")
            } else {
                print("✗ 大文件异常：HTTP \(code)，收到 \(size) 字节（应为 20971520）")
                ok = false
            }
        } else {
            print("✗ 大文件下载未能完成")
            ok = false
        }

        let t0 = Date()
        let bad = socksProbe(socksPort: cfg.labSocksPort, target: "127.0.0.1:9", timeout: 12)
        let dt = Date().timeIntervalSince(t0)
        if bad == nil && dt < 3 {
            print(String(format: "✓ 不可达目标快速失败：%.0f ms", dt * 1000))
        } else if bad == nil {
            print(String(format: "⚠ 不可达目标失败较慢：%.1f s", dt))
        } else {
            print("✗ 不可达目标竟然连通，半开连接语义可疑")
            ok = false
        }

        runner.stop()
        print("")
        print(ok ? "SELFTEST OK" : "SELFTEST FAIL")
        exit(ok ? 0 : 1)
    }

    /// 通过 SOCKS 下载 20MB，返回 (HTTP 码, 字节数)。
    static func curlBig(port: Int, site: Int) -> (String, String)? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        p.arguments = [
            "-s", "--max-time", "120",
            "--socks5-hostname", "127.0.0.1:\(port)",
            "-o", "/dev/null",
            "-w", "%{http_code} %{size_download}",
            "http://127.0.0.1:\(site)/big",
        ]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        waitExit(p, timeout: 130)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let parts = text.split(separator: " ")
        guard parts.count == 2 else { return nil }
        return (String(parts[0]), String(parts[1]))
    }
}

/// 无界面唤醒自检：`TunnelBar --woltest AA:BB:CC:DD:EE:FF`
///
/// 菜单里点一次才知道结果太慢，出问题时也不方便看细节。这个入口把
/// 「解析 → 算广播地址 → 发本机 → 发隧道」每一步都打出来，给排查用。
func wolTest(_ macArg: String) -> Never {
    let cfg = Config.load()
    print("▸ 唤醒自检")
    print("  MAC 入参：\(macArg)")

    guard let mac = WOL.parseMAC(macArg) else {
        print("✗ MAC 解析失败（应形如 AA:BB:CC:DD:EE:FF，也认 aa-bb-… 与裸 12 位）")
        exit(2)
    }
    // 包结构自查：NIC 是按比特比对的，长度对但内容错一样唤不醒
    let pkt = WOL.packet(mac)
    let head6 = pkt.prefix(6).allSatisfy { $0 == 0xFF }
    var repeatsOK = true
    for i in 0..<16 where pkt[(6 + i * 6)..<(12 + i * 6)] != mac[...] { repeatsOK = false }
    if pkt.count == 102 && head6 && repeatsOK {
        print("  MAC 规范化为：\(WOL.macString(mac))，魔术包 102 字节 · 结构校验通过")
    } else {
        print("✗ 魔术包结构不对：长度 \(pkt.count)（应 102），同步头 \(head6)，MAC 重复 \(repeatsOK)")
        exit(3)
    }

    let hosts = cfg.wolBroadcast.isEmpty ? WOL.localBroadcasts() : cfg.wolBroadcast
    print("  本机广播地址：\(hosts.isEmpty ? "（无）" : hosts.joined(separator: "、"))")
    print("  UDP 端口：\(cfg.wolPort)")

    let local = WOL.send(mac, hosts: hosts, port: cfg.wolPort)
    print("  本机广播：发出 \(local.sent) 个" + (local.errors.isEmpty ? "" : "；错误：\(local.errors.joined(separator: " / "))"))

    if cfg.wolViaTunnel {
        if let err = WOL.wakeViaTunnel(endpoint: cfg.wolEndpoint, socksPort: cfg.socksPort,
                                       mac: mac, port: cfg.wolPort) {
            print("  经隧道（\(cfg.wolEndpoint)）：失败 —— \(err)")
        } else {
            print("  经隧道（\(cfg.wolEndpoint)）：家里主机已代发")
        }
    } else {
        print("  经隧道：配置里 wolViaTunnel=false，跳过")
    }

    exit(local.sent > 0 ? 0 : 1)
}

if let i = CommandLine.arguments.firstIndex(of: "--woltest") {
    let mac = i + 1 < CommandLine.arguments.count ? CommandLine.arguments[i + 1] : ""
    wolTest(mac)
}

if CommandLine.arguments.contains("--selftest") {
    SelfTest.run()
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

let delegate = AppDelegate()
app.delegate = delegate
app.run()
