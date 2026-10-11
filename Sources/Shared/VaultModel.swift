import Foundation

// MARK: - 数据模型
//
// 设计原则：模型层不做任何 IO、不碰密钥。
// 它只是"会被序列化成 JSON 再整体加密"的纯数据，这样内存里的
// 敏感数据生命周期尽量短和服务层可控。

/// 一条密码记录。
public struct VaultEntry: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var title: String
    public var username: String
    public var password: String
    public var url: String
    public var notes: String
    public var tags: [String]
    public var createdAt: Date
    public var updatedAt: Date
    /// 最近一次使用（复制密码 / 自动填充）的时间，用于列表排序。
    public var lastUsedAt: Date?

    public init(
        id: UUID = UUID(),
        title: String = "",
        username: String = "",
        password: String = "",
        url: String = "",
        notes: String = "",
        tags: [String] = [],
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        lastUsedAt: Date? = nil
    ) {
        self.id = id
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.tags = tags
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.lastUsedAt = lastUsedAt
    }

    /// 列表里显示的标题：标题为空时退化成域名或用户名，避免出现一行空白。
    public var displayTitle: String {
        if !title.trimmed.isEmpty { return title.trimmed }
        if let host = Self.host(of: url) { return host }
        if !username.trimmed.isEmpty { return username.trimmed }
        return "(未命名)"
    }

    /// 列表里显示的副标题优先级：用户名 > 域名。
    public var displaySubtitle: String {
        let u = username.trimmed
        if !u.isEmpty { return u }
        return Self.host(of: url) ?? ""
    }

    /// 从任意用户输入里尽力抽出主机名。
    /// 用户会写 "github.com"、"https://github.com/login"、"www.github.com"，
    /// 甚至只贴一个完整 URL。这里统一归一化成小写主机名，
    /// 供排序、分组和自动填充时的域名匹配使用。
    public static func host(of raw: String) -> String? {
        var s = raw.trimmed.lowercased()
        guard !s.isEmpty else { return nil }
        if !s.contains("://") { s = "https://" + s }
        guard let host = URLComponents(string: s)?.host else { return nil }
        // 去掉 www. 前缀，否则 "www.github.com" 和 "github.com" 会被当成两个站点
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    /// 用于搜索的合并文本（预先把小写结果算好，列表过滤时直接 contains，避免逐字符重复转换）。
    public var searchHaystack: String {
        [title, username, url, notes, tags.joined(separator: " ")]
            .joined(separator: "\u{1F}")
            .lowercased()
    }
}

/// 要被加密的完整载荷。
///
/// `schema` 是给未来迁移用的：以后加字段时先读旧 schema 再升级，
/// 而不是让解码直接抛错把用户的库变成一堆无法打开的字节。
public struct VaultPayload: Codable, Sendable {
    public static let currentSchema = 1

    public var schema: Int
    public var entries: [VaultEntry]
    /// 库标识：换机导入时用来确认"这是同一个库"，也用于防止备份被张冠李戴。
    public var vaultID: UUID

    public init(schema: Int = VaultPayload.currentSchema, entries: [VaultEntry] = [], vaultID: UUID = UUID()) {
        self.schema = schema
        self.entries = entries
        self.vaultID = vaultID
    }

    enum CodingKeys: String, CodingKey {
        case schema, entries
        case vaultID = "vault_id"
    }
}

// MARK: - 展示辅助

public extension VaultEntry {
    /// 给列表显示用的 URL 文本（去掉协议头，太长就省略中间）。
    var displayURL: String {
        var s = url.trimmed
        for prefix in ["https://", "http://"] where s.lowercased().hasPrefix(prefix) {
            s = String(s.dropFirst(prefix.count))
        }
        return s
    }

    /// 站点首字母，用于列表上的圆形图标。
    ///
    /// 刻意**不联网抓 favicon**：那会把"我在用哪些网站"这件事
    /// 实时泄露给一堆第三方服务器，即使请求本身不含账号密码。
    /// 密码管理器最不该做的就是主动往外发请求。
    var monogram: String {
        let source = displayTitle
        guard let first = source.first else { return "?" }
        return String(first).uppercased()
    }

    /// 稳定的颜色索引，让同一条目每次显示同一个颜色。
    var monogramColorIndex: Int {
        abs(id.uuidString.hashValue) % 6
    }
}

// MARK: - 小工具

public extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }

    var isBlank: Bool { trimmed.isEmpty }
}

public extension Data {
    /// 常量时间比较。
    ///
    /// 直觉上"比较两个校验值"用 `==` 就行，但 `==` 会在第一个不同字节处提前返回，
    /// 泄露"前几个字节猜对了"的时序信息。这里场景虽然不直接暴露给远程攻击者，
    /// 但常量时间比较的代价是零，没有理由不用。
    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<lhs.count {
            diff |= lhs[lhs.startIndex + i] ^ rhs[rhs.startIndex + i]
        }
        return diff == 0
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - 错误类型

/// 统一的错误出口。
///
/// 关键约束：**面向用户的消息里绝不包含密钥、迭代次数、解密后数据片段**。
/// 攻击者拿到的是 UI 截图或崩溃日志，错误文案本身就是泄露面。
public enum VaultError: LocalizedError, Equatable {
    case vaultMissing
    case vaultCorrupted(String)
    case wrongMasterPassword
    case unsupportedFormat(Int)
    case keychainFailure(OSStatus)
    case biometricsUnavailable
    case userCancelled
    case ioFailure(String)
    case cryptoFailure(String)

    public var errorDescription: String? {
        switch self {
        case .vaultMissing:
            return "还没有密码库，先创建一个。"
        case .vaultCorrupted:
            return "密码库文件损坏或不是本 App 的文件。"
        case .wrongMasterPassword:
            return "主密码不对。"
        case .unsupportedFormat(let v):
            return "这个密码库是更新版本（v\(v)）创建的，请先升级 App。"
        case .keychainFailure:
            return "系统钥匙串操作失败，请重启 App 再试。"
        case .biometricsUnavailable:
            return "这台设备没有可用的 Face ID / Touch ID，请改用主密码解锁。"
        case .userCancelled:
            return "已取消。"
        case .ioFailure(let m):
            return "读写失败：\(m)"
        case .cryptoFailure(let m):
            return "加密操作失败：\(m)"
        }
    }
}
