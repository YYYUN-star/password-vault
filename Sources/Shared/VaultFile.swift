import Foundation
import CryptoKit

// MARK: - 库文件格式
//
// 格式刻意设计成"可自我描述 + 可向前兼容"，因为密码库文件是**你要存十年的东西**。
// 一个只能被当前版本 App 读的文件格式，等于给自己埋了一颗雷。
//
// 二进制布局：
//
//   ┌──────────────────────────────────────────────┐
//   │ MAGIC      "PWVLT1\0\0"        8 字节         │
//   ├──────────────────────────────────────────────┤
//   │ VERSION    UInt16 BE           2 字节         │  ← 格式版本
//   ├──────────────────────────────────────────────┤
//   │ HEADER_LEN UInt32 BE           4 字节         │  ← 头部（含以上全部）总长
//   ├──────────────────────────────────────────────┤
//   │ TLV FIELDS                     N 字节         │  ← 见下
//   ├──────────────────────────────────────────────┤
//   │ BODY       nonce||ct||tag     M 字节         │  ← AES-GCM，AAD = 上面全部字节
//   └──────────────────────────────────────────────┘
//
// TLV 字段（tag 1 字节 + 长度 4 字节 BE + 内容）：
//   0x01 KDF_ALGO    1 字节（1 = PBKDF2-SHA256）
//   0x02 KDF_ITER    UInt32 BE
//   0x03 SALT        16..64 字节
//   0x04 VAULT_ID    16 字节
//   0x7F RESERVED    任意（解析时跳过；老版本读新文件靠这个不崩）
//
// 为什么要 TLV 而不是直接 Codable JSON：加字段时老版本能"跳过未知字段继续读"，
// 而不是解码失败。JSON 也能做，但二进制省事且没有编码歧义。

public struct VaultFile {

    public static let magic = Data("PWVLT1\u{0}\u{0}".utf8)   // 8 字节
    public static let formatVersion: UInt16 = 1

    enum FieldTag: UInt8 {
        case kdfAlgorithm = 0x01
        case kdfIterations = 0x02
        case salt = 0x03
        case vaultID = 0x04
        case reserved = 0x7F
    }

    /// 解密后的完整状态。
    public struct Unlocked {
        public var payload: VaultPayload
        public var masterKey: SymmetricKey
        public var kdfAlgorithm: CryptoBox.KDFAlgorithm
        public var iterations: Int
        public var salt: Data

        /// 库内容密钥：由主密钥经 HKDF 分离，不与主密钥共用。
        /// 主密钥只用于派生校验值和这把内容密钥。
        public var contentKey: SymmetricKey {
            CryptoBox.subkey(from: masterKey, purpose: "vault-content-v1")
        }
    }

    // MARK: 元信息（不解密即可读取）

    /// 只读头部的轻量解析结果。
    ///
    /// 用途：App 启动时要先知道"这个库是不是本 App 的""要不要升级格式"，
    /// 而这两件事都不该触发一次 60 万次迭代的 KDF。
    ///
    /// 显式标注 `Sendable`：它是不可变值类型，全部存储属性都是值类型，
    /// 满足要求没有代价，但能让它在并发边界上自由传递。
    public struct Header: Sendable {
        public var formatVersion: UInt16
        public var kdfAlgorithm: CryptoBox.KDFAlgorithm
        public var iterations: Int
        public var salt: Data
        public var vaultID: UUID
        /// 头部原始字节。解密时必须原样作为 AAD 传回去——
        /// 重新序列化可能因为字段顺序/填充差异产生不同字节，导致解密失败。
        /// 直接复用读到的原始字节是最稳的做法。
        public var rawBytes: Data
        /// 密文起始偏移
        public var bodyOffset: Int
    }

    // MARK: 解析

    public static func parseHeader(_ fileData: Data) throws -> Header {
        guard fileData.count > magic.count + 2 + 4 else {
            throw VaultError.vaultCorrupted("文件过短")
        }
        guard fileData.prefix(magic.count) == magic else {
            throw VaultError.vaultCorrupted("magic 不匹配")
        }
        var cursor = fileData.startIndex + magic.count

        let version = try readUInt16(fileData, &cursor)
        guard version <= formatVersion else {
            throw VaultError.unsupportedFormat(Int(version))
        }

        let headerLen = Int(try readUInt32(fileData, &cursor))
        let headerEnd = fileData.startIndex + headerLen
        guard headerLen >= magic.count + 6, headerEnd <= fileData.endIndex else {
            throw VaultError.vaultCorrupted("头部长度非法")
        }

        var algorithm: CryptoBox.KDFAlgorithm?
        var iterations: Int?
        var salt: Data?
        var vaultID: UUID?

        while cursor < headerEnd {
            let tag = fileData[cursor]
            cursor += 1
            let len = Int(try readUInt32(fileData, &cursor))
            guard len >= 0, cursor + len <= headerEnd else {
                throw VaultError.vaultCorrupted("字段长度越界")
            }
            let value = fileData[cursor..<(cursor + len)]
            cursor += len

            switch FieldTag(rawValue: tag) {
            case .kdfAlgorithm:
                guard value.count == 1, let raw = value.first else {
                    throw VaultError.vaultCorrupted("KDF 算法字段非法")
                }
                guard let a = CryptoBox.KDFAlgorithm(rawValue: raw) else {
                    throw VaultError.cryptoFailure("未知的 KDF 算法标识")
                }
                algorithm = a
            case .kdfIterations:
                guard value.count == 4 else { throw VaultError.vaultCorrupted("迭代次数字段非法") }
                var n = 0
                for b in value { n = (n << 8) | Int(b) }
                iterations = n
            case .salt:
                salt = Data(value)
            case .vaultID:
                guard value.count == 16 else { throw VaultError.vaultCorrupted("库 ID 字段非法") }
                vaultID = UUID(uuid: (
                    value[value.startIndex],     value[value.startIndex + 1],
                    value[value.startIndex + 2], value[value.startIndex + 3],
                    value[value.startIndex + 4], value[value.startIndex + 5],
                    value[value.startIndex + 6], value[value.startIndex + 7],
                    value[value.startIndex + 8], value[value.startIndex + 9],
                    value[value.startIndex + 10], value[value.startIndex + 11],
                    value[value.startIndex + 12], value[value.startIndex + 13],
                    value[value.startIndex + 14], value[value.startIndex + 15]
                ))
            case .reserved, .none:
                continue    // 未知字段一律跳过：这是向前兼容的关键
            }
        }

        guard let algo = algorithm, let iter = iterations, let s = salt, let vid = vaultID else {
            throw VaultError.vaultCorrupted("头部缺少必需字段")
        }
        guard s.count >= 16 else { throw VaultError.vaultCorrupted("盐长度不足") }

        return Header(
            formatVersion: version,
            kdfAlgorithm: algo,
            iterations: iter,
            salt: s,
            vaultID: vid,
            rawBytes: Data(fileData[fileData.startIndex..<headerEnd]),
            bodyOffset: headerEnd - fileData.startIndex
        )
    }

    // MARK: 序列化

    public static func serialize(
        payload: VaultPayload,
        masterKey: SymmetricKey,
        kdfAlgorithm: CryptoBox.KDFAlgorithm,
        iterations: Int,
        salt: Data
    ) throws -> Data {
        var header = magic
        header.append(contentsOf: uint16BE(formatVersion))

        var fields = Data()
        fields.append(contentsOf: tlv(.kdfAlgorithm, Data([kdfAlgorithm.rawValue])))
        fields.append(contentsOf: tlv(.kdfIterations, uint32BE(UInt32(iterations))))
        fields.append(contentsOf: tlv(.salt, salt))

        // 显式拆 uuid 元组，而不是 withUnsafeBytes：跨平台/跨版本的内存布局假设
        // 不值得为省两行代码去冒风险
        let u = payload.vaultID.uuid
        let uuidBytes = Data([
            u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
            u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15
        ])
        fields.append(contentsOf: tlv(.vaultID, uuidBytes))

        // HEADER_LEN 必须涵盖 magic + version + 自身这 4 字节
        let headerLen = header.count + 4 + fields.count
        header.append(contentsOf: uint32BE(UInt32(headerLen)))
        header.append(fields)

        // AAD 就是头部原始字节：任何字段被改，解密立刻失败
        let body = try CryptoBox.seal(
            try encodePayload(payload),
            key: CryptoBox.subkey(from: masterKey, purpose: "vault-content-v1"),
            authenticating: header
        )
        return header + body
    }

    // MARK: 载荷编解码

    /// JSON 编码 + 排序键。
    ///
    /// 排序键是必须的：如果两次编码同一份数据产生不同字节，那么
    /// "内容没变就不重写文件"的判断会失效，同步场景下还会产生无意义的冲突。
    public static func encodePayload(_ payload: VaultPayload) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(payload)
    }

    public static func decodePayload(_ data: Data) throws -> VaultPayload {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        do {
            return try decoder.decode(VaultPayload.self, from: data)
        } catch {
            // 走到这里说明 AEAD 已经通过（数据没被篡改、密钥也对），
            // 那问题只可能是：文件由更新版本的 App 写入了不认识的字段结构。
            throw VaultError.vaultCorrupted("载荷结构无法识别")
        }
    }

    // MARK: 字节序工具（显式大端，避免端序假设）

    static func uint16BE(_ v: UInt16) -> Data {
        Data([UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)])
    }

    static func uint32BE(_ v: UInt32) -> Data {
        Data([
            UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF),
            UInt8(v >> 8 & 0xFF),  UInt8(v & 0xFF)
        ])
    }

    static func tlv(_ tag: FieldTag, _ value: Data) -> Data {
        var d = Data([tag.rawValue])
        d.append(uint32BE(UInt32(value.count)))
        d.append(value)
        return d
    }

    private static func readUInt16(_ data: Data, _ cursor: inout Data.Index) throws -> UInt16 {
        guard cursor + 2 <= data.endIndex else { throw VaultError.vaultCorrupted("读取越界") }
        let v = UInt16(data[cursor]) << 8 | UInt16(data[cursor + 1])
        cursor += 2
        return v
    }

    private static func readUInt32(_ data: Data, _ cursor: inout Data.Index) throws -> UInt32 {
        guard cursor + 4 <= data.endIndex else { throw VaultError.vaultCorrupted("读取越界") }
        let v = UInt32(data[cursor]) << 24
            | UInt32(data[cursor + 1]) << 16
            | UInt32(data[cursor + 2]) << 8
            | UInt32(data[cursor + 3])
        cursor += 4
        return v
    }
}
