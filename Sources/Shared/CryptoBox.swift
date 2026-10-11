import Foundation
import CryptoKit
import CommonCrypto

// MARK: - 加密内核
//
// 这个文件是整个软件的地基。三条铁律：
//
// 1. **不自己发明密码学。** 所有原语来自 CommonCrypto / CryptoKit，
//    也就是 Apple 系统里的实现（底层是 corecrypto）。没有任何第三方依赖。
// 2. **不做"加密后再算个校验和"这种自创结构。** 统一用 AEAD（AES-GCM）：
//    一个密钥、一段明文、一段 AAD（附加认证数据），要么完整还原，要么整体失败。
// 3. **密钥材料用完就尽量早地丢掉引用**，不在内存里留存"方便下次用"的副本。
//
// 威胁模型对齐：防"手机丢了/被人翻看"。这不是防国家级取证的设计，
// 详见 docs/SECURITY.md 里"不防什么"一节。

public enum CryptoBox {

    // MARK: 参数

    /// KDF 算法标识，写进文件头。
    /// 存数字而不是字符串：文件头将来可能被手工编辑，数字更好校验，
    /// 也避免了字符串编码/大小写带来的歧义。
    public enum KDFAlgorithm: UInt8, Codable {
        case pbkdf2SHA256 = 1
        // 预留给 Argon2id。将来支持时新增 case，老库照旧按 1 解读，不需要迁移。
        // case argon2id = 2
    }

    /// 迭代次数下限。
    ///
    /// 这里用一个硬下界做"防呆"：如果只从文件头读迭代次数，那么
    /// 一个被篡改的备份可以把 iterations 改成 1，把暴力破解成本降到零。
    /// 由于文件头是 AAD 的一部分、篡改会导致解密失败，所以这条更多是
    /// 二次防线；但成本极低，值得加。
    public static let minimumIterations = 100_000
    public static let defaultIterations = 600_000

    // MARK: 主密钥派生

    /// 由主密码派生 32 字节主密钥。
    ///
    /// 为什么是 PBKDF2-HMAC-SHA256 而不是 Argon2id：
    /// Argon2id 抗 GPU 更强，是更好的选择，但 iOS 系统没有内置实现，
    /// 引第三方 C 库会显著增加构建复杂度和供应链风险。对"自己用"的
    /// 威胁模型（攻击者拿到手机、有物理接触、有时间限制），
    /// 60 万次迭代的 PBKDF2 已经足够。文件头保留了算法标识位，
    /// 将来可以无损升级到 Argon2id。
    ///
    /// - Note: 这一步是**故意慢**的。旗舰机上 60 万次约 0.3–0.8 秒。
    ///   慢就是安全性本身。别为了"流畅"把它调低。
    public static func deriveMasterKey(
        password: String,
        salt: Data,
        iterations: Int,
        algorithm: KDFAlgorithm = .pbkdf2SHA256
    ) throws -> SymmetricKey {
        guard iterations >= minimumIterations else {
            throw VaultError.cryptoFailure("KDF 迭代次数低于安全下限")
        }
        guard salt.count >= 16 else {
            throw VaultError.cryptoFailure("KDF 盐长度不足")
        }
        switch algorithm {
        case .pbkdf2SHA256:
            let ikm = try pbkdf2SHA256(password: password, salt: salt, iterations: iterations, keyLength: 32)
            defer { /* ikm 是值类型，出了作用域即无强引用，交给系统回收 */ }
            return SymmetricKey(data: ikm)
        }
    }

    /// PBKDF2-HMAC-SHA256。
    ///
    /// 直接用 CommonCrypto 的 `CCKeyDerivationPBKDF`，而不是自己拼
    /// HMAC 循环：手写 PBKDF2 极易在块索引编码、XOR 顺序上出错，
    /// 而且纯 Swift 循环会比 C 实现慢一个数量级。
    public static func pbkdf2SHA256(
        password: String,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) throws -> Data {
        // 用 UTF-8 字节而不是 UTF-16：确保在其他平台/其他实现上能复现同一结果
        // （例如你以后想在 Mac 上写个恢复脚本）。
        let passwordBytes = Array(password.utf8)
        var derived = Data(count: keyLength)

        let status: Int32 = derived.withUnsafeMutableBytes { derivedBuf in
            salt.withUnsafeBytes { saltBuf in
                passwordBytes.withUnsafeBufferPointer { pwBuf in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        // 这里不用 `$0.baseAddress?.assumingMemoryBound(to: Int8.self)` 的
                        // 可空形式，而是重新绑定非空指针：CCKeyDerivationPBKDF 不接受 NULL 密码
                        pwBuf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pwBuf.count) { $0 },
                        pwBuf.count,
                        saltBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        saltBuf.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            // 不含任何密钥材料，只报状态码
            throw VaultError.cryptoFailure("PBKDF2 失败(\(status))")
        }
        return derived
    }

    // MARK: 子密钥分离

    /// 从主密钥派生用途隔离的子密钥。
    ///
    /// 为什么不让"加密库的密钥"直接等于"主密钥"：
    /// 一旦将来需要第二把密钥（比如单独给 TOTP 种子、给备份、给云同步），
    /// 直接复用主密钥会让两处密文共享同一密钥，一处泄露即全泄露。
    /// HKDF 让不同用途的密钥在密码学上互相独立，而且成本几乎为零。
    public static func subkey(from masterKey: SymmetricKey, purpose: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            salt: Data(),                       // 盐已在主密钥派生阶段用了随机盐，这里不需要重复
            info: Data(purpose.utf8),           // 用途标签就是域分隔符
            outputByteCount: 32
        )
    }

    /// 校验值：用来区分"主密码打错了"和"文件坏了"。
    ///
    /// 这里**不能**用 AEAD 解密失败来区分两种情况——AES-GCM 只会告诉你
    /// "认证失败"，它不区分密钥错还是密文错。所以额外存一段用主密钥
    /// 派生的校验值。它不是密码学必需品（解密本来就会失败），
    /// 纯粹是为了给用户一句人话错误提示。
    public static func verifier(for masterKey: SymmetricKey) -> Data {
        let key = subkey(from: masterKey, purpose: "verifier-v1")
        // 固定输入 + 固定上下文，输出只依赖密钥
        let mac = HMAC<SHA256>.authenticationCode(for: Data("pwvault.verifier.v1".utf8), using: key)
        return Data(mac)
    }

    // MARK: 认证加密

    /// 加密：返回 nonce || ciphertext || tag（CryptoKit 的 combined 表示）。
    ///
    /// `authenticating` 传入文件头。这一步是**关键设计**：
    /// 头部字段（KDF 参数、盐、库 ID）不加密是必然的（解密前要用），
    /// 但如果它们不参与认证，攻击者就能改 iterations 做降级、
    /// 或换掉 salt 做别的把戏。把头部当 AAD，任何改动都会让解密失败。
    public static func seal(
        _ plaintext: Data,
        key: SymmetricKey,
        authenticating aad: Data
    ) throws -> Data {
        do {
            let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
            guard let combined = sealed.combined else {
                throw VaultError.cryptoFailure("无法序列化密文")
            }
            return combined
        } catch let e as VaultError {
            throw e
        } catch {
            throw VaultError.cryptoFailure("加密失败")
        }
    }

    /// 解密。失败一律归一化成 `wrongMasterPassword`，
    /// 不向调用方区分"密钥错"还是"密文被改"——调用方若据此分支，
    /// 很容易在 UI 上写出可被利用的差异。
    public static func open(
        _ ciphertext: Data,
        key: SymmetricKey,
        authenticating aad: Data
    ) throws -> Data {
        do {
            let box = try AES.GCM.SealedBox(combined: ciphertext)
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw VaultError.wrongMasterPassword
        }
    }

    // MARK: 随机

    /// 密码学安全随机数。CryptoKit 的 SystemRandomNumberGenerator
    /// 直接绑定系统 CSPRNG（iOS 上是 arc4random 的现代替代），
    /// **不要**用 `Int.random(in:)` 的默认实现思路去手搓密码生成器。
    public static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            // 随机数失败是极端异常（系统熵池故障）。绝不能"退化"成伪随机，
            // 那等于静默地把所有密码变成可预测的。直接崩掉比生成弱密码安全。
            fatalError("系统随机数生成失败")
        }
        return Data(bytes)
    }

    public static func randomSalt() -> Data {
        randomBytes(32)
    }
}
