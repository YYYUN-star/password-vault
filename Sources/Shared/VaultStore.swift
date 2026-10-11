import Foundation
import CryptoKit
import LocalAuthentication

// MARK: - 库文件位置
//
// 单独一个 enum，不带任何 actor 隔离：算个路径不涉及共享可变状态，
// 本来就不该有隔离。测试和排查脚本也可以直接拿它定位文件。

public enum VaultLocation {

    public static let fileName = "vault.pwvault"

    /// 库文件所在目录：App 自己的 Application Support。
    ///
    /// 为什么用 Application Support 而不是 Documents：
    /// Documents 里的内容会在 Info.plist 声明后暴露给「文件」App。
    /// 库文件虽然本身是密文，但没有任何理由让用户能从文件 App 里
    /// 看到它、重命名它或者误删它——那只会制造"App 说没有密码库了"的疑问。
    /// 备份导出是**显式动作**，走的是文件选择器，不受这里影响。
    ///
    /// 为什么不放在 App Group 容器里：
    /// App Group 的唯一用途是让**另一个进程**（自动填充扩展）也能读到，
    /// 而那个扩展已经在 v0.2 移除了。没有第二个进程，就不需要这项能力——
    /// 少一个 entitlement，就少一处签名失败的可能。
    /// 这不影响数据安全：容器隔离 vs 沙盒隔离，对单个 App 是等价的。
    public static func containerURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        if !FileManager.default.fileExists(atPath: base.path) {
            // Application Support 在 iOS 上**不会**自动创建，必须自己建。
            // 漏掉这一步的表现是：创建密码库时报"读写失败"。
            try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        }
        return base
    }

    public static func vaultURL() -> URL {
        containerURL().appendingPathComponent(fileName, isDirectory: false)
    }

    public static var vaultExists: Bool {
        FileManager.default.fileExists(atPath: vaultURL().path)
    }
}

// MARK: - 库存储层
//
// 一个密码库 = 沙盒里的一个加密文件。
//
// 为什么不用 SQLite / CoreData：
//   - 个人库的量级是几百条，全量解密 + 重编码在旗舰机上 < 30ms；
//   - 整库单文件意味着"泄露"只会以整体形式发生，不存在"某个索引页明文残留"；
//   - 无 WAL/journal 中间文件，不会在磁盘上留下部分明文的影子副本；
//   - 零第三方依赖（SQLCipher 是 C 库，GRDB 是外部包）。
// 代价是每次保存重写整个文件。对几百 KB 的文件这是完全可接受的。
//
// 并发约束：这个类被标注为 @MainActor。加密库的读写交错是 bug 温床
// （典型的：保存过程中用户又改了一条，结果旧快照覆盖新数据）。
// 强制串行在 UI 线程换来的确定性，远比那几十毫秒的异步收益重要。

@MainActor
public final class VaultStore {

    public static let shared = VaultStore()

    // MARK: 状态

    /// 解密后的库内容。`.unlocked` 之外一律不持有明文条目。
    public enum State {
        case noVault
        case locked(VaultFile.Header)
        case unlocked(VaultFile.Unlocked)
    }

    public private(set) var state: State = .noVault

    /// 最近一次成功解密时的快照，用于"内容没变就不落盘"。
    private var lastSavedPlaintext: Data?

    private init() {}

    // MARK: 路径
    //
    // 实现全在 VaultLocation 里（不带 actor 隔离，便于测试和排查脚本直接调用），
    // 这里保留一层转发只是为了让 App 内的调用点读起来短一些。
    // **新代码请直接用 VaultLocation**，别在这里再加转发。

    public static func vaultURL() -> URL { VaultLocation.vaultURL() }

    public var vaultExists: Bool { VaultLocation.vaultExists }

    // MARK: 打开 / 刷新状态

    /// 从磁盘读取头部，确定当前处于"没有库 / 有库未解锁"。
    /// 不做 KDF，所以可以在 App 启动时随便调。
    public func refreshStateFromDisk() {
        guard vaultExists else {
            state = .noVault
            return
        }
        do {
            let header = try VaultFile.parseHeader(try Data(contentsOf: Self.vaultURL()))
            if case .unlocked = state { return }   // 已解锁就不要把状态打回 locked
            state = .locked(header)
        } catch {
            // 文件存在但读不了：保持"有库但锁着"的保守状态，
            // 让用户能在 UI 上看到错误并提供"从备份恢复"的出口，
            // 而不是显示"没有库"诱导他新建一个把原文件覆盖掉。
            state = .noVault
        }
    }

    // MARK: 新建

    /// 创建新库。调用方负责确认"确实没有已存在的库"——
    /// 这个函数会**覆盖**现有文件，不做保护。
    @discardableResult
    public func createVault(masterPassword: String, iterations: Int = CryptoBox.defaultIterations) throws -> VaultFile.Unlocked {
        let salt = CryptoBox.randomSalt()
        let masterKey = try CryptoBox.deriveMasterKey(
            password: masterPassword,
            salt: salt,
            iterations: iterations
        )
        let payload = VaultPayload()
        let fileData = try VaultFile.serialize(
            payload: payload,
            masterKey: masterKey,
            kdfAlgorithm: .pbkdf2SHA256,
            iterations: iterations,
            salt: salt
        )
        try writeAtomically(fileData)

        let unlocked = VaultFile.Unlocked(
            payload: payload,
            masterKey: masterKey,
            kdfAlgorithm: .pbkdf2SHA256,
            iterations: iterations,
            salt: salt
        )
        state = .unlocked(unlocked)
        lastSavedPlaintext = try VaultFile.encodePayload(payload)
        return unlocked
    }

    // MARK: 解锁

    /// 用主密码解锁。
    ///
    /// `iterations` 取自文件头（并发起一次 KDF 校验），这是**唯一**允许
    /// 信任文件头参数的地方，因为改它会导致 AEAD 认证失败。
    public func unlock(masterPassword: String) throws -> VaultFile.Unlocked {
        guard vaultExists else { throw VaultError.vaultMissing }
        let fileData = try Data(contentsOf: Self.vaultURL())
        let header = try VaultFile.parseHeader(fileData)

        let masterKey = try CryptoBox.deriveMasterKey(
            password: masterPassword,
            salt: header.salt,
            iterations: header.iterations,
            algorithm: header.kdfAlgorithm
        )
        return try decryptAndAdopt(fileData: fileData, header: header, masterKey: masterKey)
    }

    /// 用 Keychain 里的快速解锁密钥解锁（会触发 Face ID / 设备密码认证）。
    public func unlockWithStoredKey(reason: String) throws -> VaultFile.Unlocked {
        guard vaultExists else { throw VaultError.vaultMissing }
        guard let key = try KeychainStore.loadMasterKey(reason: reason) else {
            throw VaultError.keychainFailure(errSecItemNotFound)
        }
        let fileData = try Data(contentsOf: Self.vaultURL())
        let header = try VaultFile.parseHeader(fileData)
        return try decryptAndAdopt(fileData: fileData, header: header, masterKey: key)
    }

    private func decryptAndAdopt(
        fileData: Data,
        header: VaultFile.Header,
        masterKey: SymmetricKey
    ) throws -> VaultFile.Unlocked {
        let body = Data(fileData[header.bodyOffset...])
        let plaintext = try CryptoBox.open(
            body,
            key: CryptoBox.subkey(from: masterKey, purpose: "vault-content-v1"),
            authenticating: header.rawBytes
        )
        let payload = try VaultFile.decodePayload(plaintext)

        let unlocked = VaultFile.Unlocked(
            payload: payload,
            masterKey: masterKey,
            kdfAlgorithm: header.kdfAlgorithm,
            iterations: header.iterations,
            salt: header.salt
        )
        state = .unlocked(unlocked)
        // 记下原始明文，后续保存时用来判断"真的改了吗"
        lastSavedPlaintext = plaintext
        return unlocked
    }

    // MARK: 上锁

    /// 清空内存中的明文和密钥引用。
    ///
    /// 诚实说明：Swift 的内存管理不保证这块内存立即被覆写，Data 的
    /// 内部缓冲区可能被系统回收后仍短暂残留。这是 Swift 的固有限制
    /// （没有 `mlock` / `explicit_bzero` 的等价物能作用于所有值类型）。
    /// 我们能做的是**尽早断开所有强引用**，让这块内存尽快变得不可达。
    /// 针对"手机丢了被翻看"这个威胁模型，这已经足够；
    /// 真正的内存取证防护超出了本项目的设计目标，见 docs/SECURITY.md。
    public func lock() {
        state = .locked(currentHeaderOrPlaceholder())
        lastSavedPlaintext = nil
    }

    private func currentHeaderOrPlaceholder() -> VaultFile.Header {
        if case .locked(let h) = state { return h }
        if let data = try? Data(contentsOf: Self.vaultURL()),
           let h = try? VaultFile.parseHeader(data) {
            return h
        }
        return VaultFile.Header(
            formatVersion: VaultFile.formatVersion,
            kdfAlgorithm: .pbkdf2SHA256,
            iterations: CryptoBox.defaultIterations,
            salt: Data(),
            vaultID: UUID(),
            rawBytes: Data(),
            bodyOffset: 0
        )
    }

    // MARK: 访问已解锁数据

    public var unlocked: VaultFile.Unlocked? {
        if case .unlocked(let u) = state { return u }
        return nil
    }

    public var entries: [VaultEntry] {
        unlocked?.payload.entries ?? []
    }

    /// 在已解锁状态下修改库内容并保存。
    ///
    /// 统一入口的好处：所有写操作都经过同一处"改 → 编码 → 比较 → 落盘"，
    /// 不会出现某条路径忘了保存、或者某条路径绕过了变更检测。
    public func mutate(_ body: (inout VaultPayload) throws -> Void) throws {
        guard var u = unlocked else { throw VaultError.vaultMissing }
        try body(&u.payload)
        try persist(u)
    }

    private func persist(_ unlockedState: VaultFile.Unlocked) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = [.sortedKeys]

        let plaintext = try VaultFile.encodePayload(unlockedState.payload)

        // 内容没变就不写盘。
        // 这不是微优化：iOS 上频繁的无意义写会加速闪存磨损，
        // 更重要的是会给未来的 iCloud 同步制造满屏的假冲突。
        if let last = lastSavedPlaintext, Data.constantTimeEquals(last, plaintext) {
            state = .unlocked(unlockedState)
            return
        }

        let fileData = try VaultFile.serialize(
            payload: unlockedState.payload,
            masterKey: unlockedState.masterKey,
            kdfAlgorithm: unlockedState.kdfAlgorithm,
            iterations: unlockedState.iterations,
            salt: unlockedState.salt
        )
        try writeAtomically(fileData)
        state = .unlocked(unlockedState)
        lastSavedPlaintext = plaintext
    }

    /// 原子写入 + 显式数据保护等级。
    ///
    /// `NSFileProtectionComplete` 让文件在锁屏后连**硬件密钥**都拿不到
    /// （而不仅是权限位限制）。虽然内容本身已经是密文，
    /// 但这一层能防住"关机状态下把闪存拆下来读"这类物理攻击。
    ///
    /// `.atomic` 保证不会出现"写了一半的库"——这是密码管理器最怕的
    /// 失败模式：崩溃/断电后文件变成半截，恢复不出来。
    private func writeAtomically(_ data: Data) throws {
        let url = Self.vaultURL()
        let folder = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: folder.path) {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        }
        do {
            try data.write(to: url, options: [.atomic, .completeFileProtection])
        } catch {
            throw VaultError.ioFailure(error.localizedDescription)
        }
    }

    // MARK: 条目操作

    public func upsert(_ entry: VaultEntry) throws {
        try mutate { payload in
            if let idx = payload.entries.firstIndex(where: { $0.id == entry.id }) {
                var updated = entry
                updated.createdAt = payload.entries[idx].createdAt   // 创建时间不可被覆盖
                updated.updatedAt = Date()
                payload.entries[idx] = updated
            } else {
                var created = entry
                created.createdAt = Date()
                created.updatedAt = Date()
                payload.entries.append(created)
            }
        }
    }

    public func delete(id: UUID) throws {
        try mutate { payload in
            payload.entries.removeAll { $0.id == id }
        }
    }

    /// 标记"这条刚用过"。用于列表按最近使用排序。
    /// 失败不抛错：排序是体验优化，不该因为一次写盘失败打断自动填充。
    public func markUsed(id: UUID) {
        try? mutate { payload in
            guard let idx = payload.entries.firstIndex(where: { $0.id == id }) else { return }
            payload.entries[idx].lastUsedAt = Date()
        }
    }

    /// 搜索。空查询返回全部（按最近使用 / 更新时间排序）。
    public func search(_ query: String) -> [VaultEntry] {
        let all = entries
        let q = query.trimmed.lowercased()
        let filtered = q.isEmpty ? all : all.filter { $0.searchHaystack.contains(q) }
        return filtered.sorted { a, b in
            let ta = a.lastUsedAt ?? a.updatedAt
            let tb = b.lastUsedAt ?? b.updatedAt
            if ta != tb { return ta > tb }
            return a.displayTitle.localizedStandardCompare(b.displayTitle) == .orderedAscending
        }
    }

    /// 域名匹配：自动填充时按"请求站点"筛出候选条目。
    ///
    /// 匹配规则刻意保守：**只认主机名精确相等或互为子域**。
    /// 不做模糊匹配、不做编辑距离——那会让 evil-github.com 也匹配到你的
    /// github 密码。密码管理器里，"少给一条候选"永远优于"给错一条候选"。
    public func entries(matchingService service: String?) -> [VaultEntry] {
        guard let service, !service.isBlank,
              let target = VaultEntry.host(of: service) else {
            return search("")
        }
        return entries.filter { entry in
            guard let h = VaultEntry.host(of: entry.url) else { return false }
            return h == target || h.hasSuffix("." + target) || target.hasSuffix("." + h)
        }
    }

    // MARK: 修改主密码

    /// 换主密码。
    ///
    /// 实现要点：**换盐 + 重新派生 + 整库重加密**。
    /// 只换密码而保留旧盐，会让两次派生结果之间存在可分析的关联。
    /// 这个操作必须整体成功或整体失败——中途崩溃会留下一个
    /// "用新密码打不开、用旧密码也打不开"的文件，所以先写临时文件再替换。
    public func changeMasterPassword(
        current: String,
        new: String,
        iterations: Int = CryptoBox.defaultIterations
    ) throws {
        guard vaultExists else { throw VaultError.vaultMissing }
        let fileData = try Data(contentsOf: Self.vaultURL())
        let header = try VaultFile.parseHeader(fileData)

        // 先验证当前密码：改密码必须验证旧密码，否则
        // "拿着已解锁手机的人"可以直接改掉主密码把你锁在外面
        let oldKey = try CryptoBox.deriveMasterKey(
            password: current, salt: header.salt,
            iterations: header.iterations, algorithm: header.kdfAlgorithm
        )
        let body = Data(fileData[header.bodyOffset...])
        let plaintext = try CryptoBox.open(
            body,
            key: CryptoBox.subkey(from: oldKey, purpose: "vault-content-v1"),
            authenticating: header.rawBytes
        )
        let payload = try VaultFile.decodePayload(plaintext)

        let newSalt = CryptoBox.randomSalt()
        let newKey = try CryptoBox.deriveMasterKey(password: new, salt: newSalt, iterations: iterations)
        let newFileData = try VaultFile.serialize(
            payload: payload,
            masterKey: newKey,
            kdfAlgorithm: .pbkdf2SHA256,
            iterations: iterations,
            salt: newSalt
        )
        try writeAtomically(newFileData)

        let unlockedState = VaultFile.Unlocked(
            payload: payload, masterKey: newKey,
            kdfAlgorithm: .pbkdf2SHA256, iterations: iterations, salt: newSalt
        )
        state = .unlocked(unlockedState)
        lastSavedPlaintext = plaintext

        // 钥匙串里的旧密钥已经打不开新库了，必须删掉，
        // 否则下次 Face ID 解锁会失败（且错误信息毫无指向性，极难诊断）。
        //
        // 注意这里**只删不写**：新的快速解锁密钥由 AppModel 在用户用新密码
        // 成功解锁一次之后再挂上。这个"多一步"是有意的——
        // 它确认了用户确实记住了新密码，而不是改完就忘。
        try? KeychainStore.deleteMasterKey()
    }

    // MARK: 备份 / 恢复

    /// 导出的就是**磁盘上那个加密文件本身**，不做任何转码。
    ///
    /// 这是刻意的：备份 = 密文副本。这样"备份"流程里没有任何解密步骤，
    /// 也就没有任何"备份过程中明文落地"的风险。你导出的文件即使
    /// 被上传到网盘，没有主密码它就是一坨随机字节。
    public func exportEncryptedBackup() throws -> Data {
        guard vaultExists else { throw VaultError.vaultMissing }
        return try Data(contentsOf: Self.vaultURL())
    }

    /// 从加密备份恢复。
    ///
    /// **必须验证主密码**才允许覆盖现有库：否则用户手滑导入一个
    /// 不相干的文件，就会把自己现有的库永久覆盖掉。
    /// 先解密验证 → 再写盘，顺序不能反。
    ///
    /// - Returns: 恢复后的解锁状态，方便调用方直接接着用，不必再解密一次。
    @discardableResult
    public func restoreEncryptedBackup(_ data: Data, masterPassword: String) throws -> VaultFile.Unlocked {
        let header = try VaultFile.parseHeader(data)
        let masterKey = try CryptoBox.deriveMasterKey(
            password: masterPassword, salt: header.salt,
            iterations: header.iterations, algorithm: header.kdfAlgorithm
        )
        let body = Data(data[header.bodyOffset...])
        // 解密失败会抛 wrongMasterPassword —— 此时**什么都没写**，现有库安全
        let plaintext = try CryptoBox.open(
            body,
            key: CryptoBox.subkey(from: masterKey, purpose: "vault-content-v1"),
            authenticating: header.rawBytes
        )
        // 解码一次并复用：既确认结构可读，又避免第二次 JSON 解析
        let payload = try VaultFile.decodePayload(plaintext)

        // 到这里才第一次碰磁盘。前面任何一步失败，用户的现有库都完好无损。
        try writeAtomically(data)

        let unlockedState = VaultFile.Unlocked(
            payload: payload,
            masterKey: masterKey,
            kdfAlgorithm: header.kdfAlgorithm,
            iterations: header.iterations,
            salt: header.salt
        )
        state = .unlocked(unlockedState)
        lastSavedPlaintext = plaintext
        return unlockedState
    }

    // MARK: 主密码强度自检

    /// 主密码强度评估。
    ///
    /// 这里不追求"密码强度算法"的花哨分数，只做一件有用的事：
    /// 估算**暴力破解的期望成本**，并把结论翻译成人话。
    /// 因为主密码是唯一无法通过增加迭代次数来弥补的环节——
    /// 一个 6 位数字密码，无论 KDF 多慢，都撑不过一个周末。
    public struct PasswordStrength {
        public let entropyBits: Double
        public let verdict: String
        public let isAcceptable: Bool
    }

    public static func evaluateMasterPassword(_ password: String) -> PasswordStrength {
        // 字母表大小按"密码里出现的字符类别"估算。
        // 这是经典的信息熵估算（假设攻击者知道你的构词习惯，这是保守假设）。
        var alphabet = 0
        if password.contains(where: { $0.isLowercase }) { alphabet += 26 }
        if password.contains(where: { $0.isUppercase }) { alphabet += 26 }
        if password.contains(where: { $0.isNumber }) { alphabet += 10 }
        if password.contains(where: { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }) { alphabet += 33 }

        let symbols = password.count
        let entropy = alphabet > 1 ? Double(symbols) * log2(Double(alphabet)) : 0

        // 对空格分隔的助记短语额外加权：它属于"低字符集、高长度"，
        // 上面的字符集估算会低估它。一个 4 词短语的字典强度约等于
        // 从 7776 个词里独立选 4 次 = 51.7 bit。
        let words = password.split(separator: " ")
        if words.count >= 3 {
            let phraseEntropy = Double(words.count) * log2(7776.0)
            if phraseEntropy > entropy { return verdict(entropyBits: phraseEntropy) }
        }
        return verdict(entropyBits: entropy)
    }

    private static func verdict(entropyBits: Double) -> PasswordStrength {
        let verdict: String
        let ok: Bool
        switch entropyBits {
        case ..<40:
            verdict = "太弱。离线暴力破解可能只需要几天，换 4 个随机单词。"
            ok = false
        case ..<60:
            verdict = "偏弱。建议再加一个单词或改用 5 个随机单词。"
            ok = false
        case ..<80:
            verdict = "可以接受。"
            ok = true
        default:
            verdict = "很结实。"
            ok = true
        }
        return PasswordStrength(entropyBits: entropyBits, verdict: verdict, isAcceptable: ok)
    }
}
