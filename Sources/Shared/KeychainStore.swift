import Foundation
import Security
import LocalAuthentication
import CryptoKit

// MARK: - Keychain 密钥托管
//
// 目的只有一个：**让用户平时不用输主密码。**
//
// 权衡说明（重要，别跳过）：
//
// 主密码派生出 32 字节主密钥后，如果我们把它存进 Keychain，那么
// "拿到手机的人"面对的是 iOS 的硬件密钥保护，而不是 PBKDF2。
// 这比每次输主密码弱——但每次开 App 输 4 个单词的密码，你三天后就会卸载它。
// 一个被实际使用的密码管理器，永远强过一个完美的、被弃用的密码管理器。
//
// 三个约束用来把风险压住：
//   1. `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
//      — 锁屏时读不出来；**不随 iCloud 钥匙串同步**，不会跑到别的设备上。
//   2. `biometryCurrentSet` — 换指纹/换脸（意味着手机可能易主）后此密钥自动失效。
//   3. 主密码永远有效，且不依赖于 Keychain：密钥没了就重新输主密码。
//
// v0.2 起这里只有一个条目了：原先为了 AutoFill 扩展能后台静默读取，
// 额外存了一份"设备已解锁即可读"的副本。自动填充功能移除后，
// 那份弱保护的副本没有存在理由，已经删掉——**少一把钥匙，少一处风险**。

public enum KeychainStore {

    /// Keychain 条目的 account 名。用固定字符串，方便排查。
    private static let masterKeyAccount = "vault.masterkey.v1"

    // MARK: 访问策略

    /// 访问控制策略。
    ///
    /// 现在只剩一种（需要生物识别 + 设备密码回落）。
    /// 保留成 enum 而不是直接写死，是为了将来若要加"仅设备解锁"的
    /// 第二档时有地方落笔——但在没有实际使用场景之前，不要提前加。
    public enum Protection {
        /// 需要 Face ID / Touch ID，失败时可回落到设备密码。
        case biometry
    }

    private static func accessControl(_ protection: Protection) throws -> SecAccessControl {
        let flags: SecAccessControlCreateFlags
        switch protection {
        case .biometry:
            // `.biometryCurrentSet`（而非 `.biometryAny`）：只认"当前录入的"生物特征。
            // 如果攻击者拿到手机后录入了自己的脸，旧密钥直接失效，
            // 逼迫其回到主密码这条路上——而主密码他是猜不出的。
            //
            // `.or .devicePasscode` 是必要的回落：湿手、戴口罩、传感器故障
            // 都会让 Face ID 失败。没有回落路径的话，用户会被卡在一个
            // "只能用主密码"的界面上，而主密码又长又难输。
            flags = [.biometryCurrentSet, .or, .devicePasscode]
        }
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            throw VaultError.cryptoFailure("无法创建访问控制策略")
        }
        return ac
    }

    // MARK: 主密钥读写

    /// 保存主密钥。
    ///
    /// **先删后写**而不是 `SecItemUpdate`：Keychain 在更新时不会替换
    /// access control，导致"原来用 deviceUnlocked 存的，想升级成 biometry"
    /// 这种操作静默失效。删除重建最省心，代价只是一次多余的写。
    @discardableResult
    public static func saveMasterKey(
        _ key: SymmetricKey,
        protection: Protection
    ) throws -> Bool {
        let data = key.withUnsafeBytes { Data($0) }
        try? deleteMasterKey()

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: masterKeyAccount,
            kSecAttrAccessControl as String: try accessControl(protection),
            kSecValueData as String: data
        ]
        // 有 Face ID 时不弹"是否允许"的额外确认框，减少一次迷惑性点击
        if protection == .biometry {
            query[kSecUseAuthenticationContext as String] = LAContext()
        }
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError.keychainFailure(status)
        }
        return true
    }

    /// 读取主密钥（会触发 Face ID / 设备密码认证）。
    ///
    /// - Parameter reason: 显示在认证弹窗上的文案。**不要**把站点名或
    ///   任何库内数据放进这里——“给 github.com 解锁”这类文案会让
    ///   锁屏上出现你的账号信息，属于信息泄露。
    public static func loadMasterKey(reason: String) throws -> SymmetricKey? {
        // 这里不用已废弃的 `kSecUseOperationPrompt`。显式走 LAContext：
        // 语义清楚（先认证、再凭已认证的上下文取数据），
        // 也方便将来需要复用一个已认证的上下文时不必改签名。
        let ctx = LAContext()
        // 认证失败（用户取消 / 没设密码）时不在这里抛错，而是继续往下走，
        // 让 SecItemCopyMatching 返回真实的 Keychain 错误码，
        // 由下面的 switch 统一翻译成用户能懂的提示。
        _ = ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: masterKeyAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: ctx
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else {
                // 长度不对说明条目被破坏，删掉让用户走主密码路径
                try? deleteMasterKey()
                return nil
            }
            return SymmetricKey(data: data)
        case errSecItemNotFound:
            return nil
        case errSecUserCanceled, errSecAuthFailed:
            // 用户主动取消 Face ID：不是错误，是正常操作，交给调用方当作"没解锁"
            throw VaultError.userCancelled
        default:
            throw VaultError.keychainFailure(status)
        }
    }

    /// 静默探测主密钥条目是否存在（**绝不弹任何 UI**）。
    ///
    /// 用途：锁屏界面靠它决定"要不要显示用 Face ID 解锁的按钮"。
    /// 必须不弹窗——在锁屏界面渲染时弹一次认证，是最糟糕的首屏体验。
    public static func masterKeyExistsSilently() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: masterKeyAccount,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
            // 只查存在性，锁屏/后台也不弹窗
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        // errSecInteractionNotAllowed 说明条目存在，只是现在不允许交互读取
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// 当前设备是否有可用的生物识别（且已录入）。
    public static func biometricsAvailable() -> Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    /// 这个命名是为了让旧的调用点继续可读。等价于 `masterKeyExistsSilently()`。
    /// 新代码请直接用 `masterKeyExistsSilently()`——它的名字说明了关键性质：
    /// **不会弹任何 UI**。
    public static func hasMasterKey() -> Bool {
        masterKeyExistsSilently()
    }

    /// 保存快速解锁用的主密钥。
    ///
    /// 注意：**主密码始终是唯一权威**。删掉这把钥匙只会让你下次多输一次主密码，
    /// 不会丢数据。
    ///
    /// v0.2 起这里只写一个条目。原先为了 AutoFill 扩展能后台静默读取，
    /// 额外存了一份 `deviceUnlocked` 保护的副本；那个功能移除后，
    /// 那份弱保护的副本已经删掉。
    public static func saveUnlockKey(_ key: SymmetricKey) throws {
        try saveMasterKey(key, protection: .biometry)
    }

    public static func deleteMasterKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: masterKeyAccount
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultError.keychainFailure(status)
        }
    }

    // MARK: 环境能力探测

    /// 当前设备支持的生物识别类型。用于 UI 文案（"用 Face ID 解锁" vs "用触控 ID 解锁"）。
    public static func biometryKind() -> LABiometryType {
        let ctx = LAContext()
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return ctx.biometryType
    }

    /// 服务名。用 Bundle ID 作为前缀，避免与其他 App 的 Keychain 条目重名
    /// （虽然 Keychain 本身有访问组隔离，但同名条目在调试时很迷惑人）。
    private static var serviceName: String {
        let bundleID = Bundle.main.bundleIdentifier ?? "com.example.passwordvault"
        // 这个后缀剥离逻辑保留着，是为了兼容"曾经装过带自动填充扩展的版本"的情况：
        // 那种情况下钥匙串条目是用扩展的 service 名写的，直接改服务名会读不到旧密钥，
        // 表现为"突然要求输主密码"。留着它，旧条目还能被正确命中。
        if bundleID.hasSuffix(".autofill") {
            return String(bundleID.dropLast(".autofill".count)) + ".keychain"
        }
        return bundleID + ".keychain"
    }
}
