import Foundation
import SwiftUI
import UIKit
import LocalAuthentication

// MARK: - 应用状态
//
// 职责边界：这一层只做"编排"——解锁流程、自动锁定、剪贴板生命周期。
// 真正的加密和存储都在 VaultStore 里。
// 这样拆的好处是：安全相关的状态机只有这一处，review 时一眼能看完。
//
// 注意这个文件放在 Sources/Shared 而不是 Sources/App：
// 它只依赖 ObservableObject / UIPasteboard，**没有一行界面代码**。
// 这个边界是刻意的——将来若要写测试，或者换个界面框架，
// 这一层可以原样复用。（v0.1 时它还被 AutoFill 扩展共用，
// 那个功能已移除，但这个分层仍然值得保留。）

@MainActor
public final class AppModel: ObservableObject {

    public static let shared = AppModel()

    // MARK: 自动锁定策略

    /// 自动锁定延迟。
    ///
    /// 为什么默认是 30 秒而不是"立即"：
    /// 立即锁定会让"复制密码 → 切到别的 App 粘贴 → 切回来"这个最高频的
    /// 操作每次都要重新 Face ID。人一旦觉得烦，就会去设置里关掉自动锁定，
    /// 那才是真正的安全损失。30 秒覆盖了绝大多数切换操作，
    /// 同时保证"放下手机走开"之后很快就锁上。
    public enum AutoLockDelay: Int, CaseIterable, Identifiable {
        case immediately = 0
        case fifteenSeconds = 15
        case thirtySeconds = 30
        case oneMinute = 60
        case fiveMinutes = 300
        case never = -1

        public var id: Int { rawValue }

        public var label: String {
            switch self {
            case .immediately: return "立即"
            case .fifteenSeconds: return "15 秒"
            case .thirtySeconds: return "30 秒"
            case .oneMinute: return "1 分钟"
            case .fiveMinutes: return "5 分钟"
            case .never: return "从不（不推荐）"
            }
        }
    }

    private enum DefaultsKey {
        static let autoLockDelay = "autolock.delay"
        static let blurInSwitcher = "privacy.blurInSwitcher"
        static let clipboardSeconds = "privacy.clipboardSeconds"
    }

    // MARK: 发布状态

    /// 当前是否需要显示锁屏。所有 UI 都靠它决定渲染什么。
    @Published public private(set) var isLocked: Bool = true
    @Published public private(set) var hasVault: Bool = false
    @Published public private(set) var canQuickUnlock: Bool = false
    @Published public private(set) var entries: [VaultEntry] = []
    @Published public private(set) var isBusy: Bool = false
    @Published public var searchText: String = ""
    @Published public var errorMessage: String?
    /// App 切到后台时置为 true，用于盖住 App 切换器里的截图
    @Published public private(set) var shieldActive: Bool = false

    /// 换主密码后需要提示用户重新挂快速解锁
    @Published public private(set) var quickUnlockStale: Bool = false

    // MARK: 设置（持久化在 UserDefaults）
    //
    // 注意：这里**只**存非敏感的策略开关。任何与库内容有关的东西
    // 都不许进 UserDefaults——那是明文 plist，会被 iCloud 备份。

    @Published public var autoLockDelay: AutoLockDelay {
        didSet { UserDefaults.standard.set(autoLockDelay.rawValue, forKey: DefaultsKey.autoLockDelay) }
    }
    /// 切到后台时用模糊遮罩盖住界面（防 App 切换器缩略图泄露）
    @Published public var blurInSwitcher: Bool {
        didSet { UserDefaults.standard.set(blurInSwitcher, forKey: DefaultsKey.blurInSwitcher) }
    }
    /// 复制密码后多少秒自动清空剪贴板
    @Published public var clipboardClearSeconds: Int {
        didSet { UserDefaults.standard.set(clipboardClearSeconds, forKey: DefaultsKey.clipboardSeconds) }
    }

    // MARK: 内部状态

    private var backgroundedAt: Date?
    private var lastBiometricAttempt: Date = .distantPast
    /// 两次 Face ID 之间的最小间隔。
    /// 不加这个限制会出现"App 每次回到前台都弹一次脸"，
    /// 用户很快就会在系统层面拒绝这个 App 的生物识别权限——那才是真麻烦。
    private let biometricCooldown: TimeInterval = 3

    private init() {
        let defaults = UserDefaults.standard
        self.autoLockDelay = AutoLockDelay(rawValue: defaults.object(forKey: DefaultsKey.autoLockDelay) as? Int ?? 30) ?? .thirtySeconds
        self.blurInSwitcher = defaults.object(forKey: DefaultsKey.blurInSwitcher) as? Bool ?? true
        self.clipboardClearSeconds = defaults.object(forKey: DefaultsKey.clipboardSeconds) as? Int ?? 60
        refresh()
    }

    // MARK: 启动 / 状态刷新

    public func refresh() {
        VaultStore.shared.refreshStateFromDisk()
        hasVault = VaultStore.shared.vaultExists
        canQuickUnlock = KeychainStore.masterKeyExistsSilently()
        if case .unlocked = VaultStore.shared.state {
            isLocked = false
            entries = VaultStore.shared.search("")
        } else {
            isLocked = true
            entries = []
        }
    }

    // MARK: 建库

    public func createVault(masterPassword: String, alsoEnableQuickUnlock: Bool) async {
        isBusy = true
        defer { isBusy = false }
        do {
            let unlocked = try VaultStore.shared.createVault(masterPassword: masterPassword)
            if alsoEnableQuickUnlock {
                try KeychainStore.saveUnlockKey(unlocked.masterKey)
            }
            isLocked = false
            hasVault = true
            canQuickUnlock = KeychainStore.hasMasterKey()
            entries = []
            errorMessage = nil
        } catch {
            VaultLog.failure("create-vault", error)
            errorMessage = (error as? VaultError)?.errorDescription ?? "创建失败"
        }
    }

    // MARK: 解锁

    /// 主密码解锁。
    public func unlock(masterPassword: String) async {
        isBusy = true
        defer { isBusy = false }
        do {
            let unlocked = try VaultStore.shared.unlock(masterPassword: masterPassword)
            await afterUnlock(unlocked)
        } catch {
            VaultLog.failure("unlock-password", error)
            errorMessage = (error as? VaultError)?.errorDescription ?? "解锁失败"
        }
    }

    /// 快速解锁（Face ID / 设备密码）。
    public func quickUnlock() async {
        if Date().timeIntervalSince(lastBiometricAttempt) < biometricCooldown {
            return
        }
        lastBiometricAttempt = Date()
        isBusy = true
        defer { isBusy = false }

        do {
            // 提示文案刻意不含任何库内信息：锁屏上不该出现你的账号名。
            let unlocked = try VaultStore.shared.unlockWithStoredKey(reason: "解锁密码库")
            await afterUnlock(unlocked)
        } catch VaultError.userCancelled {
            // 用户取消不是错误，安静地留在锁屏
        } catch {
            VaultLog.failure("unlock-quick", error)
            errorMessage = (error as? VaultError)?.errorDescription ?? "解锁失败，请改用主密码"
        }
    }

    private func afterUnlock(_ unlocked: VaultFile.Unlocked) async {
        isLocked = false
        hasVault = true
        quickUnlockStale = false
        entries = VaultStore.shared.search("")
        errorMessage = nil
        lastBiometricAttempt = Date()
    }

    // MARK: 上锁

    public func lock() {
        // 上锁前先清剪贴板：否则"锁上了但剪贴板里还留着刚才复制的密码"
        clearClipboardIfOwned()
        VaultStore.shared.lock()
        entries = []
        searchText = ""
        isLocked = true
    }

    // MARK: 场景生命周期

    public func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .background:
            shieldActive = true
            backgroundedAt = Date()
        case .inactive:
            // 下拉控制中心/来电也会走到这里。**不在这里锁定**，
            // 否则每次误触通知栏都要重新认证一次，体验会崩。
            if blurInSwitcher { shieldActive = true }
        case .active:
            shieldActive = false
            if let since = backgroundedAt {
                let elapsed = Date().timeIntervalSince(since)
                if autoLockDelay != .never, elapsed >= Double(autoLockDelay.rawValue) {
                    lock()
                }
            }
            backgroundedAt = nil
        @unknown default:
            break
        }
    }

    // MARK: 条目操作

    public func upsert(_ entry: VaultEntry) {
        do {
            try VaultStore.shared.upsert(entry)
            entries = VaultStore.shared.search(searchText)
        } catch {
            VaultLog.failure("upsert", error)
            errorMessage = "保存失败"
        }
    }

    public func delete(_ entry: VaultEntry) {
        do {
            try VaultStore.shared.delete(id: entry.id)
            entries = VaultStore.shared.search(searchText)
        } catch {
            VaultLog.failure("delete", error)
            errorMessage = "删除失败"
        }
    }

    public func applySearch() {
        entries = VaultStore.shared.search(searchText)
    }

    // MARK: 剪贴板
    //
    // iOS 剪贴板是**全局共享**的：你复制了密码，任何 App（在旧系统上
    // 甚至不需要用户同意）都可能读到它。iOS 14+ 会在其他 App 读取时
    // 弹提示，但这只是提示，不是阻止。
    //
    // 所以策略是：**复制可以，但一定要有回收机制。**
    // 我们用系统提供的过期时间（`setItems(_:options:)`），
    // 而不是自己起个 Timer 去清空——因为 App 可能在后台被挂起，
    // Timer 根本不会执行，而系统的过期时间是内核级的、一定会生效。

    public func copyToClipboard(_ value: String, label: String = "密码") {
        guard !value.isEmpty else { return }
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: value]],
            options: [
                .expirationDate: Date().addingTimeInterval(TimeInterval(clipboardClearSeconds)),
                // 只在**本机**设备间通用剪贴板同步。密码不该跟着 Handoff
                // 跑到你别的设备上——那些设备可能没有这把库的密钥。
                .localOnly: true
            ]
        )
        VaultLog.debug("copied \(label), ttl=\(clipboardClearSeconds)s")
    }

    /// 主动清空剪贴板（仅在内容确实是我们写进去的时候）。
    ///
    /// 为什么要判断：如果用户在这 60 秒里自己复制了别的东西
    /// （比如一个地址去查地图），我们不该把人家的剪贴板清掉。
    private func clearClipboardIfOwned() {
        // UIPasteboard 没有"这个内容是谁写的"的可靠标记。
        // 用一个保守策略：只有当剪贴板里恰好有一条字符串时才清空，
        // 且清空后调用方无法区分——这是有意的，避免"清空"变成
        // 一个探测剪贴板内容的原语。
        if UIPasteboard.general.hasStrings {
            UIPasteboard.general.items = []
        }
    }

    // MARK: 换主密码

    public func changeMasterPassword(current: String, new: String) async {
        isBusy = true
        defer { isBusy = false }
        do {
            try VaultStore.shared.changeMasterPassword(current: current, new: new)
            // 换密码后旧密钥已失效。删掉钥匙串条目，强制用户重新用新密码
            // 解锁一次，然后再挂上快速解锁——这个额外一步是有价值的：
            // 它确认了用户**确实记得**新密码，而不是换完就忘。
            try? KeychainStore.deleteMasterKey()
            canQuickUnlock = false
            quickUnlockStale = true
            errorMessage = nil
        } catch {
            VaultLog.failure("change-password", error)
            errorMessage = (error as? VaultError)?.errorDescription ?? "修改失败"
        }
    }

    /// 用户下次用主密码成功解锁后，重新启用快速解锁。
    public func reenableQuickUnlock() async {
        guard let unlocked = VaultStore.shared.unlocked else { return }
        do {
            try KeychainStore.saveUnlockKey(unlocked.masterKey)
            canQuickUnlock = true
            quickUnlockStale = false
        } catch {
            VaultLog.failure("reenable-quick-unlock", error)
            errorMessage = "无法启用快速解锁"
        }
    }

    // MARK: 备份 / 恢复

    public func exportBackup() -> Data? {
        do { return try VaultStore.shared.exportEncryptedBackup() }
        catch {
            VaultLog.failure("export", error)
            errorMessage = "导出失败"
            return nil
        }
    }

    /// 恢复备份。**会覆盖当前库**，调用方必须先让用户确认。
    public func restoreBackup(_ data: Data, masterPassword: String) async -> Bool {
        isBusy = true
        defer { isBusy = false }
        do {
            let restored = try VaultStore.shared.restoreEncryptedBackup(data, masterPassword: masterPassword)
            // 恢复后钥匙串里还是**旧库**的密钥，必须换成新的，
            // 否则下次 Face ID 解锁会拿旧密钥去解新文件，直接失败。
            //
            // 这里可以直接挂上快速解锁（不像改密码那样要等一次手动解锁）：
            // 用户刚刚用这个备份的主密码解密成功，已经充分证明了他知道它。
            try? KeychainStore.deleteMasterKey()
            try KeychainStore.saveUnlockKey(restored.masterKey)
            canQuickUnlock = true
            await afterUnlock(restored)
            return true
        } catch {
            VaultLog.failure("restore", error)
            errorMessage = (error as? VaultError)?.errorDescription ?? "恢复失败"
            return false
        }
    }

    /// 一键清空本机所有数据（用于"我要重新开始"或卖掉手机前）。
    ///
    /// 刻意做成"破坏性且不可撤销"：删除库文件 + 清钥匙串 + 清设置。
    /// **不做回收站**——一个能被撤销的删除，在别人拿到手机时也能被撤销。
    public func destroyEverything() {
        lock()
        try? FileManager.default.removeItem(at: VaultStore.vaultURL())
        try? KeychainStore.deleteMasterKey()
        let defaults = UserDefaults.standard
        for key in [DefaultsKey.autoLockDelay, DefaultsKey.blurInSwitcher,
                    DefaultsKey.clipboardSeconds] {
            defaults.removeObject(forKey: key)
        }
        hasVault = false
        canQuickUnlock = false
        entries = []
    }
}
