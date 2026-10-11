import SwiftUI

// MARK: - 入口
//
// 这里刻意做得极薄：App 入口只负责"挑一个根视图"。
// 任何安全相关的逻辑都不在这里——入口文件是最容易被后续改动
// 顺手塞进杂七杂八东西的地方，保持它是空的能减少将来犯错的机会。

@main
struct PasswordVaultApp: App {
    @StateObject private var model = AppModel.shared

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                // 强制浅色/深色都自己控制：密码在浅色背景上更容易被旁人看到，
                // 这里统一跟随系统，但保证自定义颜色在任何模式下都有足够对比度。
                .preferredColorScheme(nil)
        }
    }
}
