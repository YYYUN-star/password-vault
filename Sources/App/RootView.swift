import SwiftUI

// MARK: - 根视图与隐私遮罩

struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ZStack {
            Group {
                if model.isLocked {
                    if model.hasVault {
                        LockView()
                    } else {
                        OnboardingView()
                    }
                } else {
                    VaultListView()
                }
            }

            // 隐私遮罩：放在最上层，直接盖住下面的真实内容。
            //
            // 为什么不能只在 `scenePhase == .inactive` 时"隐藏文字"：
            // iOS 在切到后台时会给界面拍一张快照用于 App 切换器。
            // 那张快照是**磁盘上的图片**，即使 App 被系统杀掉也还在。
            // 所以必须在拍快照之前把敏感内容替换掉——用不透明遮罩
            // 而不是 blur，因为 blur 在某些渲染时序下会把内容糊进快照。
            if model.shieldActive {
                ShieldView()
                    .transition(.opacity)
                    .zIndex(1)
            }
        }
        .animation(.easeOut(duration: 0.12), value: model.shieldActive)
        .onChange(of: scenePhase) { _, phase in
            model.handleScenePhase(phase)
        }
        .alert("出错了", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("知道了", role: .cancel) { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
    }
}

/// App 切换器遮罩。
///
/// 显示一个中性的图标 + 一句无信息量的文案。
/// 不放库名、不放条目数、不放用户名——遮罩本身也可能是截图内容。
struct ShieldView: View {
    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()
            VStack(spacing: 14) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(.secondary)
                Text("已锁定")
                    .font(.headline)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
