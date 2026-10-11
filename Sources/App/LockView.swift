import SwiftUI
import LocalAuthentication

// MARK: - 锁屏
//
// 设计取舍：**默认先试 Face ID，同时把主密码输入框摆在最显眼的位置。**
//
// 很多密码管理器在这里做纯生物识别的大按钮，结果 Face ID 一旦失败
// （戴口罩、湿手、指纹磨损、系统抽风），用户就卡在一个没有退路的界面上。
// 主密码永远是可用的兜底路径，它应该在第一次渲染时就可见，
// 而不是藏在"其他解锁方式"折叠菜单里。

struct LockView: View {
    @EnvironmentObject private var model: AppModel

    @State private var password = ""
    @State private var didAttemptBiometrics = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            VStack(spacing: 18) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)

                Text("密码库已锁定")
                    .font(.title2.weight(.semibold))

                if model.canQuickUnlock {
                    Text("用 \(biometryName) 或主密码解锁")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                } else {
                    Text("输入主密码解锁")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.bottom, 34)

            VStack(spacing: 12) {
                SecureField("主密码", text: $password)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textContentType(.password)
                    .focused($passwordFocused)
                    .submitLabel(.go)
                    .onSubmit { attemptPasswordUnlock() }
                    .padding(14)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))

                Button {
                    attemptPasswordUnlock()
                } label: {
                    if model.isBusy {
                        ProgressView().frame(maxWidth: .infinity)
                    } else {
                        Text("解锁").frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(password.isEmpty || model.isBusy)

                if model.canQuickUnlock {
                    Button {
                        Task { await model.quickUnlock() }
                    } label: {
                        Label("用 \(biometryName) 解锁", systemImage: biometrySymbol)
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(model.isBusy)
                }
            }

            Spacer()

            if model.quickUnlockStale {
                Text("主密码已修改，请先用新密码解锁一次以重新启用快速解锁。")
                    .font(.footnote)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 30)
            }
        }
        .padding(22)
        .background(Color(.systemGroupedBackground))
        .onAppear {
            // 只在第一次出现时自动弹一次 Face ID。
            // 不加 `didAttemptBiometrics` 会导致：用户在别处切回来、
            // 或者上锁动画重放时反复弹出人脸识别，非常烦人。
            guard !didAttemptBiometrics, model.canQuickUnlock else { return }
            didAttemptBiometrics = true
            Task { await model.quickUnlock() }
        }
    }

    private func attemptPasswordUnlock() {
        guard !password.isEmpty else { return }
        let candidate = password
        // 先清空输入框再发起解锁：
        // 密码错误时输入框是空的，用户不用先全选删除；
        // 而密码正确时这个字符串也会尽快离开这个 View 的状态。
        password = ""
        passwordFocused = false
        Task { await model.unlock(masterPassword: candidate) }
    }

    private var biometryName: String {
        switch KeychainStore.biometryKind() {
        case .faceID: return "Face ID"
        case .touchID: return "触控 ID"
        case .opticID: return "Optic ID"
        default: return "设备密码"
        }
    }

    private var biometrySymbol: String {
        switch KeychainStore.biometryKind() {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        default: return "lock.open"
        }
    }
}
