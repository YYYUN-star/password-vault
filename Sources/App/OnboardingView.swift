import SwiftUI

// MARK: - 首次使用：创建密码库
//
// 这个界面承担了整个 App 最重要的一次沟通：**主密码丢了就真的没了。**
// 大多数密码管理器在这里写一堆免责声明，用户点"我同意"就过去了，
// 然后在忘记密码的那天崩溃。这里换成两件事：
//
//   1. 用一句人话解释"为什么必须这样"（不是"为了安全"这种废话，
//      而是"因为这个文件只有你手上这把钥匙能打开，我们没有副本"）；
//   2. 强制用户做一次确认，而不是勾一个复选框。

struct OnboardingView: View {
    @EnvironmentObject private var model: AppModel

    @State private var step: Step = .explain
    @State private var password = ""
    @State private var confirm = ""
    @State private var acknowledgeNoRecovery = false
    @State private var showPassword = false

    private enum Step { case explain, setPassword, confirmLoss }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    switch step {
                    case .explain:
                        explainSection
                    case .setPassword:
                        setPasswordSection
                    case .confirmLoss:
                        confirmLossSection
                    }
                }
                .padding(22)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle(step == .explain ? "开始使用" : "设置主密码")
            .navigationBarTitleDisplayMode(.large)
        }
    }

    // MARK: 第一步：说明

    private var explainSection: some View {
        VStack(alignment: .leading, spacing: 18) {
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Label("数据只存在这台手机上", systemImage: "iphone")
                        .font(.headline)
                    Text("密码库是一个加密文件，放在 App 的私有目录里。没有服务器、没有账号、没有云端副本。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Label("主密码是唯一的钥匙", systemImage: "key.fill")
                        .font(.headline)
                    Text("它经过 60 万次哈希运算才变成加密密钥。这一步故意很慢——慢就是它的安全性。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Label("我们救不了你", systemImage: "exclamationmark.triangle.fill")
                        .font(.headline)
                        .foregroundStyle(.orange)
                    Text("忘记主密码 = 数据永久无法恢复。这不是偷懒，而是设计：如果我们能帮你找回，那能拿到这台手机的人也能。所以待会儿会让你做一次加密备份。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            Button {
                step = .setPassword
            } label: {
                Text("我明白了，继续")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }

    // MARK: 第二步：设置主密码

    private var setPasswordSection: some View {
        VStack(alignment: .leading, spacing: 18) {
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    Text("推荐做法：4 个随机单词")
                        .font(.headline)
                    Text("例如「咖啡 香蕉 铁路 钢琴」。比「Xy9!kL」这种更难被破解，而且你真的记得住。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Text("别用：生日、手机号、常用密码、任何在你其他账号上用过的密码。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Group {
                        if showPassword {
                            TextField("主密码", text: $password)
                        } else {
                            SecureField("主密码", text: $password)
                        }
                    }
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textContentType(.newPassword)   // 阻止系统"智能"建议和自动填充

                    Button {
                        showPassword.toggle()
                    } label: {
                        Image(systemName: showPassword ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
                .padding(14)
                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))

                SecureField("再输一遍", text: $confirm)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(14)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))

                strengthMeter
            }

            Button {
                step = .confirmLoss
            } label: {
                Text("下一步")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!canProceedToConfirm)
        }
    }

    private var strengthMeter: some View {
        let strength = VaultStore.evaluateMasterPassword(password)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                ForEach(0..<4, id: \.self) { i in
                    RoundedRectangle(cornerRadius: 3)
                        .fill(color(for: i, strength: strength.entropyBits))
                        .frame(height: 5)
                }
            }
            Text(password.isEmpty
                 ? "长度优先于复杂度。"
                 : "约 \(Int(strength.entropyBits)) bit 强度 · \(strength.verdict)")
                .font(.footnote)
                .foregroundStyle(strength.isAcceptable ? .secondary : .orange)
        }
    }

    private func color(for index: Int, strength: Double) -> Color {
        let filled = min(4, Int(strength / 20) + 1)
        guard index < filled else { return Color(.systemFill) }
        switch strength {
        case ..<40: return .red
        case ..<60: return .orange
        case ..<80: return .yellow
        default: return .green
        }
    }

    private var canProceedToConfirm: Bool {
        !password.isEmpty
            && password == confirm
            && VaultStore.evaluateMasterPassword(password).isAcceptable
    }

    // MARK: 第三步：确认不可恢复

    private var confirmLossSection: some View {
        VStack(alignment: .leading, spacing: 18) {
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Label("最后一件事", systemImage: "checkmark.shield.fill")
                        .font(.headline)
                        .foregroundStyle(.green)
                    Text("请确认你记住了这个主密码。创建之后没有任何找回方式。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            Toggle(isOn: $acknowledgeNoRecovery) {
                Text("我知道忘记主密码就无法恢复任何数据")
                    .font(.subheadline)
            }
            .padding(14)
            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))

            // 用 LabeledContent 而不是绑了常量的 Toggle：
            // 一个"钉住不动"的开关会让用户反复去点它，然后怀疑是不是坏了。
            Card {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "faceid")
                        .font(.title3)
                        .foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("将启用 Face ID 快速解锁")
                            .font(.subheadline)
                        Text("主密码始终有效，创建后随时可以在设置里关掉这一项。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Button {
                Task {
                    await model.createVault(masterPassword: password, alsoEnableQuickUnlock: true)
                }
            } label: {
                if model.isBusy {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    Text("创建密码库").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!acknowledgeNoRecovery || model.isBusy)

            Text("创建时会有约 1 秒的计算，这是主密码派生密钥的过程，属正常现象。")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - 通用卡片容器

/// 统一的卡片样式。抽出来是为了让"间距/圆角/背景"只有一处定义，
/// 改视觉时不用满项目找 `.padding(14)`。
struct Card<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14))
    }
}
