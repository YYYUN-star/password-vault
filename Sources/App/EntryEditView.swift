import SwiftUI

// MARK: - 新建 / 编辑条目

struct EntryEditView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    /// nil 表示新建
    private let existing: VaultEntry?

    @State private var title = ""
    @State private var username = ""
    @State private var password = ""
    @State private var url = ""
    @State private var notes = ""
    @State private var tagsText = ""
    @State private var revealPassword = false
    @State private var showGenerator = false
    /// 用户是否手动改过名称（改过就不再随网址自动变更）
    @State private var titleManuallyEdited: Bool
    /// 当前名称是否由"网址自动填充"写入。用于区分程序改动与用户改动。
    @State private var autoFilledTitle = false

    init(entry: VaultEntry?) {
        self.existing = entry
        _title = State(initialValue: entry?.title ?? "")
        _username = State(initialValue: entry?.username ?? "")
        _password = State(initialValue: entry?.password ?? "")
        _url = State(initialValue: entry?.url ?? "")
        _notes = State(initialValue: entry?.notes ?? "")
        _tagsText = State(initialValue: entry?.tags.joined(separator: ", ") ?? "")
        // 已有条目：名称视为用户已经定过，不再自动跟着网址变。
        // 新建条目：从空开始，允许自动填充。
        _titleManuallyEdited = State(initialValue: entry != nil && !(entry?.title ?? "").isBlank)
    }

    private var isNew: Bool { existing == nil }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("名称", text: $title)
                        .textInputAutocapitalization(.words)
                    TextField("用户名 / 邮箱", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textContentType(.username)
                    TextField("网址", text: $url)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                } header: {
                    Text("基本信息")
                } footer: {
                    // 这条提示很关键：用户不知道"网址"字段会决定自动填充能不能
                    // 自动弹出候选。写下域名 = 让自动填充在正确站点自动工作。
                    Text("填上网址（例如 github.com），以后在 Safari 里打开这个网站时，系统会自动把这条密码排到候选第一位。")
                }

                Section {
                    HStack {
                        Group {
                            if revealPassword {
                                TextField("密码", text: $password)
                            } else {
                                SecureField("密码", text: $password)
                            }
                        }
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.system(.body, design: .monospaced))

                        Button {
                            revealPassword.toggle()
                        } label: {
                            Image(systemName: revealPassword ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.secondary)

                        Button {
                            showGenerator = true
                        } label: {
                            Image(systemName: "wand.and.stars")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.tint)
                    }

                    if !password.isEmpty {
                        passwordStrengthHint
                    }
                } header: {
                    Text("密码")
                }

                Section("备注") {
                    TextField("备注（安全问题答案、备用邮箱等）", text: $notes, axis: .vertical)
                        .lineLimit(3...8)
                }

                Section {
                    TextField("用逗号分隔，例如：工作, 邮箱", text: $tagsText)
                } header: {
                    Text("标签")
                } footer: {
                    Text("标签会参与搜索。")
                }
            }
            .navigationTitle(isNew ? "新建密码" : "编辑")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { save() }
                        .disabled(!canSave)
                }
            }
            .sheet(isPresented: $showGenerator) {
                // 生成器回填到这个表单，而不是存到剪贴板——
                // 少一次剪贴板往返，就少一次密码被别的 App 读到的机会。
                GeneratorView { generated in
                    password = generated
                    revealPassword = true
                    // 用户没手动改过名称时，顺手用域名填上，省一步输入
                    if title.isBlank, let host = VaultEntry.host(of: url) {
                        title = host
                    }
                }
            }
            .onChange(of: url) { _, newValue in
                // 只在"用户没自己起过名字"时才自动填名称，
                // 否则会把用户精心起的名字覆盖掉。
                guard !titleManuallyEdited, title.isBlank || autoFilledTitle else { return }
                if let host = VaultEntry.host(of: newValue), !host.isBlank {
                    autoFilledTitle = true          // 这次是程序填的，别当成用户输入
                    title = host
                }
            }
            .onChange(of: title) { _, newValue in
                // 程序回填的那一次不算"用户改过"。
                // iOS 17 起程序化改动同样会触发 onChange，所以必须显式区分，
                // 否则用户改完网址后名字就再也不会自动更新了。
                if autoFilledTitle, newValue == VaultEntry.host(of: url) {
                    return
                }
                autoFilledTitle = false
                titleManuallyEdited = true
            }
        }
    }

    private var passwordStrengthHint: some View {
        // 对"已有密码"做强度提示时，只按长度和字符集粗估，
        // 不查询网络、不记录日志。
        let entropy = estimatedEntropy(password)
        return HStack(spacing: 6) {
            Image(systemName: entropy < 50 ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(entropy < 50 ? .orange : .green)
            Text(entropy < 50
                 ? "这个密码偏弱（约 \(Int(entropy)) bit），建议用生成器换一个。"
                 : "强度约 \(Int(entropy)) bit。")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func estimatedEntropy(_ s: String) -> Double {
        var alphabet = 0
        if s.contains(where: { $0.isLowercase }) { alphabet += 26 }
        if s.contains(where: { $0.isUppercase }) { alphabet += 26 }
        if s.contains(where: { $0.isNumber }) { alphabet += 10 }
        if s.contains(where: { !$0.isLetter && !$0.isNumber }) { alphabet += 33 }
        guard alphabet > 1 else { return 0 }
        return Double(s.count) * log2(Double(alphabet))
    }

    private var canSave: Bool {
        !title.isBlank && (!username.isBlank || !password.isEmpty)
    }

    private func save() {
        var entry = existing ?? VaultEntry()
        entry.title = title.trimmed
        entry.username = username.trimmed
        entry.password = password
        entry.url = url.trimmed
        entry.notes = notes
        entry.tags = tagsText
            .split(separator: ",")
            .map { $0.trimmed }
            .filter { !$0.isEmpty }

        model.upsert(entry)
        dismiss()
    }
}
