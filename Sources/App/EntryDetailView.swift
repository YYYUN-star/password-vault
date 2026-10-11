import SwiftUI
import UIKit

// MARK: - 条目详情

struct EntryDetailView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    let entry: VaultEntry

    @State private var revealPassword = false
    @State private var showingEdit = false
    @State private var breachResult: BreachChecker.Result?
    @State private var isCheckingBreach = false
    @State private var showingDeleteConfirm = false

    var body: some View {
        List {
            header

            Section {
                field(label: "用户名", value: entry.username, sensitive: false)
                passwordField
                if !entry.url.isBlank {
                    urlField
                }
            }

            if !entry.notes.isBlank {
                Section("备注") {
                    Text(entry.notes)
                        .font(.callout)
                        .textSelection(.enabled)
                }
            }

            if !entry.tags.isEmpty {
                Section("标签") {
                    HStack(spacing: 8) {
                        ForEach(entry.tags, id: \.self) { tag in
                            Text(tag)
                                .font(.caption)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                                .background(Color(.tertiarySystemFill), in: Capsule())
                        }
                    }
                }
            }

            breachSection

            Section {
                Button(role: .destructive) {
                    showingDeleteConfirm = true
                } label: {
                    Label("删除这条", systemImage: "trash")
                }
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    if let used = entry.lastUsedAt {
                        Text("最近使用：\(used.formatted(date: .abbreviated, time: .shortened))")
                    }
                    Text("创建于 \(entry.createdAt.formatted(date: .abbreviated, time: .omitted)) · 修改于 \(entry.updatedAt.formatted(date: .abbreviated, time: .omitted))")
                }
            }
        }
        .navigationTitle(entry.displayTitle)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("编辑") { showingEdit = true }
            }
        }
        .sheet(isPresented: $showingEdit) {
            EntryEditView(entry: entry)
        }
        .confirmationDialog(
            "删除「\(entry.displayTitle)」？",
            isPresented: $showingDeleteConfirm,
            titleVisibility: .visible
        ) {
            Button("删除", role: .destructive) {
                model.delete(entry)
                dismiss()
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("删除后无法撤销。")
        }
        .onDisappear {
            // 离开页面时把已揭示的密码收回状态。
            // 否则用户返回列表再进来，密码可能还处于显示状态。
            revealPassword = false
        }
    }

    // MARK: 头部

    private var header: some View {
        Section {
            VStack(spacing: 10) {
                Text(entry.monogram)
                    .font(.system(size: 30, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                    .frame(width: 68, height: 68)
                    .background(Color.accentColor.gradient, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                Text(entry.displaySubtitle.isEmpty ? entry.displayTitle : entry.displaySubtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .listRowBackground(Color.clear)
        }
    }

    // MARK: 字段行

    private func field(label: String, value: String, sensitive: Bool) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value.isBlank ? "—" : value)
                    .font(.body)
                    .lineLimit(2)
                    .truncationMode(.middle)
            }
            Spacer()
            if !value.isBlank {
                Button {
                    model.copyToClipboard(value, label: label)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.tint)
            }
        }
    }

    private var passwordField: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text("密码")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if revealPassword {
                    Text(entry.password)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(2)
                        .truncationMode(.middle)
                } else {
                    Text(String(repeating: "•", count: min(max(entry.password.count, 8), 20)))
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button {
                withAnimation(.easeOut(duration: 0.12)) { revealPassword.toggle() }
            } label: {
                Image(systemName: revealPassword ? "eye.slash" : "eye")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)

            Button {
                model.copyToClipboard(entry.password)
                model.markUsed(id: entry.id)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.tint)
        }
    }

    private var urlField: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text("网址")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(entry.displayURL)
                    .font(.body)
                    .lineLimit(1)
            }
            Spacer()
            Button {
                // 用 openURL 而不是自己拼 URL 再打开：
                // openURL 走系统校验，畸形 URL 会被系统拒绝，
                // 而不是被我们"尽力修复"后打开一个非预期的地址。
                if let url = normalizedURL {
                    openURL(url)
                }
            } label: {
                Image(systemName: "safari")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.tint)
            .disabled(normalizedURL == nil)
        }
    }

    /// 只在输入看起来是 http/https 时才生成可打开链接。
    /// 拒绝 file://、javascript: 等 scheme —— 这些字段是从明文笔记里来的，
    /// 不该有能力触发任意 URL 打开。
    private var normalizedURL: URL? {
        var s = entry.url.trimmed
        guard !s.isEmpty else { return nil }
        if !s.contains("://") { s = "https://" + s }
        guard let url = URL(string: s),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.host?.isEmpty == false else {
            return nil
        }
        return url
    }

    // MARK: 泄露检测

    private var breachSection: some View {
        Section {
            Button {
                Task { await runBreachCheck() }
            } label: {
                HStack {
                    Label("检查是否已泄露", systemImage: "shield.lefthalf.filled")
                    Spacer()
                    if isCheckingBreach {
                        ProgressView()
                    }
                }
            }
            .disabled(entry.password.isEmpty || isCheckingBreach)

            if let result = breachResult {
                breachResultRow(result)
            }
        } footer: {
            Text("只会把密码 SHA-1 的**前 5 位**发给 Have I Been Pwned，密码本身不会离开这台手机。但这条请求会暴露你的 IP。")
        }
    }

    @ViewBuilder
    private func breachResultRow(_ result: BreachChecker.Result) -> some View {
        switch result {
        case .found(let count):
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "exclamationmark.octagon.fill")
                    .foregroundStyle(.red)
                VStack(alignment: .leading, spacing: 4) {
                    Text("这个密码已在泄露库中出现")
                        .font(.subheadline.weight(.semibold))
                    Text("累计 \(count.formatted()) 次。攻击者会用它尝试登录你的所有账号——请立刻更换。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        case .notFound:
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 4) {
                    Text("没有出现在已知泄露库中")
                        .font(.subheadline.weight(.semibold))
                    Text("注意：这只说明它没在**已公开**的泄露数据里，不代表绝对安全。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        case .unknown(let why):
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "questionmark.circle.fill")
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 4) {
                    Text("没能完成检查")
                        .font(.subheadline.weight(.semibold))
                    Text("\(why)。这不代表安全，只是没查到结果。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func runBreachCheck() async {
        isCheckingBreach = true
        defer { isCheckingBreach = false }
        breachResult = await BreachChecker.check(password: entry.password)
    }
}
