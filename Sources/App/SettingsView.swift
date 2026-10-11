import SwiftUI
import UniformTypeIdentifiers
import UIKit

// MARK: - 设置

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var showingChangePassword = false
    @State private var showingExporter = false
    @State private var showingImporter = false
    @State private var showingDestroyConfirm = false
    @State private var exportData: Data?
    @State private var restorePassword = ""
    @State private var pendingRestoreData: Data?
    @State private var showingRestorePrompt = false
    @State private var restoreError: String?
    @State private var isBatchChecking = false
    @State private var batchProgress: (done: Int, total: Int, current: String) = (0, 0, "")
    @State private var batchFindings: [UUID: BreachChecker.Result] = [:]
    @State private var showingBatchReport = false

    var body: some View {
        NavigationStack {
            Form {
                securitySection
                privacySection
                backupSection
                maintenanceSection
                aboutSection
            }
            .navigationTitle("设置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
            .sheet(isPresented: $showingChangePassword) {
                ChangeMasterPasswordView()
            }
            .sheet(isPresented: $showingBatchReport) {
                BatchBreachReportView(findings: batchFindings)
            }
            .fileExporter(
                isPresented: $showingExporter,
                document: exportData.map { VaultBackupDocument(data: $0) },
                contentType: .data,
                defaultFilename: backupFilename
            ) { result in
                if case .failure(let error) = result {
                    VaultLog.failure("export-file", error)
                }
                exportData = nil
            }
            .fileImporter(
                isPresented: $showingImporter,
                allowedContentTypes: [.data],
                allowsMultipleSelection: false
            ) { result in
                handleImport(result)
            }
            .alert("恢复需要主密码", isPresented: $showingRestorePrompt) {
                SecureField("这个备份的主密码", text: $restorePassword)
                Button("恢复", role: .destructive) { Task { await performRestore() } }
                Button("取消", role: .cancel) {
                    pendingRestoreData = nil
                    restorePassword = ""
                }
            } message: {
                Text("恢复会**覆盖**当前的密码库。请输入这个备份文件的主密码来确认——密码不对就不会写入任何东西。")
            }
            .alert("恢复失败", isPresented: Binding(
                get: { restoreError != nil },
                set: { if !$0 { restoreError = nil } }
            )) {
                Button("知道了", role: .cancel) { restoreError = nil }
            } message: {
                Text(restoreError ?? "")
            }
            .confirmationDialog(
                "清空所有数据？",
                isPresented: $showingDestroyConfirm,
                titleVisibility: .visible
            ) {
                Button("永久删除", role: .destructive) {
                    model.destroyEverything()
                    dismiss()
                }
                Button("取消", role: .cancel) {}
            } message: {
                Text("会删除加密库文件、钥匙串里的密钥和所有设置。没有回收站，无法撤销。")
            }
        }
    }

    // MARK: 安全

    private var securitySection: some View {
        Section {
            Picker("自动锁定", selection: $model.autoLockDelay) {
                ForEach(AppModel.AutoLockDelay.allCases) { delay in
                    Text(delay.label).tag(delay)
                }
            }

            Toggle("切到后台时遮挡界面", isOn: $model.blurInSwitcher)

            if model.quickUnlockStale {
                Button {
                    Task { await model.reenableQuickUnlock() }
                } label: {
                    Label("重新启用 Face ID 快速解锁", systemImage: "faceid")
                }
            } else if model.canQuickUnlock {
                Button(role: .destructive) {
                    try? KeychainStore.deleteMasterKey()
                    model.refresh()
                } label: {
                    Label("关闭快速解锁（只能用主密码）", systemImage: "key.slash")
                }
            }

            Button {
                showingChangePassword = true
            } label: {
                Label("修改主密码", systemImage: "key.fill")
            }

            Button {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            } label: {
                Label("打开系统设置（通知、隐私等）", systemImage: "gearshape.2")
            }
        } header: {
            Text("安全")
        } footer: {
            Text("关闭快速解锁后，每次打开 App 都要输主密码。这是安全性最高、也最麻烦的配置。\n自动锁定的计时从 App 进入后台开始算。")
        }
    }

    // MARK: 隐私

    private var privacySection: some View {
        Section {
            Picker("复制密码后自动清空剪贴板", selection: $model.clipboardClearSeconds) {
                Text("30 秒").tag(30)
                Text("60 秒").tag(60)
                Text("2 分钟").tag(120)
                Text("5 分钟").tag(300)
            }
        } header: {
            Text("隐私")
        } footer: {
            Text("剪贴板是所有 App 共享的。清空时间越短越安全，但太短会导致你来不及粘贴。")
        }
    }

    // MARK: 备份

    private var backupSection: some View {
        Section {
            Button {
                exportData = model.exportBackup()
                if exportData != nil { showingExporter = true }
            } label: {
                Label("导出加密备份", systemImage: "square.and.arrow.up")
            }

            Button {
                showingImporter = true
            } label: {
                Label("从备份恢复", systemImage: "square.and.arrow.down")
            }

            Button {
                Task { await runBatchBreachCheck() }
            } label: {
                HStack {
                    Label("全库检查泄露", systemImage: "shield.lefthalf.filled")
                    Spacer()
                    if isBatchChecking {
                        Text("\(batchProgress.done)/\(batchProgress.total)")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .disabled(isBatchChecking || model.entries.isEmpty)
        } header: {
            Text("备份与检查")
        } footer: {
            Text("""
            导出的文件是**加密后的库本身**，里面没有任何明文。建议存到 iCloud Drive 或电脑上——这是你唯一的灾备手段。

            全库检查会对每条不同的密码各发一次网络请求（分批进行，约每条 0.15 秒）。
            """)
        }
    }

    private var backupFilename: String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmm"
        return "密码库备份-\(f.string(from: Date())).pvault"
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first else { return }
            // 安全作用域：iOS 上从"文件"App 拿到的 URL 必须显式申请访问权限，
            // 否则读取会静默失败（这是非常常见的坑）。
            let needsScope = url.startAccessingSecurityScopedResource()
            defer { if needsScope { url.stopAccessingSecurityScopedResource() } }
            do {
                let data = try Data(contentsOf: url)
                // 先只解析头部，确认它确实是一个密码库文件，
                // 再让用户输密码。避免用户输完密码才被告知"这不是备份文件"。
                _ = try VaultFile.parseHeader(data)
                pendingRestoreData = data
                restorePassword = ""
                showingRestorePrompt = true
            } catch {
                restoreError = "这个文件不是有效的密码库备份。"
            }
        case .failure(let error):
            VaultLog.failure("import-file", error)
            restoreError = "无法读取所选文件。"
        }
    }

    private func performRestore() async {
        guard let data = pendingRestoreData else { return }
        let password = restorePassword
        pendingRestoreData = nil
        restorePassword = ""
        let ok = await model.restoreBackup(data, masterPassword: password)
        if ok { dismiss() }
    }

    // MARK: 危险操作

    private var maintenanceSection: some View {
        Section {
            Button(role: .destructive) {
                showingDestroyConfirm = true
            } label: {
                Label("清空所有数据", systemImage: "trash")
            }
        } header: {
            Text("危险操作")
        } footer: {
            Text("没有回收站。做之前请先导出一次备份。")
        }
    }

    // MARK: 关于

    private var aboutSection: some View {
        Section {
            LabeledContent("版本", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—")
            LabeledContent("库文件位置", value: "App 私有目录")
            LabeledContent("条目数", value: "\(model.entries.count)")
            LabeledContent("加密", value: "AES-256-GCM")
            LabeledContent("密钥派生", value: "PBKDF2-SHA256 · 600,000 次")
        } header: {
            Text("关于")
        } footer: {
            Text("本 App 不联网（除了你主动触发的泄露检查），不含任何统计 SDK，不上传任何数据。")
        }
    }

    // MARK: 全库泄露检查

    private func runBatchBreachCheck() async {
        isBatchChecking = true
        batchFindings = [:]
        defer { isBatchChecking = false }

        let entries = model.entries
        batchProgress = (0, entries.count, "")

        let findings = await BreachChecker.checkAll(entries: entries) { done, total, current in
            // 这个回调已经是 @MainActor 的（见 BreachChecker.checkAll 的签名），
            // 所以这里可以直接更新 @State，不需要再包一层 Task。
            // 包一层反而有害：派发的 Task 是异步的，最后几次更新
            // 可能在整个检查结束后才落地，UI 看起来像卡住了。
            batchProgress = (done, total, current)
        }

        batchFindings = findings
        showingBatchReport = !findings.isEmpty
    }
}

// MARK: - 修改主密码

struct ChangeMasterPasswordView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var current = ""
    @State private var newPassword = ""
    @State private var confirm = ""
    @State private var acknowledged = false

    var body: some View {
        NavigationStack {
            Form {
                Section("当前主密码") {
                    SecureField("当前主密码", text: $current)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section {
                    SecureField("新主密码", text: $newPassword)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("再输一遍", text: $confirm)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if !newPassword.isEmpty {
                        let s = VaultStore.evaluateMasterPassword(newPassword)
                        Text("强度约 \(Int(s.entropyBits)) bit · \(s.verdict)")
                            .font(.footnote)
                            .foregroundStyle(s.isAcceptable ? .secondary : .orange)
                    }
                } header: {
                    Text("新主密码")
                }

                Section {
                    Toggle("我知道忘记新密码就再也打不开了", isOn: $acknowledged)
                } footer: {
                    Text("""
                    修改密码会重新生成随机盐并整库重新加密。这一步需要约 1–2 秒。

                    改完之后需要先用新密码解锁一次，Face ID 快速解锁才会重新生效——这是为了确认你真的记住了新密码。
                    """)
                }
            }
            .navigationTitle("修改主密码")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("修改") {
                        Task {
                            await model.changeMasterPassword(current: current, new: newPassword)
                            if model.errorMessage == nil { dismiss() }
                        }
                    }
                    .disabled(!canSubmit || model.isBusy)
                }
            }
        }
    }

    private var canSubmit: Bool {
        !current.isEmpty
            && !newPassword.isEmpty
            && newPassword == confirm
            && acknowledged
            && VaultStore.evaluateMasterPassword(newPassword).isAcceptable
            && !model.isBusy
    }
}

// MARK: - 备份文档封装
//
// 用 FileDocument 而不是自己拼 UIActivityViewController：
// 前者能直接进「文件」App，用户可以存到 iCloud Drive，
// 这正是我们要的备份路径。

struct VaultBackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }

    var data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        guard let d = configuration.file.regularFileContents else {
            throw CocoaError(.fileReadCorruptFile)
        }
        data = d
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

// MARK: - 全库泄露报告

struct BatchBreachReportView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let findings: [UUID: BreachChecker.Result]

    private var compromised: [(VaultEntry, Int)] {
        model.entries.compactMap { entry in
            if case .found(let count) = findings[entry.id] { return (entry, count) }
            return nil
        }
        .sorted { $0.1 > $1.1 }
    }

    private var unknownCount: Int {
        findings.values.filter { if case .unknown = $0 { return true } else { return false } }.count
    }

    var body: some View {
        NavigationStack {
            List {
                if compromised.isEmpty {
                    Section {
                        Label("没有发现已泄露的密码", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                    }
                } else {
                    Section {
                        ForEach(compromised, id: \.0.id) { entry, count in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(entry.displayTitle)
                                    .font(.body.weight(.medium))
                                Text("出现 \(count.formatted()) 次")
                                    .font(.footnote)
                                    .foregroundStyle(.red)
                            }
                        }
                    } header: {
                        Text("需要立即更换（\(compromised.count) 条）")
                    } footer: {
                        Text("这些密码已经公开在互联网上。请优先更换其中用于邮箱和银行账号的那些。")
                    }
                }

                if unknownCount > 0 {
                    Section {
                        Label("\(unknownCount) 条没能检查（网络问题）", systemImage: "questionmark.circle")
                            .foregroundStyle(.orange)
                    } footer: {
                        Text("未完成检查 ≠ 安全。稍后可以再试一次。")
                    }
                }
            }
            .navigationTitle("泄露检查结果")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
        }
    }
}
