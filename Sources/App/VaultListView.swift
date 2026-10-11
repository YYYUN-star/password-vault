import SwiftUI

// MARK: - 库列表

struct VaultListView: View {
    @EnvironmentObject private var model: AppModel

    @State private var editingEntry: VaultEntry?
    @State private var showingNewEntry = false
    @State private var showingSettings = false
    @State private var showingGenerator = false
    @State private var copiedEntryID: UUID?

    var body: some View {
        NavigationStack {
            Group {
                if model.entries.isEmpty {
                    emptyState
                } else {
                    entryList
                }
            }
            .navigationTitle("密码库")
            .searchable(text: $model.searchText, prompt: "搜索名称、账号、网站")
            .onChange(of: model.searchText) { _, _ in
                model.applySearch()
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        model.lock()
                    } label: {
                        Label("上锁", systemImage: "lock.fill")
                    }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button {
                        showingGenerator = true
                    } label: {
                        Label("生成密码", systemImage: "wand.and.stars")
                    }
                    Button {
                        showingSettings = true
                    } label: {
                        Label("设置", systemImage: "gearshape")
                    }
                }
                ToolbarItem(placement: .bottomBar) {
                    Button {
                        showingNewEntry = true
                    } label: {
                        Label("新建", systemImage: "plus.circle.fill")
                    }
                }
            }
            .sheet(isPresented: $showingNewEntry) {
                EntryEditView(entry: nil)
            }
            .sheet(item: $editingEntry) { entry in
                EntryEditView(entry: entry)
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView()
            }
            .sheet(isPresented: $showingGenerator) {
                GeneratorView()
            }
        }
    }

    // MARK: 列表

    private var entryList: some View {
        List {
            ForEach(model.entries) { entry in
                NavigationLink {
                    EntryDetailView(entry: entry)
                } label: {
                    EntryRow(entry: entry, justCopied: copiedEntryID == entry.id)
                }
                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                    Button(role: .destructive) {
                        model.delete(entry)
                    } label: {
                        Label("删除", systemImage: "trash")
                    }
                    Button {
                        model.copyToClipboard(entry.password)
                        flashCopied(entry.id)
                    } label: {
                        Label("复制密码", systemImage: "doc.on.doc")
                    }
                    .tint(.blue)
                }
                .swipeActions(edge: .leading, allowsFullSwipe: true) {
                    Button {
                        editingEntry = entry
                    } label: {
                        Label("编辑", systemImage: "pencil")
                    }
                    .tint(.orange)
                }
            }
        }
        .listStyle(.plain)
    }

    // MARK: 空状态

    private var emptyState: some View {
        Group {
            if model.searchText.isBlank {
                ContentUnavailableView {
                    Label("还没有存任何密码", systemImage: "key.horizontal")
                } description: {
                    Text("点下面的「新建」加第一条。\n建议从你最在意的那个账号开始。")
                } actions: {
                    Button("新建密码") { showingNewEntry = true }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                ContentUnavailableView.search(text: model.searchText)
            }
        }
    }

    // MARK: 复制反馈
    //
    // 复制是**没有系统反馈**的操作（iOS 不会弹提示，只会有一条很淡的
    // 顶部胶囊）。没有反馈时用户会反复点，点三次的结果是剪贴板被覆盖了三次，
    // 而他会以为"没生效"。这里给一个 1.2 秒的行内确认。

    private func flashCopied(_ id: UUID) {
        copiedEntryID = id
        Task {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            if copiedEntryID == id { copiedEntryID = nil }
        }
    }
}

// MARK: - 列表行

struct EntryRow: View {
    let entry: VaultEntry
    let justCopied: Bool

    private static let palette: [Color] = [.blue, .purple, .teal, .indigo, .pink, .brown]

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Self.palette[entry.monogramColorIndex].gradient)
                Text(entry.monogram)
                    .font(.system(size: 17, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
            }
            .frame(width: 38, height: 38)

            VStack(alignment: .leading, spacing: 3) {
                Text(entry.displayTitle)
                    .font(.body)
                    .lineLimit(1)
                if !entry.displaySubtitle.isEmpty {
                    Text(entry.displaySubtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: 8)

            if justCopied {
                Label("已复制", systemImage: "checkmark.circle.fill")
                    .labelStyle(.iconOnly)
                    .foregroundStyle(.green)
                    .transition(.scale.combined(with: .opacity))
            }
        }
        .padding(.vertical, 2)
        .animation(.easeOut(duration: 0.15), value: justCopied)
    }
}
