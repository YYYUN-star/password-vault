import SwiftUI

// MARK: - 密码生成器

struct GeneratorView: View {
    @Environment(\.dismiss) private var dismiss

    /// 有回调时表示"用来填某个表单"，会把结果交给调用方；
    /// 没有回调时表示"独立工具页"，结果走剪贴板。
    private let onUse: ((String) -> Void)?

    @State private var options = PasswordGenerator.Options.default
    @State private var generated: String = ""
    @State private var copied = false

    init(onUse: ((String) -> Void)? = nil) {
        self.onUse = onUse
        _generated = State(initialValue: PasswordGenerator.generate(.default))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(generated)
                            // 等宽字体 + 可换行：让用户能"看出"字符差异，
                            // 而不是一坨挤在一起看不清
                            .font(.system(.title3, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(14)
                            .background(Color(.tertiarySystemFill), in: RoundedRectangle(cornerRadius: 10))

                        HStack(spacing: 10) {
                            Button {
                                regenerate()
                            } label: {
                                Label("换一个", systemImage: "arrow.clockwise")
                            }
                            .buttonStyle(.bordered)

                            Button {
                                useGenerated()
                            } label: {
                                if copied {
                                    Label("已复制", systemImage: "checkmark")
                                } else {
                                    Label(onUse == nil ? "复制" : "使用", systemImage: onUse == nil ? "doc.on.doc" : "checkmark.circle")
                                }
                            }
                            .buttonStyle(.borderedProminent)
                        }
                    }
                    .padding(.vertical, 4)
                } header: {
                    Text("生成的密码")
                } footer: {
                    Text("强度约 \(Int(PasswordGenerator.entropyBits(options))) bit。每次换一个都会立刻丢弃上一个，不留历史。")
                }

                Section("长度") {
                    HStack {
                        Slider(
                            value: Binding(
                                get: { Double(options.length) },
                                set: { options.length = Int($0.rounded()) }
                            ),
                            in: 8...64,
                            step: 1
                        )
                        Text("\(options.length)")
                            .font(.system(.body, design: .monospaced))
                            .frame(width: 34, alignment: .trailing)
                    }
                }

                Section {
                    Toggle("小写字母 a-z", isOn: $options.useLowercase)
                    Toggle("大写字母 A-Z", isOn: $options.useUppercase)
                    Toggle("数字 0-9", isOn: $options.useDigits)
                    Toggle("符号 !@#$%", isOn: $options.useSymbols)
                } header: {
                    Text("字符集")
                }

                Section {
                    Toggle("排除易混淆字符", isOn: $options.avoidAmbiguous)
                } footer: {
                    Text("开启后会去掉 l / I / 1、O / 0 这些肉眼难分的字符。适合需要手抄到别的设备上的场景；只靠复制粘贴的话不必开。")
                }
            }
            .navigationTitle(onUse == nil ? "密码生成器" : "生成密码")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(onUse == nil ? "完成" : "取消") { dismiss() }
                }
            }
            .onChange(of: options) { _, _ in
                regenerate()
            }
        }
    }

    private func regenerate() {
        // 每次改动设置就重新生成：让用户立刻看到参数变化的效果，
        // 而不是"改完参数还得再点一次生成"。
        // 代价是旧密码被丢弃 —— 这是有意的，不该留可回溯的历史。
        generated = PasswordGenerator.generate(options)
        copied = false
    }

    private func useGenerated() {
        if let onUse {
            onUse(generated)
            dismiss()
        } else {
            UIPasteboard.general.setItems(
                [[UIPasteboard.typeAutomatic: generated]],
                options: [
                    .expirationDate: Date().addingTimeInterval(60),
                    .localOnly: true
                ]
            )
            copied = true
        }
    }
}
