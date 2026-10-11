# 架构说明

## 目录结构

```
.
├── project.yml                  # 唯一事实来源：Xcode 工程由它生成
├── Config/
│   └── PasswordVault.entitlements   # 故意是空的，见 docs/PAID_FEATURES.md
├── Sources/
│   ├── Shared/                  # 加密内核 + 存储 + 编排（与 UI 完全解耦）
│   │   ├── VaultModel.swift       数据模型 + 展示辅助 + 错误类型
│   │   ├── CryptoBox.swift        密码学原语封装（PBKDF2 / HKDF / AES-GCM / CSPRNG）
│   │   ├── VaultFile.swift        库文件格式：TLV 头部 + AEAD 载荷
│   │   ├── KeychainStore.swift    主密钥托管（Face ID 保护）
│   │   ├── VaultStore.swift       存储层：建库 / 解锁 / 读写 / 备份恢复
│   │   ├── AppModel.swift         编排层：解锁流程 / 自动锁定 / 剪贴板
│   │   ├── PasswordGenerator.swift 密码生成（拒绝采样，无取模偏差）
│   │   ├── BreachChecker.swift     HIBP k-匿名泄露查询
│   │   └── VaultLog.swift          仅 Debug 生效的日志出口
│   └── App/                     # SwiftUI 界面层
│       ├── PasswordVaultApp.swift
│       ├── RootView.swift         根视图 + App 切换器遮罩
│       ├── LockView.swift
│       ├── OnboardingView.swift
│       ├── VaultListView.swift
│       ├── EntryEditView.swift
│       ├── EntryDetailView.swift
│       ├── SettingsView.swift
│       └── GeneratorView.swift
└── docs/
    ├── ARCHITECTURE.md          （本文件）
    ├── SECURITY.md              威胁模型
    ├── PAID_FEATURES.md         哪些能力需要付费账号（加功能前先查这里）
    └── SETUP.md                 构建与安装
```

## 分层

```
        ┌──────────────────────────────────────────┐
        │  Views (SwiftUI)                         │  只做渲染和用户意图
        │  LockView / VaultListView / ...          │  不含任何密钥、不碰文件
        └───────────────────┬──────────────────────┘
                            │ @Published / 方法调用
        ┌───────────────────▼──────────────────────┐
        │  AppModel  (@MainActor)                  │  状态机：解锁/上锁/生命周期
        │  ── 唯一的编排点 ──                       │  自动锁定、剪贴板 TTL
        └───────────────────┬──────────────────────┘
                            │
        ┌───────────────────▼──────────────────────┐
        │  VaultStore  (@MainActor)                │  串行化的读写
        │  建库 / 解锁 / mutate / 备份恢复          │  变更检测，避免无意义写盘
        └──────┬──────────────────────┬────────────┘
               │                      │
   ┌───────────▼──────────┐  ┌────────▼─────────────┐
   │  VaultFile           │  │  KeychainStore       │
   │  文件格式 + AEAD      │  │  主密钥托管           │
   └───────────┬──────────┘  └────────┬─────────────┘
               │                      │
   ┌───────────▼──────────────────────▼─────────────┐
   │  CryptoBox                                     │  纯函数，无状态
   │  CommonCrypto (PBKDF2) + CryptoKit (HKDF/AEAD) │  唯一允许出现密钥运算的地方
   └────────────────────────────────────────────────┘
```

**为什么这样切**：安全相关的状态机只有 `AppModel` 一处，
密码学调用只有 `CryptoBox` 一处。
review 安全问题时不需要读 UI 代码，读 UI 代码时不需要担心密码学。

`Sources/Shared` 与 `Sources/App` 的边界是刻意的：
`Shared` 里没有一行 SwiftUI，`App` 里没有一行密码学。
将来如果要写单元测试或命令行恢复工具，可以直接复用 `Shared`。

## 数据流：一次"复制密码"

```
用户点复制
  → EntryDetailView / VaultListView
  → AppModel.copyToClipboard(value)
  → UIPasteboard.setItems(options: [.expirationDate: +60s, .localOnly: true])
  → 系统在内核层保证 60 秒后失效（即使 App 被挂起/杀掉）
```

注意这里**没有**经过 VaultStore：复制不改变库内容，
不应该触发任何写盘或变更检测。

**这是 v0.2 之后最主要的取用路径**（因为自动填充已移除）。
也正因为密码必须经过全局剪贴板，那个 60 秒的过期时间不是可选项而是必须项。

## 数据流：一次解锁

```
用户输主密码 或 Face ID
  → AppModel.unlock / quickUnlock
  → VaultStore.unlock / unlockWithStoredKey
      → 读文件 → VaultFile.parseHeader（不涉及 KDF，很快）
      → CryptoBox.deriveMasterKey（60 万次 PBKDF2，约 0.3–0.8 秒，故意慢）
      → AES-GCM open（AAD = 头部原始字节）
      → VaultFile.decodePayload
  → AppModel.afterUnlock
      → 清空 isLocked、加载 entries
```

## 关键设计决策速查

| 决策 | 选择 | 被否决的方案 | 理由 |
|---|---|---|---|
| 存储引擎 | 单文件整体加密 | SQLite + SQLCipher | 个人量级不需要索引；避免 WAL/journal 明文残留；零第三方依赖 |
| KDF | PBKDF2-SHA256 ×600k | Argon2id | 系统内置 vs 引 C 库；格式头预留了升级位 |
| 密钥链 | 只存一个条目 | 再存一份弱保护副本 | v0.1 为自动填充存了第二份"设备解锁即可读"的副本；功能移除后那份副本没有存在理由——少一把钥匙，少一处风险 |
| 库文件位置 | App 沙盒 `Application Support` | App Group 容器 | App Group 的唯一用途是给第二个进程读；没有扩展就不需要这项能力，少一个 entitlement 就少一处签名失败 |
| entitlements | **空** | App Group + Keychain 共享组 | 每多一个能力就多一处免费签名失败的可能 |
| 同步 | 加密备份/恢复 | CloudKit record 同步 | 需要付费账号 + 做错的同步会静默丢数据；复杂度高一个数量级 |
| favicon | 不抓，用字母图标 | 抓第三方图标服务 | 会实时泄露"我在用哪些网站" |
| 变更检测 | 明文比对，相同则不写 | 每次都写 | 减少闪存磨损；为将来同步避免假冲突 |
| 并发 | `@MainActor` 强制串行 | 后台队列 + 锁 | 加密库的读写交错是 bug 温床；几十毫秒的代价换确定性 |
| 取用密码 | 复制到剪贴板（60 秒过期） | 自动填充扩展 | 后者需要付费账号；见 docs/PAID_FEATURES.md |

## 加新功能时该改哪里

| 想做的事 | 动哪里 | 注意 |
|---|---|---|
| 加一个条目字段 | `VaultEntry` + `EntryEditView` + `EntryDetailView` | 新字段给默认值，保证旧库能解码；`schema` 版本号要升 |
| 加一种 KDF | `CryptoBox.KDFAlgorithm` + `deriveMasterKey` | 新增 rawValue，绝不改动已有的 `1` 的含义 |
| 加一个设置项 | `AppModel` 的 `DefaultsKey` + `@Published` + `SettingsView` | 只允许存非敏感策略；**任何库内容都不许进 UserDefaults** |
| 加一个新界面 | `Sources/App/` 新文件 | 不要在 View 里直接调 `VaultStore`，一律走 `AppModel` |
| 改文件格式 | `VaultFile` + 提升 `formatVersion` | 新版本写新格式时要想清楚老版本读到会怎样（会抛 `unsupportedFormat`，这是预期的） |
| **任何新功能** | 先查 `docs/PAID_FEATURES.md` | 如果落在"需要付费账号"那一节，**先问用户再动手** |

## 版本变更记录

### v0.2（当前）

- **移除** Safari / App 内自动填充（Credential Provider 扩展需要付费开发者账号）
- 随之移除：`Sources/AutoFill/`、扩展 target、App Group 依赖、
  弱保护的备用密钥、自动填充相关的三个设置项
- 库文件位置从 App Group 容器改为 App 沙盒（加密格式**未变**，
  所以 v0.1 的备份可以直接导入 v0.2）
- entitlements 变成空文件

### v0.1

- 首个版本：加密库、Face ID、生成器、泄露检测、加密备份、自动填充扩展
