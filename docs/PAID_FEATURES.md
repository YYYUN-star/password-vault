# 需要付费 Apple 开发者账号的能力清单

**这份文档的用途：以后每加一个功能，先在这里查一下是否要花钱。
需要花钱的，我不动手，先问你。**

当前状态：**这个工程不需要 $99/年开发者账号。**
唯一需要它的功能（Safari 自动填充）已于 v0.2 移除。

---

## 一、为什么会有"免费账号做不到"这回事

免费 Apple ID 也能在真机上跑代码（Personal Team 签名），但它授予的能力是**受限的**：

| 项目 | 免费 Apple ID | 付费账号（$99/年） |
|---|---|---|
| 装到自己设备上 | 能，3 个 App，**7 天过期** | 能，100 台设备，1 年 |
| App 内自用（沙盒、Keychain、Face ID、文件加密） | **全部可以** | 全部可以 |
| 网络请求（HTTPS） | 可以 | 可以 |
| App Group（多进程/多 App 共享数据） | 通常可以 | 可以 |
| iCloud 容器（CloudKit / iCloud Documents） | **不可以** | 可以 |
| Credential Provider 扩展（自动填充） | **不可以** | 可以 |
| HealthKit / HomeKit / Push / Wallet / Sign in with Apple 等 | **不可以** | 可以 |
| App Store 上架 | 不可以 | 可以 |

判断标准：**功能是否需要"服务器端或系统级信任"**。
纯本地计算（加密、UI、文件读写）永远免费；
凡是系统要"相信你是谁"才能开的门，都要付费账号。

---

## 二、明确需要付费账号的功能（**加之前必须先问我**）

| 功能 | 为什么需要付费 | 你想要吗 |
|---|---|---|
| **Safari / App 内自动填充** | Credential Provider 扩展的 entitlement 只在付费 profile 里授予 | v0.2 已按你的要求移除 |
| **iCloud / CloudKit 多设备同步** | 需要 iCloud 容器 entitlement | 未实现 |
| **iCloud 自动备份**（无需手动导出） | 同上 | 未实现，替代方案见下 |
| **推送通知**（如"检测到泄露"提醒） | 需要 Push Notifications 能力 | 未实现 |
| **账号密码泄露监控后台轮询** | 需要后台任务 + 推送 | 未实现 |
| **Sign in with Apple / 用自己的域名做 Deep Link** | 需要对应能力 | 不需要 |
| **App Store 上架给别人用** | 需要账号 | 你的需求是自己用，不需要 |

## 三、不需要付费账号、可以随时加的（我说了算，不用问你）

这些是纯本地能力，随时可以加：

- 更丰富的条目类型（信用卡、身份证、软件许可证、Wi-Fi 密码）
- 条目分组、收藏、拖拽排序
- TOTP 两步验证码生成器（本地算，不联网）
- 密码强度报告、重复密码检测、弱密码筛选
- 更聪明的搜索（拼音、模糊匹配用户名）
- 导入/导出格式（CSV、1Password/Bitwarden 格式）
- 自动备份到本机（保留最近 N 份历史版本）
- 反截图（检测录屏状态时隐藏密码）
- 安全审计页（哪些条目很久没换密码）
- 自定义字段、附件（加密存图片）
- 多语言 / 主题

## 四、"我想同步到别的设备"的免费替代方案

不买账号也能做到，只是要手动一点：

| 方案 | 怎么做 | 代价 |
|---|---|---|
| **手动导出到 iCloud Drive**（当前支持） | 设置 → 导出加密备份 → 存到 iCloud Drive | 每次要手动点一次 |
| 「文件」App 里的共享文件夹 | 同上，但固定存到同一个文件夹，形成"可提现的最近备份" | 手动 |
| AirDrop 到 Mac / 另一台 iPhone | 导出后 AirDrop | 手动 |
| 自己搭一个同步服务器 | 需要写服务端 + 处理冲突，工作量大 | 复杂，且暴露面变大 |

**如果你想要真正的自动同步，这就是那个需要问你的事**——
它不只是 $99 的问题，还要多写 1500 行左右（CloudKit 记录合并、
冲突解决、墓碑、时钟偏移）。要做到不丢数据，工作量和风险都比现有代码大。

## 五、如果哪天你买了账号：怎么把自动填充加回来

**代码不在当前工作区里了**（v0.2 已删除，免得误导）。
完整实现留在 git 历史的 v0.1 提交里，用
`git show <v0.1提交>:Sources/AutoFill/CredentialProviderViewController.swift`
就能取回，不是从零重写。

需要恢复的部分：

1. `Sources/AutoFill/` 整个目录
2. `Config/PasswordVaultAutoFill.entitlements`（内容模板见本文末尾）
3. `project.yml` 里的第二个 target
4. `KeychainStore` 里的"弱保护备用密钥"（v0.1 的 `saveSeed` / `loadSeed`）——
   扩展要在后台静默读取，需要一份 `deviceUnlocked` 保护的副本，
   而 v0.2 只保留了 `biometryCurrentSet` 那一份
5. `AppModel.registerAutoFillIdentities()` 与两个开关
6. `Config/PasswordVault.entitlements` 里加回 App Group 与 Credential Provider 能力
7. `VaultLocation` 改回 App Group 容器

**恢复时务必注意三个已验证过的坑：**

- iOS 18 起 passkey-aware 表单**只调用** `prepareCredentialList(for:requestParameters:)`，
  不重写它，用户看到的是**纯黑空屏**，没有任何错误提示；
- 扩展里**不能**调 `LAContext.evaluatePolicy`，会让系统把扩展界面拆掉；
  要用"读 biometry 保护的钥匙串条目"来换系统人脸认证；
- 扩展的资源上限约 80MB / 30s，**绝不能在扩展里跑 KDF**。

扩展 entitlements 的原始内容（三个能力都需要付费账号）：

```xml
<key>com.apple.developer.authentication-services.autofill-credential-provider</key>
<true/>
<key>com.apple.security.application-groups</key>
<array>
    <string>group.com.example.passwordvault</string>
</array>
<key>keychain-access-groups</key>
<array>
    <string>$(AppIdentifierPrefix)com.example.passwordvault</string>
</array>
```

---

## 六、我的工作约定

以后我提议的任何功能，如果落在第二节那张表里，我会：

1. **先说清"需要 $99/年"或"需要某项付费能力"**；
2. 说明它**具体买到了什么**（不要笼统说"更安全"）；
3. 给一个**不花钱的替代方案**（如果有）；
4. **然后停下来等你决定**，不先写代码。

反过来，第三节那些功能我会直接做，不打扰你。
