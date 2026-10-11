# 从零到装上手机：完整操作步骤

你在 Windows 上，没有 Mac。这份文档把每一步都写清楚，
包括每一步**为什么**要这么做，以及出错了怎么排查。

---

## 0. 先做几个决定

### 决定 1：不需要买 Apple 开发者账号

**这个工程只需要免费 Apple ID。** 唯一需要付费账号的功能
（Safari 自动填充）已经在 v0.2 移除。

| | 免费 Apple ID |
|---|---|
| 能装到自己 iPhone 上 | 能（最多 3 个 App） |
| 加密库 / Face ID / 生成器 / 泄露检测 / 备份 | ✅ 全部可用 |
| 签名有效期 | **7 天**，过期 App 打不开（**数据不丢**） |
| 续签 | 手动，或 AltStore + AltServer 自动续签 |

**签名过期不等于数据丢失**：库文件在沙盒里完好无损，
重新签名装回去（**不要选"卸载重装"**）数据原样还在。
这就是为什么第一件要做的事是导出备份。

以后如果我想加需要付费能力的功能（iCloud 同步、推送等），
我会先看 [`PAID_FEATURES.md`](PAID_FEATURES.md) 然后**停下来问你**。

### 决定 2：Bundle ID 前缀

打开 `project.yml`，把 `com.example` 换成你自己的（例如 `com.zhangsan`）。
免费模式下只需要改两个地方：

1. `project.yml` 的 `bundleIdPrefix`
2. `project.yml` 里 `PRODUCT_BUNDLE_IDENTIFIER` 和
   `UTExportedTypeDeclarations` 里的 `com.example.passwordvault`

`Config/PasswordVault.entitlements` 是空文件，不用改；
`Sources/Shared/VaultStore.swift` 里也不再有 App Group 相关配置。

---

## 1. 把代码推到 GitHub

```bash
git init
git add .
git commit -m "v0.2：加密密码库（无自动填充）"
git branch -M main
git remote add origin git@github.com:你的用户名/password-vault.git
git push -u origin main
```

推上去之后，Actions 里会自动跑一次 `build`，走
"检查签名材料 → 未配置 → 编译验证（无签名）"这条路径。
**这一步会成功**，日志里能看到每个 Swift 文件编译通过，
以及当前是"免费版（无 AutoFill 扩展）"。

> 如果这一步就失败了，先别往下走。CI 日志会指出是哪个文件哪一行。
> 编译都不过就折腾签名，只会把两类问题混在一起，排查成本翻倍。

到这一步为止，**代码正确性已经被验证了**。剩下的只是"怎么装到手机上"。

---

## 2. 怎么拿到可安装的 ipa

CI 现在默认只做编译验证，**不产出 ipa**——因为它没有签名材料。
免费 Apple ID 的签名必须在**你自己的电脑**上完成
（需要用你的 Apple ID 登录，不可能自动化在 CI 里做）。

所以现实中只有两条路：

### 路线 A（推荐，最省事）：配 CI 签名，产出 ipa

这条路需要一个 `.p12` 证书和一个描述文件。**免费 Apple ID 也能生成**
（用 Sideloadly 或 AltStore 的"创建证书"功能，或在一台 Mac 上用 Xcode 生成
Personal Team 证书后导出）。

拿到材料后按第 2.1–2.3 节填进 GitHub Secrets，CI 就会产出 ipa。

**这条路的唯一风险**：免费账号的描述文件有效期只有 7 天，
所以你可能需要每 7 天更新一次 `PROVISIONING_PROFILE_BASE64` secret。
不想这么麻烦就选路线 B。

### 路线 B：AltStore 自动续签（长期用推荐）

[AltStore](https://altstore.io/) + AltServer（装在你的 Windows 电脑上）
可以做两件 CI 做不到的事：

1. **自动续签**：手机和电脑在同一 WiFi 时，AltStore 会在后台自动重新签名，
   你基本感知不到 7 天的限制；
2. **自带签名流程**：它自己就会用你的 Apple ID 生成证书和描述文件，
   不用你去开发者后台折腾。

它需要一个 ipa 或一个 Xcode 工程。**如果你有一台 Mac**（哪怕是借的），
用 Xcode 直接连手机跑一次是最简单的——Xcode 会自动处理免费签名。

> ### ⚠️ 一个我无法验证的环节，提前说明
>
> 我在 Windows 上写的这套代码，**没有 Mac 可以实际编译和安装一次**。
> 所以"免费 Apple ID 到底能不能装上这个 App"这件事，
> 我只能从工程配置上保证它**不需要任何特殊 entitlement**
> （`Config/PasswordVault.entitlements` 是空的，这是刻意为之），
> 从而把签名失败的风险降到最低。
>
> 但我不能声称"一定装得上"。**如果签名环节卡住了，把报错原文发给我**，
> 我按报错改工程配置——这类问题通常就是某个能力声明或 Info.plist 键的问题，
> 改起来很快。

### 2.1 生成证书和描述文件（只有走路线 A 才需要）

**证书**：Certificates → 新建 → `Apple Development` →
上传 CSR（Mac 上用"钥匙串访问"生成；Windows 上可以用 OpenSSL）→
下载 `.cer` → 导入到有私钥的机器 → 导出 `.p12`（设一个密码）。

**描述文件**：Profiles → 新建 → `iOS App Development` →
选你的证书 + 你的设备（需要先在 Devices 里加上你的 iPhone 的 UDID）→
下载 `.mobileprovision`。

**只需要创建一个 App ID**：`com.你的前缀.passwordvault`，
**不需要勾选任何能力**（App Groups、Keychain Sharing、Credential Provider 都不需要）。

> 这是 v0.2 相比 v0.1 最大的简化：v0.1 需要两个 App ID + App Group +
> Credential Provider 能力，任何一项配错都会导致签名失败或运行时崩溃。
> 现在这些全都不需要了。

### 2.2 把材料转成 base64 填进 GitHub Secrets

在仓库 Settings → Secrets and variables → Actions 里加这几个：

| Secret 名 | 内容 | 获取方式 |
|---|---|---|
| `SIGNING_CERT_P12_BASE64` | p12 文件的 base64 | `base64 -w0 cert.p12`（Windows: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.p12"))`） |
| `SIGNING_CERT_PASSWORD` | 导出 p12 时设的密码 | 你自己设的 |
| `KEYCHAIN_PASSWORD` | 随便一个临时密码 | 随便生成，只在 CI 用一次 |
| `PROVISIONING_PROFILE_BASE64` | mobileprovision 的 base64 | 同上 |
| `DEVELOPMENT_TEAM` | 你的 Team ID（10 位） | 后台右上角，或 `security find-identity` |
| `CODE_SIGN_IDENTITY` | 例如 `Apple Development: 你的名字 (XXXXXXXXXX)` | 证书的 Common Name |
| `PROVISIONING_PROFILE_SPECIFIER` | 描述文件的名字 | 创建时填的 Name，**不是**文件名 |

填完之后，手动触发一次 Actions（workflow_dispatch），
走"路径 B"，构建产物里会出现 `PasswordVault-ipa`，下载它。

---

## 3. 装到手机上的两种方式

拿到 ipa 之后：

1. 安装 [Sideloadly](https://sideloadly.io/) 或 [AltStore](https://altstore.io/)。
2. 用数据线连上 iPhone，把 ipa 拖进 Sideloadly，
   填你的 Apple ID，点 Start。
3. **用 AltStore 的话**，配置好 AltServer 之后它会自动续签，
   你只需要每 7 天让手机和电脑在同一个 WiFi 下待一会儿。

> **免费账号的限制**：最多 3 个自签 App。到期后 App 图标变灰、点不开，
> 但**数据不会丢**——库文件在沙盒里完好。重新签名安装后一切照旧。
> （千万不要在安装时选"卸载"，那才会删数据。）

---

## 4. 装到手机上之后必须做的四件事

### ① 在 App 里创建库，然后立刻导出一次备份

这是唯一不可省略的步骤。忘主密码 = 数据永久丢失。

导出的 `.pvault` 文件存到：iCloud Drive / 电脑 / U 盘。**建议存两份。**
（导出走「文件」App，不需要 iCloud 开发者能力，免费账号完全可用。）

### ② 验证加密备份真的能恢复

别等到需要它的那天才发现备份是坏的：

1. 再导出一次，确认文件能存到你想要的位置（比如 iCloud Drive）；
2. 把文件删掉，用"从备份恢复"重新导入一次，确认主密码能解开、条目都在。

**这一步花 2 分钟，但它验证的是"你的灾备方案真的有效"。**

### ③ 关闭"共享分析"里的 App 分析（可选但推荐）

「设置 › 隐私与安全性 › 分析与改进」。这一项会向 Apple 发送崩溃日志，
虽然我们的代码里刻意不往错误信息里放敏感数据，
但少一条外发通道总是好的。

### ④ 建一个"安全笔记"条目，写下你的备份在哪

听起来很傻，但 3 个月后你确实会忘记备份文件放在哪。
条目里写："加密备份在 iCloud Drive/密码库备份/，2025-01-15 导出的；
主密码是 4 个词，提示：咖啡 + 一种水果 + 交通工具 + 乐器。"
**不要写完整的主密码**——提示就够了。

---

## 5. 改代码之后怎么重新构建

```bash
# 改完源码
git add .
git commit -m "调整自动锁定默认值"
git push
```

CI 自动跑，2-3 分钟出结果。
在 Actions 页面下载新的 ipa（如果配了签名），用 Sideloadly 覆盖安装。
**覆盖安装不会丢数据**（库文件在沙盒里，重装同一个 Bundle ID 会保留，
但为了保险，动手前先导一次备份）。

### 如果你后来搞到了一台 Mac

```bash
brew install xcodegen
xcodegen generate
open PasswordVault.xcodeproj
```

之后就可以在 Xcode 里直接跑、下断点、看 Instruments 了，
免费 Apple ID 的签名也由 Xcode 自动处理，这是最省事的路径。

`project.yml` 是唯一事实来源，`.xcodeproj` 是生成物——
**不要**手动改 Xcode 工程文件然后提交，改动会在下次生成时被覆盖。
要加文件就加进 `Sources/` 目录，要加配置就改 `project.yml`。

---

## 6. 常见问题

**Q: 构建报 `No signing certificate "iOS Development" found`**
A: 你漏了 `CODE_SIGN_IDENTITY` secret，或者它的值不对。
注意这个值要填证书的 **Common Name**（形如 `Apple Development: 张三 (ABC123DEFG)`），
不是文件名，也不是 SHA1 指纹。

**Q: App 装上后一启动就崩**
A: 这个版本已经没有 App Group 依赖了，所以崩溃原因大概率是别的。
看 iPhone 上的「设置 › 隐私与安全性 › 分析与改进 › 分析数据」，
找到 `PasswordVault` 开头的崩溃日志，把最上面几行发我。
（v0.1 时代最常见的原因是 App Group 配错，现在这个可能性已经不存在。）

**Q: 我用 Sideloadly 签名时报 `entitlement not permitted`**
A: 这个版本不该出现了——`Config/PasswordVault.entitlements` 是空的，
整个工程只声明了零个能力。
如果还是报这个错，检查 `project.yml` 里的 `CODE_SIGN_ENTITLEMENTS`
有没有被改过，或者 `Config/` 目录下是否被人放进了别的 entitlements 文件。

**Q: 检查泄露一直失败**
A: `api.pwnedpasswords.com` 在国内网络环境下可能不稳定。
这个功能是可选的，失败不影响其他任何功能。
重要的是：**失败 ≠ 安全**，界面上也明确写了这一点。

**Q: 没有自动填充，用起来会不会很麻烦**
A: 会多两步。实际流程是「密码库」里点复制 → 切 Safari 粘贴。
缓解办法：把常用站点「添加到主屏幕」，两者切换只要两下。
另外剪贴板 60 秒后会自动清空，不会长期残留。

**Q: 我能把主密码改成更简单的吗**
A: 不能，强度门槛（60 bit）是硬编码的。
如果你真的想绕过，改 `VaultStore.evaluateMasterPassword` 里的
`isAcceptable` 判断——但请先重读 `docs/SECURITY.md` 第三节的妥协 2。

**Q: 以后想加功能，怎么知道要不要花钱**
A: 看 [`PAID_FEATURES.md`](PAID_FEATURES.md)。那张表列了所有需要付费账号的能力。
我的工作约定是：**凡是落在那一节的功能，我先问你，不动手写代码。**
