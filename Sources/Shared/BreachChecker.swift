import Foundation
import CryptoKit

// MARK: - 泄露检测（Have I Been Pwned，k-匿名查询）
//
// **隐私设计要点：密码本体永远不离开手机。**
//
// 做法（k-匿名 / 范围查询）：
//   1. 本地算 SHA-1(password)，得到 40 位十六进制串；
//   2. 只把**前 5 位**发给 api.pwnedpasswords.com；
//   3. 服务端返回"所有以这 5 位开头的泄露密码"的后 35 位 + 出现次数
//      （通常 800~1000 条，约 40KB）；
//   4. 在**本地**比对自己那 35 位，得出是否泄露。
//
// 服务端从始至终只知道"有人查了某个 5 位前缀"，不知道你查的是哪一条。
// 前 5 位十六进制对应约 100 万个桶，无法反推具体密码。
//
// 三个必须说明的边界条件：
//
//   a) **必须用 SHA-1，不能"升级"成 SHA-256。**
//      这不是安全缺陷，而是这个 API 的协议约定：泄露库里存的是
//      SHA-1 摘要（因为历史泄露数据就是这么归档的）。改成 SHA-256
//      会导致永远查不到结果——一个静默失效的安全功能比没有更危险。
//
//   b) **这条网络请求本身就是元数据泄露。** 你的 IP 会暴露给 HIBP。
//      因此默认关闭，且只在用户主动点击"检查泄露"时发起，
//      绝不在保存密码时自动后台请求。
//
//   c) **查询失败必须明确区分于"未泄露"。** 把网络错误显示成
//      "安全"是最危险的实现方式。这里用三态结果
//      （found / notFound / unknown）强制调用方处理未知状态。

public enum BreachChecker {

    public enum Result: Equatable {
        case found(count: Int)      // 在泄露库里，出现了 count 次
        case notFound               // 确认不在泄露库里
        case unknown(String)        // 查询失败，**不能**当作安全

        public var isCompromised: Bool {
            if case .found = self { return true }
            return false
        }
    }

    private static let endpoint = URL(string: "https://api.pwnedpasswords.com/range/")!

    /// 查询单个密码是否出现在已知泄露库中。
    ///
    /// - Note: 加 `Add-Padding: true` 头会让服务端返回固定大小的响应，
    ///   使得"响应长度"不再泄露前缀对应的条目数量。这是个免费的隐私增强。
    public static func check(password: String) async -> Result {
        guard !password.isEmpty else { return .unknown("密码为空") }

        let digest = Insecure.SHA1.hash(data: Data(password.utf8))
        let hashHex = digest.map { String(format: "%02X", $0) }.joined()

        let prefix = String(hashHex.prefix(5))
        let suffix = String(hashHex.dropFirst(5))

        var request = URLRequest(url: endpoint.appendingPathComponent(prefix))
        request.httpMethod = "GET"
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        request.setValue("text/plain", forHTTPHeaderField: "Accept")
        // 短超时：让用户等 30 秒的转圈比"查询失败"更糟。
        // 一个悬着的安全检查会让用户以为检查过了。
        request.timeoutInterval = 12
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let http = response as? HTTPURLResponse else {
                return .unknown("响应格式异常")
            }
            guard http.statusCode == 200 else {
                return .unknown("服务返回 \(http.statusCode)")
            }
            guard let body = String(data: data, encoding: .utf8) else {
                return .unknown("响应无法解码")
            }

            // 响应每行形如 "0018A45C4D1DEF81644B54AB7F969B88D65:12"
            for line in body.split(separator: "\n") {
                let parts = line.split(separator: ":", maxSplits: 1)
                guard parts.count == 2 else { continue }
                let candidateSuffix = parts[0].trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
                guard candidateSuffix.count == 35 else { continue }   // Padding 行会被这里跳过
                if candidateSuffix == suffix {
                    let count = Int(parts[1].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 1
                    return .found(count: count)
                }
            }
            return .notFound
        } catch {
            // 注意：这里**不**把 error.localizedDescription 带出去给用户看，
            // 它可能包含 URL 等细节。只给一个笼统的"网络问题"。
            VaultLog.failure("breach-check", error)
            return .unknown("网络请求失败")
        }
    }

    /// 批量检查一组条目。
    ///
    /// 刻意**串行 + 带间隔**：
    ///   - 串行避免瞬时并发请求把自己的 IP 特征暴露得更明显；
    ///   - 每个请求之间留间隔是基本的礼貌（这是免费公益 API，不是你的服务器）。
    ///
    /// - Parameter progress: 进度回调，**显式标注为 @MainActor**。
    ///   这样做而不是"后台线程随便调、调用方自己调度回主线程"，
    ///   是因为后者会强迫调用方写 `Task { @MainActor in ... }`，
    ///   而那个 Task 是异步派发的——最后几次进度更新可能在检查结束
    ///   之后才到达，UI 上看起来像"卡在 47/50"。
    ///   直接要求回调在主 actor 上，语义清楚，且不会丢事件。
    public static func checkAll(
        entries: [VaultEntry],
        progress: @MainActor @escaping (Int, Int, String) -> Void
    ) async -> [UUID: Result] {
        var results: [UUID: Result] = [:]
        let total = entries.count

        // 同一个密码出现多次时只查一次：既省请求，也减少元数据泄露
        var cache: [String: Result] = [:]

        for (index, entry) in entries.enumerated() {
            if Task.isCancelled { break }

            let password = entry.password
            if password.isEmpty {
                results[entry.id] = .unknown("没有密码")
            } else if let cached = cache[password] {
                results[entry.id] = cached
            } else {
                let result = await check(password: password)
                cache[password] = result
                results[entry.id] = result
                // 免费 API 限速，礼貌间隔。取消时立即退出，不要拖住 UI。
                try? await Task.sleep(nanoseconds: 120_000_000)   // 120ms
            }
            await progress(index + 1, total, entry.displayTitle)
        }
        return results
    }
}
