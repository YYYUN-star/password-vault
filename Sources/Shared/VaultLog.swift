import Foundation

// MARK: - 日志
//
// 密码管理器里"随手 print 一下调试"是灾难的开始：日志会进系统控制台、
// 可能被备份、可能被其他 App 读取（在旧系统上）。
// 所以这里只提供一个**经过审查的**日志出口，并且在 Release 构建里
// 完全编译掉（`#if DEBUG`），确保发布版本一个字节都不会写出去。
//
// 铁律：这个函数永远不能收到密码、主密钥、明文条目、盐、密文片段。
// 只允许收到不敏感的事件名和状态码。

public enum VaultLog {

    public static func debug(_ message: @autoclosure () -> String) {
        #if DEBUG
        // 即使在 Debug 下也只打时间 + 事件名。要排查问题时，
        // 临时加 print 比留下一个"能打任意内容"的日志口更安全。
        print("[vault] \(message())")
        #endif
    }

    /// 记录一次错误。只记录错误的**类型**，不记录 `errorDescription`
    /// （它可能包含文件名、状态码等；而出错路径上的上下文信息
    /// 恰恰是最容易夹带敏感数据的地方）。
    public static func failure(_ context: String, _ error: Error) {
        #if DEBUG
        print("[vault][fail] \(context): \(type(of: error))")
        #endif
    }
}
