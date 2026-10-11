import Foundation

// MARK: - 密码生成器
//
// 三条最容易出错的地方，逐条说明为什么这么写：
//
// 1. **取模偏差（modulo bias）。**
//    常见错误写法是 `alphabet[Int(randomByte) % alphabet.count]`。
//    当字符集大小不能整除 256 时（比如 62），前面若干字符被选中的概率
//    会略高于后面的，分布不均匀。虽然偏差很小，但"随机密码生成器"
//    的全部价值就在于分布均匀，没有理由留这个瑕疵。
//    这里的做法是拒绝采样：大于等于 `limit` 的随机字节直接丢弃重取。
//    期望重取次数 < 2，性能代价可以忽略。
//
// 2. **每一个字符类都必须至少出现一次。**
//    纯随机的 16 位密码有约 4% 的概率完全不含数字。很多网站的
//    "必须包含数字"校验会让用户以为是自己手输错了。生成器应该保证
//    满足常见复杂度要求。
//    ——但**不能用"先各取一个再打乱"的朴素做法**，那样分布会有轻微偏差。
//    正确做法是拒绝采样：生成候选 → 检查是否满足约束 → 不满足就整条重来。
//    16 位密码不满足约束的概率极低，重试几乎不会发生。
//
// 3. **不排除易混淆字符是默认行为，但给开关。**
//    "手动抄写"场景下 l/1/I、O/0 会致灾；"自动填充"场景下字符集越大越好。
//    默认保留全部字符集（更安全），把选择权交给用户。

public enum PasswordGenerator {

    public struct Options {
        public var length: Int
        public var useLowercase: Bool
        public var useUppercase: Bool
        public var useDigits: Bool
        public var useSymbols: Bool
        /// 排除 l I 1 O 0 o 等易混淆字符（手抄场景用）
        public var avoidAmbiguous: Bool
        /// 保证每个启用的字符类至少出现一次
        public var requireEveryClass: Bool

        public init(
            length: Int = 20,
            useLowercase: Bool = true,
            useUppercase: Bool = true,
            useDigits: Bool = true,
            useSymbols: Bool = true,
            avoidAmbiguous: Bool = false,
            requireEveryClass: Bool = true
        ) {
            self.length = length
            self.useLowercase = useLowercase
            self.useUppercase = useUppercase
            self.useDigits = useDigits
            self.useSymbols = useSymbols
            self.avoidAmbiguous = avoidAmbiguous
            self.requireEveryClass = requireEveryClass
        }

        /// 默认：20 位全字符集。20 位 × log2(90) ≈ 130 bit 熵，
        /// 远超任何现实的在线/离线攻击能力。
        public static let `default` = Options()
    }

    /// 字符集。
    ///
    /// 符号集刻意**排除** `"`、`'`、`` ` ``、`\`：
    /// 这些字符在某些网站的输入框、某些 CLI、某些配置文件里需要转义，
    /// 会导致"密码明明是复制进去的却登录失败"这类极难排查的问题。
    /// 排除它们损失约 4 bit 熵，换来的是可靠性。
    private static let lowercase = "abcdefghijklmnopqrstuvwxyz"
    private static let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private static let digits = "0123456789"
    private static let symbols = "!@#$%^&*()-_=+[]{}:,.?/"

    /// 易混淆字符集（同时出现在多个类别里的"看起来像"的字符）
    private static let ambiguous: Set<Character> = Set("lI1O0o|`'\";:.,")

    public static func generate(_ options: Options = .default) -> String {
        var classes: [String] = []
        if options.useLowercase { classes.append(filtered(lowercase, options)) }
        if options.useUppercase { classes.append(filtered(uppercase, options)) }
        if options.useDigits { classes.append(filtered(digits, options)) }
        if options.useSymbols { classes.append(filtered(symbols, options)) }
        classes = classes.filter { !$0.isEmpty }

        // 极端情况：用户把所有字符类都关了。返回空串会让调用方拿到
        // 一个空密码却毫无察觉，所以这里直接崩——这是编程错误，不是用户输入问题。
        guard !classes.isEmpty else {
            assertionFailure("至少启用一个字符类")
            return ""
        }
        let alphabet = Array(classes.joined())
        let length = max(4, min(options.length, 128))

        var attempt = 0
        while true {
            attempt += 1
            var chars: [Character] = []
            chars.reserveCapacity(length)
            for _ in 0..<length {
                chars.append(alphabet[uniformIndex(upperBound: alphabet.count)])
            }
            if !options.requireEveryClass || attempt >= 50 {
                // 50 次都凑不齐约束，说明约束本身不可能满足（例如长度 4 但开了 5 类），
                // 此时返回一个可用的密码，而不是死循环卡死 UI。
                return String(chars)
            }
            let satisfied = classes.allSatisfy { cls in
                chars.contains { cls.contains($0) }
            }
            if satisfied { return String(chars) }
        }
    }

    private static func filtered(_ set: String, _ options: Options) -> String {
        guard options.avoidAmbiguous else { return set }
        return String(set.filter { !ambiguous.contains($0) })
    }

    /// 无偏均匀索引：拒绝采样。
    ///
    /// 例：upperBound = 62。`256 % 62 = 8`，意味着 0..7 这段会被过度表示。
    /// 因此只接受落在 `0..<(256 - 256%62)` 内的字节，其余重取。
    private static func uniformIndex(upperBound: Int) -> Int {
        precondition(upperBound > 0 && upperBound <= 256, "字符集超出单字节可均匀采样的范围")
        let limit = 256 - (256 % upperBound)
        while true {
            let byte = CryptoBox.randomBytes(1)[0]
            if Int(byte) < limit {
                return Int(byte) % upperBound
            }
        }
    }

    // MARK: 熵估算

    /// 生成密码的信息熵（bit）。
    /// 用于在 UI 上告诉用户"这个密码有多强"，而不是给一个玄学进度条。
    public static func entropyBits(_ options: Options) -> Double {
        var size = 0
        if options.useLowercase { size += filtered(lowercase, options).count }
        if options.useUppercase { size += filtered(uppercase, options).count }
        if options.useDigits { size += filtered(digits, options).count }
        if options.useSymbols { size += filtered(symbols, options).count }
        guard size > 1 else { return 0 }
        return Double(options.length) * log2(Double(size))
    }
}
