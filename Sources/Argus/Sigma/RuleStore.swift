import AppKit
import Foundation

/// Loads and manages the Sigma rule catalog: bundled rules shipped with the
/// app (imported from SigmaHQ, plus Argus's own gap-filling rules) and
/// user rules dropped into `~/Library/Application Support/Argus/rules/` —
/// the "rule management" surface. No rebuild is needed to add a rule: drop
/// a `.yml` file into that folder (reachable via `revealUserRulesFolder()`)
/// and hit reload.
@MainActor
final class RuleStore: ObservableObject {
    @Published private(set) var rules: [SigmaRule] = []
    @Published private(set) var disabledRuleIDs: Set<String> = []
    /// Rules dropped at load time because their `logsource` isn't something
    /// this app can actually evaluate (see `isCompatibleLogsource`) — e.g. a
    /// Windows-only rule dropped into the user rules folder by mistake.
    @Published private(set) var skippedIncompatibleCount: Int = 0

    private let bundledRulesDirectory: URL?
    let userRulesDirectory: URL
    private let stateFileURL: URL

    var activeRules: [SigmaRule] { rules.filter { !disabledRuleIDs.contains($0.id) } }

    init(bundledRulesDirectory: URL? = nil, userRulesDirectory: URL? = nil, stateFileURL: URL? = nil) {
        let appSupport = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Argus", isDirectory: true)
        self.bundledRulesDirectory = bundledRulesDirectory ?? Bundle.main.resourceURL?.appendingPathComponent("Rules", isDirectory: true)
        self.userRulesDirectory = userRulesDirectory ?? appSupport.appendingPathComponent("rules", isDirectory: true)
        self.stateFileURL = stateFileURL ?? appSupport.appendingPathComponent("rules-state.json")
        try? FileManager.default.createDirectory(at: self.userRulesDirectory, withIntermediateDirectories: true)
        // Keep the shared Argus support directory owner-only (see EventStore).
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: appSupport.path)

        loadDisabledState()
        reload()
    }

    func reload() {
        var loaded: [SigmaRule] = []
        var skipped = 0
        if let bundledRulesDirectory {
            for (directory, origin) in [
                (bundledRulesDirectory.appendingPathComponent("imported"), RuleOrigin.sigmaHQMacOS),
                (bundledRulesDirectory.appendingPathComponent("imported-portable"), RuleOrigin.sigmaHQPortable),
                (bundledRulesDirectory.appendingPathComponent("custom"), RuleOrigin.custom),
            ] {
                let (loadedRules, skippedCount) = Self.loadRules(from: directory, origin: origin)
                loaded += loadedRules
                skipped += skippedCount
            }
        }
        let (userRules, userSkipped) = Self.loadRules(from: userRulesDirectory, origin: .user)
        loaded += userRules
        skipped += userSkipped
        rules = loaded.sorted { $0.title < $1.title }
        skippedIncompatibleCount = skipped
    }

    func isEnabled(_ rule: SigmaRule) -> Bool {
        !disabledRuleIDs.contains(rule.id)
    }

    func toggle(_ rule: SigmaRule) {
        if disabledRuleIDs.contains(rule.id) {
            disabledRuleIDs.remove(rule.id)
        } else {
            disabledRuleIDs.insert(rule.id)
        }
        saveDisabledState()
    }

    /// Enabling/disabling a detection rule is security-relevant — an
    /// attacker with local execution could otherwise blind a rule silently
    /// before running the technique it detects. Require Touch ID/password
    /// and log every attempt (granted or denied) to the diagnostic log,
    /// independent of whether the toggle itself succeeds.
    func requestToggle(_ rule: SigmaRule, completion: @escaping (Bool) -> Void = { _ in }) {
        let willEnable = !isEnabled(rule)
        let verb = willEnable ? "enable" : "disable"
        RuleAuthenticator.authenticate(reason: "Authenticate to \(verb) the rule \u{201c}\(rule.title)\u{201d}.") { [weak self] granted in
            guard let self else { return }
            if granted {
                self.toggle(rule)
                DiagnosticsLog.write("rule \(verb)d: \(rule.id) (\(rule.title))")
            } else {
                DiagnosticsLog.write("rule \(verb) denied (authentication failed): \(rule.id) (\(rule.title))")
            }
            completion(granted)
        }
    }

    func revealUserRulesFolder() {
        NSWorkspace.shared.activateFileViewerSelecting([userRulesDirectory])
    }

    /// Loads every rule in `directory`, returning the rules this app can
    /// actually evaluate alongside a count of how many were dropped for
    /// having an incompatible `logsource` — a nonisolated static, so the
    /// count is handed back rather than written straight to a `@MainActor`
    /// property; `reload()` aggregates it across directories.
    nonisolated static func loadRules(from directory: URL, origin: RuleOrigin) -> (rules: [SigmaRule], skipped: Int) {
        guard let files = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) else { return ([], 0) }
        var result: [SigmaRule] = []
        var skipped = 0
        for file in files.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard ["yml", "yaml"].contains(file.pathExtension.lowercased()) else { continue }
            guard let content = try? String(contentsOf: file, encoding: .utf8) else { continue }
            for (text, value) in YAMLParser.parseDocumentsWithSource(content) {
                guard let rule = SigmaRule.parse(value, sourceFile: file.lastPathComponent, origin: origin, rawYAML: text) else { continue }
                guard isCompatibleLogsource(product: rule.logsourceProduct, category: rule.logsourceCategory) else {
                    skipped += 1
                    continue
                }
                result.append(rule)
            }
        }
        return (result, skipped)
    }

    /// This app only ever samples macOS process-creation events, so a rule
    /// is evaluable only if its `logsource.category` is unset or
    /// `process_creation`, and its `logsource.product` is unset, `macos`,
    /// or `linux` — `linux` because the bundled imported-portable/ rules are
    /// genuinely portable shell/interpreter techniques that apply unchanged
    /// on macOS (see RuleOrigin.sigmaHQPortable).
    nonisolated private static func isCompatibleLogsource(product: String?, category: String?) -> Bool {
        let categoryOK = category == nil || category?.lowercased() == "process_creation"
        let productOK: Bool
        if let product {
            let normalized = product.lowercased()
            productOK = normalized == "macos" || normalized == "linux"
        } else {
            productOK = true
        }
        return categoryOK && productOK
    }

    private func loadDisabledState() {
        guard let data = try? Data(contentsOf: stateFileURL),
              let decoded = try? JSONDecoder().decode(Set<String>.self, from: data) else { return }
        disabledRuleIDs = decoded
    }

    private func saveDisabledState() {
        guard let data = try? JSONEncoder().encode(disabledRuleIDs) else { return }
        try? data.write(to: stateFileURL, options: .atomic)
    }
}
