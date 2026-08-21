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

        loadDisabledState()
        reload()
    }

    func reload() {
        var loaded: [SigmaRule] = []
        if let bundledRulesDirectory {
            loaded += Self.loadRules(from: bundledRulesDirectory.appendingPathComponent("imported"), origin: .sigmaHQMacOS)
            loaded += Self.loadRules(from: bundledRulesDirectory.appendingPathComponent("imported-portable"), origin: .sigmaHQPortable)
            loaded += Self.loadRules(from: bundledRulesDirectory.appendingPathComponent("custom"), origin: .custom)
        }
        loaded += Self.loadRules(from: userRulesDirectory, origin: .user)
        rules = loaded.sorted { $0.title < $1.title }
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

    func revealUserRulesFolder() {
        NSWorkspace.shared.activateFileViewerSelecting([userRulesDirectory])
    }

    nonisolated static func loadRules(from directory: URL, origin: RuleOrigin) -> [SigmaRule] {
        guard let files = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) else { return [] }
        var result: [SigmaRule] = []
        for file in files.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard ["yml", "yaml"].contains(file.pathExtension.lowercased()) else { continue }
            guard let content = try? String(contentsOf: file, encoding: .utf8) else { continue }
            for (text, value) in YAMLParser.parseDocumentsWithSource(content) {
                if let rule = SigmaRule.parse(value, sourceFile: file.lastPathComponent, origin: origin, rawYAML: text) {
                    result.append(rule)
                }
            }
        }
        return result
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
