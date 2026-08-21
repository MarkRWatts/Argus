import AppKit
import Foundation

/// On-disk shape of `rules-state.json`. `disabled` mirrors
/// `RuleStore.disabledRuleIDs`; `supersessionsApplied` records which
/// entries of `RuleStore.supersededBundledRuleIDs` have already been
/// auto-applied, so a user who deliberately re-enables a superseded rule
/// via the Touch ID-gated `requestToggle` has that stick across restarts
/// instead of the rule being silently disabled again on the next launch.
/// Older installs wrote this file as a bare `Set<String>` of disabled IDs —
/// `RuleStore.loadDisabledState` falls back to that shape when this one
/// fails to decode, treating `supersessionsApplied` as empty.
private struct RuleDisabledState: Codable {
    var disabled: [String]
    var supersessionsApplied: [String]
}

/// Loads and manages the Sigma rule catalog: bundled rules shipped with the
/// app (imported from SigmaHQ, plus Argus's own gap-filling rules) and
/// user rules dropped into `~/Library/Application Support/Argus/rules/` —
/// the "rule management" surface. No rebuild is needed to add a rule: drop
/// a `.yml` file into that folder (reachable via `revealUserRulesFolder()`)
/// and hit reload.
@MainActor
final class RuleStore: ObservableObject {
    /// Bundled imported rules superseded by a more precise Argus-authored
    /// replacement — keyed by the superseded imported rule's `id`, valued
    /// by the replacement's `id`. Applied once per entry (see
    /// `supersessionsApplied` in `RuleDisabledState`) so re-enabling the
    /// superseded rule by hand isn't undone on the next launch.
    static let supersededBundledRuleIDs: [String: String] = [
        // SigmaHQ "Gatekeeper Bypass via Xattr": CommandLine|contains|all
        // of '-d' and 'com.apple.quarantine' can false-positive on the safe
        // xattr -w (add-quarantine) direction Homebrew uses, when a '-d'
        // substring lands inside the quarantine value's UUID by chance.
        // Superseded by the whitespace-bounded-flag Argus rule, which tells
        // removal (-d/-c) apart from addition (-w).
        "f5141b6d-9f42-41c6-a7bf-2a780678b29b": "8cbd6022-931f-4017-ab5e-a15264ac91e7",
    ]

    @Published private(set) var rules: [SigmaRule] = []
    @Published private(set) var disabledRuleIDs: Set<String> = []
    /// Which entries of `supersededBundledRuleIDs` have already been
    /// auto-disabled at some past launch — see `RuleDisabledState`.
    private var supersessionsApplied: Set<String> = []
    /// Rules dropped at load time because their `logsource` isn't something
    /// this app can actually evaluate (see `isCompatibleLogsource`) — e.g. a
    /// Windows-only rule dropped into the user rules folder by mistake.
    @Published private(set) var skippedIncompatibleCount: Int = 0
    /// Result of verifying `rules-state.json` against the last MAC recorded
    /// by an authenticated write. `nil` until `verifyIntegrity` completes —
    /// verification is deliberately not done in init, because the Keychain
    /// key fetch can present a consent prompt that would otherwise block app
    /// launch (see `IntegrityGuard`'s threading note). The store itself
    /// doesn't emit events; the app acts on the verdict.
    private(set) var integrityVerdict: IntegrityVerdict?

    private let bundledRulesDirectory: URL?
    let userRulesDirectory: URL
    let stateFileURL: URL
    /// Optional so that constructing a store (in tests, previews, tools)
    /// never touches the real Keychain or the shared sidecar as a side
    /// effect — the app opts in explicitly with `.shared`.
    private let integrityGuard: IntegrityGuard?

    var activeRules: [SigmaRule] { rules.filter { !disabledRuleIDs.contains($0.id) } }

    init(bundledRulesDirectory: URL? = nil, userRulesDirectory: URL? = nil, stateFileURL: URL? = nil, integrityGuard: IntegrityGuard? = nil) {
        let appSupport = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Argus", isDirectory: true)
        self.bundledRulesDirectory = bundledRulesDirectory ?? Bundle.main.resourceURL?.appendingPathComponent("Rules", isDirectory: true)
        self.userRulesDirectory = userRulesDirectory ?? appSupport.appendingPathComponent("rules", isDirectory: true)
        self.stateFileURL = stateFileURL ?? appSupport.appendingPathComponent("rules-state.json")
        self.integrityGuard = integrityGuard
        try? FileManager.default.createDirectory(at: self.userRulesDirectory, withIntermediateDirectories: true)
        // Keep the shared Argus support directory owner-only (see EventStore).
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: appSupport.path)

        loadDisabledState()
        reload()
        applySupersessions()
    }

    /// Verifies `rules-state.json` off the main thread and stores the
    /// verdict (also handed to `completion`, on the main actor). A no-op
    /// when no guard was injected.
    func verifyIntegrity(completion: @escaping @MainActor (IntegrityVerdict) -> Void = { _ in }) {
        guard let integrityGuard else { return }
        integrityGuard.verifyAsync(stateFileURL) { [weak self] verdict in
            Task { @MainActor in
                self?.integrityVerdict = verdict
                completion(verdict)
            }
        }
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

    /// For each not-yet-applied entry in `supersededBundledRuleIDs` whose
    /// superseded rule actually loaded (guards against disabling — and
    /// writing state for — an id that isn't even part of this rule set, e.g.
    /// a minimal test fixture or a build missing the imported directory),
    /// disables the superseded rule and records the entry as applied. Only
    /// once per entry, ever: a user who deliberately re-enables the
    /// superseded rule afterward (Touch ID-gated `requestToggle`) keeps it
    /// enabled across restarts, since `supersessionsApplied` already has
    /// the entry and this loop skips it. Called after `reload()` so `rules`
    /// is populated.
    private func applySupersessions() {
        let loadedRuleIDs = Set(rules.map(\.id))
        var changed = false
        for (supersededID, replacementID) in Self.supersededBundledRuleIDs {
            guard loadedRuleIDs.contains(supersededID) else { continue }
            guard !supersessionsApplied.contains(supersededID) else { continue }
            disabledRuleIDs.insert(supersededID)
            supersessionsApplied.insert(supersededID)
            changed = true
            DiagnosticsLog.write("rule auto-disabled (superseded by \(replacementID)): \(supersededID)")
        }
        if changed {
            saveDisabledState()
        }
    }

    private func loadDisabledState() {
        guard let data = try? Data(contentsOf: stateFileURL) else { return }
        if let decoded = try? JSONDecoder().decode(RuleDisabledState.self, from: data) {
            disabledRuleIDs = Set(decoded.disabled)
            supersessionsApplied = Set(decoded.supersessionsApplied)
        } else if let legacy = try? JSONDecoder().decode(Set<String>.self, from: data) {
            // Pre-supersession state file: just the disabled IDs, no record
            // of which supersessions had already run.
            disabledRuleIDs = legacy
            supersessionsApplied = []
        }
    }

    private func saveDisabledState() {
        let state = RuleDisabledState(disabled: Array(disabledRuleIDs), supersessionsApplied: Array(supersessionsApplied))
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? data.write(to: stateFileURL, options: .atomic)
        integrityGuard?.recordAuthenticatedWrite(of: stateFileURL)
    }
}
