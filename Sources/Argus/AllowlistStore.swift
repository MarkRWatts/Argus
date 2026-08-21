import Foundation

struct AllowlistEntry: Identifiable, Codable, Equatable {
    let id: UUID
    let ruleName: String
    let executable: String
    let createdAt: Date
    /// When set, this entry only suppresses alerts for a process whose
    /// `ProcessEvent.provenance` includes this label (case-insensitively) —
    /// e.g. "claude", so allowlisting (rule, zsh) doesn't blind the rule for
    /// every `zsh` on the system, only the ones running under that
    /// supervisor. `nil` (the default) means unconditional, matching the
    /// suppression semantics from before this field existed.
    ///
    /// Matching is by provenance *label*, not a raw ancestry substring —
    /// deliberately reusing `ProvenanceClassifier` as the single source of
    /// truth for what an ancestry means, rather than giving the allowlist
    /// its own, possibly divergent, notion of "under claude".
    ///
    /// Declared `Optional` so the compiler-synthesized `Decodable` decodes it
    /// with `decodeIfPresent`: `allowlist.json` entries written before this
    /// field existed are missing the key entirely and still decode, as
    /// unconditional entries.
    let requiredProvenance: String?

    init(id: UUID = UUID(), ruleName: String, executable: String, createdAt: Date = Date(), requiredProvenance: String? = nil) {
        self.id = id
        self.ruleName = ruleName
        self.executable = executable
        self.createdAt = createdAt
        self.requiredProvenance = requiredProvenance
    }

    /// Whether this entry suppresses an alert for the given rule/executable
    /// observed with the given provenance labels — the one definition of
    /// "does this entry apply", shared by `AllowlistStore.isAllowed`
    /// (live suppression) and `AllowlistStore.allow` (redundancy checks on
    /// write) so the two can never drift apart.
    func matches(ruleName: String, executable: String, provenance: [String]) -> Bool {
        guard self.ruleName == ruleName, self.executable == executable else { return false }
        guard let requiredProvenance else { return true }
        return provenance.contains { $0.caseInsensitiveCompare(requiredProvenance) == .orderedSame }
    }
}

/// Persists "stop alerting me about this rule for this binary" decisions so a
/// legitimate, repeated automation doesn't retrigger the same alert forever.
/// Suppression is scoped to (rule name, executable), not the full command
/// line — narrow enough that allowlisting one automation doesn't blind Argus
/// to a *different* technique that happens to involve the same binary.
@MainActor
final class AllowlistStore: ObservableObject {
    @Published private(set) var entries: [AllowlistEntry] = []
    /// Result of verifying `allowlist.json` against the last MAC recorded by
    /// an authenticated write. `nil` until `verifyIntegrity` completes —
    /// verification is deliberately not done in init, because the Keychain
    /// key fetch can present a consent prompt that would otherwise block app
    /// launch (see `IntegrityGuard`'s threading note). The store itself
    /// doesn't emit events; the app acts on the verdict.
    private(set) var integrityVerdict: IntegrityVerdict?

    let fileURL: URL
    /// Optional so that constructing a store (in tests, previews, tools)
    /// never touches the real Keychain or the shared sidecar as a side
    /// effect — the app opts in explicitly with `.shared`.
    private let integrityGuard: IntegrityGuard?

    init(fileURL: URL? = nil, integrityGuard: IntegrityGuard? = nil) {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            let dir = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/Argus", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            // Keep the shared Argus support directory owner-only (see EventStore).
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
            self.fileURL = dir.appendingPathComponent("allowlist.json")
        }
        self.integrityGuard = integrityGuard
        load()
    }

    /// Verifies `allowlist.json` off the main thread and stores the verdict
    /// (also handed to `completion`, on the main actor). A no-op when no
    /// guard was injected.
    func verifyIntegrity(completion: @escaping @MainActor (IntegrityVerdict) -> Void = { _ in }) {
        guard let integrityGuard else { return }
        integrityGuard.verifyAsync(fileURL) { [weak self] verdict in
            Task { @MainActor in
                self?.integrityVerdict = verdict
                completion(verdict)
            }
        }
    }

    func isAllowed(ruleName: String, executable: String, provenance: [String]) -> Bool {
        entries.contains { $0.matches(ruleName: ruleName, executable: executable, provenance: provenance) }
    }

    /// True when an existing entry already covers a request to allowlist
    /// (ruleName, executable) at `requiredProvenance`'s scope — either an
    /// exact-scope duplicate, or a broader unconditional entry that already
    /// suppresses everything a narrower scoped request would. Distinct from
    /// `isAllowed`: that answers "would this suppress a live event right
    /// now"; this answers "would adding this entry be redundant".
    private func alreadyCovers(ruleName: String, executable: String, requiredProvenance: String?) -> Bool {
        entries.contains { entry in
            guard entry.ruleName == ruleName, entry.executable == executable else { return false }
            return entry.requiredProvenance == nil || entry.requiredProvenance == requiredProvenance
        }
    }

    func allow(ruleName: String, executable: String, requiredProvenance: String? = nil) {
        guard !alreadyCovers(ruleName: ruleName, executable: executable, requiredProvenance: requiredProvenance) else { return }
        entries.append(AllowlistEntry(ruleName: ruleName, executable: executable, requiredProvenance: requiredProvenance))
        save()
    }

    func remove(_ id: UUID) {
        entries.removeAll { $0.id == id }
        save()
    }

    /// Adding or removing an allowlist entry silences (or restores) alerts
    /// for a (rule, executable) pair — the same kind of silent-blinding risk
    /// as disabling a rule outright, so it goes through the same Touch
    /// ID/password gate as `RuleStore.requestToggle`, with every attempt
    /// logged regardless of outcome.
    func requestAllow(ruleName: String, executable: String, requiredProvenance: String? = nil, completion: @escaping (Bool) -> Void = { _ in }) {
        guard !alreadyCovers(ruleName: ruleName, executable: executable, requiredProvenance: requiredProvenance) else {
            completion(true)
            return
        }
        let scopeSuffix = requiredProvenance.map { " (only under \($0))" } ?? ""
        RuleAuthenticator.authenticate(reason: "Authenticate to allowlist \u{201c}\(ruleName)\u{201d} alerts from \(executable)\(scopeSuffix).") { [weak self] granted in
            guard let self else { return }
            if granted {
                self.allow(ruleName: ruleName, executable: executable, requiredProvenance: requiredProvenance)
                DiagnosticsLog.write("allowlist added: \(ruleName) / \(executable)\(scopeSuffix)")
            } else {
                DiagnosticsLog.write("allowlist add denied (authentication failed): \(ruleName) / \(executable)\(scopeSuffix)")
            }
            completion(granted)
        }
    }

    func requestRemove(_ id: UUID, completion: @escaping (Bool) -> Void = { _ in }) {
        guard let entry = entries.first(where: { $0.id == id }) else {
            completion(false)
            return
        }
        RuleAuthenticator.authenticate(reason: "Authenticate to revoke the allowlist entry for \u{201c}\(entry.ruleName)\u{201d} / \(entry.executable).") { [weak self] granted in
            guard let self else { return }
            if granted {
                self.remove(id)
                DiagnosticsLog.write("allowlist removed: \(entry.ruleName) / \(entry.executable)")
            } else {
                DiagnosticsLog.write("allowlist remove denied (authentication failed): \(entry.ruleName) / \(entry.executable)")
            }
            completion(granted)
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([AllowlistEntry].self, from: data) else { return }
        entries = decoded
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        try? data.write(to: fileURL, options: .atomic)
        integrityGuard?.recordAuthenticatedWrite(of: fileURL)
    }
}

/// Pure filtering logic, kept free of the actor-isolated store so it's
/// trivially unit-testable without spinning up MainActor/async plumbing.
enum AllowlistFilter {
    static func apply(_ matches: [MatchedRule], executable: String, provenance: [String], isAllowed: (String, String, [String]) -> Bool) -> [MatchedRule] {
        matches.filter { !isAllowed($0.name, executable, provenance) }
    }
}
