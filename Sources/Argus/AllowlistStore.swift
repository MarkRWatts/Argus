import Foundation

struct AllowlistEntry: Identifiable, Codable, Equatable {
    let id: UUID
    let ruleName: String
    let executable: String
    let createdAt: Date

    init(id: UUID = UUID(), ruleName: String, executable: String, createdAt: Date = Date()) {
        self.id = id
        self.ruleName = ruleName
        self.executable = executable
        self.createdAt = createdAt
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
    /// an authenticated write, computed once at init. See `IntegrityGuard` —
    /// the app checks this after construction to decide whether to report a
    /// tamper event; the store itself doesn't emit events.
    private(set) var integrityVerdict: IntegrityVerdict

    let fileURL: URL
    private let integrityGuard: IntegrityGuard

    init(fileURL: URL? = nil, integrityGuard: IntegrityGuard = .shared) {
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
        integrityVerdict = integrityGuard.verify(self.fileURL)
        load()
    }

    func isAllowed(ruleName: String, executable: String) -> Bool {
        entries.contains { $0.ruleName == ruleName && $0.executable == executable }
    }

    func allow(ruleName: String, executable: String) {
        guard !isAllowed(ruleName: ruleName, executable: executable) else { return }
        entries.append(AllowlistEntry(ruleName: ruleName, executable: executable))
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
    func requestAllow(ruleName: String, executable: String, completion: @escaping (Bool) -> Void = { _ in }) {
        guard !isAllowed(ruleName: ruleName, executable: executable) else {
            completion(true)
            return
        }
        RuleAuthenticator.authenticate(reason: "Authenticate to allowlist \u{201c}\(ruleName)\u{201d} alerts from \(executable).") { [weak self] granted in
            guard let self else { return }
            if granted {
                self.allow(ruleName: ruleName, executable: executable)
                DiagnosticsLog.write("allowlist added: \(ruleName) / \(executable)")
            } else {
                DiagnosticsLog.write("allowlist add denied (authentication failed): \(ruleName) / \(executable)")
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
        integrityGuard.recordAuthenticatedWrite(of: fileURL)
    }
}

/// Pure filtering logic, kept free of the actor-isolated store so it's
/// trivially unit-testable without spinning up MainActor/async plumbing.
enum AllowlistFilter {
    static func apply(_ matches: [MatchedRule], executable: String, isAllowed: (String, String) -> Bool) -> [MatchedRule] {
        matches.filter { !isAllowed($0.name, executable) }
    }
}
