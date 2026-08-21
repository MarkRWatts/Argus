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

    private let fileURL: URL

    init(fileURL: URL? = nil) {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            let dir = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/Argus", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            self.fileURL = dir.appendingPathComponent("allowlist.json")
        }
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

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([AllowlistEntry].self, from: data) else { return }
        entries = decoded
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}

/// Pure filtering logic, kept free of the actor-isolated store so it's
/// trivially unit-testable without spinning up MainActor/async plumbing.
enum AllowlistFilter {
    static func apply(_ matches: [MatchedRule], executable: String, isAllowed: (String, String) -> Bool) -> [MatchedRule] {
        matches.filter { !isAllowed($0.name, executable) }
    }
}
