import Foundation

enum Severity: Int, Comparable, CaseIterable, Codable {
    case info = 0
    case watch = 1
    case elevated = 2
    case critical = 3

    static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rawValue < rhs.rawValue }

    var label: String {
        switch self {
        case .info: return "INFO"
        case .watch: return "WATCH"
        case .elevated: return "ELEVATED"
        case .critical: return "CRITICAL"
        }
    }

    var weight: Double {
        switch self {
        case .info: return 2
        case .watch: return 8
        case .elevated: return 20
        case .critical: return 42
        }
    }
}

struct MatchedRule: Identifiable, Codable {
    let id: UUID
    let name: String
    let severity: Severity
    let technique: String
    let explanation: String

    init(id: UUID = UUID(), name: String, severity: Severity, technique: String, explanation: String) {
        self.id = id
        self.name = name
        self.severity = severity
        self.technique = technique
        self.explanation = explanation
    }
}

/// A single OS process observed via a `ps` sample.
struct RawProcess: Identifiable, Equatable {
    let id: Int32          // pid
    let ppid: Int32
    let command: String    // full command line
    let executable: String // short name, e.g. "curl"
    /// Sigma's "Image" field, normalized to always end in "/<name>" even
    /// when the process was launched with a bare command name (typing
    /// `curl ...` at a shell reports argv[0] as literally "curl", not
    /// "/usr/bin/curl" — verified empirically against this ps). Without
    /// this normalization, every imported rule's `Image|endswith: '/curl'`
    /// would silently never match ordinary typed shell usage.
    let image: String
    /// The owning account's short username, as reported by `ps -o user`.
    /// macOS short usernames never contain spaces, which is what makes the
    /// fixed-width `pid ppid user command...` column parse tractable.
    let user: String
}

/// A process that tripped one or more rules — what the dashboard actually shows.
/// Codable so it can round-trip through EventStore's on-disk history log.
struct ProcessEvent: Identifiable, Codable {
    let id: UUID
    let pid: Int32
    let ppid: Int32
    let executable: String
    let command: String
    let rules: [MatchedRule]
    let timestamp: Date
    /// Supervisor labels from `ProvenanceClassifier` (e.g. "claude",
    /// "docker") — attribution for triage, never a trust signal; see
    /// `ProvenanceTag`'s doc comment. Empty for synthetic events (chain,
    /// persistence, tamper) that don't carry a real process ancestry.
    let provenance: [String]

    init(id: UUID = UUID(), pid: Int32, ppid: Int32, executable: String, command: String, rules: [MatchedRule], timestamp: Date, provenance: [String] = []) {
        self.id = id
        self.pid = pid
        self.ppid = ppid
        self.executable = executable
        self.command = command
        self.rules = rules
        self.timestamp = timestamp
        self.provenance = provenance
    }

    private enum CodingKeys: String, CodingKey {
        case id, pid, ppid, executable, command, rules, timestamp, provenance
    }

    // Custom decode so historical events.jsonl lines written before
    // `provenance` existed still decode: `decodeIfPresent` falls back to `[]`
    // instead of failing the whole load on a missing key. `encode(to:)` is
    // left to the synthesized Encodable conformance — every newly-written
    // event always carries the key.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        pid = try container.decode(Int32.self, forKey: .pid)
        ppid = try container.decode(Int32.self, forKey: .ppid)
        executable = try container.decode(String.self, forKey: .executable)
        command = try container.decode(String.self, forKey: .command)
        rules = try container.decode([MatchedRule].self, forKey: .rules)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        provenance = try container.decodeIfPresent([String].self, forKey: .provenance) ?? []
    }

    var topSeverity: Severity { rules.map(\.severity).max() ?? .info }
}

/// Lightweight node the Orbit view renders — kept alive for a while after the event fires
/// so the visualization has something to animate, then aged out.
struct OrbitNode: Identifiable {
    let id: UUID
    let pid: Int32
    let ppid: Int32
    let severity: Severity
    let label: String
    let bornAt: Date
    var angle: Double
}
