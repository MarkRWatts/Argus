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

    init(id: UUID = UUID(), pid: Int32, ppid: Int32, executable: String, command: String, rules: [MatchedRule], timestamp: Date) {
        self.id = id
        self.pid = pid
        self.ppid = ppid
        self.executable = executable
        self.command = command
        self.rules = rules
        self.timestamp = timestamp
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
