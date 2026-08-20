import Foundation

enum Severity: Int, Comparable, CaseIterable {
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

struct MatchedRule: Identifiable {
    let id = UUID()
    let name: String
    let severity: Severity
    let technique: String
    let explanation: String
}

/// A single OS process observed via a `ps` sample.
struct RawProcess: Identifiable, Equatable {
    let id: Int32          // pid
    let ppid: Int32
    let command: String    // full command line
    let executable: String // short name, e.g. "curl"
}

/// A process that tripped one or more rules — what the dashboard actually shows.
struct ProcessEvent: Identifiable {
    let id = UUID()
    let pid: Int32
    let ppid: Int32
    let executable: String
    let command: String
    let rules: [MatchedRule]
    let timestamp: Date

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
