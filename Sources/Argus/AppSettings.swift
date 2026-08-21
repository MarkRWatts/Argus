import Foundation

/// How aggressively Argus should interrupt you with a system notification.
enum NotificationThreshold: String, Codable, CaseIterable {
    case off
    case criticalOnly
    case elevatedAndAbove
    case allMatches

    var label: String {
        switch self {
        case .off: return "Off"
        case .criticalOnly: return "Critical only"
        case .elevatedAndAbove: return "Elevated and above"
        case .allMatches: return "Every match"
        }
    }

    /// Pure decision logic, kept free of UNUserNotificationCenter so it's
    /// directly unit-testable without an app bundle or notification
    /// permissions — neither of which a plain `swift test` run has.
    func shouldNotify(for severity: Severity) -> Bool {
        switch self {
        case .off: return false
        case .criticalOnly: return severity == .critical
        case .elevatedAndAbove: return severity >= .elevated
        case .allMatches: return severity >= .watch
        }
    }
}

/// User-tunable knobs, persisted to UserDefaults. Everything here previously
/// lived as hardcoded constants in ProcessMonitor — poll cadence and risk
/// decay in particular are genuinely a matter of taste (how twitchy vs. how
/// patient you want the gauge to be), so they're exposed rather than fixed.
@MainActor
final class AppSettings: ObservableObject {
    @Published var pollIntervalSeconds: Double { didSet { defaults.set(pollIntervalSeconds, forKey: Keys.pollInterval) } }
    @Published var riskDecayHalfLifeSeconds: Double { didSet { defaults.set(riskDecayHalfLifeSeconds, forKey: Keys.decayHalfLife) } }
    @Published var notificationThreshold: NotificationThreshold {
        didSet { defaults.set(notificationThreshold.rawValue, forKey: Keys.notificationThreshold) }
    }
    /// When true (the default), a `.routine` agent-attributed event — see
    /// `AgentActivityPolicy.Assessment` — skips the system notification it
    /// would otherwise have earned under `notificationThreshold`. Nothing
    /// else about the event changes: it still lands in the feed, history,
    /// and risk score exactly as usual, and a `.sensitive` agent-attributed
    /// event is never quieted regardless of this setting. Default true
    /// because routine agent activity (an AI coding session reading files,
    /// running builds) is expected to be frequent and is already
    /// distinguishable in the feed via its provenance tag — the interrupt
    /// is what this setting turns down, not the record.
    @Published var quietAgentNotifications: Bool {
        didSet { defaults.set(quietAgentNotifications, forKey: Keys.quietAgentNotifications) }
    }

    private let defaults: UserDefaults

    static let pollIntervalRange: ClosedRange<Double> = 0.5...5.0
    static let decayHalfLifeRange: ClosedRange<Double> = 15.0...180.0

    private enum Keys {
        static let pollInterval = "argus.pollIntervalSeconds"
        static let decayHalfLife = "argus.riskDecayHalfLifeSeconds"
        static let notificationThreshold = "argus.notificationThreshold"
        static let quietAgentNotifications = "argus.quietAgentNotifications"
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults

        let storedInterval = defaults.object(forKey: Keys.pollInterval) as? Double
        self.pollIntervalSeconds = Self.clamp(storedInterval ?? 1.2, to: Self.pollIntervalRange)

        let storedHalfLife = defaults.object(forKey: Keys.decayHalfLife) as? Double
        self.riskDecayHalfLifeSeconds = Self.clamp(storedHalfLife ?? 55.0, to: Self.decayHalfLifeRange)

        if let raw = defaults.string(forKey: Keys.notificationThreshold), let threshold = NotificationThreshold(rawValue: raw) {
            self.notificationThreshold = threshold
        } else {
            self.notificationThreshold = .criticalOnly
        }

        if let stored = defaults.object(forKey: Keys.quietAgentNotifications) as? Bool {
            self.quietAgentNotifications = stored
        } else {
            self.quietAgentNotifications = true
        }
    }

    private static func clamp(_ value: Double, to range: ClosedRange<Double>) -> Double {
        min(max(value, range.lowerBound), range.upperBound)
    }
}
