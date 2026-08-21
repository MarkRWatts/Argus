import Foundation
import UserNotifications

/// Thin wrapper around UNUserNotificationCenter. Deliberately not exercised
/// by the test suite — it needs a running app bundle and OS-level
/// permission, neither of which `swift test` has, and the actual decision
/// of *whether* to notify lives in NotificationThreshold.shouldNotify,
/// which is pure and tested there instead.
enum NotificationManager {
    /// Category attached to every delivered event notification. Must match
    /// what `NotificationResponder` (the `UNUserNotificationCenterDelegate`
    /// wired up in `ArgusApp.init`) switches on when handling actions.
    static let categoryIdentifier = "argus.event"
    static let showActionIdentifier = "argus.event.show"
    static let allowlistActionIdentifier = "argus.event.allowlist"

    /// userInfo keys carrying just enough context for `NotificationResponder`
    /// to act on a notification without re-reading the event store.
    static let ruleNameKey = "ruleName"
    static let executableKey = "executable"

    static func requestAuthorizationIfNeeded() {
        let center = UNUserNotificationCenter.current()
        center.setNotificationCategories([actionableCategory])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// "Show in Argus" brings the app forward regardless of authentication —
    /// it's read-only. "Allowlist…" changes what Argus suppresses, so it
    /// carries `.authenticationRequired`: macOS itself will demand the
    /// screen be unlocked before invoking it, on top of the Touch
    /// ID/password prompt `AllowlistStore.requestAllow` raises once it runs.
    private static var actionableCategory: UNNotificationCategory {
        let show = UNNotificationAction(identifier: showActionIdentifier, title: "Show in Argus", options: [.foreground])
        let allow = UNNotificationAction(identifier: allowlistActionIdentifier, title: "Allowlist…", options: [.authenticationRequired])
        return UNNotificationCategory(identifier: categoryIdentifier, actions: [show, allow], intentIdentifiers: [], options: [])
    }

    static func notify(event: ProcessEvent) {
        let content = UNMutableNotificationContent()
        content.title = "Argus — \(event.topSeverity.label)"
        content.subtitle = event.executable
        content.body = event.rules.map(\.name).joined(separator: ", ")
        content.sound = .default
        content.categoryIdentifier = categoryIdentifier
        // An event can trip several rules; only the top-severity one is
        // actionable from the notification's "Allowlist…" action (see
        // NotificationResponder's doc comment on that limitation), so that's
        // the only one worth carrying in userInfo.
        if let topRule = event.rules.first(where: { $0.severity == event.topSeverity }) {
            content.userInfo = [ruleNameKey: topRule.name, executableKey: event.executable]
        }

        let request = UNNotificationRequest(identifier: event.id.uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
