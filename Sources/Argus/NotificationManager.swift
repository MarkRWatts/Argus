import Foundation
import UserNotifications

/// Thin wrapper around UNUserNotificationCenter. Deliberately not exercised
/// by the test suite — it needs a running app bundle and OS-level
/// permission, neither of which `swift test` has, and the actual decision
/// of *whether* to notify lives in NotificationThreshold.shouldNotify,
/// which is pure and tested there instead.
enum NotificationManager {
    static func requestAuthorizationIfNeeded() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func notify(event: ProcessEvent) {
        let content = UNMutableNotificationContent()
        content.title = "Argus — \(event.topSeverity.label)"
        content.subtitle = event.executable
        content.body = event.rules.map(\.name).joined(separator: ", ")
        content.sound = .default

        let request = UNNotificationRequest(identifier: event.id.uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
