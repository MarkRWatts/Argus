import Foundation
import AppKit
import UserNotifications

/// Handles taps and actions on delivered Argus notifications — the
/// notification-side counterpart to the event feed's right-click menu.
/// Instantiated once in `ArgusApp.init` and held there for the app's
/// lifetime (see `ArgusApp.notificationResponder`), since
/// `UNUserNotificationCenter.delegate` is a weak reference and nothing else
/// keeps this object alive otherwise.
final class NotificationResponder: NSObject, UNUserNotificationCenterDelegate {
    /// Weak so this responder never becomes the thing keeping `AllowlistStore`
    /// (and its disk I/O, Touch ID plumbing) alive past the app's own
    /// `_allowlist` StateObject — mirrors the `[weak m]` pattern `App.swift`
    /// already uses when wiring `PersistenceWatcher`.
    private weak var allowlist: AllowlistStore?
    private let mainWindowID: String

    init(allowlist: AllowlistStore, mainWindowID: String) {
        self.allowlist = allowlist
        self.mainWindowID = mainWindowID
    }

    /// UNUserNotificationCenter delegate callbacks can arrive off the main
    /// thread, and both `AllowlistStore` and AppKit require the main thread —
    /// hence `nonisolated` here with an explicit hop to `@MainActor` below
    /// rather than isolating this whole class (which would fight the
    /// framework's expectation that these delegate methods are plain,
    /// synchronously-callable ObjC hooks).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        // Before this delegate existed, Argus had no
        // UNUserNotificationCenter delegate at all, and with no delegate the
        // system still shows the alert while the app is frontmost. Adding a
        // delegate opts back into the platform's foreground-suppression
        // behavior unless it explicitly re-requests presentation — this
        // override exists purely to preserve that prior behavior, not to add
        // anything new.
        completionHandler([.banner, .sound])
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        let userInfo = response.notification.request.content.userInfo
        let ruleName = userInfo[NotificationManager.ruleNameKey] as? String
        let executable = userInfo[NotificationManager.executableKey] as? String
        let actionIdentifier = response.actionIdentifier

        Task { @MainActor [weak self] in
            switch actionIdentifier {
            case UNNotificationDefaultActionIdentifier, NotificationManager.showActionIdentifier:
                self?.showMainWindow()
            case NotificationManager.allowlistActionIdentifier:
                // The event that triggered this notification may have
                // matched several rules; NotificationManager.notify only
                // attaches the single top-severity one to userInfo (see its
                // doc comment), so only that rule is allowlisted here — not
                // every rule the event tripped. Going through
                // `requestAllow` means this takes the exact same Touch
                // ID/password gate and DiagnosticsLog trail as right-clicking
                // the event in-app; the notification action is not a bypass
                // of that control, just another entry point into it.
                if let ruleName, let executable {
                    self?.allowlist?.requestAllow(ruleName: ruleName, executable: executable)
                }
            default:
                break
            }
            completionHandler()
        }
    }

    /// Reopens/activates the dashboard the same way `MenuBarPanel`'s "Open
    /// Argus" button does — by locating the `NSWindow` whose `identifier`
    /// matches `App.swift`'s `mainWindowID` (see its doc comment) — but
    /// without SwiftUI's `openWindow` environment action, which only exists
    /// inside a View's environment and isn't reachable from a plain
    /// `UNUserNotificationCenterDelegate` object living outside the view
    /// hierarchy. That means this can only bring an already-created window
    /// forward; unlike `openWindow(id:)` it can't spin one up from nothing.
    /// In practice the dashboard's `Window` scene is created at launch, so
    /// this only matters if that window were later fully deallocated rather
    /// than just ordered out.
    @MainActor
    private func showMainWindow() {
        NSApp.activate(ignoringOtherApps: true)
        guard let window = NSApp.windows.first(where: { $0.identifier?.rawValue == mainWindowID }) else {
            DiagnosticsLog.write("notification action: main window not found (identifier \(mainWindowID))")
            return
        }
        window.makeKeyAndOrderFront(nil)
    }
}
