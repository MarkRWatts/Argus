import Foundation
import UserNotifications

/// Publishes whether macOS will actually deliver Argus's notifications.
///
/// Exists because every layer above this one is silent about the only way
/// delivery really fails in practice: `NotificationThreshold` decides
/// *whether* to notify (pure, tested) and `NotificationManager` submits the
/// request, but when the app's OS-level authorization is denied — or reset,
/// which happens whenever an ad-hoc-signed rebuild changes the app's
/// code-signing identity (see scripts/build_app.sh) — UNUserNotificationCenter
/// drops every request without any visible failure. A monitor whose critical
/// alerts can be silently off needs to say so: this object is what the
/// settings pane's warning row and the launch-time diagnostics line read.
///
/// A singleton (like `IntegrityGuard.shared`) rather than another
/// constructor-injected store: it carries no per-instance state worth
/// isolating in tests — the underlying UNUserNotificationCenter is itself
/// process-global — and singleton access spares threading it through
/// `DashboardView`'s already five-parameter init.
@MainActor
final class NotificationAuthorization: ObservableObject {
    static let shared = NotificationAuthorization()

    enum Status: Equatable {
        /// Not fetched yet this launch — the UI treats this as "no warning"
        /// rather than alarming before the first `refresh` lands.
        case unknown
        /// macOS has no allow/deny recorded for this build. Either the
        /// permission prompt is still pending, or the app's signing identity
        /// changed since the user last answered it.
        case notDetermined
        case denied
        case authorized
    }

    @Published private(set) var status: Status = .unknown

    /// Re-fetches the OS-level status, publishes it, and writes one
    /// diagnostics line per *transition* — refreshing on every settings-pane
    /// open must not spam the log with an unchanged status.
    func refresh() {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            let mapped: Status
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral: mapped = .authorized
            case .denied: mapped = .denied
            case .notDetermined: mapped = .notDetermined
            @unknown default: mapped = .unknown
            }
            Task { @MainActor in
                let shared = NotificationAuthorization.shared
                guard shared.status != mapped else { return }
                shared.status = mapped
                switch mapped {
                case .denied:
                    DiagnosticsLog.write("notification authorization DENIED — alerts (including critical) will not appear until Argus is enabled in System Settings → Notifications")
                case .notDetermined:
                    DiagnosticsLog.write("notification authorization not determined — macOS has no allow/deny recorded for this build (permission resets when the app's code signature changes)")
                case .authorized:
                    DiagnosticsLog.write("notification authorization granted")
                case .unknown:
                    break
                }
            }
        }
    }
}
