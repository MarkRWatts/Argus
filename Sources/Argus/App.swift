import SwiftUI
import AppKit

/// Argus runs `LSUIElement` (menu-bar-only by default, no Dock icon) —
/// closing the main window should hide it, not quit the app, since the menu
/// bar item is the app's actual home. But a Dock icon is what makes
/// Cmd+Tab and "click the Dock to get back" work, so we show one for as
/// long as the window is actually on screen and drop it again once the
/// window closes, rather than hiding it permanently.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NotificationCenter.default.addObserver(self, selector: #selector(updateActivationPolicy), name: NSWindow.didBecomeMainNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(updateActivationPolicy), name: NSWindow.willCloseNotification, object: nil)
    }

    @objc private func updateActivationPolicy() {
        DispatchQueue.main.async {
            let hasVisibleWindow = NSApp.windows.contains { $0.isVisible && $0.canBecomeMain }
            NSApp.setActivationPolicy(hasVisibleWindow ? .regular : .accessory)
        }
    }
}

@main
struct ArgusApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var monitor: ProcessMonitor
    @StateObject private var allowlist: AllowlistStore
    @StateObject private var settings: AppSettings
    @StateObject private var ruleStore: RuleStore
    private let eventStore: EventStore
    /// Held for the app's lifetime purely to keep its `DispatchSource`s
    /// alive — `PersistenceWatcher` isn't observed by any view, so nothing
    /// else in the view hierarchy retains it.
    private let persistenceWatcher: PersistenceWatcher

    /// Identifies the main dashboard's `NSWindow`. Verified empirically
    /// (via a standalone probe app mirroring this app's Window + MenuBarExtra
    /// shape) that SwiftUI reliably sets `NSWindow.identifier` to the scene's
    /// `id` string for a `Window(id:)` scene — it's present as soon as the
    /// window is created, survives `orderOut(nil)`, and is still correct
    /// after the window is reopened via `openWindow(id:)`. That makes it a
    /// stable, title-independent way to pick the dashboard out of
    /// `NSApp.windows` (the menu bar's own popover window, by contrast, has
    /// a `nil` identifier and `canBecomeMain == false`).
    private static let mainWindowID = "main"

    /// Monitoring must run regardless of whether the main window ever
    /// appears — Argus is a menu-bar app first, and someone may never open
    /// the dashboard at all. Wiring this in the window's `.onAppear` (the
    /// previous approach) meant no monitoring happened until the window was
    /// shown. Doing it here, in the app's own init, means it starts at
    /// launch every time.
    init() {
        let allowlistStore = AllowlistStore()
        let appSettings = AppSettings()
        let rules = RuleStore()
        let events = EventStore()

        let m = ProcessMonitor()
        m.configure(allowlist: allowlistStore)
        m.configure(eventStore: events)
        m.configure(settings: appSettings)
        m.configure(ruleStore: rules)
        m.start()
        NotificationManager.requestAuthorizationIfNeeded()

        // Second, independent sensor: catches persistence artifacts left on
        // disk even when the process that wrote them was too short-lived for
        // ProcessMonitor's ~1.2s poll to ever sample it.
        let watcher = PersistenceWatcher()
        watcher.onEvent = { [weak m] event in
            m?.ingestExternal(event)
        }
        watcher.start()

        // IntegrityGuard verified rules-state.json/allowlist.json against
        // their last authenticated-write MAC during each store's own init
        // (above). A `.tampered` verdict means the file changed outside
        // Argus's Touch ID/password-gated write path — exactly what a local
        // attacker would do to blind a rule or re-enable a suppressed alert
        // silently — so surface it as a critical event in the feed.
        // `.baselineEstablished`/`.unverifiable` are informational only and
        // already logged by IntegrityGuard itself.
        for (verdict, fileURL) in [(rules.integrityVerdict, rules.stateFileURL), (allowlistStore.integrityVerdict, allowlistStore.fileURL)] {
            if verdict == .tampered {
                DiagnosticsLog.write("integrity-guard: tamper detected outside Argus for \(fileURL.lastPathComponent)")
                m.ingestExternal(IntegrityGuard.tamperEvent(for: fileURL))
            }
        }

        _monitor = StateObject(wrappedValue: m)
        _allowlist = StateObject(wrappedValue: allowlistStore)
        _settings = StateObject(wrappedValue: appSettings)
        _ruleStore = StateObject(wrappedValue: rules)
        eventStore = events
        persistenceWatcher = watcher
    }

    var body: some Scene {
        Window("Argus", id: Self.mainWindowID) {
            DashboardView(monitor: monitor, allowlist: allowlist, eventStore: eventStore, settings: settings, ruleStore: ruleStore)
                .frame(minWidth: 980, minHeight: 680)
                .preferredColorScheme(.dark)
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 1040, height: 720)
        .commandsRemoved()

        MenuBarExtra {
            MenuBarPanel(monitor: monitor, dismissFlyout: dismissMenuBarFlyout)
        } label: {
            Image(systemName: monitor.isDegraded ? "exclamationmark.triangle.fill" : "eye.fill")
                .foregroundStyle(monitor.isDegraded ? Theme.color(for: .elevated) : Theme.color(for: monitor.riskLevel))
        }
        .menuBarExtraStyle(.window)
    }

    /// `.menuBarExtraStyle(.window)`'s popover is a plain NSWindow under the
    /// hood, but it apparently overrides `close()`'s should-close handling
    /// (both `keyWindow?.close()` and toggling `isInserted` failed to
    /// dismiss it in practice). `orderOut(nil)` skips that machinery
    /// entirely — it just hides the window — so hide every visible window
    /// that isn't the main dashboard. Identified by `NSWindow.identifier`
    /// (see `mainWindowID` above) rather than by title, which is fragile if
    /// the window is ever retitled or localized.
    private func dismissMenuBarFlyout() {
        for window in NSApp.windows where window.isVisible && window.identifier?.rawValue != Self.mainWindowID {
            window.orderOut(nil)
        }
    }
}
