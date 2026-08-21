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
    @StateObject private var monitor = ProcessMonitor()
    @StateObject private var allowlist = AllowlistStore()
    @StateObject private var settings = AppSettings()
    @StateObject private var ruleStore = RuleStore()
    private let eventStore = EventStore()

    var body: some Scene {
        Window("Argus", id: "main") {
            DashboardView(monitor: monitor, allowlist: allowlist, eventStore: eventStore, settings: settings, ruleStore: ruleStore)
                .frame(minWidth: 980, minHeight: 680)
                .onAppear {
                    monitor.configure(allowlist: allowlist)
                    monitor.configure(eventStore: eventStore)
                    monitor.configure(settings: settings)
                    monitor.configure(ruleStore: ruleStore)
                    monitor.start()
                    NotificationManager.requestAuthorizationIfNeeded()
                }
                .preferredColorScheme(.dark)
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 1040, height: 720)
        .commandsRemoved()

        MenuBarExtra {
            MenuBarPanel(monitor: monitor)
        } label: {
            Image(systemName: "eye.fill")
                .foregroundStyle(Theme.color(for: monitor.riskLevel))
        }
        .menuBarExtraStyle(.window)
    }
}
