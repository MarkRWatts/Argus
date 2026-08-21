import SwiftUI

@main
struct ArgusApp: App {
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
