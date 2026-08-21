import SwiftUI

@main
struct ArgusApp: App {
    @StateObject private var monitor = ProcessMonitor()
    @StateObject private var allowlist = AllowlistStore()

    var body: some Scene {
        Window("Argus", id: "main") {
            DashboardView(monitor: monitor, allowlist: allowlist)
                .frame(minWidth: 980, minHeight: 680)
                .onAppear {
                    monitor.configure(allowlist: allowlist)
                    monitor.start()
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
