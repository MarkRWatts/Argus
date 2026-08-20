import SwiftUI

@main
struct ArgusApp: App {
    @StateObject private var monitor = ProcessMonitor()

    var body: some Scene {
        Window("Argus", id: "main") {
            DashboardView(monitor: monitor)
                .frame(minWidth: 980, minHeight: 680)
                .onAppear { monitor.start() }
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
