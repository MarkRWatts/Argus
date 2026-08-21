import SwiftUI

/// Compact popover shown from the menu bar item — glanceable posture without
/// opening the full dashboard window.
struct MenuBarPanel: View {
    @ObservedObject var monitor: ProcessMonitor
    var dismissFlyout: () -> Void = {}
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "eye.fill")
                    .foregroundStyle(Theme.color(for: monitor.riskLevel))
                Text("Argus")
                    .font(Theme.mono(13, weight: .bold))
                    .tracking(1.5)
                Spacer()
                Text(monitor.riskLevel.label)
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(Theme.color(for: monitor.riskLevel))
            }

            if monitor.isDegraded {
                HStack(spacing: 5) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 9))
                    Text("Monitor degraded — process sampling is failing")
                        .font(.system(size: 9.5, weight: .medium))
                        .lineLimit(1)
                }
                .foregroundStyle(Theme.color(for: .elevated))
            }

            GaugeView(score: monitor.riskScore, level: monitor.riskLevel)
                .scaleEffect(0.7)
                .frame(height: 90)

            Divider().background(Theme.border)

            Text("RECENT")
                .font(.system(size: 9, weight: .bold))
                .tracking(1.2)
                .foregroundStyle(Theme.dim)

            if monitor.events.isEmpty {
                Text("No suspicious activity yet.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.muted)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(monitor.events.prefix(4)) { event in
                        HStack(spacing: 6) {
                            Circle().fill(Theme.color(for: event.topSeverity)).frame(width: 6, height: 6)
                            Text(event.executable)
                                .font(Theme.mono(11, weight: .medium))
                            Spacer()
                            Text(event.rules.first?.technique ?? "")
                                .font(.system(size: 9))
                                .foregroundStyle(Theme.dim)
                                .lineLimit(1)
                        }
                    }
                }
            }

            Divider().background(Theme.border)

            Button {
                dismissFlyout()
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            } label: {
                Label("Open Argus", systemImage: "macwindow")
                    .font(.system(size: 11, weight: .semibold))
            }
            .buttonStyle(.plain)
            .foregroundStyle(Theme.accent)

            Divider().background(Theme.border)

            HStack {
                Text("\(monitor.totalSeen) processes observed")
                    .font(.system(size: 9))
                    .foregroundStyle(Theme.dim)
                Spacer()
                Button("Quit Argus") { NSApplication.shared.terminate(nil) }
                    .buttonStyle(.plain)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(Theme.muted)
            }
        }
        .padding(14)
        .frame(width: 260)
        .background(Theme.bg)
        .foregroundStyle(Theme.text)
    }
}
