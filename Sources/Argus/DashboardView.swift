import SwiftUI

struct DashboardView: View {
    @ObservedObject var monitor: ProcessMonitor
    @ObservedObject var allowlist: AllowlistStore
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var uptimeStart = Date()
    @State private var showingAllowlist = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().background(Theme.border)

            HStack(alignment: .top, spacing: 16) {
                orbitCard
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                VStack(spacing: 16) {
                    metricsCard
                    sparklineCard
                }
                .frame(width: 260)
            }
            .padding(16)
            .frame(maxHeight: 380)

            Divider().background(Theme.border)
            eventFeed
        }
        .background(Theme.bg)
        .foregroundStyle(Theme.text)
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            HStack(spacing: 10) {
                Image(systemName: "eye.fill")
                    .font(.system(size: 18))
                    .foregroundStyle(Theme.color(for: monitor.riskLevel))
                VStack(alignment: .leading, spacing: 1) {
                    Text("ARGUS")
                        .font(Theme.mono(17, weight: .bold))
                        .tracking(3)
                    Text("Living-off-the-land activity radar · local only, nothing leaves this Mac")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.muted)
                }
            }
            Spacer()
            HStack(spacing: 18) {
                statField(label: "PROCESSES SEEN", value: "\(monitor.totalSeen)")
                statField(label: "SAMPLES", value: "\(monitor.sampleCount)")
                statField(label: "RULES LOADED", value: "\(RuleEngine.catalog.count)")
                Button {
                    showingAllowlist = true
                } label: {
                    statField(label: "ALLOWLISTED", value: "\(allowlist.entries.count)")
                }
                .buttonStyle(.plain)
                .popover(isPresented: $showingAllowlist, arrowEdge: .bottom) {
                    AllowlistPanel(allowlist: allowlist)
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private func statField(label: String, value: String) -> some View {
        VStack(alignment: .trailing, spacing: 2) {
            Text(value)
                .font(Theme.mono(15, weight: .semibold))
                .monospacedDigit()
            Text(label)
                .font(.system(size: 9, weight: .semibold))
                .tracking(1)
                .foregroundStyle(Theme.dim)
        }
    }

    private var orbitCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("PROCESS ORBIT")
                .font(.system(size: 10, weight: .bold))
                .tracking(1.5)
                .foregroundStyle(Theme.muted)
                .padding(.horizontal, 14)
                .padding(.top, 12)
            OrbitView(nodes: monitor.orbitNodes, riskLevel: monitor.riskLevel, reduceMotion: reduceMotion)
                .padding(8)
        }
        .background(cardBackground)
    }

    private var metricsCard: some View {
        VStack(spacing: 12) {
            Text("THREAT LEVEL")
                .font(.system(size: 10, weight: .bold))
                .tracking(1.5)
                .foregroundStyle(Theme.muted)
                .frame(maxWidth: .infinity, alignment: .leading)
            GaugeView(score: monitor.riskScore, level: monitor.riskLevel)
            legend
        }
        .padding(14)
        .background(cardBackground)
    }

    private var legend: some View {
        HStack(spacing: 10) {
            ForEach(Severity.allCases, id: \.self) { s in
                HStack(spacing: 4) {
                    Circle().fill(Theme.color(for: s)).frame(width: 6, height: 6)
                    Text(s.label)
                        .font(.system(size: 8, weight: .medium))
                        .foregroundStyle(Theme.dim)
                }
            }
        }
    }

    private var sparklineCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("ACTIVITY · 5 MIN")
                .font(.system(size: 10, weight: .bold))
                .tracking(1.5)
                .foregroundStyle(Theme.muted)
            SparklineView(activityLog: monitor.activityLog, accent: Theme.color(for: monitor.riskLevel))
                .frame(height: 64)
        }
        .padding(14)
        .background(cardBackground)
    }

    private var cardBackground: some View {
        RoundedRectangle(cornerRadius: 12)
            .fill(Theme.surface)
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.border, lineWidth: 1))
    }

    private var eventFeed: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("EVENT FEED")
                    .font(.system(size: 10, weight: .bold))
                    .tracking(1.5)
                    .foregroundStyle(Theme.muted)
                Spacer()
                if monitor.suppressedCount > 0 {
                    Text("\(monitor.suppressedCount) suppressed by allowlist")
                        .font(.system(size: 9))
                        .foregroundStyle(Theme.dim)
                    Text("·")
                        .font(.system(size: 9))
                        .foregroundStyle(Theme.dim)
                }
                Text("newest first")
                    .font(.system(size: 9))
                    .foregroundStyle(Theme.dim)
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 8)

            if monitor.events.isEmpty {
                VStack(spacing: 6) {
                    Spacer()
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 22))
                        .foregroundStyle(Theme.dim)
                    Text("No suspicious activity observed yet — Argus is watching.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.muted)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 1) {
                        ForEach(monitor.events) { event in
                            EventRow(event: event, allowlist: allowlist)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.bottom, 12)
                }
            }
        }
    }
}

struct EventRow: View {
    let event: ProcessEvent
    let allowlist: AllowlistStore
    @State private var expanded = false

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    var body: some View {
        Button {
            withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() }
        } label: {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 10) {
                    Rectangle()
                        .fill(Theme.color(for: event.topSeverity))
                        .frame(width: 3)
                    Text(Self.timeFormatter.string(from: event.timestamp))
                        .font(Theme.mono(11))
                        .foregroundStyle(Theme.dim)
                    Text(event.executable)
                        .font(Theme.mono(12, weight: .semibold))
                        .foregroundStyle(Theme.text)
                    Text("pid \(event.pid)")
                        .font(Theme.mono(10))
                        .foregroundStyle(Theme.dim)
                    Spacer()
                    ForEach(event.rules.prefix(expanded ? event.rules.count : 1)) { rule in
                        Text(rule.technique)
                            .font(.system(size: 9, weight: .semibold))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Theme.color(for: rule.severity).opacity(0.15))
                            .foregroundStyle(Theme.color(for: rule.severity))
                            .clipShape(Capsule())
                    }
                    Text(event.topSeverity.label)
                        .font(.system(size: 9, weight: .bold))
                        .tracking(0.5)
                        .foregroundStyle(Theme.color(for: event.topSeverity))
                }
                Text(event.command)
                    .font(Theme.mono(11))
                    .foregroundStyle(Theme.muted)
                    .lineLimit(expanded ? nil : 1)
                    .truncationMode(.tail)
                    .padding(.leading, 13)

                if expanded {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(event.rules) { rule in
                            Text("• \(rule.explanation)")
                                .font(.system(size: 10.5))
                                .foregroundStyle(Theme.muted)
                        }
                    }
                    .padding(.leading, 13)
                    .padding(.top, 2)
                }
            }
            .padding(.vertical, 7)
            .padding(.horizontal, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(expanded ? Theme.surfaceRaised : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .contextMenu {
            ForEach(event.rules) { rule in
                Button("Allow future \u{201c}\(rule.name)\u{201d} alerts from \(event.executable)") {
                    allowlist.allow(ruleName: rule.name, executable: event.executable)
                }
            }
        }
    }
}

/// Popover from the header's "ALLOWLISTED" stat — review and revoke
/// suppression rules. Nothing here is hidden: every automatic suppression
/// is a decision the user made explicitly by right-clicking an event.
struct AllowlistPanel: View {
    @ObservedObject var allowlist: AllowlistStore

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("ALLOWLIST")
                .font(.system(size: 10, weight: .bold))
                .tracking(1.5)
                .foregroundStyle(Theme.muted)

            if allowlist.entries.isEmpty {
                Text("Nothing allowlisted. Right-click an event in the feed to stop alerting on it.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.muted)
                    .frame(width: 260)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(allowlist.entries) { entry in
                        HStack(alignment: .top, spacing: 8) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.ruleName)
                                    .font(Theme.mono(11, weight: .semibold))
                                Text("\(entry.executable) · since \(Self.dateFormatter.string(from: entry.createdAt))")
                                    .font(.system(size: 9))
                                    .foregroundStyle(Theme.dim)
                            }
                            Spacer()
                            Button {
                                allowlist.remove(entry.id)
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(Theme.dim)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .frame(width: 280)
            }
        }
        .padding(14)
        .background(Theme.bg)
        .foregroundStyle(Theme.text)
    }
}
