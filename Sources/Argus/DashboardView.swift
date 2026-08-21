import SwiftUI

struct DashboardView: View {
    @ObservedObject var monitor: ProcessMonitor
    @ObservedObject var allowlist: AllowlistStore
    let eventStore: EventStore
    @ObservedObject var settings: AppSettings
    @ObservedObject var ruleStore: RuleStore
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var uptimeStart = Date()
    @State private var showingAllowlist = false
    @State private var showingRules = false
    @State private var showingHistory = false
    @State private var showingSettings = false
    @State private var searchText = ""
    @State private var activeSeverities: Set<Severity> = Set(Severity.allCases)
    @State private var focusedSessionPPID: Int32?

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
            HStack(spacing: 10) {
                statField(label: "PROCESSES SEEN", value: "\(monitor.totalSeen)")
                statField(label: "SAMPLES", value: "\(monitor.sampleCount)")

                Button {
                    showingRules = true
                } label: {
                    interactiveStatField(label: "RULES LOADED", value: "\(ruleStore.rules.count)")
                }
                .buttonStyle(.plain)
                .help("Manage the detection rule catalog")
                .popover(isPresented: $showingRules, arrowEdge: .bottom) {
                    RuleManagementPanel(ruleStore: ruleStore)
                }

                Button {
                    showingAllowlist = true
                } label: {
                    interactiveStatField(label: "ALLOWLISTED", value: "\(allowlist.entries.count)")
                }
                .buttonStyle(.plain)
                .help("Review or revoke allowlisted rules")
                .popover(isPresented: $showingAllowlist, arrowEdge: .bottom) {
                    AllowlistPanel(allowlist: allowlist)
                }

                Button {
                    showingHistory = true
                } label: {
                    interactiveStatField(label: "HISTORY", value: "\(monitor.historicalEventCount)")
                }
                .buttonStyle(.plain)
                .help("Browse activity history — daily heatmap and technique frequency")
                .popover(isPresented: $showingHistory, arrowEdge: .bottom) {
                    HistoryPanel(eventStore: eventStore)
                }

                Button {
                    showingSettings = true
                } label: {
                    Image(systemName: "gearshape.fill")
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.accent)
                        .padding(8)
                        .background(
                            Circle().fill(Theme.surfaceRaised)
                                .overlay(Circle().strokeBorder(Theme.border, lineWidth: 1))
                        )
                }
                .buttonStyle(.plain)
                .help("Settings — poll interval, risk decay, notifications")
                .popover(isPresented: $showingSettings, arrowEdge: .bottom) {
                    SettingsPanel(settings: settings)
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
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
    }

    /// Same shape as `statField`, but visibly a control: bordered chip, a
    /// chevron, and an accent-tinted value — so it doesn't blend into the
    /// read-only stats sitting right next to it.
    private func interactiveStatField(label: String, value: String) -> some View {
        VStack(alignment: .trailing, spacing: 2) {
            HStack(spacing: 3) {
                Text(value)
                    .font(Theme.mono(15, weight: .semibold))
                    .monospacedDigit()
                Image(systemName: "chevron.down")
                    .font(.system(size: 7, weight: .bold))
            }
            .foregroundStyle(Theme.accent)
            Text(label)
                .font(.system(size: 9, weight: .semibold))
                .tracking(1)
                .foregroundStyle(Theme.dim)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Theme.surfaceRaised)
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Theme.border, lineWidth: 1))
        )
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

    private var filteredEvents: [ProcessEvent] {
        EventFilter.apply(monitor.events, searchText: searchText, severities: activeSeverities, sessionPPID: focusedSessionPPID)
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

            filterBar
                .padding(.horizontal, 20)
                .padding(.bottom, 10)

            if let focusedSessionPPID {
                sessionBanner(ppid: focusedSessionPPID)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 8)
            }

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
            } else if filteredEvents.isEmpty {
                VStack(spacing: 6) {
                    Spacer()
                    Image(systemName: "line.3.horizontal.decrease.circle")
                        .font(.system(size: 22))
                        .foregroundStyle(Theme.dim)
                    Text("Nothing matches the current filter.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.muted)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 1) {
                        ForEach(filteredEvents) { event in
                            EventRow(event: event, allowlist: allowlist) { ppid in
                                focusedSessionPPID = ppid
                            }
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.bottom, 12)
                }
            }
        }
    }

    private var filterBar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.dim)
                TextField("Search executable, command, or technique…", text: $searchText)
                    .textFieldStyle(.plain)
                    .font(Theme.mono(11))
                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 10))
                            .foregroundStyle(Theme.dim)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(Theme.surface)
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Theme.border, lineWidth: 1))
            )
            .frame(maxWidth: 280)

            HStack(spacing: 6) {
                ForEach(Severity.allCases, id: \.self) { severity in
                    severityChip(severity)
                }
            }
        }
    }

    private func severityChip(_ severity: Severity) -> some View {
        let isOn = activeSeverities.contains(severity)
        return Button {
            if isOn {
                activeSeverities.remove(severity)
            } else {
                activeSeverities.insert(severity)
            }
        } label: {
            HStack(spacing: 4) {
                Circle().fill(Theme.color(for: severity)).frame(width: 6, height: 6)
                Text(severity.label)
                    .font(.system(size: 9, weight: .semibold))
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(
                Capsule()
                    .fill(isOn ? Theme.color(for: severity).opacity(0.15) : Theme.surface)
                    .overlay(Capsule().strokeBorder(isOn ? Theme.color(for: severity).opacity(0.5) : Theme.border, lineWidth: 1))
            )
            .foregroundStyle(isOn ? Theme.color(for: severity) : Theme.dim)
        }
        .buttonStyle(.plain)
    }

    private func sessionBanner(ppid: Int32) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 10))
            Text("Focused on session pid \(ppid) — showing only events sharing this parent process")
                .font(.system(size: 10.5))
            Spacer()
            Button("Clear") { focusedSessionPPID = nil }
                .buttonStyle(.plain)
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(Theme.accent)
        }
        .foregroundStyle(Theme.text)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Theme.accent.opacity(0.1))
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Theme.accent.opacity(0.3), lineWidth: 1))
        )
    }
}

struct EventRow: View {
    let event: ProcessEvent
    let allowlist: AllowlistStore
    let onFocusSession: (Int32) -> Void
    @State private var expanded = false

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    var body: some View {
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

                Button {
                    onFocusSession(event.ppid)
                } label: {
                    HStack(spacing: 3) {
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .font(.system(size: 8))
                        Text("pid \(event.pid)")
                            .font(Theme.mono(10))
                    }
                    .foregroundStyle(Theme.dim)
                }
                .buttonStyle(.plain)
                .help("Show every event sharing this process's parent (pid \(event.ppid))")

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
        .contentShape(Rectangle())
        .onTapGesture {
            withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() }
        }
        .contextMenu {
            ForEach(event.rules) { rule in
                Button("Allow future \u{201c}\(rule.name)\u{201d} alerts from \(event.executable)") {
                    allowlist.allow(ruleName: rule.name, executable: event.executable)
                }
            }
        }
    }
}

/// Popover from the header's "RULES LOADED" stat — the rule management
/// surface. Every rule is a real Sigma detection (imported verbatim from
/// SigmaHQ, or authored for Argus in the same format), individually
/// toggleable, with its raw YAML source viewable inline. Drop a `.yml` file
/// into the user rules folder and hit reload — no rebuild required.
struct RuleManagementPanel: View {
    @ObservedObject var ruleStore: RuleStore
    @State private var searchText = ""
    @State private var originFilter: RuleOrigin?

    private var filteredRules: [SigmaRule] {
        var rules = ruleStore.rules
        if let originFilter {
            rules = rules.filter { $0.origin == originFilter }
        }
        let trimmed = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        guard !trimmed.isEmpty else { return rules }
        return rules.filter {
            $0.title.lowercased().contains(trimmed) ||
            $0.techniqueLabel.lowercased().contains(trimmed) ||
            $0.tags.joined(separator: " ").lowercased().contains(trimmed)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("DETECTION RULES")
                    .font(.system(size: 10, weight: .bold))
                    .tracking(1.5)
                    .foregroundStyle(Theme.muted)
                Spacer()
                Text("\(ruleStore.activeRules.count) of \(ruleStore.rules.count) active")
                    .font(.system(size: 9.5))
                    .foregroundStyle(Theme.dim)
            }

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.dim)
                TextField("Search title, technique, or tag…", text: $searchText)
                    .textFieldStyle(.plain)
                    .font(Theme.mono(11))
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(Theme.surface)
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Theme.border, lineWidth: 1))
            )

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    originChip(nil, label: "All")
                    originChip(.sigmaHQMacOS, label: RuleOrigin.sigmaHQMacOS.label)
                    originChip(.sigmaHQPortable, label: RuleOrigin.sigmaHQPortable.label)
                    originChip(.custom, label: RuleOrigin.custom.label)
                    originChip(.user, label: RuleOrigin.user.label)
                }
            }

            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(filteredRules) { rule in
                        RuleManagementRow(rule: rule, isEnabled: ruleStore.isEnabled(rule)) {
                            ruleStore.toggle(rule)
                        }
                        Divider().background(Theme.border)
                    }
                }
            }
            .frame(height: 340)

            Divider().background(Theme.border)

            HStack {
                Button {
                    ruleStore.revealUserRulesFolder()
                } label: {
                    Label("Rules folder", systemImage: "folder")
                }
                .buttonStyle(.plain)
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.accent)

                Spacer()

                Button {
                    ruleStore.reload()
                } label: {
                    Label("Reload", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.plain)
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.accent)
            }
        }
        .padding(14)
        .frame(width: 420)
        .background(Theme.bg)
        .foregroundStyle(Theme.text)
    }

    private func originChip(_ origin: RuleOrigin?, label: String) -> some View {
        let isOn = originFilter == origin
        return Button {
            originFilter = origin
        } label: {
            Text(label)
                .font(.system(size: 9, weight: .semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(
                    Capsule()
                        .fill(isOn ? Theme.accent.opacity(0.18) : Theme.surface)
                        .overlay(Capsule().strokeBorder(isOn ? Theme.accent.opacity(0.5) : Theme.border, lineWidth: 1))
                )
                .foregroundStyle(isOn ? Theme.accent : Theme.dim)
        }
        .buttonStyle(.plain)
    }
}

struct RuleManagementRow: View {
    let rule: SigmaRule
    let isEnabled: Bool
    let onToggle: () -> Void
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .top, spacing: 8) {
                Button(action: onToggle) {
                    Image(systemName: isEnabled ? "checkmark.circle.fill" : "circle")
                        .font(.system(size: 13))
                        .foregroundStyle(isEnabled ? Theme.color(for: rule.severity) : Theme.dim)
                }
                .buttonStyle(.plain)
                .help(isEnabled ? "Disable this rule" : "Enable this rule")

                VStack(alignment: .leading, spacing: 3) {
                    Text(rule.title)
                        .font(Theme.mono(11.5, weight: .semibold))
                        .foregroundStyle(isEnabled ? Theme.text : Theme.dim)
                    HStack(spacing: 6) {
                        Text(rule.techniqueLabel)
                            .font(.system(size: 9.5, weight: .medium))
                            .foregroundStyle(Theme.accent)
                        Text(rule.origin.label)
                            .font(.system(size: 8.5))
                            .foregroundStyle(Theme.dim)
                    }
                }

                Spacer(minLength: 8)
                Text(rule.severity.label)
                    .font(.system(size: 8.5, weight: .bold))
                    .tracking(0.5)
                    .foregroundStyle(Theme.color(for: rule.severity))
            }

            if expanded {
                VStack(alignment: .leading, spacing: 6) {
                    if let description = rule.description {
                        Text(description)
                            .font(.system(size: 10.5))
                            .foregroundStyle(Theme.muted)
                    }
                    ScrollView {
                        Text(rule.rawYAML)
                            .font(Theme.mono(9.5))
                            .foregroundStyle(Theme.muted)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .frame(maxHeight: 160)
                    .padding(6)
                    .background(RoundedRectangle(cornerRadius: 5).fill(Theme.surface))
                }
                .padding(.leading, 21)
                .padding(.top, 2)
            }
        }
        .padding(.vertical, 8)
        .contentShape(Rectangle())
        .onTapGesture { withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() } }
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

/// Popover from the header's "HISTORY" stat — a day-by-day activity heatmap
/// (last ~12 weeks) plus which techniques have fired most. Reads the full
/// persisted log once when opened rather than on every dashboard tick.
struct HistoryPanel: View {
    let eventStore: EventStore
    @State private var events: [ProcessEvent] = []

    private var dailyActivity: [DayActivity] { HistoryStats.dailyActivity(events) }
    private var techniqueFrequency: [(technique: String, count: Int)] { HistoryStats.techniqueFrequency(events) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("ACTIVITY HISTORY")
                .font(.system(size: 10, weight: .bold))
                .tracking(1.5)
                .foregroundStyle(Theme.muted)

            if events.isEmpty {
                Text("No history yet — matched events accumulate here as Argus runs, and survive a restart.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.muted)
                    .frame(width: 300)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Text("\(events.count) events recorded — last ~12 weeks")
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.dim)
                    heatmap
                }

                Divider().background(Theme.border)

                VStack(alignment: .leading, spacing: 8) {
                    Text("TOP TECHNIQUES")
                        .font(.system(size: 9, weight: .bold))
                        .tracking(1)
                        .foregroundStyle(Theme.muted)
                    ForEach(techniqueFrequency.prefix(8), id: \.technique) { item in
                        techniqueBar(item)
                    }
                }
            }
        }
        .padding(14)
        .frame(width: 320)
        .background(Theme.bg)
        .foregroundStyle(Theme.text)
        .onAppear {
            events = eventStore.loadAll()
        }
    }

    private var heatmap: some View {
        let calendar = Calendar.current
        let today = calendar.startOfDay(for: Date())
        let dayCount = 84
        let days: [Date] = (0..<dayCount).map { calendar.date(byAdding: .day, value: -(dayCount - 1 - $0), to: today)! }
        let byDay = Dictionary(uniqueKeysWithValues: dailyActivity.map { ($0.id, $0) })
        let weekCount = (days.count + 6) / 7

        return HStack(alignment: .top, spacing: 3) {
            ForEach(0..<weekCount, id: \.self) { weekIndex in
                VStack(spacing: 3) {
                    ForEach(0..<7, id: \.self) { dayIndex in
                        let flatIndex = weekIndex * 7 + dayIndex
                        if flatIndex < days.count {
                            let day = days[flatIndex]
                            let activity = byDay[day]
                            RoundedRectangle(cornerRadius: 2)
                                .fill(cellColor(for: activity))
                                .frame(width: 10, height: 10)
                                .help(cellTooltip(day: day, activity: activity))
                        } else {
                            Color.clear.frame(width: 10, height: 10)
                        }
                    }
                }
            }
        }
    }

    private func cellColor(for activity: DayActivity?) -> Color {
        guard let activity, activity.count > 0 else { return Theme.border.opacity(0.5) }
        let intensity = min(1.0, 0.35 + Double(activity.count) / 10.0)
        return Theme.color(for: activity.maxSeverity).opacity(intensity)
    }

    private func cellTooltip(day: Date, activity: DayActivity?) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        let count = activity?.count ?? 0
        return "\(f.string(from: day)): \(count) event\(count == 1 ? "" : "s")"
    }

    private func techniqueBar(_ item: (technique: String, count: Int)) -> some View {
        let maxCount = max(1, techniqueFrequency.first?.count ?? 1)
        return VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(item.technique)
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.muted)
                    .lineLimit(1)
                Spacer()
                Text("\(item.count)")
                    .font(Theme.mono(10, weight: .semibold))
                    .foregroundStyle(Theme.text)
            }
            GeometryReader { geo in
                RoundedRectangle(cornerRadius: 2)
                    .fill(Theme.accent.opacity(0.6))
                    .frame(width: geo.size.width * CGFloat(item.count) / CGFloat(maxCount), height: 4)
            }
            .frame(height: 4)
        }
    }
}

/// Popover from the header's gear icon. Poll cadence and risk decay were
/// hardcoded constants before this — genuinely a matter of taste (how
/// twitchy vs. how patient the gauge should be), so they're exposed here
/// rather than fixed in code.
struct SettingsPanel: View {
    @ObservedObject var settings: AppSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("SETTINGS")
                .font(.system(size: 10, weight: .bold))
                .tracking(1.5)
                .foregroundStyle(Theme.muted)

            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Poll interval")
                        .font(.system(size: 11, weight: .medium))
                    Spacer()
                    Text(String(format: "%.1fs", settings.pollIntervalSeconds))
                        .font(Theme.mono(11, weight: .semibold))
                        .foregroundStyle(Theme.accent)
                }
                Slider(value: $settings.pollIntervalSeconds, in: AppSettings.pollIntervalRange, step: 0.1)
                Text("How often Argus samples the process table. Lower = faster detection, more CPU.")
                    .font(.system(size: 9.5))
                    .foregroundStyle(Theme.dim)
            }

            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Risk decay half-life")
                        .font(.system(size: 11, weight: .medium))
                    Spacer()
                    Text("\(Int(settings.riskDecayHalfLifeSeconds))s")
                        .font(Theme.mono(11, weight: .semibold))
                        .foregroundStyle(Theme.accent)
                }
                Slider(value: $settings.riskDecayHalfLifeSeconds, in: AppSettings.decayHalfLifeRange, step: 5)
                Text("How long the threat gauge takes to settle after a spike. Higher = longer memory.")
                    .font(.system(size: 9.5))
                    .foregroundStyle(Theme.dim)
            }

            Divider().background(Theme.border)

            VStack(alignment: .leading, spacing: 8) {
                Text("Notify me for")
                    .font(.system(size: 11, weight: .medium))
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(NotificationThreshold.allCases, id: \.self) { threshold in
                        Button {
                            settings.notificationThreshold = threshold
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: settings.notificationThreshold == threshold ? "largecircle.fill.circle" : "circle")
                                    .font(.system(size: 11))
                                    .foregroundStyle(settings.notificationThreshold == threshold ? Theme.accent : Theme.dim)
                                Text(threshold.label)
                                    .font(.system(size: 11))
                                    .foregroundStyle(Theme.text)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .padding(14)
        .frame(width: 300)
        .background(Theme.bg)
        .foregroundStyle(Theme.text)
    }
}
