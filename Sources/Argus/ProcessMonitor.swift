import Foundation
import Combine

/// Polls the local process table, diffs it against the previous sample to find
/// newly-spawned processes, and runs each one through the RuleEngine.
///
/// This is deliberately poll-based rather than kernel-event-based: capturing
/// true exec() events on macOS requires the `com.apple.developer.endpoint-security`
/// entitlement, which Apple grants by application, not something obtainable in a
/// single unattended session. Polling `ps` every ~1.2s trades event-level precision
/// for zero entitlements and zero permission prompts — appropriate for a personal
/// visibility tool rather than an enterprise EDR.
@MainActor
final class ProcessMonitor: ObservableObject {
    @Published private(set) var events: [ProcessEvent] = []
    @Published private(set) var orbitNodes: [OrbitNode] = []
    @Published private(set) var riskScore: Double = 0
    @Published private(set) var totalSeen: Int = 0
    @Published private(set) var sampleCount: Int = 0
    @Published private(set) var suppressedCount: Int = 0
    @Published private(set) var historicalEventCount: Int = 0
    @Published private(set) var activityLog: [(Date, Int)] = [] // (time, matched-event count) per tick, for the sparkline

    var riskLevel: Severity {
        switch riskScore {
        case ..<15: return .info
        case ..<40: return .watch
        case ..<70: return .elevated
        default: return .critical
        }
    }

    private var knownPIDs: Set<Int32> = []
    private var baselined = false
    private var timerTask: Task<Void, Never>?
    private var allowlist: AllowlistStore?
    private var eventStore: EventStore?
    private var settings: AppSettings?
    private let ownPID = ProcessInfo.processInfo.processIdentifier
    private let defaultIntervalSeconds: Double = 1.2
    private let defaultHalfLifeSeconds: Double = 55.0

    func configure(allowlist: AllowlistStore) {
        self.allowlist = allowlist
    }

    func configure(settings: AppSettings) {
        self.settings = settings
    }

    /// Loads recent persisted history into the live feed so a restart no
    /// longer means losing everything that happened before it.
    func configure(eventStore: EventStore) {
        self.eventStore = eventStore
        let all = eventStore.loadAll()
        historicalEventCount = all.count
        events = Array(all.suffix(300).reversed())
    }

    func start() {
        guard timerTask == nil else { return }
        timerTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                await self.tick()
                let seconds = self.currentPollInterval
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            }
        }
    }

    private var currentPollInterval: Double {
        settings?.pollIntervalSeconds ?? defaultIntervalSeconds
    }

    func stop() {
        timerTask?.cancel()
        timerTask = nil
    }

    private func tick() async {
        let raw = await Self.sampleProcesses()
        sampleCount += 1
        let halfLife = settings?.riskDecayHalfLifeSeconds ?? defaultHalfLifeSeconds
        let decayFactor = pow(0.5, currentPollInterval / halfLife)
        riskScore = max(0, riskScore * decayFactor)
        pruneOrbitNodes()

        let currentPIDs = Set(raw.map(\.id))
        defer { knownPIDs = currentPIDs }

        guard baselined else {
            baselined = true
            activityLog.append((Date(), 0))
            trimActivityLog()
            DiagnosticsLog.write("baseline established — \(raw.count) processes tracked")
            return
        }

        let newProcs = raw.filter {
            !knownPIDs.contains($0.id) && $0.id != ownPID && $0.ppid != ownPID
        }

        var matchedThisTick = 0
        for proc in newProcs {
            totalSeen += 1
            let rawMatches = RuleEngine.evaluate(proc.command)
            let matches: [MatchedRule]
            if let allowlist {
                matches = AllowlistFilter.apply(rawMatches, executable: proc.executable, isAllowed: allowlist.isAllowed)
            } else {
                matches = rawMatches
            }
            suppressedCount += rawMatches.count - matches.count

            let angle = Double.random(in: 0..<360)
            if matches.isEmpty {
                orbitNodes.append(OrbitNode(id: UUID(), pid: proc.id, ppid: proc.ppid,
                                             severity: .info, label: proc.executable,
                                             bornAt: Date(), angle: angle))
            } else {
                matchedThisTick += 1
                let event = ProcessEvent(pid: proc.id, ppid: proc.ppid, executable: proc.executable,
                                          command: proc.command, rules: matches, timestamp: Date())
                events.insert(event, at: 0)
                if events.count > 300 { events.removeLast(events.count - 300) }
                eventStore?.append(event)
                historicalEventCount += 1
                if let settings, settings.notificationThreshold.shouldNotify(for: event.topSeverity) {
                    NotificationManager.notify(event: event)
                }
                riskScore = min(100, riskScore + event.topSeverity.weight)
                orbitNodes.append(OrbitNode(id: event.id, pid: proc.id, ppid: proc.ppid,
                                             severity: event.topSeverity, label: proc.executable,
                                             bornAt: Date(), angle: angle))
                let techniques = matches.map(\.technique).joined(separator: "; ")
                DiagnosticsLog.write("[\(event.topSeverity.label)] pid=\(proc.id) \(proc.executable) — \(techniques) — risk=\(Int(riskScore))")
            }
        }
        if orbitNodes.count > 400 { orbitNodes.removeFirst(orbitNodes.count - 400) }

        activityLog.append((Date(), matchedThisTick))
        trimActivityLog()

        if sampleCount % 150 == 0 {
            DiagnosticsLog.write("heartbeat — samples=\(sampleCount) seen=\(totalSeen) events=\(events.count) suppressed=\(suppressedCount) risk=\(Int(riskScore))")
        }
    }

    private func trimActivityLog() {
        let cutoff = Date().addingTimeInterval(-300)
        activityLog.removeAll { $0.0 < cutoff }
    }

    private func pruneOrbitNodes() {
        let cutoff = Date().addingTimeInterval(-14)
        orbitNodes.removeAll { $0.bornAt < cutoff }
    }

    nonisolated private static func sampleProcesses() async -> [RawProcess] {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                cont.resume(returning: runPS())
            }
        }
    }

    nonisolated private static func runPS() -> [RawProcess] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axww", "-o", "pid,ppid,command"]
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return []
        }
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard let output = String(data: data, encoding: .utf8) else { return [] }

        var results: [RawProcess] = []
        let lines = output.split(separator: "\n", omittingEmptySubsequences: true)
        for line in lines.dropFirst() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let parts = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard parts.count == 3, let pid = Int32(parts[0]), let ppid = Int32(parts[1]) else { continue }
            let command = String(parts[2])
            let firstToken = command.split(separator: " ").first.map(String.init) ?? command
            let short = (firstToken as NSString).lastPathComponent
            results.append(RawProcess(id: pid, ppid: ppid, command: command, executable: short))
        }
        return results
    }
}
