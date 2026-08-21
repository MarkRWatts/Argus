import Foundation
import Combine

/// Caches pid → image/command/user across polling ticks so a newly-spawned
/// child's ParentImage/ParentCommandLine/ParentUser can still be resolved
/// after the parent has already exited by the next poll — a common race:
/// many LOLBin chains spawn a short-lived parent (e.g. a one-shot `sh -c`)
/// that's gone from the process table before the ~1.2s sample interval
/// elapses. Without this cache those Sigma rules that key off parent
/// context would silently never match such chains.
///
/// The current sample's entries always overwrite older ones. Entries for
/// pids no longer present in the sample are kept for `retentionTicks` more
/// ticks (default 3, ~30s at the default poll interval) and then dropped —
/// pruning matters because macOS recycles pids; without it, a new,
/// unrelated process could inherit a long-dead process's stale identity as
/// its "parent".
struct ParentContextCache {
    struct Entry {
        var image: String
        var command: String
        var user: String
        var ppid: Int32
        var lastSeenTick: Int
    }

    private(set) var entries: [Int32: Entry] = [:]
    let retentionTicks: Int

    init(retentionTicks: Int = 3) {
        self.retentionTicks = retentionTicks
    }

    /// Merges the current sample into the cache and prunes anything not
    /// refreshed within the retention window.
    mutating func update(with sample: [RawProcess], tick: Int) {
        for p in sample {
            entries[p.id] = Entry(image: p.image, command: p.command, user: p.user, ppid: p.ppid, lastSeenTick: tick)
        }
        entries = entries.filter { tick - $0.value.lastSeenTick <= retentionTicks }
    }

    func image(for pid: Int32) -> String? { entries[pid]?.image }
    func command(for pid: Int32) -> String? { entries[pid]?.command }
    func user(for pid: Int32) -> String? { entries[pid]?.user }
    func ppid(for pid: Int32) -> Int32? { entries[pid]?.ppid }

    /// Walks ppid links from `pid` up through the cache to build its ancestor
    /// records (pid plus that pid's cached image/command), nearest ancestor
    /// first, excluding `pid` itself. Stops at `pid <= 1` (launchd/kernel —
    /// the root of every process tree, so it carries no chain-correlation or
    /// provenance signal), at a pid the cache has no *ppid link* for (parent
    /// already aged out or was never sampled), at a cycle (should never
    /// happen on a real process table, but a corrupted/adversarial sample
    /// must not spin forever), or at `maxDepth` hops.
    ///
    /// A pid can appear in the chain (discovered as another pid's ppid) even
    /// when the cache never itself sampled that pid — e.g. a parent that
    /// exited and aged out past `retentionTicks` before this walk ran. Such a
    /// pid still terminates the walk one hop later (its own ppid link is
    /// unknown) but is reported here with empty `image`/`command` rather than
    /// silently dropped, so callers keying off ancestor pids (chain
    /// correlation) and callers keying off ancestor identity (provenance
    /// attribution) both see the exact same chain length.
    func ancestorRecords(of pid: Int32, maxDepth: Int = 20) -> [(pid: Int32, image: String, command: String)] {
        var chain: [(pid: Int32, image: String, command: String)] = []
        var seen: Set<Int32> = [pid]
        var current = pid
        while chain.count < maxDepth {
            guard let parent = ppid(for: current), parent > 1, !seen.contains(parent) else { break }
            let entry = entries[parent]
            chain.append((pid: parent, image: entry?.image ?? "", command: entry?.command ?? ""))
            seen.insert(parent)
            current = parent
        }
        return chain
    }

    /// The pid-only projection of `ancestorRecords(of:maxDepth:)` — see that
    /// method for the walk/termination semantics, which this shares exactly.
    func ancestry(of pid: Int32, maxDepth: Int = 20) -> [Int32] {
        ancestorRecords(of: pid, maxDepth: maxDepth).map(\.pid)
    }
}

/// Why a `ps` sample didn't yield a usable process list.
enum SampleFailure: Error {
    case launchFailed
    case timeout
    case decodeFailed
}

/// Tracks consecutive sampling failures and reports edge-triggered
/// transitions into/out of the "degraded" state. Isolated from the actor and
/// from `Process` so the threshold logic can be driven directly in tests
/// without spawning `ps`.
struct SamplingHealthTracker {
    enum Transition { case none, becameDegraded, recovered }

    private(set) var consecutiveFailures = 0
    private(set) var isDegraded = false
    let threshold: Int

    init(threshold: Int = 3) {
        self.threshold = threshold
    }

    /// Only the tick where the failure streak *reaches* the threshold
    /// reports `.becameDegraded` — later failures in the same streak report
    /// `.none` so callers log the transition once, not on every failure.
    mutating func recordFailure() -> Transition {
        consecutiveFailures += 1
        if consecutiveFailures == threshold {
            isDegraded = true
            return .becameDegraded
        }
        return .none
    }

    mutating func recordSuccess() -> Transition {
        let wasDegraded = isDegraded
        consecutiveFailures = 0
        isDegraded = false
        return wasDegraded ? .recovered : .none
    }
}

/// Polls the local process table, diffs it against the previous sample to find
/// newly-spawned processes, and runs each one through the active Sigma rules.
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
    /// True once sampling has failed `samplingHealth.threshold` times in a row.
    /// A hung or missing `/bin/ps` must not be silently mistaken for "no
    /// processes running" — this is the signal the UI can surface instead.
    @Published private(set) var isDegraded: Bool = false
    /// Count of `.routine` agent-attributed notifications skipped this
    /// session because `AppSettings.quietAgentNotifications` is on — see
    /// `AgentActivityPolicy.Assessment`. Only incremented when the event
    /// would otherwise have crossed `notificationThreshold`; a routine
    /// agent event that wouldn't have notified anyway isn't "quieted".
    /// Purely a UI counter for the settings pane caption — never consulted
    /// by detection logic, and reset only by relaunch.
    @Published private(set) var agentQuietedNotificationCount: Int = 0

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
    private var ruleStore: RuleStore?
    private let ownPID = ProcessInfo.processInfo.processIdentifier
    private let defaultIntervalSeconds: Double = 1.2
    private let defaultHalfLifeSeconds: Double = 55.0

    private var parentCache = ParentContextCache()
    private var tickIndex = 0
    private var samplingHealth = SamplingHealthTracker()
    private let chainCorrelator = ChainCorrelator()

    func configure(allowlist: AllowlistStore) {
        self.allowlist = allowlist
    }

    func configure(settings: AppSettings) {
        self.settings = settings
    }

    func configure(ruleStore: RuleStore) {
        self.ruleStore = ruleStore
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
        let result = await Self.sampleProcesses()
        sampleCount += 1

        switch result {
        case .failure(let failure):
            let transition = samplingHealth.recordFailure()
            isDegraded = samplingHealth.isDegraded
            if transition == .becameDegraded {
                DiagnosticsLog.write("monitor degraded — \(samplingHealth.consecutiveFailures) consecutive sampling failures (\(failure))")
            }
            // A failed sample is not "every process exited" — knownPIDs, the
            // baseline, and this tick's diff are all left untouched so the
            // next successful sample resumes from the real prior state.
            return
        case .success(let raw):
            let transition = samplingHealth.recordSuccess()
            isDegraded = samplingHealth.isDegraded
            if transition == .recovered {
                DiagnosticsLog.write("monitor recovered — sampling succeeded")
            }
            processSample(raw)
        }
    }

    private func processSample(_ raw: [RawProcess]) {
        let halfLife = settings?.riskDecayHalfLifeSeconds ?? defaultHalfLifeSeconds
        let decayFactor = pow(0.5, currentPollInterval / halfLife)
        riskScore = max(0, riskScore * decayFactor)
        pruneOrbitNodes()

        let currentPIDs = Set(raw.map(\.id))
        defer { knownPIDs = currentPIDs }

        parentCache.update(with: raw, tick: tickIndex)
        tickIndex += 1

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

        let activeRules = ruleStore?.activeRules ?? []
        var matchedThisTick = 0
        for proc in newProcs {
            totalSeen += 1

            // Computed once per process and reused below both for the Sigma
            // record's Ancestor* fields and for the chain correlator's
            // ancestry — walking the cache twice would be redundant work for
            // identical results.
            let ancestors = parentCache.ancestorRecords(of: proc.id)

            var record: [String: String] = ["CommandLine": proc.command, "Image": proc.image, "User": proc.user]
            if let parentImage = parentCache.image(for: proc.ppid) { record["ParentImage"] = parentImage }
            if let parentCommand = parentCache.command(for: proc.ppid) { record["ParentCommandLine"] = parentCommand }
            if let parentUser = parentCache.user(for: proc.ppid) { record["ParentUser"] = parentUser }
            // ";"-joined, nearest ancestor first, so a user rule can express
            // e.g. `AncestorCommandLines|contains: claude` to match anywhere
            // up the tree rather than only the immediate parent.
            record["AncestorImages"] = ancestors.map(\.image).joined(separator: ";")
            record["AncestorCommandLines"] = ancestors.map(\.command).joined(separator: ";")

            let rawMatches: [MatchedRule] = activeRules.compactMap { rule in
                guard SigmaMatcher.matches(rule, record: record) else { return nil }
                return MatchedRule(name: rule.title, severity: rule.severity, technique: rule.techniqueLabel,
                                    explanation: rule.description ?? "")
            }
            // Provenance is classified before allowlist filtering (rather
            // than only after, once matches are known) so a scoped entry —
            // e.g. "(rule, zsh) only under claude" — can actually see the
            // ancestry it's scoped to. Skipped when there are no raw matches
            // to filter: classification is pure but not free, and most
            // sampled processes never trip a rule at all.
            let provenanceTags: [ProvenanceTag]
            let provenance: [String]
            let matches: [MatchedRule]
            if rawMatches.isEmpty {
                provenanceTags = []
                provenance = []
                matches = rawMatches
            } else {
                provenanceTags = ProvenanceClassifier.classify(
                    ancestorImages: ancestors.map(\.image),
                    ancestorCommandLines: ancestors.map(\.command)
                )
                provenance = provenanceTags.map(\.label)
                if let allowlist {
                    matches = AllowlistFilter.apply(rawMatches, executable: proc.executable, provenance: provenance, isAllowed: allowlist.isAllowed)
                } else {
                    matches = rawMatches
                }
            }
            suppressedCount += rawMatches.count - matches.count

            let angle = Double.random(in: 0..<360)
            if matches.isEmpty {
                orbitNodes.append(OrbitNode(id: UUID(), pid: proc.id, ppid: proc.ppid,
                                             severity: .info, label: proc.executable,
                                             bornAt: Date(), angle: angle))
            } else {
                matchedThisTick += 1

                // Captured before the synthetic escalation rule (if any) is
                // appended, so chain correlation below keys off only the
                // rules this process tree actually triggered — the
                // escalation rule's fixed name must not be what makes two
                // unrelated agent-attributed events "chain" with each other.
                let originalRuleNames = Set(matches.map(\.name))
                let originalTechniques = Set(matches.map(\.technique))

                let assessment = AgentActivityPolicy.assessment(tags: provenanceTags, matchedRules: matches)
                var eventRules = matches
                if case .sensitive(let sensitiveTechniques) = assessment {
                    eventRules.append(AgentActivityPolicy.escalationRule(
                        matchedTechniques: sensitiveTechniques,
                        otherSeverities: matches.map(\.severity)
                    ))
                }

                let event = ProcessEvent(pid: proc.id, ppid: proc.ppid, executable: proc.executable,
                                          command: proc.command, rules: eventRules, timestamp: Date(),
                                          provenance: provenance)
                events.insert(event, at: 0)
                if events.count > 300 { events.removeLast(events.count - 300) }
                eventStore?.append(event)
                historicalEventCount += 1
                if let settings, settings.notificationThreshold.shouldNotify(for: event.topSeverity) {
                    // A `.routine` agent-attributed event earns a quieter
                    // UI, not a quieter record: the notification is the
                    // only thing skipped here — feed, history, and risk
                    // score above are all already unconditional. `.sensitive`
                    // assessments always fall through to a real notification.
                    if settings.quietAgentNotifications, assessment == .routine {
                        agentQuietedNotificationCount += 1
                    } else {
                        NotificationManager.notify(event: event)
                    }
                }
                riskScore = min(100, riskScore + event.topSeverity.weight)
                orbitNodes.append(OrbitNode(id: event.id, pid: proc.id, ppid: proc.ppid,
                                             severity: event.topSeverity, label: proc.executable,
                                             bornAt: Date(), angle: angle))
                let techniques = eventRules.map(\.technique).joined(separator: "; ")
                DiagnosticsLog.write("[\(event.topSeverity.label)] pid=\(proc.id) \(proc.executable) — \(techniques) — risk=\(Int(riskScore))")

                if let detection = chainCorrelator.register(
                    eventID: event.id, pid: proc.id, executable: proc.executable,
                    ruleNames: originalRuleNames, techniques: originalTechniques,
                    severity: event.topSeverity, timestamp: event.timestamp, ancestry: ancestors.map(\.pid)
                ) {
                    ingestExternal(Self.chainEvent(from: detection, pid: proc.id, ppid: proc.ppid))
                }
            }
        }
        if orbitNodes.count > 400 { orbitNodes.removeFirst(orbitNodes.count - 400) }

        activityLog.append((Date(), matchedThisTick))
        trimActivityLog()

        if sampleCount % 150 == 0 {
            DiagnosticsLog.write("heartbeat — samples=\(sampleCount) seen=\(totalSeen) events=\(events.count) suppressed=\(suppressedCount) risk=\(Int(riskScore))")
        }
    }

    /// Entry point for events discovered by a sensor other than the `ps`
    /// poll loop (currently `PersistenceWatcher`). Mirrors the matched-event
    /// branch of `processSample` — insert-at-front with the 300 cap, persist,
    /// bump counters, threshold-gated notification, risk contribution,
    /// diagnostics line — but skips orbit-node handling: pid 0 has no orbit
    /// meaning (the Orbit view visualizes the live process graph, and a
    /// synthetic artifact event isn't part of it), and skips allowlist
    /// filtering, since these events represent a persistence-artifact change
    /// rather than a rule matching an observed process (see
    /// `PersistenceEventBuilder`'s doc comment).
    func ingestExternal(_ event: ProcessEvent) {
        events.insert(event, at: 0)
        if events.count > 300 { events.removeLast(events.count - 300) }
        eventStore?.append(event)
        historicalEventCount += 1
        if let settings, settings.notificationThreshold.shouldNotify(for: event.topSeverity) {
            NotificationManager.notify(event: event)
        }
        riskScore = min(100, riskScore + event.topSeverity.weight)
        let techniques = event.rules.map(\.technique).joined(separator: "; ")
        DiagnosticsLog.write("[\(event.topSeverity.label)] external pid=\(event.pid) \(event.executable) — \(techniques) — risk=\(Int(riskScore))")
    }

    /// Short, human-scannable timestamps for the chain explanation text below
    /// — the full date is already on the enclosing `ProcessEvent`.
    nonisolated private static let chainTimestampFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    /// Builds the synthetic `ProcessEvent` representing a `ChainDetection` so
    /// it can flow through `ingestExternal` like any other externally-sourced
    /// event (feed insert, persist, threshold-gated notification, risk).
    /// Attributed to the triggering process's own pid/ppid rather than pid 0
    /// — unlike a `PersistenceWatcher` artifact this isn't sourced from a
    /// pid-less filesystem change, it's a statement about a real process
    /// tree, so it keeps that tree's identity.
    nonisolated private static func chainEvent(from detection: ChainDetection, pid: Int32, ppid: Int32) -> ProcessEvent {
        let command = detection.members.map(\.executable).joined(separator: " → ")
        let technique = detection.techniques.sorted().joined(separator: ", ")
        let explanation = detection.members.map { member -> String in
            let names = member.ruleNames.sorted().joined(separator: ", ")
            let time = chainTimestampFormatter.string(from: member.timestamp)
            return "\(member.executable) (pid \(member.pid), \(time)): \(names)"
        }.joined(separator: "; ")

        let rule = MatchedRule(
            name: "Suspicious sequence: \(detection.techniques.count) techniques in one process tree",
            severity: detection.escalatedSeverity,
            technique: technique,
            explanation: explanation
        )
        return ProcessEvent(pid: pid, ppid: ppid, executable: "chain", command: command, rules: [rule], timestamp: Date())
    }

    private func trimActivityLog() {
        let cutoff = Date().addingTimeInterval(-300)
        activityLog.removeAll { $0.0 < cutoff }
    }

    private func pruneOrbitNodes() {
        let cutoff = Date().addingTimeInterval(-14)
        orbitNodes.removeAll { $0.bornAt < cutoff }
    }

    nonisolated private static func sampleProcesses() async -> Result<[RawProcess], SampleFailure> {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                cont.resume(returning: runPS())
            }
        }
    }

    /// Hard ceiling on how long a single `ps` invocation may run. Without
    /// this, a wedged `/bin/ps` (seen in practice on macOS under heavy I/O
    /// contention) blocks `readDataToEndOfFile()` forever, silently freezing
    /// the entire poll loop with no error and no indication anything is wrong.
    nonisolated private static let samplingTimeoutSeconds: Double = 10

    nonisolated private static func runPS() -> Result<[RawProcess], SampleFailure> {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axww", "-o", "pid,ppid,user,command"]
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return .failure(.launchFailed)
        }

        // Watchdog: kill `ps` if it hasn't finished by the deadline, so the
        // blocking read below is bounded no matter what `ps` does.
        let watchdog = DispatchWorkItem {
            if process.isRunning { process.terminate() }
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + samplingTimeoutSeconds, execute: watchdog)

        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        watchdog.cancel()

        if process.terminationReason == .uncaughtSignal {
            return .failure(.timeout)
        }
        guard let output = String(data: data, encoding: .utf8) else { return .failure(.decodeFailed) }
        return .success(parsePSOutput(output))
    }

    /// Parses `ps -axww -o pid,ppid,user,command` output into `RawProcess`
    /// records. Pure and side-effect free so it can be exercised directly in
    /// tests without spawning `ps`.
    ///
    /// Tolerant of malformed rows: the header line and any line that doesn't
    /// split into the expected four columns (or whose pid/ppid aren't
    /// integers) is skipped rather than aborting the whole sample — one odd
    /// row from `ps` shouldn't blind the monitor to every other process
    /// running at the same time.
    nonisolated static func parsePSOutput(_ output: String) -> [RawProcess] {
        var results: [RawProcess] = []
        let lines = output.split(separator: "\n", omittingEmptySubsequences: true)
        for line in lines.dropFirst() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let parts = trimmed.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
            guard parts.count == 4, let pid = Int32(parts[0]), let ppid = Int32(parts[1]) else { continue }
            let user = String(parts[2])
            // `USER` is left-justified and padded to a fixed column width by
            // `ps`, so the run of spaces separating it from `COMMAND` is
            // often more than one character. `split(maxSplits:)` only
            // collapses a whitespace run when it's not the final split, so
            // that padding can survive as leading whitespace on this last
            // component — trim it rather than let it corrupt Image/CommandLine.
            let command = String(parts[3]).trimmingCharacters(in: .whitespaces)
            let firstToken = command.split(separator: " ").first.map(String.init) ?? command
            let short = (firstToken as NSString).lastPathComponent
            let image = firstToken.contains("/") ? firstToken : "/" + firstToken
            results.append(RawProcess(id: pid, ppid: ppid, command: command, executable: short, image: image, user: user))
        }
        return results
    }
}
