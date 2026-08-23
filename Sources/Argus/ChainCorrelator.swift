import Foundation

/// One matched process folded into the correlator's rolling window.
///
/// `lineage` is `{pid} ∪ ancestry(of: pid)` with every pid `<= 1` stripped
/// out. Excluding launchd/kernel pids matters: on macOS every process
/// eventually descends from launchd (pid 1), so if `1` were left in, every
/// pair of events observed anywhere on the machine would share it and the
/// correlator would chain unrelated processes together constantly.
struct ChainMember {
    let eventID: UUID
    let pid: Int32
    let executable: String
    /// The member's full command line, carried so the synthetic chain event
    /// can show *what* each step actually did — for a `curl` upload that's
    /// the URL it touched, which is the single most useful triage fact a
    /// "curl → hdiutil → osascript" summary otherwise loses.
    let command: String
    let ruleNames: Set<String>
    let techniques: Set<String>
    let severity: Severity
    let timestamp: Date
    let lineage: Set<Int32>
}

/// A chain the correlator has fired: the prior member(s) it joined together
/// with the newly-registered one, in chronological order.
struct ChainDetection {
    let members: [ChainMember]
    let techniques: Set<String>
    let escalatedSeverity: Severity
}

/// Correlates matched processes into ancestry-linked "chains" — the same
/// signal the README's core thesis calls out: a single LOLBin invocation is
/// often unremarkable, but two or more *different* techniques firing inside
/// the same process tree within a short window is a much stronger signal
/// than either alone.
///
/// Deliberately independent of `ProcessMonitor`/`@MainActor` and of `ps` —
/// callers supply the pid, its precomputed ancestry, and the rule/technique
/// data already extracted from a match, so this class can be driven and
/// tested with plain values.
final class ChainCorrelator {
    private var members: [ChainMember] = []
    let window: TimeInterval

    init(window: TimeInterval = 600) {
        self.window = window
    }

    /// Registers one matched process and reports a `ChainDetection` if it
    /// joins an existing, still-live member of a different technique in the
    /// same process tree.
    ///
    /// - Parameter ancestry: the pid's ancestor chain (nearest first),
    ///   typically `ParentContextCache.ancestry(of:)` — *not* including the
    ///   pid itself.
    ///
    /// Two members are related iff one's pid is present in the other's
    /// lineage, or their lineages otherwise intersect (a shared ancestor
    /// further up the tree). A detection only fires when a related member's
    /// `ruleNames` are not a subset of the incoming event's `ruleNames` —
    /// this is what stops the same rule re-matching a retried command (or a
    /// process that legitimately matches several rules at once) from
    /// "chaining" with itself: that's already visible as a single
    /// multi-rule event, not a sequence of distinct techniques.
    ///
    /// The new member is recorded whether or not a detection fires — even
    /// after a chain has already been reported, a later, third technique in
    /// the same tree is new information and re-fires with all prior related
    /// members included. Growth is bounded by the rolling `window`, which is
    /// pruned (relative to the incoming event's timestamp) before anything
    /// else runs.
    func register(
        eventID: UUID,
        pid: Int32,
        executable: String,
        command: String,
        ruleNames: Set<String>,
        techniques: Set<String>,
        severity: Severity,
        timestamp: Date,
        ancestry: [Int32]
    ) -> ChainDetection? {
        let cutoff = timestamp.addingTimeInterval(-window)
        members.removeAll { $0.timestamp < cutoff }

        let lineage = Set(([pid] + ancestry).filter { $0 > 1 })

        // A chain always needs two distinct processes: a single process
        // matching multiple rules is one multi-rule event, not a sequence.
        let related = members.filter { existing in
            guard existing.pid != pid else { return false }
            let sameTree = lineage.contains(existing.pid)
                || existing.lineage.contains(pid)
                || !lineage.isDisjoint(with: existing.lineage)
            guard sameTree else { return false }
            return !existing.ruleNames.isSubset(of: ruleNames)
        }

        let newMember = ChainMember(eventID: eventID, pid: pid, executable: executable,
                                     command: command, ruleNames: ruleNames, techniques: techniques,
                                     severity: severity, timestamp: timestamp, lineage: lineage)
        members.append(newMember)

        guard !related.isEmpty else { return nil }

        let allMembers = (related + [newMember]).sorted { $0.timestamp < $1.timestamp }
        let allTechniques = allMembers.reduce(into: Set<String>()) { $0.formUnion($1.techniques) }
        let maxSeverity = allMembers.map(\.severity).max() ?? severity
        let escalatedRaw = min(maxSeverity.rawValue + 1, Severity.critical.rawValue)
        let escalated = Severity(rawValue: escalatedRaw) ?? .critical

        return ChainDetection(members: allMembers, techniques: allTechniques, escalatedSeverity: escalated)
    }
}
