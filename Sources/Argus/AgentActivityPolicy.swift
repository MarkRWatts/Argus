import Foundation

/// Turns provenance attribution ("this ancestry looks like it was launched
/// under an AI coding agent") into a triage decision, without ever letting
/// that attribution suppress or downgrade a detection.
///
/// Design position: a supervised AI-agent session (e.g. Claude Code) is a
/// **distinct trust domain**, not benign background noise. Its command
/// stream can be steered by content the agent reads — a prompt injection —
/// so activity attributed to an agent deserves *more* scrutiny for the
/// technique categories a hijacked agent would plausibly reach for
/// (persistence, credential theft, defense evasion), even while routine
/// agent-attributed activity is allowed to be quieter in the UI. This file
/// only classifies; `ProcessMonitor` decides what to do with the result
/// (escalate a sensitive match, quiet a routine notification).
enum AgentActivityPolicy {
    /// The `ProvenanceTag.category` `ProvenanceClassifier` assigns its "AI
    /// coding agent" supervisor row (currently just `claude`). Named here
    /// once, rather than repeating the string literal, so this file's
    /// agent-attribution check can't silently drift from the category
    /// `ProvenanceClassifier` actually produces. `ProvenanceClassifier.swift`
    /// itself is not otherwise touched by this feature — if its supervisor
    /// table ever renames or splits that category, this constant is the one
    /// place to update.
    static let agentProvenanceCategory = "AI agent"

    /// MITRE ATT&CK technique-ID prefixes (the "TNNNN" part, sub-techniques
    /// included via prefix match) this package treats as sensitive when
    /// they show up in an agent-attributed process tree:
    ///
    /// - Persistence — T1543 (Create/Modify System Process), T1547
    ///   (Boot/Logon Autostart Execution), T1053 (Scheduled Task/Job)
    /// - Credential access — T1555 (Credentials from Password Stores),
    ///   T1552 (Unsecured Credentials), T1539 (Steal Web Session Cookie)
    /// - Defense evasion / impairment — T1562 (Impair Defenses), T1553
    ///   (Subvert Trust Controls)
    ///
    /// These are exactly the categories a hijacked (prompt-injected) agent
    /// session would plausibly reach for to survive a restart, exfiltrate
    /// secrets, or blind the tooling that would otherwise catch it. Every
    /// other technique an agent trips is still logged and risk-scored like
    /// any other match — it's just not escalated.
    static let sensitiveTechniquePrefixes: Set<String> = [
        "T1543", "T1547", "T1053",
        "T1555", "T1552", "T1539",
        "T1562", "T1553",
    ]

    /// The outcome of weighing one event's provenance tags and matched
    /// rules against the sensitive-technique table.
    enum Assessment: Equatable {
        /// No tag identifies an AI-agent supervisor in this event's
        /// ancestry — agent policy doesn't apply.
        case notAgentAttributed
        /// Agent-attributed, but none of its matched rules touch a
        /// sensitive technique — eligible for quieter notifications.
        case routine
        /// Agent-attributed *and* at least one matched rule falls in the
        /// sensitive-technique table — must be escalated, never quieted.
        /// `matchedTechniques` lists the sensitive IDs found, in first-seen
        /// order, deduplicated.
        case sensitive(matchedTechniques: [String])
    }

    /// True when any tag identifies the AI-agent supervisor category.
    static func isAgentAttributed(_ tags: [ProvenanceTag]) -> Bool {
        tags.contains { $0.category == agentProvenanceCategory }
    }

    /// Classifies an event's agent attribution and, if attributed, whether
    /// any of its matched rules land in the sensitive-technique table.
    ///
    /// `matchedRules` is scanned rather than a single technique string
    /// because an event can carry several matched rules at once, and each
    /// rule's `technique` field can itself be several comma-separated IDs
    /// (`MatchedRule.technique`, built from `SigmaRule.techniqueLabel`, e.g.
    /// "T1548, T1059.002") — both need splitting apart before the prefix
    /// check runs.
    static func assessment(tags: [ProvenanceTag], matchedRules: [MatchedRule]) -> Assessment {
        guard isAgentAttributed(tags) else { return .notAgentAttributed }

        var matchedTechniques: [String] = []
        var seen: Set<String> = []
        for rule in matchedRules {
            for id in techniqueIDs(in: rule.technique) where isSensitive(id) {
                if seen.insert(id).inserted {
                    matchedTechniques.append(id)
                }
            }
        }
        return matchedTechniques.isEmpty ? .routine : .sensitive(matchedTechniques: matchedTechniques)
    }

    /// One level above the highest severity in `severities`, capped at
    /// `.critical` — "one level worse than this process tree would
    /// otherwise have scored," never wrapping past the top of the scale.
    static func escalatedSeverity(above severities: [Severity]) -> Severity {
        let current = severities.max() ?? .info
        let nextRaw = min(current.rawValue + 1, Severity.critical.rawValue)
        return Severity(rawValue: nextRaw) ?? .critical
    }

    /// Builds the synthetic rule `ProcessMonitor` appends to an event's
    /// matched rules when `assessment` comes back `.sensitive` — this is
    /// what actually raises `topSeverity` (and therefore risk and
    /// notification eligibility) rather than the sensitive assessment doing
    /// so directly.
    static func escalationRule(matchedTechniques: [String], otherSeverities: [Severity]) -> MatchedRule {
        MatchedRule(
            name: "AI agent session touched a sensitive technique",
            severity: escalatedSeverity(above: otherSeverities),
            technique: matchedTechniques.joined(separator: ", "),
            explanation: "A supervised AI-agent process tree performed activity matching a "
                + "persistence, credential-access, or defense-evasion technique. A hijacked "
                + "(prompt-injected) agent session is exactly how this class of compromise "
                + "presents, so this is escalated above the underlying rule's own severity "
                + "regardless of how routine the rest of the session looks."
        )
    }

    /// Splits a `MatchedRule.technique` string (e.g. "T1548, T1059.002")
    /// into its individual IDs, trimming the separator whitespace.
    private static func techniqueIDs(in technique: String) -> [String] {
        technique.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    /// Whether `techniqueID` (e.g. "T1053" or "T1053.005") falls under one
    /// of `sensitiveTechniquePrefixes`. Prefix match alone would let
    /// "T15430" (not a real technique) falsely match "T1543" — real
    /// technique IDs only ever continue past the four-digit prefix with a
    /// "." sub-technique separator, so that's what's required here too.
    private static func isSensitive(_ techniqueID: String) -> Bool {
        sensitiveTechniquePrefixes.contains { prefix in
            guard techniqueID.hasPrefix(prefix) else { return false }
            let rest = techniqueID.dropFirst(prefix.count)
            return rest.isEmpty || rest.hasPrefix(".")
        }
    }
}
