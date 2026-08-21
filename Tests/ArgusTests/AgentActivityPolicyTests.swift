import XCTest
@testable import Argus

final class AgentActivityPolicyTests: XCTestCase {
    private func rule(technique: String, severity: Severity = .watch) -> MatchedRule {
        MatchedRule(name: "rule", severity: severity, technique: technique, explanation: "")
    }

    private let agentTag = ProvenanceTag(category: "AI agent", label: "claude")
    private let dockerTag = ProvenanceTag(category: "Container tooling", label: "docker")

    // MARK: - isAgentAttributed

    func testIsAgentAttributedFalseForNoTags() {
        XCTAssertFalse(AgentActivityPolicy.isAgentAttributed([]))
    }

    func testIsAgentAttributedFalseForNonAgentTags() {
        XCTAssertFalse(AgentActivityPolicy.isAgentAttributed([dockerTag]))
    }

    func testIsAgentAttributedTrueWhenAgentTagPresent() {
        XCTAssertTrue(AgentActivityPolicy.isAgentAttributed([dockerTag, agentTag]))
    }

    // MARK: - assessment matrix

    func testNoTagsIsNotAgentAttributed() {
        let result = AgentActivityPolicy.assessment(tags: [], matchedRules: [rule(technique: "T1053")])
        XCTAssertEqual(result, .notAgentAttributed)
    }

    func testNonAgentTagWithSensitiveTechniqueIsNotAgentAttributed() {
        // A sensitive technique alone must not trigger escalation — only an
        // AI-agent-attributed ancestry does.
        let result = AgentActivityPolicy.assessment(tags: [dockerTag], matchedRules: [rule(technique: "T1053")])
        XCTAssertEqual(result, .notAgentAttributed)
    }

    func testAgentTagWithBenignTechniqueIsRoutine() {
        let result = AgentActivityPolicy.assessment(tags: [agentTag], matchedRules: [rule(technique: "T1059")])
        XCTAssertEqual(result, .routine)
    }

    func testAgentTagWithNoMatchedRulesIsRoutine() {
        let result = AgentActivityPolicy.assessment(tags: [agentTag], matchedRules: [])
        XCTAssertEqual(result, .routine)
    }

    func testAgentTagWithEachSensitivePrefixIsSensitive() {
        let sensitivePrefixes = ["T1543", "T1547", "T1053", "T1555", "T1552", "T1539", "T1562", "T1553"]
        for prefix in sensitivePrefixes {
            let result = AgentActivityPolicy.assessment(tags: [agentTag], matchedRules: [rule(technique: prefix)])
            XCTAssertEqual(result, .sensitive(matchedTechniques: [prefix]), "expected \(prefix) to be sensitive")
        }
    }

    func testAgentTagWithSensitiveSubTechniqueIsSensitive() {
        let result = AgentActivityPolicy.assessment(tags: [agentTag], matchedRules: [rule(technique: "T1053.005")])
        XCTAssertEqual(result, .sensitive(matchedTechniques: ["T1053.005"]))
    }

    func testLookalikeTechniqueIDIsNotFalselySensitive() {
        // "T15430" is not a real technique ID and must not match the
        // "T1543" prefix just because it starts with those characters.
        let result = AgentActivityPolicy.assessment(tags: [agentTag], matchedRules: [rule(technique: "T15430")])
        XCTAssertEqual(result, .routine)
    }

    func testMultiIDTechniqueStringSplitsAndFiltersToSensitiveOnly() {
        let result = AgentActivityPolicy.assessment(
            tags: [agentTag],
            matchedRules: [rule(technique: "T1059, T1053.005, T1547")]
        )
        XCTAssertEqual(result, .sensitive(matchedTechniques: ["T1053.005", "T1547"]))
    }

    func testSensitiveTechniquesAcrossMultipleRulesAreDeduplicatedInFirstSeenOrder() {
        let result = AgentActivityPolicy.assessment(
            tags: [agentTag],
            matchedRules: [
                rule(technique: "T1547"),
                rule(technique: "T1555, T1547"),
            ]
        )
        XCTAssertEqual(result, .sensitive(matchedTechniques: ["T1547", "T1555"]))
    }

    // MARK: - severity escalation

    func testEscalatedSeverityIsOneLevelAboveMax() {
        XCTAssertEqual(AgentActivityPolicy.escalatedSeverity(above: [.watch, .elevated]), .critical)
        XCTAssertEqual(AgentActivityPolicy.escalatedSeverity(above: [.info]), .watch)
    }

    func testEscalatedSeverityCapsAtCritical() {
        XCTAssertEqual(AgentActivityPolicy.escalatedSeverity(above: [.critical]), .critical)
    }

    func testEscalatedSeverityDefaultsFromEmptySeverities() {
        XCTAssertEqual(AgentActivityPolicy.escalatedSeverity(above: []), .watch)
    }

    func testEscalationRuleCapsAtCriticalAndJoinsTechniques() {
        let escalation = AgentActivityPolicy.escalationRule(
            matchedTechniques: ["T1053", "T1555"],
            otherSeverities: [.critical, .watch]
        )
        XCTAssertEqual(escalation.name, "AI agent session touched a sensitive technique")
        XCTAssertEqual(escalation.severity, .critical)
        XCTAssertEqual(escalation.technique, "T1053, T1555")
        XCTAssertTrue(escalation.explanation.contains("prompt-injected"))
    }
}
