import XCTest
@testable import Argus

/// Loads every rule file actually shipped with the app (not paraphrased
/// fixtures) straight from the source tree and validates the whole set:
/// every file parses, every condition parses, every selection is
/// non-empty, rule IDs are unique, and — for Argus's own custom rules,
/// which embed `x-example-match` / `x-example-safe` fixtures — the rule
/// actually matches what it claims to and doesn't match nearby benign
/// commands. This is the rule-count-scales-past-hand-maintained-Swift-list
/// replacement for the old RuleEngineTests "one sample per rule" pattern.
final class BundledRulesTests: XCTestCase {

    /// Resources/Rules lives three directories up from this test file
    /// (Tests/ArgusTests/BundledRulesTests.swift → repo root → Resources/Rules).
    private static let rulesRoot: URL = {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // ArgusTests/
            .deletingLastPathComponent() // Tests/
            .deletingLastPathComponent() // repo root
            .appendingPathComponent("Resources/Rules")
    }()

    private static let allRules: [SigmaRule] = {
        var rules: [SigmaRule] = []
        rules += RuleStore.loadRules(from: rulesRoot.appendingPathComponent("imported"), origin: .sigmaHQMacOS).rules
        rules += RuleStore.loadRules(from: rulesRoot.appendingPathComponent("imported-portable"), origin: .sigmaHQPortable).rules
        rules += RuleStore.loadRules(from: rulesRoot.appendingPathComponent("custom"), origin: .custom).rules
        return rules
    }()

    func testRulesFolderIsReachable() {
        XCTAssertTrue(FileManager.default.fileExists(atPath: Self.rulesRoot.path), "expected \(Self.rulesRoot.path) to exist")
    }

    func testExpectedRuleCount() {
        // 67 SigmaHQ macOS + 8 SigmaHQ portable-shell + 10 Argus custom = 85.
        // A specific number, not a >0 check, so silently losing a whole
        // directory of rules (bad bundle path, parse regression) fails loudly.
        XCTAssertEqual(Self.allRules.count, 85, "rule count changed — update this if the change was deliberate")
    }

    func testEveryRuleHasNonEmptyConditionAndDetection() {
        for rule in Self.allRules {
            XCTAssertNotNil(rule.parsedCondition, "\(rule.sourceFile): condition failed to parse: '\(rule.condition)'")
            XCTAssertFalse(rule.detection.isEmpty, "\(rule.sourceFile): empty detection block")
        }
    }

    func testRuleIDsAreUnique() {
        let ids = Self.allRules.map(\.id)
        XCTAssertEqual(ids.count, Set(ids).count, "duplicate rule IDs would break enable/disable state and allowlisting")
    }

    func testRuleTitlesAreUnique() {
        let titles = Self.allRules.map(\.title)
        XCTAssertEqual(titles.count, Set(titles).count, "duplicate titles are confusing in the rule browser even if IDs differ")
    }

    func testEveryRuleHasATechniqueLabel() {
        for rule in Self.allRules {
            XCTAssertFalse(rule.techniqueLabel.isEmpty, "\(rule.title) produced an empty technique label")
        }
    }

    /// The actual coverage test: every command line an Argus-authored rule
    /// claims to match, it must match — and every "safe" lookalike, it
    /// must not.
    func testCustomRuleExampleFixtures() {
        let customRules = Self.allRules.filter { $0.origin == .custom }
        XCTAssertFalse(customRules.isEmpty, "expected at least one custom rule with example fixtures")

        var rulesWithoutFixtures: [String] = []
        for rule in customRules {
            if rule.exampleMatches.isEmpty { rulesWithoutFixtures.append(rule.title) }
            for command in rule.exampleMatches {
                let record = ["CommandLine": command, "Image": Self.image(from: command)]
                XCTAssertTrue(SigmaMatcher.matches(rule, record: record),
                              "'\(rule.title)' should match its own x-example-match: \(command)")
            }
            for command in rule.exampleSafe {
                let record = ["CommandLine": command, "Image": Self.image(from: command)]
                XCTAssertFalse(SigmaMatcher.matches(rule, record: record),
                               "'\(rule.title)' should NOT match its own x-example-safe: \(command)")
            }
        }
        XCTAssertTrue(rulesWithoutFixtures.isEmpty, "custom rules missing x-example-match fixtures: \(rulesWithoutFixtures)")
    }

    /// Mirrors ProcessMonitor's own Image normalization so fixtures behave
    /// the same way in tests as they will at runtime.
    private static func image(from command: String) -> String {
        let firstToken = command.split(separator: " ").first.map(String.init) ?? command
        return firstToken.contains("/") ? firstToken : "/" + firstToken
    }
}
