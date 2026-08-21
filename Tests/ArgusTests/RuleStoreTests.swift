import XCTest
@testable import Argus

@MainActor
final class RuleStoreTests: XCTestCase {
    private func makeStore() -> (RuleStore, bundled: URL, user: URL, state: URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let bundled = root.appendingPathComponent("bundled")
        let user = root.appendingPathComponent("user")
        let state = root.appendingPathComponent("rules-state.json")
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("custom"), withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("imported"), withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("imported-portable"), withIntermediateDirectories: true)

        let sampleRule = """
        title: Test Rule
        id: 11111111-1111-1111-1111-111111111111
        status: stable
        description: A rule for testing.
        author: Test
        date: 2026-08-21
        tags:
            - attack.execution
            - attack.t1059
        logsource:
            category: process_creation
            product: macos
        detection:
            selection:
                CommandLine|contains: 'dangerous-thing'
            condition: selection
        level: high
        """
        try? sampleRule.write(to: bundled.appendingPathComponent("custom/test.yml"), atomically: true, encoding: .utf8)

        let store = RuleStore(bundledRulesDirectory: bundled, userRulesDirectory: user, stateFileURL: state)
        return (store, bundled, user, state)
    }

    func testLoadsBundledRule() {
        let (store, _, _, _) = makeStore()
        XCTAssertEqual(store.rules.count, 1)
        XCTAssertEqual(store.rules.first?.title, "Test Rule")
        XCTAssertTrue(store.isEnabled(store.rules[0]))
        XCTAssertEqual(store.activeRules.count, 1)
    }

    func testToggleDisablesAndReenables() {
        let (store, _, _, _) = makeStore()
        let rule = store.rules[0]
        store.toggle(rule)
        XCTAssertFalse(store.isEnabled(rule))
        XCTAssertEqual(store.activeRules.count, 0)

        store.toggle(rule)
        XCTAssertTrue(store.isEnabled(rule))
        XCTAssertEqual(store.activeRules.count, 1)
    }

    func testDisabledStatePersistsAcrossInstances() {
        let (store, bundled, user, state) = makeStore()
        let rule = store.rules[0]
        store.toggle(rule)
        XCTAssertFalse(store.isEnabled(rule))

        let reloaded = RuleStore(bundledRulesDirectory: bundled, userRulesDirectory: user, stateFileURL: state)
        XCTAssertFalse(reloaded.isEnabled(rule), "disabled state should survive a fresh RuleStore instance")
    }

    func testUserRuleIsLoadedAndDistinguishedByOrigin() {
        let (store, _, user, _) = makeStore()
        let userRule = """
        title: My Custom Watch
        id: 22222222-2222-2222-2222-222222222222
        status: stable
        author: Me
        date: 2026-08-21
        tags:
            - attack.discovery
        logsource:
            category: process_creation
            product: macos
        detection:
            selection:
                CommandLine|contains: 'my-tool'
            condition: selection
        level: low
        """
        try? userRule.write(to: user.appendingPathComponent("mine.yml"), atomically: true, encoding: .utf8)
        store.reload()

        XCTAssertEqual(store.rules.count, 2)
        let mine = store.rules.first { $0.title == "My Custom Watch" }
        XCTAssertEqual(mine?.origin, .user)
    }

    func testIncompatibleLogsourceRuleIsSkippedAndCounted() {
        let (store, _, user, _) = makeStore()
        XCTAssertEqual(store.skippedIncompatibleCount, 0, "the one bundled rule is macos/process_creation and should load cleanly")

        let windowsRule = """
        title: Windows Only Rule
        id: 33333333-3333-3333-3333-333333333333
        status: stable
        author: Me
        date: 2026-08-21
        tags:
            - attack.execution
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|contains: 'powershell'
            condition: selection
        level: high
        """
        try? windowsRule.write(to: user.appendingPathComponent("windows.yml"), atomically: true, encoding: .utf8)
        store.reload()

        XCTAssertEqual(store.rules.count, 1, "the windows/process_creation rule should be skipped, not loaded")
        XCTAssertFalse(store.rules.contains { $0.title == "Windows Only Rule" })
        XCTAssertEqual(store.skippedIncompatibleCount, 1)
    }

    func testIncompatibleCategoryRuleIsSkippedAndCounted() {
        let (store, _, user, _) = makeStore()

        let networkRule = """
        title: Network Connection Rule
        id: 44444444-4444-4444-4444-444444444444
        status: stable
        author: Me
        date: 2026-08-21
        tags:
            - attack.command-and-control
        logsource:
            category: network_connection
            product: macos
        detection:
            selection:
                DestinationPort: 4444
            condition: selection
        level: high
        """
        try? networkRule.write(to: user.appendingPathComponent("network.yml"), atomically: true, encoding: .utf8)
        store.reload()

        XCTAssertEqual(store.rules.count, 1, "a non-process_creation category should be skipped")
        XCTAssertEqual(store.skippedIncompatibleCount, 1)
    }
}
