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
}
