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

    func testStoreWiredWithIntegrityGuardRecordsMACOnSave() {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let bundled = root.appendingPathComponent("bundled")
        let user = root.appendingPathComponent("user")
        let state = root.appendingPathComponent("rules-state.json")
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("custom"), withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("imported"), withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("imported-portable"), withIntermediateDirectories: true)

        let fixedKeyGuard = IntegrityGuard(
            keyProvider: FixedKeyProviderForTests(data: Data(repeating: 0x11, count: 32)),
            sidecarURL: root.appendingPathComponent("integrity.json")
        )

        let sampleRule = """
        title: Test Rule
        id: 55555555-5555-5555-5555-555555555555
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

        let store = RuleStore(bundledRulesDirectory: bundled, userRulesDirectory: user, stateFileURL: state, integrityGuard: fixedKeyGuard)
        // Verification is async-on-request now (a Keychain prompt must never
        // block init), so init leaves the verdict unset. No rules-state.json
        // exists yet — nothing has been authenticated, nothing to verify.
        XCTAssertNil(store.integrityVerdict)
        XCTAssertEqual(fixedKeyGuard.verify(state), .unverifiable)
        XCTAssertEqual(store.rules.count, 1)

        store.toggle(store.rules[0])
        XCTAssertEqual(fixedKeyGuard.verify(state), .verified, "saveDisabledState should have recorded a MAC via the injected guard")
    }
    // MARK: - Supersession

    private static let supersededImportedID = "f5141b6d-9f42-41c6-a7bf-2a780678b29b"

    /// Bundled/user directories, not yet turned into a `RuleStore`, whose
    /// "imported" folder carries a stand-in for the real SigmaHQ xattr rule
    /// (same `id` as the real one — content otherwise irrelevant) so
    /// `RuleStore.applySupersessions()`'s loaded-rule-presence gate lets the
    /// supersession fire, mirroring what the real bundle looks like.
    private func makeDirsWithImportedGatekeeperRule() -> (bundled: URL, user: URL, state: URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let bundled = root.appendingPathComponent("bundled")
        let user = root.appendingPathComponent("user")
        let state = root.appendingPathComponent("rules-state.json")
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("custom"), withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("imported"), withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: bundled.appendingPathComponent("imported-portable"), withIntermediateDirectories: true)

        let importedRule = """
        title: Gatekeeper Bypass via Xattr
        id: \(Self.supersededImportedID)
        status: test
        description: Detects macOS Gatekeeper bypass via xattr utility
        author: Test
        date: 2026-08-21
        tags:
            - attack.defense-impairment
            - attack.t1553.001
        logsource:
            category: process_creation
            product: macos
        detection:
            selection:
                Image|endswith: '/xattr'
                CommandLine|contains|all:
                    - '-d'
                    - 'com.apple.quarantine'
            condition: selection
        level: low
        """
        try? importedRule.write(to: bundled.appendingPathComponent("imported/xattr.yml"), atomically: true, encoding: .utf8)
        return (bundled, user, state)
    }

    func testSupersessionDisablesImportedRuleOnFirstLoadAndRecordsApplied() {
        let (bundled, user, state) = makeDirsWithImportedGatekeeperRule()
        let store = RuleStore(bundledRulesDirectory: bundled, userRulesDirectory: user, stateFileURL: state)

        XCTAssertTrue(store.disabledRuleIDs.contains(Self.supersededImportedID),
                       "the superseded imported rule should be auto-disabled on first load")

        guard let data = try? Data(contentsOf: state),
              let decoded = try? JSONDecoder().decode(RuleDisabledStateForTests.self, from: data) else {
            XCTFail("expected a persisted rules-state.json after supersession ran")
            return
        }
        XCTAssertTrue(decoded.disabled.contains(Self.supersededImportedID))
        XCTAssertTrue(decoded.supersessionsApplied.contains(Self.supersededImportedID),
                       "the supersession should be recorded as applied so it isn't redone if the user re-enables the rule")
    }

    func testReenabledSupersededRuleStaysEnabledAcrossReload() {
        let (bundled, user, state) = makeDirsWithImportedGatekeeperRule()
        // Simulate a prior launch where supersession already ran, and the
        // user then deliberately re-enabled the imported rule (removing it
        // from `disabled` without clearing the `supersessionsApplied` marker).
        let priorState = RuleDisabledStateForTests(disabled: [], supersessionsApplied: [Self.supersededImportedID])
        if let encoded = try? JSONEncoder().encode(priorState) {
            try? encoded.write(to: state)
        }

        let store = RuleStore(bundledRulesDirectory: bundled, userRulesDirectory: user, stateFileURL: state)

        XCTAssertFalse(store.disabledRuleIDs.contains(Self.supersededImportedID),
                        "a user-re-enabled superseded rule should not be disabled again on reload")
    }

    func testLegacyBareSetStateFileStillDecodesAndSupersessionAppliesOnTop() {
        let (bundled, user, state) = makeDirsWithImportedGatekeeperRule()
        // Pre-supersession on-disk format: a bare JSON array of disabled IDs.
        let legacyDisabledID = "some-other-rule-id"
        if let encoded = try? JSONEncoder().encode([legacyDisabledID]) {
            try? encoded.write(to: state)
        }

        let store = RuleStore(bundledRulesDirectory: bundled, userRulesDirectory: user, stateFileURL: state)

        XCTAssertTrue(store.disabledRuleIDs.contains(legacyDisabledID),
                       "existing disabled ids from a legacy bare-Set state file should be preserved")
        XCTAssertTrue(store.disabledRuleIDs.contains(Self.supersededImportedID),
                       "supersession should still apply on top of a migrated legacy state file")
    }
}

/// Local fixed-key provider so this test doesn't depend on
/// `IntegrityGuardTests`'s private helper across files.
private struct FixedKeyProviderForTests: IntegrityKeyProvider {
    let data: Data?
    func key() -> Data? { data }
}

/// Mirrors `RuleStore`'s private on-disk state shape so these tests can
/// decode/encode `rules-state.json` without exposing that type.
private struct RuleDisabledStateForTests: Codable {
    var disabled: [String]
    var supersessionsApplied: [String]
}
