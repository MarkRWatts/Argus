import XCTest
@testable import Argus

final class AllowlistFilterTests: XCTestCase {
    func testRemovesOnlyTheAllowedRule() {
        let matches = [
            MatchedRule(name: "A", severity: .critical, technique: "T1", explanation: "e"),
            MatchedRule(name: "B", severity: .watch, technique: "T2", explanation: "e2"),
        ]
        let filtered = AllowlistFilter.apply(matches, executable: "osascript", provenance: []) { name, exe, _ in
            name == "A" && exe == "osascript"
        }
        XCTAssertEqual(filtered.map(\.name), ["B"])
    }

    func testScopedToExecutable() {
        let matches = [MatchedRule(name: "A", severity: .critical, technique: "T1", explanation: "e")]
        let filtered = AllowlistFilter.apply(matches, executable: "bash", provenance: []) { name, exe, _ in
            name == "A" && exe == "osascript"
        }
        XCTAssertEqual(filtered.count, 1, "a different executable running the same-named rule should not be suppressed")
    }

    func testEmptyAllowlistFiltersNothing() {
        let matches = [MatchedRule(name: "A", severity: .critical, technique: "T1", explanation: "e")]
        let filtered = AllowlistFilter.apply(matches, executable: "osascript", provenance: []) { _, _, _ in false }
        XCTAssertEqual(filtered.count, 1)
    }

    /// `AllowlistFilter.apply` doesn't interpret provenance itself — it just
    /// hands whatever was passed straight through to `isAllowed`. Verified
    /// here so a bug that dropped or reordered the parameter on its way in
    /// would fail loudly rather than only showing up as a live suppression
    /// bug that's hard to trace back to this pass-through.
    func testPassesProvenanceThroughToIsAllowed() {
        let matches = [MatchedRule(name: "A", severity: .critical, technique: "T1", explanation: "e")]
        var seenProvenance: [String] = []
        let filtered = AllowlistFilter.apply(matches, executable: "zsh", provenance: ["claude", "tmux"]) { _, _, provenance in
            seenProvenance = provenance
            return false
        }
        XCTAssertEqual(seenProvenance, ["claude", "tmux"])
        XCTAssertEqual(filtered.count, 1)
    }
}

@MainActor
final class AllowlistStoreTests: XCTestCase {
    private func makeStore() -> (AllowlistStore, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("allowlist.json")
        return (AllowlistStore(fileURL: url), url)
    }

    func testAllowThenIsAllowed() {
        let (store, _) = makeStore()
        XCTAssertFalse(store.isAllowed(ruleName: "AppleScript privilege escalation", executable: "osascript", provenance: []))
        store.allow(ruleName: "AppleScript privilege escalation", executable: "osascript")
        XCTAssertTrue(store.isAllowed(ruleName: "AppleScript privilege escalation", executable: "osascript", provenance: []))
        XCTAssertEqual(store.entries.count, 1)
    }

    func testAllowIsIdempotent() {
        let (store, _) = makeStore()
        store.allow(ruleName: "A", executable: "osascript")
        store.allow(ruleName: "A", executable: "osascript")
        XCTAssertEqual(store.entries.count, 1)
    }

    func testRemove() {
        let (store, _) = makeStore()
        store.allow(ruleName: "A", executable: "osascript")
        guard let id = store.entries.first?.id else { return XCTFail("expected an entry") }
        store.remove(id)
        XCTAssertTrue(store.entries.isEmpty)
    }

    func testPersistsAcrossInstances() {
        let (store, url) = makeStore()
        store.allow(ruleName: "A", executable: "osascript")

        let reloaded = AllowlistStore(fileURL: url)
        XCTAssertEqual(reloaded.entries.count, 1)
        XCTAssertTrue(reloaded.isAllowed(ruleName: "A", executable: "osascript", provenance: []))
    }

    func testStoreWiredWithIntegrityGuardRecordsMACOnSave() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("allowlist.json")

        let fixedKeyGuard = IntegrityGuard(
            keyProvider: FixedKeyProviderForAllowlistTests(data: Data(repeating: 0x22, count: 32)),
            sidecarURL: dir.appendingPathComponent("integrity.json")
        )

        let store = AllowlistStore(fileURL: url, integrityGuard: fixedKeyGuard)
        // Verification is async-on-request now (a Keychain prompt must never
        // block init), so init leaves the verdict unset. No allowlist.json
        // exists yet — nothing has been authenticated, nothing to verify.
        XCTAssertNil(store.integrityVerdict)
        let verified = expectation(description: "verifyIntegrity completes")
        store.verifyIntegrity { verdict in
            XCTAssertEqual(verdict, .unverifiable)
            verified.fulfill()
        }
        wait(for: [verified], timeout: 5)
        XCTAssertEqual(store.integrityVerdict, .unverifiable)

        store.allow(ruleName: "A", executable: "osascript")
        XCTAssertEqual(fixedKeyGuard.verify(url), .verified, "save() should have recorded a MAC via the injected guard")
    }

    // MARK: - Provenance-scoped entries

    func testScopedEntrySuppressesWhenLabelPresent() {
        let (store, _) = makeStore()
        store.allow(ruleName: "Pipe-to-Interpreter Fetch and Execute", executable: "zsh", requiredProvenance: "claude")
        XCTAssertTrue(store.isAllowed(ruleName: "Pipe-to-Interpreter Fetch and Execute", executable: "zsh", provenance: ["claude"]))
    }

    /// Same rule and executable as the previous test, but without "claude"
    /// in the observed provenance — a scoped entry must not blind the rule
    /// for every other `zsh` on the system, only the ones under its scope.
    func testScopedEntryDoesNotSuppressWhenLabelAbsent() {
        let (store, _) = makeStore()
        store.allow(ruleName: "Pipe-to-Interpreter Fetch and Execute", executable: "zsh", requiredProvenance: "claude")
        XCTAssertFalse(store.isAllowed(ruleName: "Pipe-to-Interpreter Fetch and Execute", executable: "zsh", provenance: []))
        XCTAssertFalse(store.isAllowed(ruleName: "Pipe-to-Interpreter Fetch and Execute", executable: "zsh", provenance: ["docker"]))
    }

    func testUnscopedEntrySuppressesRegardlessOfProvenance() {
        let (store, _) = makeStore()
        store.allow(ruleName: "A", executable: "osascript")
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "osascript", provenance: []))
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "osascript", provenance: ["claude"]))
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "osascript", provenance: ["docker", "brew"]))
    }

    func testScopeMatchingIsCaseInsensitive() {
        let (store, _) = makeStore()
        store.allow(ruleName: "A", executable: "zsh", requiredProvenance: "claude")
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "zsh", provenance: ["Claude"]))
    }

    /// A pre-existing `allowlist.json` written before `requiredProvenance`
    /// existed has no such key at all — `decodeIfPresent` must fall back to
    /// `nil` rather than fail decoding the whole array, and the resulting
    /// entry must behave exactly as unconditional entries always have.
    func testLegacyEntryWithoutProvenanceKeyDecodesUnconditional() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("allowlist.json")
        let legacyJSON = """
        [
          {
            "id": "\(UUID().uuidString)",
            "ruleName": "A",
            "executable": "osascript",
            "createdAt": 700000000.0
          }
        ]
        """
        try! legacyJSON.write(to: url, atomically: true, encoding: .utf8)

        let store = AllowlistStore(fileURL: url)
        XCTAssertEqual(store.entries.count, 1)
        XCTAssertNil(store.entries.first?.requiredProvenance)
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "osascript", provenance: []))
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "osascript", provenance: ["claude"]))
    }

    // MARK: - Duplicate/redundancy handling across scopes

    /// Two entries for the same (rule, executable) but different scopes are
    /// genuinely distinct — one doesn't make the other redundant.
    func testDifferentScopesForSamePairCoexist() {
        let (store, _) = makeStore()
        store.allow(ruleName: "A", executable: "zsh", requiredProvenance: "claude")
        store.allow(ruleName: "A", executable: "zsh", requiredProvenance: "docker")
        XCTAssertEqual(store.entries.count, 2)
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "zsh", provenance: ["claude"]))
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "zsh", provenance: ["docker"]))
        XCTAssertFalse(store.isAllowed(ruleName: "A", executable: "zsh", provenance: ["brew"]))
    }

    /// An existing unconditional entry already suppresses everything a
    /// scoped request for the same pair would — adding the narrower entry
    /// on top would be redundant, so it's silently skipped rather than
    /// cluttering the panel with a scoped entry that can never matter.
    func testUnconditionalEntryAlreadyCoversScopedAdd() {
        let (store, _) = makeStore()
        store.allow(ruleName: "A", executable: "zsh")
        store.allow(ruleName: "A", executable: "zsh", requiredProvenance: "claude")
        XCTAssertEqual(store.entries.count, 1, "the unconditional entry already covers any scoped request for the same pair")
        XCTAssertNil(store.entries.first?.requiredProvenance)
    }

    /// The same scoped request twice is a plain duplicate, same as the
    /// existing unconditional idempotency test.
    func testScopedAllowIsIdempotent() {
        let (store, _) = makeStore()
        store.allow(ruleName: "A", executable: "zsh", requiredProvenance: "claude")
        store.allow(ruleName: "A", executable: "zsh", requiredProvenance: "claude")
        XCTAssertEqual(store.entries.count, 1)
    }

    /// The reverse ordering of `testUnconditionalEntryAlreadyCoversScopedAdd`:
    /// a scoped entry doesn't stop a later, broader unconditional request
    /// from being added — the scoped entry doesn't cover the general case.
    func testScopedEntryDoesNotBlockLaterUnconditionalAdd() {
        let (store, _) = makeStore()
        store.allow(ruleName: "A", executable: "zsh", requiredProvenance: "claude")
        store.allow(ruleName: "A", executable: "zsh")
        XCTAssertEqual(store.entries.count, 2)
        XCTAssertTrue(store.isAllowed(ruleName: "A", executable: "zsh", provenance: []))
    }
}

/// Fixed-key provider so this test doesn't touch the real Keychain.
private struct FixedKeyProviderForAllowlistTests: IntegrityKeyProvider {
    let data: Data?
    func key() -> Data? { data }
}
