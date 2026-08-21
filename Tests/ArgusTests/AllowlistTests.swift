import XCTest
@testable import Argus

final class AllowlistFilterTests: XCTestCase {
    func testRemovesOnlyTheAllowedRule() {
        let matches = [
            MatchedRule(name: "A", severity: .critical, technique: "T1", explanation: "e"),
            MatchedRule(name: "B", severity: .watch, technique: "T2", explanation: "e2"),
        ]
        let filtered = AllowlistFilter.apply(matches, executable: "osascript") { name, exe in
            name == "A" && exe == "osascript"
        }
        XCTAssertEqual(filtered.map(\.name), ["B"])
    }

    func testScopedToExecutable() {
        let matches = [MatchedRule(name: "A", severity: .critical, technique: "T1", explanation: "e")]
        let filtered = AllowlistFilter.apply(matches, executable: "bash") { name, exe in
            name == "A" && exe == "osascript"
        }
        XCTAssertEqual(filtered.count, 1, "a different executable running the same-named rule should not be suppressed")
    }

    func testEmptyAllowlistFiltersNothing() {
        let matches = [MatchedRule(name: "A", severity: .critical, technique: "T1", explanation: "e")]
        let filtered = AllowlistFilter.apply(matches, executable: "osascript") { _, _ in false }
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
        XCTAssertFalse(store.isAllowed(ruleName: "AppleScript privilege escalation", executable: "osascript"))
        store.allow(ruleName: "AppleScript privilege escalation", executable: "osascript")
        XCTAssertTrue(store.isAllowed(ruleName: "AppleScript privilege escalation", executable: "osascript"))
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
        XCTAssertTrue(reloaded.isAllowed(ruleName: "A", executable: "osascript"))
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
        // No allowlist.json exists yet — nothing has been authenticated, nothing to verify.
        XCTAssertEqual(store.integrityVerdict, .unverifiable)

        store.allow(ruleName: "A", executable: "osascript")
        XCTAssertEqual(fixedKeyGuard.verify(url), .verified, "save() should have recorded a MAC via the injected guard")
    }
}

/// Fixed-key provider so this test doesn't touch the real Keychain.
private struct FixedKeyProviderForAllowlistTests: IntegrityKeyProvider {
    let data: Data?
    func key() -> Data? { data }
}
