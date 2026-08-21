import XCTest
@testable import Argus

/// Fixed, in-memory key so these tests never touch the real Keychain (the
/// production `KeychainIntegrityKeyProvider` is exercised only via
/// `IntegrityGuard.shared`, which these tests deliberately avoid).
private struct FixedKeyProvider: IntegrityKeyProvider {
    let data: Data?
    func key() -> Data? { data }
}

final class IntegrityGuardTests: XCTestCase {
    private func makeTempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func makeGuard(dir: URL, key: Data? = Data(repeating: 0x42, count: 32)) -> IntegrityGuard {
        IntegrityGuard(keyProvider: FixedKeyProvider(data: key), sidecarURL: dir.appendingPathComponent("integrity.json"))
    }

    func testVerifiedRoundTrip() throws {
        let dir = makeTempDir()
        let file = dir.appendingPathComponent("rules-state.json")
        try "[\"a\"]".write(to: file, atomically: true, encoding: .utf8)

        let guardInstance = makeGuard(dir: dir)
        guardInstance.recordAuthenticatedWrite(of: file)

        XCTAssertEqual(guardInstance.verify(file), .verified)
    }

    func testBaselineEstablishedOnFirstSight() throws {
        let dir = makeTempDir()
        let file = dir.appendingPathComponent("allowlist.json")
        try "[]".write(to: file, atomically: true, encoding: .utf8)

        let guardInstance = makeGuard(dir: dir)
        XCTAssertEqual(guardInstance.verify(file), .baselineEstablished)
        // The baseline just adopted should verify cleanly next time, with no
        // further authenticated write in between.
        XCTAssertEqual(guardInstance.verify(file), .verified)
    }

    func testTamperDetection() throws {
        let dir = makeTempDir()
        let file = dir.appendingPathComponent("rules-state.json")
        try "[\"a\"]".write(to: file, atomically: true, encoding: .utf8)

        let guardInstance = makeGuard(dir: dir)
        guardInstance.recordAuthenticatedWrite(of: file)

        // Simulate a local attacker rewriting the file directly, bypassing
        // RuleStore's authenticated save path entirely.
        try "[\"a\", \"b\"]".write(to: file, atomically: true, encoding: .utf8)

        XCTAssertEqual(guardInstance.verify(file), .tampered)
    }

    func testRebaselinesAfterTamperSoItDoesNotRefire() throws {
        let dir = makeTempDir()
        let file = dir.appendingPathComponent("rules-state.json")
        try "[\"a\"]".write(to: file, atomically: true, encoding: .utf8)

        let guardInstance = makeGuard(dir: dir)
        guardInstance.recordAuthenticatedWrite(of: file)
        try "[\"a\", \"b\"]".write(to: file, atomically: true, encoding: .utf8)

        XCTAssertEqual(guardInstance.verify(file), .tampered)
        // Same file, unchanged since the tamper was reported: should now
        // verify cleanly rather than reporting .tampered again forever.
        XCTAssertEqual(guardInstance.verify(file), .verified)
    }

    func testNilKeyIsUnverifiable() throws {
        let dir = makeTempDir()
        let file = dir.appendingPathComponent("rules-state.json")
        try "[\"a\"]".write(to: file, atomically: true, encoding: .utf8)

        let guardInstance = makeGuard(dir: dir, key: nil)
        // Should not crash, and should decline to write a MAC with no key.
        guardInstance.recordAuthenticatedWrite(of: file)
        XCTAssertEqual(guardInstance.verify(file), .unverifiable)
    }

    func testUnreadableFileIsUnverifiable() {
        let dir = makeTempDir()
        let missing = dir.appendingPathComponent("does-not-exist.json")

        let guardInstance = makeGuard(dir: dir)
        XCTAssertEqual(guardInstance.verify(missing), .unverifiable)
    }

    func testTamperEventConstruction() throws {
        let fileURL = URL(fileURLWithPath: "/Users/test/Library/Application Support/Argus/rules-state.json")
        let event = IntegrityGuard.tamperEvent(for: fileURL)

        XCTAssertEqual(event.pid, 0)
        XCTAssertEqual(event.ppid, 0)
        XCTAssertEqual(event.executable, "rules-state.json")
        XCTAssertEqual(event.command, fileURL.path)
        XCTAssertEqual(event.rules.count, 1)
        let rule = try XCTUnwrap(event.rules.first)
        XCTAssertEqual(rule.name, "Detection state modified outside Argus")
        XCTAssertEqual(rule.technique, "T1562.001")
        XCTAssertEqual(rule.severity, .critical)
        XCTAssertTrue(rule.explanation.contains("rules-state.json"))
    }
}
