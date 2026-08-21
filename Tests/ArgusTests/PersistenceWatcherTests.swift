import XCTest
@testable import Argus

final class SnapshotDiffTests: XCTestCase {
    func testAddedFileIsReported() {
        let previous: DirectorySnapshot = [:]
        let current: DirectorySnapshot = ["com.evil.agent.plist": Date()]
        let changes = SnapshotDiff.diff(previous: previous, current: current)
        XCTAssertEqual(changes, [ArtifactChange(filename: "com.evil.agent.plist", kind: .added)])
    }

    func testModifiedFileIsReportedWhenModDateChanges() {
        let older = Date(timeIntervalSince1970: 1000)
        let newer = Date(timeIntervalSince1970: 2000)
        let previous: DirectorySnapshot = ["com.example.agent.plist": older]
        let current: DirectorySnapshot = ["com.example.agent.plist": newer]
        let changes = SnapshotDiff.diff(previous: previous, current: current)
        XCTAssertEqual(changes, [ArtifactChange(filename: "com.example.agent.plist", kind: .modified)])
    }

    func testRemovedFileIsReported() {
        let previous: DirectorySnapshot = ["com.example.agent.plist": Date()]
        let current: DirectorySnapshot = [:]
        let changes = SnapshotDiff.diff(previous: previous, current: current)
        XCTAssertEqual(changes, [ArtifactChange(filename: "com.example.agent.plist", kind: .removed)])
    }

    func testUnchangedFileYieldsNoChange() {
        let same = Date(timeIntervalSince1970: 5000)
        let previous: DirectorySnapshot = ["com.example.agent.plist": same]
        let current: DirectorySnapshot = ["com.example.agent.plist": same]
        XCTAssertEqual(SnapshotDiff.diff(previous: previous, current: current), [])
    }

    func testFirstBaselineProducesNoChangesAgainstItself() {
        // Simulates DirectoryWatch's silent-baseline behavior: diffing a
        // snapshot against itself (as happens when the first rescan runs
        // before anything on disk has actually changed) must report nothing,
        // so pre-existing files never alert at startup.
        let baseline: DirectorySnapshot = [
            "com.apple.something.plist": Date(timeIntervalSince1970: 100),
            "com.example.other.plist": Date(timeIntervalSince1970: 200),
        ]
        XCTAssertEqual(SnapshotDiff.diff(previous: baseline, current: baseline), [])
    }

    func testMixedAddModifyRemoveInSingleDiff() {
        let previous: DirectorySnapshot = [
            "kept.plist": Date(timeIntervalSince1970: 100),
            "changed.plist": Date(timeIntervalSince1970: 100),
            "gone.plist": Date(timeIntervalSince1970: 100),
        ]
        let current: DirectorySnapshot = [
            "kept.plist": Date(timeIntervalSince1970: 100),
            "changed.plist": Date(timeIntervalSince1970: 200),
            "new.plist": Date(timeIntervalSince1970: 300),
        ]
        let changes = SnapshotDiff.diff(previous: previous, current: current)
        XCTAssertEqual(changes, [
            ArtifactChange(filename: "changed.plist", kind: .modified),
            ArtifactChange(filename: "gone.plist", kind: .removed),
            ArtifactChange(filename: "new.plist", kind: .added),
        ], "results are sorted by filename for determinism")
    }
}

final class PersistenceEventBuilderTests: XCTestCase {
    func testLaunchAgentsAddedIsElevatedWithLaunchAgentTechnique() {
        let event = PersistenceEventBuilder.makeEvent(
            filename: "com.evil.agent.plist", changeKind: .added,
            locationKind: .launchAgents, directoryPath: "/Users/mark/Library/LaunchAgents"
        )
        XCTAssertEqual(event.pid, 0)
        XCTAssertEqual(event.ppid, 0)
        XCTAssertEqual(event.executable, "com.evil.agent.plist")
        XCTAssertEqual(event.command, "/Users/mark/Library/LaunchAgents/com.evil.agent.plist")
        XCTAssertEqual(event.rules.count, 1)
        let rule = event.rules[0]
        XCTAssertEqual(rule.severity, .elevated)
        XCTAssertEqual(rule.technique, "T1547.011")
        XCTAssertEqual(rule.name, "Persistence artifact added: LaunchAgents")
        XCTAssertTrue(rule.explanation.contains("LaunchAgents"))
    }

    func testLaunchAgentsModifiedIsElevated() {
        let event = PersistenceEventBuilder.makeEvent(
            filename: "com.evil.agent.plist", changeKind: .modified,
            locationKind: .launchAgents, directoryPath: "/Library/LaunchAgents"
        )
        XCTAssertEqual(event.rules[0].severity, .elevated)
        XCTAssertEqual(event.rules[0].name, "Persistence artifact modified: LaunchAgents")
    }

    func testLaunchAgentsRemovedIsWatch() {
        let event = PersistenceEventBuilder.makeEvent(
            filename: "com.evil.agent.plist", changeKind: .removed,
            locationKind: .launchAgents, directoryPath: "/Library/LaunchAgents"
        )
        XCTAssertEqual(event.rules[0].severity, .watch)
        XCTAssertEqual(event.rules[0].name, "Persistence artifact removed: LaunchAgents")
    }

    func testLaunchDaemonsUsesDaemonTechnique() {
        let event = PersistenceEventBuilder.makeEvent(
            filename: "com.evil.daemon.plist", changeKind: .added,
            locationKind: .launchDaemons, directoryPath: "/Library/LaunchDaemons"
        )
        XCTAssertEqual(event.rules[0].technique, "T1543.001")
        XCTAssertEqual(event.rules[0].severity, .elevated)
        XCTAssertEqual(event.rules[0].name, "Persistence artifact added: LaunchDaemons")
        XCTAssertTrue(event.rules[0].explanation.contains("root"))
    }

    func testPeriodicCronUsesCronTechnique() {
        let event = PersistenceEventBuilder.makeEvent(
            filename: "daily-evil", changeKind: .added,
            locationKind: .periodicCron, directoryPath: "/etc/periodic/daily"
        )
        XCTAssertEqual(event.rules[0].technique, "T1053.003")
        XCTAssertEqual(event.rules[0].severity, .elevated)
    }

    func testFullPathIsJoinedFromDirectoryAndFilename() {
        let event = PersistenceEventBuilder.makeEvent(
            filename: "foo.plist", changeKind: .added,
            locationKind: .launchAgents, directoryPath: "/Library/LaunchAgents"
        )
        XCTAssertEqual(event.command, "/Library/LaunchAgents/foo.plist")
    }
}

final class PersistenceLocationKindTests: XCTestCase {
    func testDisplayNames() {
        XCTAssertEqual(PersistenceLocationKind.launchAgents.displayName, "LaunchAgents")
        XCTAssertEqual(PersistenceLocationKind.launchDaemons.displayName, "LaunchDaemons")
        XCTAssertEqual(PersistenceLocationKind.periodicCron.displayName, "periodic")
    }
}

/// Drives a real `DirectoryWatch` against a temp directory to exercise the
/// end-to-end event → debounce → rescan → diff → callback path. Kept
/// deterministic with a short debounce and a generous, bounded wait via
/// `XCTestExpectation` rather than a fixed sleep.
final class DirectoryWatchIntegrationTests: XCTestCase {
    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("ArgusPersistenceWatcherTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    func testExistingFileDoesNotAlertAtStartup() throws {
        let existing = tempDir.appendingPathComponent("preexisting.plist")
        try Data("preexisting".utf8).write(to: existing)

        let notified = XCTestExpectation(description: "onChange should not fire for pre-existing file")
        notified.isInverted = true

        let watch = DirectoryWatch(path: tempDir.path, kind: .launchAgents, debounceInterval: 0.2) { _ in
            notified.fulfill()
        }
        XCTAssertNotNil(watch)

        wait(for: [notified], timeout: 0.8)
        watch?.cancel()
    }

    func testNewFileTriggersAddedEvent() throws {
        let received = XCTestExpectation(description: "onChange fires for a new file")
        var observedEvent: ProcessEvent?

        let watch = DirectoryWatch(path: tempDir.path, kind: .launchAgents, debounceInterval: 0.2) { event in
            observedEvent = event
            received.fulfill()
        }
        XCTAssertNotNil(watch)

        let newFile = tempDir.appendingPathComponent("com.new.agent.plist")
        try Data("new".utf8).write(to: newFile)

        wait(for: [received], timeout: 5.0)
        watch?.cancel()

        XCTAssertEqual(observedEvent?.executable, "com.new.agent.plist")
        XCTAssertEqual(observedEvent?.rules.first?.severity, .elevated)
    }

    func testUnreadableDirectoryReturnsNil() {
        let missing = tempDir.appendingPathComponent("does-not-exist")
        let watch = DirectoryWatch(path: missing.path, kind: .launchAgents) { _ in }
        XCTAssertNil(watch)
    }
}
