import XCTest
@testable import Argus

final class ProcessMonitorParsingTests: XCTestCase {
    func testParsesNormalLines() {
        let output = """
          PID  PPID USER             COMMAND
            1     0 root             /sbin/launchd
          412     1 mark             /usr/bin/curl -s https://example.com
        """
        let procs = ProcessMonitor.parsePSOutput(output)
        XCTAssertEqual(procs.count, 2)
        XCTAssertEqual(procs[0].id, 1)
        XCTAssertEqual(procs[0].ppid, 0)
        XCTAssertEqual(procs[0].user, "root")
        XCTAssertEqual(procs[0].command, "/sbin/launchd")
        XCTAssertEqual(procs[1].id, 412)
        XCTAssertEqual(procs[1].ppid, 1)
        XCTAssertEqual(procs[1].user, "mark")
        XCTAssertEqual(procs[1].command, "/usr/bin/curl -s https://example.com")
    }

    func testHeaderLineIsSkipped() {
        let output = """
          PID  PPID USER             COMMAND
            1     0 root             /sbin/launchd
        """
        let procs = ProcessMonitor.parsePSOutput(output)
        XCTAssertEqual(procs.count, 1)
        XCTAssertFalse(procs.contains { $0.command.contains("COMMAND") })
    }

    func testMalformedLinesAreSkipped() {
        let output = """
          PID  PPID USER             COMMAND
            1     0 root             /sbin/launchd
          not-a-pid   1 mark bash
            5             root
            7     2 mark             /bin/echo hi
        """
        let procs = ProcessMonitor.parsePSOutput(output)
        // Only the two well-formed rows (pid 1, pid 7) should survive; the
        // non-numeric pid row and the too-short row are dropped.
        XCTAssertEqual(procs.map(\.id), [1, 7])
    }

    func testAbsolutePathImageIsPreservedAsIs() {
        let output = """
          PID  PPID USER             COMMAND
          200     1 mark             /usr/bin/curl -s https://example.com
        """
        let procs = ProcessMonitor.parsePSOutput(output)
        XCTAssertEqual(procs.first?.image, "/usr/bin/curl")
        XCTAssertEqual(procs.first?.executable, "curl")
    }

    func testBareCommandArgv0IsNormalizedToLeadingSlashImage() {
        let output = """
          PID  PPID USER             COMMAND
          201     1 mark             curl -s https://example.com
        """
        let procs = ProcessMonitor.parsePSOutput(output)
        XCTAssertEqual(procs.first?.image, "/curl")
        XCTAssertEqual(procs.first?.executable, "curl")
    }

    func testUserColumnIsParsed() {
        let output = """
          PID  PPID USER             COMMAND
          300     1 _spotlight       /usr/bin/mdworker
        """
        let procs = ProcessMonitor.parsePSOutput(output)
        XCTAssertEqual(procs.first?.user, "_spotlight")
    }

    func testEmptyOutputYieldsNoProcesses() {
        XCTAssertEqual(ProcessMonitor.parsePSOutput(""), [])
        XCTAssertEqual(ProcessMonitor.parsePSOutput("  PID  PPID USER             COMMAND"), [])
    }
}

final class ParentContextCacheTests: XCTestCase {
    private func raw(_ id: Int32, ppid: Int32, image: String, user: String = "mark") -> RawProcess {
        RawProcess(id: id, ppid: ppid, command: image, executable: (image as NSString).lastPathComponent, image: image, user: user)
    }

    func testCurrentSampleIsResolvable() {
        var cache = ParentContextCache(retentionTicks: 3)
        cache.update(with: [raw(10, ppid: 1, image: "/bin/bash", user: "mark")], tick: 0)
        XCTAssertEqual(cache.image(for: 10), "/bin/bash")
        XCTAssertEqual(cache.user(for: 10), "mark")
    }

    func testRetainsExitedParentWithinGraceWindow() {
        var cache = ParentContextCache(retentionTicks: 3)
        // Parent pid 10 present at tick 0, then gone from every later sample.
        cache.update(with: [raw(10, ppid: 1, image: "/bin/bash")], tick: 0)

        cache.update(with: [raw(11, ppid: 10, image: "/usr/bin/curl")], tick: 1)
        XCTAssertEqual(cache.image(for: 10), "/bin/bash", "still within the grace window")

        cache.update(with: [raw(12, ppid: 10, image: "/usr/bin/curl")], tick: 2)
        XCTAssertEqual(cache.image(for: 10), "/bin/bash")

        cache.update(with: [raw(13, ppid: 10, image: "/usr/bin/curl")], tick: 3)
        XCTAssertEqual(cache.image(for: 10), "/bin/bash", "last tick of the retention window")
    }

    func testPrunesAfterGraceWindowExpires() {
        var cache = ParentContextCache(retentionTicks: 3)
        cache.update(with: [raw(10, ppid: 1, image: "/bin/bash")], tick: 0)

        cache.update(with: [], tick: 4)
        XCTAssertNil(cache.image(for: 10), "pid should be pruned once past the retention window")
        XCTAssertNil(cache.command(for: 10))
        XCTAssertNil(cache.user(for: 10))
    }

    func testCurrentSampleAlwaysWinsOverCachedEntry() {
        var cache = ParentContextCache(retentionTicks: 3)
        cache.update(with: [raw(10, ppid: 1, image: "/bin/bash")], tick: 0)
        cache.update(with: [raw(10, ppid: 1, image: "/bin/zsh")], tick: 1)
        XCTAssertEqual(cache.image(for: 10), "/bin/zsh")
    }

    func testPpidIsResolvable() {
        var cache = ParentContextCache(retentionTicks: 3)
        cache.update(with: [raw(10, ppid: 1, image: "/bin/bash")], tick: 0)
        XCTAssertEqual(cache.ppid(for: 10), 1)
        XCTAssertNil(cache.ppid(for: 999))
    }

    func testAncestryWalksThroughKnownAncestors() {
        var cache = ParentContextCache(retentionTicks: 3)
        cache.update(with: [
            raw(10, ppid: 1, image: "/sbin/launchd"),
            raw(20, ppid: 10, image: "/bin/bash"),
            raw(30, ppid: 20, image: "/usr/bin/curl"),
        ], tick: 0)
        XCTAssertEqual(cache.ancestry(of: 30), [20, 10])
    }

    func testAncestryExcludesPidOneAndBelow() {
        var cache = ParentContextCache(retentionTicks: 3)
        cache.update(with: [raw(10, ppid: 1, image: "/bin/bash")], tick: 0)
        XCTAssertEqual(cache.ancestry(of: 10), [], "pid 1 (launchd) carries no chain-correlation signal and must be excluded")
    }

    func testAncestryStopsAtUnknownParent() {
        var cache = ParentContextCache(retentionTicks: 3)
        // pid 40's own ppid (99) is known, but 99 has no entry of its own —
        // the walk must include the known link and stop there rather than
        // fabricate anything further up.
        cache.update(with: [raw(40, ppid: 99, image: "/bin/bash")], tick: 0)
        XCTAssertEqual(cache.ancestry(of: 40), [99])
    }

    func testAncestryOfUnknownPidIsEmpty() {
        var cache = ParentContextCache(retentionTicks: 3)
        cache.update(with: [raw(10, ppid: 1, image: "/bin/bash")], tick: 0)
        XCTAssertEqual(cache.ancestry(of: 999), [])
    }

    func testAncestryIsCycleSafe() {
        var cache = ParentContextCache(retentionTicks: 3)
        // Corrupted/adversarial data: 50 and 60 point at each other. Must
        // terminate rather than loop forever.
        cache.update(with: [
            raw(50, ppid: 60, image: "/bin/a"),
            raw(60, ppid: 50, image: "/bin/b"),
        ], tick: 0)
        XCTAssertEqual(cache.ancestry(of: 50), [60])
    }

    func testAncestryRespectsMaxDepth() {
        var cache = ParentContextCache(retentionTicks: 3)
        var sample: [RawProcess] = []
        for pid in Int32(2)...30 {
            sample.append(raw(pid, ppid: pid - 1, image: "/bin/p\(pid)"))
        }
        cache.update(with: sample, tick: 0)
        XCTAssertEqual(cache.ancestry(of: 30, maxDepth: 5), [29, 28, 27, 26, 25])
    }
}

final class SamplingHealthTrackerTests: XCTestCase {
    func testStaysHealthyBelowThreshold() {
        var tracker = SamplingHealthTracker(threshold: 3)
        XCTAssertEqual(tracker.recordFailure(), .none)
        XCTAssertFalse(tracker.isDegraded)
        XCTAssertEqual(tracker.recordFailure(), .none)
        XCTAssertFalse(tracker.isDegraded)
    }

    func testBecomesDegradedExactlyAtThreshold() {
        var tracker = SamplingHealthTracker(threshold: 3)
        _ = tracker.recordFailure()
        _ = tracker.recordFailure()
        XCTAssertEqual(tracker.recordFailure(), .becameDegraded)
        XCTAssertTrue(tracker.isDegraded)
    }

    func testDoesNotReReportDegradedOnFurtherFailures() {
        var tracker = SamplingHealthTracker(threshold: 3)
        _ = tracker.recordFailure()
        _ = tracker.recordFailure()
        _ = tracker.recordFailure()
        XCTAssertEqual(tracker.recordFailure(), .none, "already degraded — no repeat transition")
        XCTAssertTrue(tracker.isDegraded)
    }

    func testRecoversAfterSuccess() {
        var tracker = SamplingHealthTracker(threshold: 3)
        _ = tracker.recordFailure()
        _ = tracker.recordFailure()
        _ = tracker.recordFailure()
        XCTAssertTrue(tracker.isDegraded)
        XCTAssertEqual(tracker.recordSuccess(), .recovered)
        XCTAssertFalse(tracker.isDegraded)
        XCTAssertEqual(tracker.consecutiveFailures, 0)
    }

    func testSuccessWithoutPriorDegradationReportsNone() {
        var tracker = SamplingHealthTracker(threshold: 3)
        _ = tracker.recordFailure()
        XCTAssertEqual(tracker.recordSuccess(), .none)
        XCTAssertFalse(tracker.isDegraded)
    }
}
