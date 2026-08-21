import XCTest
@testable import Argus

final class NotificationRollupTests: XCTestCase {
    private let base = Date(timeIntervalSince1970: 1_700_000_000)

    private func rollup(window: TimeInterval = 300, budget: Int = 3) -> NotificationRollup {
        NotificationRollup(window: window, budget: budget)
    }

    // MARK: - budget

    func testFirstBudgetEventsDeliverIndividually() {
        let r = rollup(budget: 3)
        for i in 0..<3 {
            let decision = r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base.addingTimeInterval(Double(i)))
            XCTAssertEqual(decision, .deliver, "event \(i) should still be within budget")
        }
    }

    func testEventAfterBudgetBecomesDigestWithCorrectCountAndTechniques() {
        let r = rollup(budget: 3)
        for i in 0..<3 {
            _ = r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base.addingTimeInterval(Double(i)))
        }
        let decision = r.record(rootPID: 100, techniques: ["T1553"], severity: .watch, timestamp: base.addingTimeInterval(3))
        XCTAssertEqual(decision, .digest(count: 4, techniques: ["T1059", "T1553"], since: base, isFirstDigest: true))
    }

    func testSubsequentDigestEventsAreNotFirstDigestAndAccumulateCount() {
        let r = rollup(budget: 3)
        for i in 0..<3 {
            _ = r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base.addingTimeInterval(Double(i)))
        }
        let first = r.record(rootPID: 100, techniques: [], severity: .watch, timestamp: base.addingTimeInterval(3))
        XCTAssertEqual(first, .digest(count: 4, techniques: ["T1059"], since: base, isFirstDigest: true))

        let second = r.record(rootPID: 100, techniques: [], severity: .watch, timestamp: base.addingTimeInterval(4))
        XCTAssertEqual(second, .digest(count: 5, techniques: ["T1059"], since: base, isFirstDigest: false))
    }

    // MARK: - critical always delivers

    func testCriticalAlwaysDeliversAndDoesNotConsumeBudget() {
        let r = rollup(budget: 1)
        // Exhaust the budget with a non-critical event.
        XCTAssertEqual(r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base), .deliver)
        // Now digesting.
        if case .digest = r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base.addingTimeInterval(1)) {
            // expected
        } else {
            XCTFail("expected digest once budget exhausted")
        }
        // A critical event still delivers individually even though the
        // budget is exhausted and this root is already digesting.
        let criticalDecision = r.record(rootPID: 100, techniques: ["T1562"], severity: .critical, timestamp: base.addingTimeInterval(2))
        XCTAssertEqual(criticalDecision, .deliver)
    }

    func testCriticalDeliveryDoesNotConsumeBudgetForLaterEvents() {
        let r = rollup(budget: 1)
        // Critical events, however many, never consume the single-slot budget.
        for i in 0..<5 {
            let decision = r.record(rootPID: 100, techniques: ["T1562"], severity: .critical, timestamp: base.addingTimeInterval(Double(i)))
            XCTAssertEqual(decision, .deliver, "critical event \(i) must always deliver")
        }
        // The budget is still untouched, so the next non-critical event
        // still delivers individually.
        let watchDecision = r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base.addingTimeInterval(5))
        XCTAssertEqual(watchDecision, .deliver)
    }

    // MARK: - window expiry

    func testWindowExpiryResetsToIndividualDelivery() {
        let r = rollup(window: 300, budget: 1)
        XCTAssertEqual(r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base), .deliver)
        if case .digest = r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base.addingTimeInterval(1)) {
            // expected: digesting within the same window
        } else {
            XCTFail("expected digest before window expiry")
        }

        // Past the window boundary — a brand new window opens with a fresh budget.
        let afterExpiry = r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base.addingTimeInterval(301))
        XCTAssertEqual(afterExpiry, .deliver)
    }

    // MARK: - independent roots

    func testTwoDistinctRootsTrackIndependently() {
        let r = rollup(budget: 1)
        XCTAssertEqual(r.record(rootPID: 100, techniques: ["T1059"], severity: .watch, timestamp: base), .deliver)
        // A different root's first event still delivers, unaffected by root
        // 100 already having used its budget.
        XCTAssertEqual(r.record(rootPID: 200, techniques: ["T1059"], severity: .watch, timestamp: base), .deliver)

        // Root 100's second event digests...
        if case .digest = r.record(rootPID: 100, techniques: [], severity: .watch, timestamp: base.addingTimeInterval(1)) {
            // expected
        } else {
            XCTFail("expected root 100 to be digesting")
        }
        // ...while root 200's second event still digests independently,
        // with its own isFirstDigest and its own count, not root 100's.
        let root200Second = r.record(rootPID: 200, techniques: ["T1553"], severity: .watch, timestamp: base.addingTimeInterval(1))
        XCTAssertEqual(root200Second, .digest(count: 2, techniques: ["T1059", "T1553"], since: base, isFirstDigest: true))
    }

    // MARK: - isFirstDigest exactly once per window per root

    func testIsFirstDigestTrueExactlyOncePerWindow() {
        let r = rollup(budget: 2)
        _ = r.record(rootPID: 100, techniques: [], severity: .watch, timestamp: base)
        _ = r.record(rootPID: 100, techniques: [], severity: .watch, timestamp: base.addingTimeInterval(1))

        var firstDigestCount = 0
        for i in 2..<10 {
            let decision = r.record(rootPID: 100, techniques: [], severity: .watch, timestamp: base.addingTimeInterval(Double(i)))
            if case .digest(_, _, _, let isFirst) = decision, isFirst {
                firstDigestCount += 1
            }
        }
        XCTAssertEqual(firstDigestCount, 1)
    }

    // MARK: - technique dedup order

    func testTechniquesDedupPreservesFirstSeenOrder() {
        let r = rollup(budget: 1)
        _ = r.record(rootPID: 100, techniques: ["T1059", "T1553"], severity: .watch, timestamp: base)
        let decision = r.record(rootPID: 100, techniques: ["T1553", "T1547", "T1059"], severity: .watch, timestamp: base.addingTimeInterval(1))
        XCTAssertEqual(decision, .digest(count: 2, techniques: ["T1059", "T1553", "T1547"], since: base, isFirstDigest: true))
    }
}
