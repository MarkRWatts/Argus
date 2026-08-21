import XCTest
@testable import Argus

final class HistoryStatsTests: XCTestCase {
    private var utcCalendar: Calendar {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal
    }

    private func date(_ iso: String) -> Date {
        let f = ISO8601DateFormatter()
        return f.date(from: iso)!
    }

    private func event(technique: String, severity: Severity, timestamp: Date) -> ProcessEvent {
        ProcessEvent(
            pid: 1, ppid: 1, executable: "x", command: "x",
            rules: [MatchedRule(name: "rule", severity: severity, technique: technique, explanation: "e")],
            timestamp: timestamp
        )
    }

    func testDailyActivityBucketsByDay() {
        let events = [
            event(technique: "T1", severity: .watch, timestamp: date("2026-08-20T08:00:00Z")),
            event(technique: "T1", severity: .critical, timestamp: date("2026-08-20T22:00:00Z")),
            event(technique: "T2", severity: .watch, timestamp: date("2026-08-21T01:00:00Z")),
        ]
        let daily = HistoryStats.dailyActivity(events, calendar: utcCalendar)
        XCTAssertEqual(daily.count, 2)

        let day1 = daily.first { utcCalendar.isDate($0.id, inSameDayAs: date("2026-08-20T00:00:00Z")) }
        XCTAssertEqual(day1?.count, 2)
        XCTAssertEqual(day1?.maxSeverity, .critical, "day bucket should record the highest severity seen that day")

        let day2 = daily.first { utcCalendar.isDate($0.id, inSameDayAs: date("2026-08-21T00:00:00Z")) }
        XCTAssertEqual(day2?.count, 1)
    }

    func testDailyActivitySortedAscending() {
        let events = [
            event(technique: "T1", severity: .watch, timestamp: date("2026-08-21T00:00:00Z")),
            event(technique: "T1", severity: .watch, timestamp: date("2026-08-19T00:00:00Z")),
            event(technique: "T1", severity: .watch, timestamp: date("2026-08-20T00:00:00Z")),
        ]
        let daily = HistoryStats.dailyActivity(events, calendar: utcCalendar)
        XCTAssertEqual(daily.map(\.id), daily.map(\.id).sorted())
    }

    func testTechniqueFrequencySortedDescending() {
        let events = [
            event(technique: "A", severity: .watch, timestamp: Date()),
            event(technique: "B", severity: .watch, timestamp: Date()),
            event(technique: "A", severity: .watch, timestamp: Date()),
            event(technique: "A", severity: .watch, timestamp: Date()),
        ]
        let freq = HistoryStats.techniqueFrequency(events)
        XCTAssertEqual(freq.first?.technique, "A")
        XCTAssertEqual(freq.first?.count, 3)
        XCTAssertEqual(freq.count, 2)
    }

    func testEmptyInputProducesEmptyOutput() {
        XCTAssertTrue(HistoryStats.dailyActivity([]).isEmpty)
        XCTAssertTrue(HistoryStats.techniqueFrequency([]).isEmpty)
    }
}
