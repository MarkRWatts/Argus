import XCTest
@testable import Argus

final class EventExportTests: XCTestCase {
    private func sampleEvent(
        pid: Int32 = 1,
        ppid: Int32 = 99,
        executable: String = "osascript",
        command: String = "osascript -e 'do shell script \"id\" with administrator privileges'",
        rules: [MatchedRule]? = nil,
        timestamp: Date = Date(timeIntervalSince1970: 1_700_000_000)
    ) -> ProcessEvent {
        ProcessEvent(
            pid: pid,
            ppid: ppid,
            executable: executable,
            command: command,
            rules: rules ?? [MatchedRule(name: "AppleScript privilege escalation", severity: .critical,
                                          technique: "T1548 – Elevated Execution", explanation: "e")],
            timestamp: timestamp
        )
    }

    // MARK: - JSON

    func testJSONRoundTripsSingleEvent() throws {
        let event = sampleEvent()
        guard let json = EventExport.json(for: event) else {
            return XCTFail("expected JSON string")
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ProcessEvent.self, from: Data(json.utf8))

        XCTAssertEqual(decoded.id, event.id)
        XCTAssertEqual(decoded.pid, event.pid)
        XCTAssertEqual(decoded.ppid, event.ppid)
        XCTAssertEqual(decoded.executable, event.executable)
        XCTAssertEqual(decoded.command, event.command)
        XCTAssertEqual(decoded.rules.map(\.name), event.rules.map(\.name))
        XCTAssertEqual(decoded.rules.map(\.severity), event.rules.map(\.severity))
        XCTAssertEqual(decoded.timestamp.timeIntervalSince1970, event.timestamp.timeIntervalSince1970, accuracy: 0.001)
    }

    func testJSONArrayRoundTripsMultipleEvents() throws {
        let events = [sampleEvent(pid: 1), sampleEvent(pid: 2), sampleEvent(pid: 3)]
        guard let data = EventExport.json(events: events) else {
            return XCTFail("expected JSON data")
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode([ProcessEvent].self, from: data)

        XCTAssertEqual(decoded.count, 3)
        XCTAssertEqual(decoded.map(\.pid), [1, 2, 3])
        XCTAssertEqual(decoded.map(\.id), events.map(\.id))
    }

    func testJSONForEventsIsEmptyArrayForEmptyInput() throws {
        guard let data = EventExport.json(events: []) else {
            return XCTFail("expected JSON data")
        }
        let decoder = JSONDecoder()
        let decoded = try decoder.decode([ProcessEvent].self, from: data)
        XCTAssertTrue(decoded.isEmpty)
    }

    // MARK: - CSV

    func testCSVHeaderAndRowCount() {
        let events = [sampleEvent(pid: 1), sampleEvent(pid: 2), sampleEvent(pid: 3)]
        let csv = EventExport.csv(events: events)

        let lines = csv.split(separator: "\n", omittingEmptySubsequences: false)
        XCTAssertEqual(lines.first, "timestamp,pid,ppid,executable,severity,techniques,rules,command")
        // header + 3 data rows, trailing newline leaves one empty trailing element
        XCTAssertEqual(lines.count, 5)
        XCTAssertEqual(lines.last, "")
    }

    func testCSVEmptyEventListProducesHeaderOnly() {
        let csv = EventExport.csv(events: [])
        XCTAssertEqual(csv, "timestamp,pid,ppid,executable,severity,techniques,rules,command\n")
    }

    func testCSVMultiRuleEventJoinsRulesAndTechniquesWithSemicolons() {
        let rules = [
            MatchedRule(name: "Rule A", severity: .watch, technique: "T1059", explanation: "e1"),
            MatchedRule(name: "Rule B", severity: .critical, technique: "T1548", explanation: "e2")
        ]
        let event = sampleEvent(command: "echo hi", rules: rules)
        let csv = EventExport.csv(events: [event])
        let isoTimestamp = ISO8601DateFormatter().string(from: event.timestamp)

        let expected = "timestamp,pid,ppid,executable,severity,techniques,rules,command\n"
            + "\(isoTimestamp),1,99,osascript,CRITICAL,T1059;T1548,Rule A;Rule B,echo hi\n"
        XCTAssertEqual(csv, expected)
    }

    /// The load-bearing quoting test: a command containing a comma, embedded
    /// double quotes, and a literal newline must survive RFC 4180 quoting
    /// exactly — comma/newline alone would misalign columns, unescaped
    /// quotes would prematurely close the field. Also exercises quoting on a
    /// non-command field (a rule name containing a comma).
    func testCSVQuotesFieldsContainingCommasQuotesAndNewlines() {
        let command = "echo \"hello, world\"\nsecond line"
        let event = sampleEvent(
            pid: 42,
            ppid: 7,
            executable: "bash",
            command: command,
            rules: [MatchedRule(name: "Rule, A", severity: .critical, technique: "T1059", explanation: "e")]
        )

        let csv = EventExport.csv(events: [event])
        let isoTimestamp = ISO8601DateFormatter().string(from: event.timestamp)

        let expectedCommandField = "\"echo \"\"hello, world\"\"\nsecond line\""
        let expectedRuleField = "\"Rule, A\""
        let expected = "timestamp,pid,ppid,executable,severity,techniques,rules,command\n"
            + "\(isoTimestamp),42,7,bash,CRITICAL,T1059,\(expectedRuleField),\(expectedCommandField)\n"

        XCTAssertEqual(csv, expected)
    }
}
