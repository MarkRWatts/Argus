import XCTest
@testable import Argus

final class ProcessEventCodableTests: XCTestCase {
    /// A hand-written JSON line shaped exactly like something written by a
    /// build of Argus before `provenance` existed — no `provenance` key at
    /// all. Real events.jsonl history on disk looks like this; decoding it
    /// must not fail or the user's persisted history silently disappears.
    private let legacyJSON = """
    {
      "id": "9B1DE1B1-6E23-4B47-9C1B-1F6A0B9E2B10",
      "pid": 412,
      "ppid": 99,
      "executable": "osascript",
      "command": "osascript -e 'do shell script \\"id\\" with administrator privileges'",
      "rules": [
        {
          "id": "3C1D2E3F-4A5B-6C7D-8E9F-0A1B2C3D4E5F",
          "name": "AppleScript privilege escalation",
          "severity": 3,
          "technique": "T1548 \\u2013 Elevated Execution",
          "explanation": "e"
        }
      ],
      "timestamp": 700000000.0
    }
    """

    func testDecodesLegacyEventWithoutProvenanceKey() throws {
        let data = try XCTUnwrap(legacyJSON.data(using: .utf8))
        let event = try JSONDecoder().decode(ProcessEvent.self, from: data)
        XCTAssertEqual(event.pid, 412)
        XCTAssertEqual(event.executable, "osascript")
        XCTAssertEqual(event.rules.first?.name, "AppleScript privilege escalation")
        XCTAssertEqual(event.provenance, [], "missing key must default to empty, not fail decoding")
    }

    func testRoundTripsProvenanceThroughEncodeAndDecode() throws {
        let event = ProcessEvent(pid: 1, ppid: 2, executable: "claude", command: "claude", rules: [], timestamp: Date(), provenance: ["claude", "tmux"])
        let data = try JSONEncoder().encode(event)
        let decoded = try JSONDecoder().decode(ProcessEvent.self, from: data)
        XCTAssertEqual(decoded.provenance, ["claude", "tmux"])
    }

    func testProvenanceDefaultsToEmptyWhenOmittedFromInitializer() {
        let event = ProcessEvent(pid: 1, ppid: 2, executable: "chain", command: "a -> b", rules: [], timestamp: Date())
        XCTAssertEqual(event.provenance, [], "synthetic events (chain/persistence/tamper) keep an empty provenance")
    }
}
