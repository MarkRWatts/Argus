import XCTest
@testable import Argus

@MainActor
final class EventStoreTests: XCTestCase {
    private func makeStore(maxRetained: Int = 5000) -> (EventStore, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("events.jsonl")
        return (EventStore(fileURL: url, maxRetained: maxRetained), url)
    }

    private func sampleEvent(pid: Int32 = 1, executable: String = "osascript", timestamp: Date = Date()) -> ProcessEvent {
        ProcessEvent(
            pid: pid,
            ppid: 99,
            executable: executable,
            command: "osascript -e 'do shell script \"id\" with administrator privileges'",
            rules: [MatchedRule(name: "AppleScript privilege escalation", severity: .critical,
                                 technique: "T1548 – Elevated Execution", explanation: "e")],
            timestamp: timestamp
        )
    }

    func testAppendThenLoadAll() {
        let (store, _) = makeStore()
        store.append(sampleEvent())
        store.append(sampleEvent(pid: 2))

        let loaded = store.loadAll()
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(loaded[0].executable, "osascript")
        XCTAssertEqual(loaded[0].rules.first?.name, "AppleScript privilege escalation")
    }

    func testLoadRecentReturnsMostRecentSuffix() {
        let (store, _) = makeStore()
        for i in 0..<5 {
            store.append(sampleEvent(pid: Int32(i)))
        }
        let recent = store.loadRecent(limit: 2)
        XCTAssertEqual(recent.map(\.pid), [3, 4])
    }

    func testPersistsAcrossInstances() {
        let (store, url) = makeStore()
        store.append(sampleEvent())

        let reloaded = EventStore(fileURL: url)
        XCTAssertEqual(reloaded.loadAll().count, 1)
    }

    func testTrimsWhenOverCapacity() {
        // Trimming is checked every 200 appends (not on every single append,
        // to avoid re-reading the whole file constantly), so the cap is
        // enforced at that cadence rather than instantaneously. Append
        // exactly enough to cross one trim cycle and check it fired.
        let (store, _) = makeStore(maxRetained: 10)
        for i in 0..<200 {
            store.append(sampleEvent(pid: Int32(i)))
        }
        let loaded = store.loadAll()
        XCTAssertEqual(loaded.count, 10, "trim should fire exactly at the 200th append")
        XCTAssertEqual(loaded.last?.pid, 199, "survivors should be the most recently appended")
        XCTAssertEqual(loaded.first?.pid, 190)
    }
}
