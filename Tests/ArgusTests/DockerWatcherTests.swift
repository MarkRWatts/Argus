import XCTest
@testable import Argus

/// Real-shaped fixtures for `docker events --format '{{json .}}'` lines.
/// Field names/casing/nesting match Docker's actual JSON event schema.
private enum Fixture {
    static let containerStart = """
    {"status":"start","id":"abc123","from":"nginx:latest","Type":"container","Action":"start","Actor":{"ID":"abc123","Attributes":{"image":"nginx:latest","name":"web1"}},"scope":"local","time":1700000000,"timeNano":1700000000000000000}
    """

    static let execCreate = """
    {"status":"exec_create: /bin/sh -c ls","id":"abc123","from":"nginx:latest","Type":"container","Action":"exec_create: /bin/sh -c ls","Actor":{"ID":"abc123","Attributes":{"image":"nginx:latest","name":"web1"}},"scope":"local","time":1700000001,"timeNano":1700000001000000000}
    """

    static let execStart = """
    {"status":"exec_start: /bin/sh -c ls","id":"abc123","from":"nginx:latest","Type":"container","Action":"exec_start: /bin/sh -c ls","Actor":{"ID":"abc123","Attributes":{"image":"nginx:latest","name":"web1"}},"scope":"local","time":1700000002,"timeNano":1700000002000000000}
    """

    static let networkConnect = """
    {"status":"connect","id":"net1","Type":"network","Action":"connect","Actor":{"ID":"net1","Attributes":{"container":"abc123","name":"bridge"}},"scope":"local","time":1700000003}
    """

    static let imagePull = """
    {"status":"pull","id":"nginx:latest","Type":"image","Action":"pull","Actor":{"ID":"nginx:latest","Attributes":{"name":"nginx:latest"}},"scope":"local","time":1700000004}
    """

    static let volumeCreate = """
    {"status":"create","id":"vol1","Type":"volume","Action":"create","Actor":{"ID":"vol1","Attributes":{}},"scope":"local","time":1700000005}
    """

    static let containerDie = """
    {"status":"die","id":"abc123","from":"nginx:latest","Type":"container","Action":"die","Actor":{"ID":"abc123","Attributes":{"image":"nginx:latest","name":"web1"}},"scope":"local","time":1700000006}
    """

    static let missingAttributes = """
    {"status":"start","id":"abc123","Type":"container","Action":"start","Actor":{"ID":"abc123"},"scope":"local","time":1700000007}
    """

    static let missingActor = """
    {"status":"start","id":"abc123","Type":"container","Action":"start","scope":"local","time":1700000008}
    """
}

final class DockerEventClassifierTests: XCTestCase {
    func testSplitActionOnSimpleVerb() {
        let (verb, detail) = DockerEventClassifier.splitAction("start")
        XCTAssertEqual(verb, "start")
        XCTAssertNil(detail)
    }

    func testSplitActionSplitsOnFirstColonSpace() {
        let (verb, detail) = DockerEventClassifier.splitAction("exec_start: /bin/sh -c echo hi: there")
        XCTAssertEqual(verb, "exec_start")
        XCTAssertEqual(detail, "/bin/sh -c echo hi: there")
    }

    func testClassifyIgnoresNonContainerType() {
        let line = try! JSONDecoder().decode(DockerEventLine.self, from: Data(Fixture.networkConnect.utf8))
        XCTAssertNil(DockerEventClassifier.classify(line))
    }

    func testClassifyIgnoresDieAction() {
        let line = try! JSONDecoder().decode(DockerEventLine.self, from: Data(Fixture.containerDie.utf8))
        XCTAssertNil(DockerEventClassifier.classify(line))
    }

    func testClassifyStart() {
        let line = try! JSONDecoder().decode(DockerEventLine.self, from: Data(Fixture.containerStart.utf8))
        let result = DockerEventClassifier.classify(line)
        XCTAssertEqual(result?.kind, .start)
        XCTAssertNil(result?.execCommand)
    }

    func testClassifyExecStartExtractsCommand() {
        let line = try! JSONDecoder().decode(DockerEventLine.self, from: Data(Fixture.execStart.utf8))
        let result = DockerEventClassifier.classify(line)
        XCTAssertEqual(result?.kind, .execStart)
        XCTAssertEqual(result?.execCommand, "/bin/sh -c ls")
    }

    func testClassifyExecCreateExtractsCommand() {
        let line = try! JSONDecoder().decode(DockerEventLine.self, from: Data(Fixture.execCreate.utf8))
        let result = DockerEventClassifier.classify(line)
        XCTAssertEqual(result?.kind, .execCreate)
        XCTAssertEqual(result?.execCommand, "/bin/sh -c ls")
    }
}

final class DockerEventBuilderTests: XCTestCase {
    func testStartProducesInfoT1610WithNameAndImage() {
        let event = DockerEventBuilder.makeEvent(kind: .start, execCommand: nil, image: "nginx:latest", name: "web1", timestamp: Date())
        XCTAssertNotNil(event)
        XCTAssertEqual(event?.pid, 0)
        XCTAssertEqual(event?.ppid, 0)
        XCTAssertEqual(event?.executable, "web1")
        XCTAssertTrue(event!.command.contains("nginx:latest"))
        XCTAssertTrue(event!.command.contains("web1"))
        XCTAssertEqual(event?.rules.count, 1)
        XCTAssertEqual(event?.rules.first?.severity, .info)
        XCTAssertEqual(event?.rules.first?.technique, "T1610")
        XCTAssertEqual(event?.provenance, ["docker"])
    }

    func testExecCreateIsIgnored() {
        let event = DockerEventBuilder.makeEvent(kind: .execCreate, execCommand: "/bin/sh -c ls", image: "nginx:latest", name: "web1", timestamp: Date())
        XCTAssertNil(event)
    }

    func testExecStartProducesWatchT1609WithCommand() {
        let event = DockerEventBuilder.makeEvent(kind: .execStart, execCommand: "/bin/sh -c ls", image: "nginx:latest", name: "web1", timestamp: Date())
        XCTAssertNotNil(event)
        XCTAssertEqual(event?.rules.first?.severity, .watch)
        XCTAssertEqual(event?.rules.first?.technique, "T1609")
        XCTAssertTrue(event!.command.contains("/bin/sh -c ls"))
        XCTAssertTrue(event!.command.contains("web1"))
        XCTAssertEqual(event?.provenance, ["docker"])
    }

    func testFallsBackToImageWhenNameMissing() {
        let event = DockerEventBuilder.makeEvent(kind: .start, execCommand: nil, image: "nginx:latest", name: nil, timestamp: Date())
        XCTAssertEqual(event?.executable, "nginx:latest")
    }

    func testUnknownWhenBothNameAndImageMissing() {
        let event = DockerEventBuilder.makeEvent(kind: .start, execCommand: nil, image: nil, name: nil, timestamp: Date())
        XCTAssertEqual(event?.executable, "unknown")
    }
}

final class DockerLineProcessorTests: XCTestCase {
    func testContainerStartLineProducesEvent() {
        let event = DockerLineProcessor.processLine(Fixture.containerStart)
        XCTAssertNotNil(event)
        XCTAssertEqual(event?.executable, "web1")
        XCTAssertEqual(event?.rules.first?.technique, "T1610")
        XCTAssertEqual(event?.provenance, ["docker"])
    }

    func testExecStartLineProducesEvent() {
        let event = DockerLineProcessor.processLine(Fixture.execStart)
        XCTAssertNotNil(event)
        XCTAssertEqual(event?.rules.first?.technique, "T1609")
        XCTAssertTrue(event!.command.contains("/bin/sh -c ls"))
    }

    func testExecCreateLineIsIgnored() {
        XCTAssertNil(DockerLineProcessor.processLine(Fixture.execCreate))
    }

    func testNetworkTypeLineIsIgnored() {
        XCTAssertNil(DockerLineProcessor.processLine(Fixture.networkConnect))
    }

    func testImageTypeLineIsIgnored() {
        XCTAssertNil(DockerLineProcessor.processLine(Fixture.imagePull))
    }

    func testVolumeTypeLineIsIgnored() {
        XCTAssertNil(DockerLineProcessor.processLine(Fixture.volumeCreate))
    }

    func testContainerDieLineIsIgnored() {
        XCTAssertNil(DockerLineProcessor.processLine(Fixture.containerDie))
    }

    func testNonJSONGarbageLineDoesNotCrash() {
        XCTAssertNil(DockerLineProcessor.processLine("this is not json at all {{{"))
    }

    func testEmptyLineIsIgnored() {
        XCTAssertNil(DockerLineProcessor.processLine(""))
        XCTAssertNil(DockerLineProcessor.processLine("   \n"))
    }

    func testMissingAttributesIsTolerated() {
        let event = DockerLineProcessor.processLine(Fixture.missingAttributes)
        XCTAssertNotNil(event)
        XCTAssertEqual(event?.executable, "unknown")
    }

    func testMissingActorIsTolerated() {
        let event = DockerLineProcessor.processLine(Fixture.missingActor)
        XCTAssertNotNil(event)
        XCTAssertEqual(event?.executable, "unknown")
    }

    func testMalformedPartialJSONLineIsIgnored() {
        let partial = String(Fixture.containerStart.prefix(40))
        XCTAssertNil(DockerLineProcessor.processLine(partial))
    }
}

final class LineBufferTests: XCTestCase {
    func testSingleCompleteLine() {
        var buffer = ""
        let lines = LineBuffer.consume("hello\n", buffer: &buffer)
        XCTAssertEqual(lines, ["hello"])
        XCTAssertEqual(buffer, "")
    }

    func testPartialLineIsHeldBack() {
        var buffer = ""
        let lines = LineBuffer.consume("hel", buffer: &buffer)
        XCTAssertEqual(lines, [])
        XCTAssertEqual(buffer, "hel")
    }

    func testChunkBoundaryMidLineIsReassembled() {
        var buffer = ""
        // Simulates a readabilityHandler delivering an NDJSON line split
        // across two separate chunks, as a real pipe read can do.
        let firstLines = LineBuffer.consume("{\"Type\":\"cont", buffer: &buffer)
        XCTAssertEqual(firstLines, [])
        XCTAssertEqual(buffer, "{\"Type\":\"cont")

        let secondLines = LineBuffer.consume("ainer\"}\n", buffer: &buffer)
        XCTAssertEqual(secondLines, ["{\"Type\":\"container\"}"])
        XCTAssertEqual(buffer, "")
    }

    func testMultipleLinesInOneChunk() {
        var buffer = ""
        let lines = LineBuffer.consume("line1\nline2\nline3\n", buffer: &buffer)
        XCTAssertEqual(lines, ["line1", "line2", "line3"])
        XCTAssertEqual(buffer, "")
    }

    func testTrailingPartialAfterMultipleCompleteLines() {
        var buffer = ""
        let lines = LineBuffer.consume("line1\nline2\npartial", buffer: &buffer)
        XCTAssertEqual(lines, ["line1", "line2"])
        XCTAssertEqual(buffer, "partial")
    }
}

/// Verifies the watcher itself never touches a real `docker` binary and
/// stays silent (beyond the diagnostics line) when none is found — the CI
/// environment and most dev machines have no Docker installed at all.
final class DockerWatcherTests: XCTestCase {
    func testStartIsInertWithoutRealDockerCLI() {
        // DockerWatcher only ever probes the three fixed candidate paths;
        // on a machine (like CI) without any of them present this must not
        // throw, hang, or spawn anything — just log and return.
        let watcher = DockerWatcher()
        watcher.start()
        watcher.stop()
        // No assertion beyond "did not crash/hang" — there is no real docker
        // CLI in this environment to assert against, by design.
    }

    func testStopBeforeStartIsSafe() {
        let watcher = DockerWatcher()
        watcher.stop()
    }
}
