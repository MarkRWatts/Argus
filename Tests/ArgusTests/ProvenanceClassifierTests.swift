import XCTest
@testable import Argus

final class ProvenanceClassifierTests: XCTestCase {
    func testUnrelatedAncestryYieldsNoTags() {
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/bin/bash", "/sbin/launchd"],
            ancestorCommandLines: ["/bin/bash -l", "/sbin/launchd"]
        )
        XCTAssertEqual(tags, [])
    }

    func testEmptyAncestryYieldsNoTags() {
        XCTAssertEqual(ProvenanceClassifier.classify(ancestorImages: [], ancestorCommandLines: []), [])
    }

    func testClaudeMatchesByCommandLinePath() {
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/usr/bin/node"],
            ancestorCommandLines: ["node /Users/mark/.claude/local/claude.js"]
        )
        XCTAssertEqual(tags.map(\.label), ["claude"])
        XCTAssertEqual(tags.first?.category, "AI agent")
    }

    func testClaudeMatchesByImageBasename() {
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/usr/local/bin/claude"],
            ancestorCommandLines: ["claude --resume"]
        )
        XCTAssertEqual(tags.map(\.label), ["claude"])
    }

    func testDockerMatchesCLIImage() {
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/usr/local/bin/docker"],
            ancestorCommandLines: ["docker run -it alpine sh"]
        )
        XCTAssertEqual(tags.map(\.label), ["docker"])
        XCTAssertEqual(tags.first?.category, "Container tooling")
    }

    func testDockerMatchesComDockerImage() {
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/Applications/Docker.app/Contents/MacOS/com.docker.backend"],
            ancestorCommandLines: ["com.docker.backend"]
        )
        XCTAssertEqual(tags.map(\.label), ["docker"])
    }

    func testBrewMatchesByCommandLinePath() {
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/usr/bin/ruby"],
            ancestorCommandLines: ["/opt/Homebrew/bin/brew install curl"]
        )
        XCTAssertEqual(tags.map(\.label), ["brew"])
        XCTAssertEqual(tags.first?.category, "Package manager")
    }

    func testBrewMatchesByImageBasename() {
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/opt/homebrew/bin/brew"],
            ancestorCommandLines: ["brew upgrade"]
        )
        XCTAssertEqual(tags.map(\.label), ["brew"])
    }

    func testTerminalSupervisorsMatch() {
        XCTAssertEqual(
            ProvenanceClassifier.classify(ancestorImages: ["/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"], ancestorCommandLines: ["Terminal"]).map(\.label),
            ["Terminal"]
        )
        XCTAssertEqual(
            ProvenanceClassifier.classify(ancestorImages: ["/Applications/iTerm.app/Contents/MacOS/iTerm2"], ancestorCommandLines: ["iTerm2"]).map(\.label),
            ["iTerm2"]
        )
        XCTAssertEqual(
            ProvenanceClassifier.classify(ancestorImages: ["/opt/homebrew/bin/tmux"], ancestorCommandLines: ["tmux new-session"]).map(\.label),
            ["tmux"]
        )
    }

    func testIDESupervisorsMatch() {
        XCTAssertEqual(
            ProvenanceClassifier.classify(
                ancestorImages: ["/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)"],
                ancestorCommandLines: ["Code Helper (Plugin)"]
            ).map(\.label),
            ["Code"]
        )
        XCTAssertEqual(
            ProvenanceClassifier.classify(ancestorImages: ["/Applications/Cursor.app/Contents/MacOS/Cursor"], ancestorCommandLines: ["Cursor"]).map(\.label),
            ["Cursor"]
        )
    }

    func testDeduplicatesRepeatedSupervisorByLabel() {
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/usr/local/bin/claude", "/usr/local/bin/claude"],
            ancestorCommandLines: ["claude --resume", "claude --resume"]
        )
        XCTAssertEqual(tags.map(\.label), ["claude"], "repeated ancestry match must not duplicate the tag")
    }

    func testNearestSupervisorReportedFirst() {
        // Nearest ancestor (index 0) is tmux; further up is claude. Tag
        // order must follow ancestry order, nearest first — not table order.
        let tags = ProvenanceClassifier.classify(
            ancestorImages: ["/opt/homebrew/bin/tmux", "/usr/local/bin/claude"],
            ancestorCommandLines: ["tmux new-session", "claude --resume"]
        )
        XCTAssertEqual(tags.map(\.label), ["tmux", "claude"])
    }
}
