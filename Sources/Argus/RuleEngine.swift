import Foundation

/// Catalog of macOS "living-off-the-land" behaviors: legitimate, Apple-signed
/// binaries whose *arguments* and *combinations* are what adversary tradecraft
/// actually looks like. No single rule here flags a binary — it flags a usage
/// pattern. Technique tags are informal shorthand, not a formal ATT&CK claim.
struct Rule {
    let name: String
    let severity: Severity
    let technique: String
    let explanation: String
    let match: (String) -> Bool

    init(_ name: String, _ severity: Severity, _ technique: String, _ explanation: String, patterns: [String]) {
        self.name = name
        self.severity = severity
        self.technique = technique
        self.explanation = explanation
        self.match = { cmd in
            let lower = cmd.lowercased()
            return patterns.contains { lower.contains($0) }
        }
    }

    init(_ name: String, _ severity: Severity, _ technique: String, _ explanation: String, regex: String) {
        self.name = name
        self.severity = severity
        self.technique = technique
        self.explanation = explanation
        let re = try? NSRegularExpression(pattern: regex, options: [.caseInsensitive])
        self.match = { cmd in
            guard let re else { return false }
            let range = NSRange(cmd.startIndex..<cmd.endIndex, in: cmd)
            return re.firstMatch(in: cmd, options: [], range: range) != nil
        }
    }
}

enum RuleEngine {
    static let catalog: [Rule] = [
        Rule("AppleScript privilege escalation", .critical, "T1548 – Elevated Execution",
             "osascript requesting administrator privileges to run an embedded shell command.",
             regex: #"osascript\s+.*(with administrator privileges|do shell script)"#),

        Rule("Pipe-to-interpreter download", .critical, "T1059 – Remote Script Execution",
             "A downloader piped straight into a shell/interpreter — fetch-and-execute with no file ever hitting disk.",
             regex: #"(curl|wget|nscurl)\s+.*\|\s*(sh|bash|zsh|python3?|osascript)"#),

        Rule("Base64-obfuscated shell", .critical, "T1140 – Deobfuscate/Decode",
             "Base64-decoded payload piped directly into a shell.",
             regex: #"base64\s+(-d|--decode).*\|\s*(sh|bash|zsh)"#),

        Rule("Gatekeeper quarantine strip", .elevated, "T1553.001 – Gatekeeper Bypass",
             "xattr removing com.apple.quarantine, which lets a downloaded binary skip the Gatekeeper prompt.",
             patterns: ["xattr -d com.apple.quarantine", "xattr -c "]),

        Rule("Ad-hoc code signature removal", .elevated, "T1553.001 – Gatekeeper Bypass",
             "codesign stripping a binary's signature, often paired with re-signing to dodge notarization checks.",
             patterns: ["codesign --remove-signature", "codesign -f -s -"]),

        Rule("LaunchAgent persistence", .critical, "T1543.001 – Launch Agent",
             "launchctl loading a LaunchAgent/LaunchDaemon plist — the classic macOS persistence mechanism.",
             regex: #"launchctl\s+(load|bootstrap)\s+.*(launchagents|launchdaemons)"#),

        Rule("Login Item persistence", .elevated, "T1547 – Login Item",
             "A login item or launch plist being written directly rather than via System Settings.",
             patterns: ["loginitems", "sfl2bookmarkdata", "servicemanagement"]),

        Rule("Keychain credential access", .critical, "T1555.001 – Keychain",
             "security CLI dumping or searching the keychain for stored passwords.",
             regex: #"security\s+(dump-keychain|find-generic-password|find-internet-password).*(-w|-g)"#),

        Rule("Browser cookie/session store access", .critical, "T1539 – Steal Web Session Cookie",
             "Direct sqlite3/file access to a browser's Cookies or Login Data store outside the browser process.",
             regex: #"(sqlite3|cat|cp)\s+.*(cookies\.sqlite|cookies\b|login data)"#),

        Rule("TCC database tampering", .critical, "T1548 – TCC Manipulation",
             "Direct read/write of TCC.db, the database backing macOS privacy permission prompts.",
             patterns: ["tcc.db", "tccutil reset"]),

        Rule("User/account enumeration", .watch, "T1087 – Account Discovery",
             "dscl/dscacheutil walking local user or group records — reconnaissance before lateral movement.",
             regex: #"dscl\s+\.\s+-(list|read)\s+/(users|groups)"#),

        Rule("Sensitive file discovery sweep", .watch, "T1083 – File & Directory Discovery",
             "mdfind/find scanning broadly for credential- or key-shaped filenames.",
             regex: #"(mdfind|find)\s+.*(\.pem|id_rsa|\.ovpn|wallet\.dat|\.aws/credentials)"#),

        Rule("SIP / Gatekeeper status probing", .watch, "T1497 – Security Software Discovery",
             "csrutil/spctl being queried or toggled — checking or disabling System Integrity Protection and app review.",
             regex: #"(csrutil\s+(status|disable)|spctl\s+(--status|--master-disable))"#),

        Rule("Reverse shell primitive", .critical, "T1059 – Reverse Shell",
             "A classic reverse-shell one-liner: /dev/tcp redirection, `nc -e`, or a socket-exec Python snippet.",
             regex: #"(/dev/tcp/|nc\s+.*-e\s+/bin/(ba)?sh|socket\.socket\(.*exec)"#),

        Rule("Piped credential to sudo", .elevated, "T1078 – Use of Stolen Credential",
             "A password being piped straight into sudo -S rather than typed interactively.",
             patterns: ["| sudo -s", "|sudo -s"]),

        Rule("Unsigned profile install", .elevated, "T1556 – MDM Profile Abuse",
             "profiles CLI installing a configuration profile, which can silently change trust roots or MDM enrollment.",
             patterns: ["profiles install", "profiles -i "]),

        Rule("Accessibility-driven keystroke injection", .elevated, "T1056 – Input Capture",
             "osascript driving System Events to synthesize keystrokes — used for both automation and keylogging/UI-injection.",
             regex: #"osascript\s+.*system events.*(keystroke|key code)"#),

        Rule("AMFI / kernel protection toggle", .critical, "T1562 – Impair Defenses",
             "nvram or boot-args changes targeting AMFI or kernel-level code-signing enforcement.",
             patterns: ["nvram boot-args", "amfi_get_out_of_my_way"]),

        Rule("Curl to raw IP endpoint", .watch, "T1071 – Non-Standard C2 Endpoint",
             "A download target expressed as a bare IP:port rather than a hostname — mild but a real C2 tell.",
             regex: #"curl\s+.*https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?"#),

        Rule("Hidden LaunchAgent write", .elevated, "T1564 – Hide Artifacts",
             "A plist being written into a hidden or non-standard LaunchAgents path.",
             regex: #"(cp|mv|cat)\s+.*\.plist.*(\.[a-z]+launchagents|/\.[^/]+/launchagents)"#),
    ]

    static func evaluate(_ command: String) -> [MatchedRule] {
        catalog.filter { $0.match(command) }.map {
            MatchedRule(name: $0.name, severity: $0.severity, technique: $0.technique, explanation: $0.explanation)
        }
    }
}
