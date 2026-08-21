import Foundation

/// Minimal on-disk activity log, independent of the UI, so posture can be
/// inspected (`tail -f`) without the window ever being on screen.
enum DiagnosticsLog {
    static let url: URL = {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/Argus", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // The log records full process command lines, which routinely carry
        // secrets (passwords/tokens on argv). Keep the directory owner-only so
        // other local user accounts can't read it. Applied every launch so
        // directories created by an earlier, laxer build get tightened too.
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        return dir.appendingPathComponent("argus.log")
    }()

    private static let formatter: ISO8601DateFormatter = ISO8601DateFormatter()

    static func write(_ line: String) {
        // Strip CR/LF so a process whose command line contains newlines can't
        // forge additional log lines (log injection). The record we append
        // ends with the one newline added below.
        let sanitized = line.replacingOccurrences(of: "\r", with: " ")
                            .replacingOccurrences(of: "\n", with: " ")
        let stamped = "\(formatter.string(from: Date())) \(sanitized)\n"
        guard let data = stamped.data(using: .utf8) else { return }
        if FileManager.default.fileExists(atPath: url.path), let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile()
            handle.write(data)
            try? handle.close()
        } else {
            try? data.write(to: url)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
    }
}
