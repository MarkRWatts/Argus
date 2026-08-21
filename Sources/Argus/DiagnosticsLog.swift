import Foundation

/// Minimal on-disk activity log, independent of the UI, so posture can be
/// inspected (`tail -f`) without the window ever being on screen.
enum DiagnosticsLog {
    /// True when this process is an XCTest run rather than the real app.
    /// Both signals are checked: the XCTest environment variable covers
    /// `swift test`/xcodebuild runs, and the class lookup covers any harness
    /// that loads XCTest without setting it.
    private static let isRunningUnderXCTest =
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
            || NSClassFromString("XCTestCase") != nil

    static let url: URL = {
        // Test runs exercise the same code paths as the app (store inits,
        // integrity verdicts, rule supersession) and used to append their
        // noise to the real log — and since log lines only carry basenames
        // like "rules-state.json", test lines were indistinguishable from
        // real app activity when tailing it. Route tests to a per-process
        // temp file instead: the write path still runs for real, but the
        // user's log stays an honest record of the app alone.
        if isRunningUnderXCTest {
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent("argus-test-logs", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            return dir.appendingPathComponent("argus-\(ProcessInfo.processInfo.processIdentifier).log")
        }
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

    /// Serializes appends: `write` is called from the main actor, the
    /// integrity guard's queue, and the persistence watcher's queues, and
    /// two concurrent seek-then-write appends to one file can interleave
    /// mid-record. Fire-and-forget onto one serial queue keeps records whole
    /// without making any caller wait on file I/O.
    private static let queue = DispatchQueue(label: "argus.diagnostics-log", qos: .utility)

    static func write(_ line: String) {
        // Strip CR/LF so a process whose command line contains newlines can't
        // forge additional log lines (log injection). The record we append
        // ends with the one newline added below. Stamped here, not on the
        // queue, so the timestamp reflects when the event happened rather
        // than when the queue got to it.
        let sanitized = line.replacingOccurrences(of: "\r", with: " ")
                            .replacingOccurrences(of: "\n", with: " ")
        let stamped = "\(formatter.string(from: Date())) \(sanitized)\n"
        guard let data = stamped.data(using: .utf8) else { return }
        queue.async {
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
}
