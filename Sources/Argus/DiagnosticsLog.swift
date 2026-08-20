import Foundation

/// Minimal on-disk activity log, independent of the UI, so posture can be
/// inspected (`tail -f`) without the window ever being on screen.
enum DiagnosticsLog {
    static let url: URL = {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/Argus", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("argus.log")
    }()

    private static let formatter: ISO8601DateFormatter = ISO8601DateFormatter()

    static func write(_ line: String) {
        let stamped = "\(formatter.string(from: Date())) \(line)\n"
        guard let data = stamped.data(using: .utf8) else { return }
        if FileManager.default.fileExists(atPath: url.path), let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile()
            handle.write(data)
            try? handle.close()
        } else {
            try? data.write(to: url)
        }
    }
}
