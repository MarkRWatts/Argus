import Foundation

/// Append-only, newline-delimited JSON log of matched events, independent of
/// the in-memory feed ProcessMonitor shows. This is what makes history
/// survive a restart — previously every event lived only in a @Published
/// array and a restart (crash, relaunch, this very rebuild) wiped it.
///
/// Trimmed periodically rather than on every append, since trimming requires
/// reading the whole file back — cheap at the cadence real alert volume
/// produces, wasteful to do per-event.
@MainActor
final class EventStore {
    private let fileURL: URL
    private let maxRetained: Int
    private let encoder: JSONEncoder = JSONEncoder()
    private let decoder: JSONDecoder = JSONDecoder()
    private var appendsSinceTrim = 0

    init(fileURL: URL? = nil, maxRetained: Int = 5000) {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            let dir = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/Argus", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            // events.jsonl records full process command lines (which often
            // carry secrets on argv). Keep the Argus support directory
            // owner-only so no other local account can read the history.
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
            self.fileURL = dir.appendingPathComponent("events.jsonl")
        }
        self.maxRetained = maxRetained
    }

    func append(_ event: ProcessEvent) {
        guard let data = try? encoder.encode(event),
              let line = String(data: data, encoding: .utf8) else { return }
        guard let entryData = (line + "\n").data(using: .utf8) else { return }

        if FileManager.default.fileExists(atPath: fileURL.path), let handle = try? FileHandle(forWritingTo: fileURL) {
            handle.seekToEndOfFile()
            handle.write(entryData)
            try? handle.close()
        } else {
            try? entryData.write(to: fileURL)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        }

        appendsSinceTrim += 1
        if appendsSinceTrim >= 200 {
            appendsSinceTrim = 0
            trimIfNeeded()
        }
    }

    /// All persisted events, oldest first.
    func loadAll() -> [ProcessEvent] {
        guard let content = try? String(contentsOf: fileURL, encoding: .utf8) else { return [] }
        return content.split(separator: "\n").compactMap { line in
            guard let data = line.data(using: .utf8) else { return nil }
            return try? decoder.decode(ProcessEvent.self, from: data)
        }
    }

    /// The most recent `limit` events, oldest first (matches loadAll's ordering).
    func loadRecent(limit: Int) -> [ProcessEvent] {
        Array(loadAll().suffix(limit))
    }

    private func trimIfNeeded() {
        let all = loadAll()
        guard all.count > maxRetained else { return }
        let trimmed = all.suffix(maxRetained)
        let lines = trimmed.compactMap { event -> String? in
            guard let data = try? encoder.encode(event) else { return nil }
            return String(data: data, encoding: .utf8)
        }
        let content = lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
        try? content.data(using: .utf8)?.write(to: fileURL, options: .atomic)
        // An atomic write replaces the file with a fresh inode carrying
        // default (umask) permissions, so re-assert owner-only here.
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }
}
