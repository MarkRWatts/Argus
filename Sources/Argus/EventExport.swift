import Foundation

/// Pure serialization for getting evidence out of Argus — copy-as-JSON from
/// the event feed's context menu, and JSON/CSV export from the History
/// panel. Kept free of AppKit/NSPasteboard/NSSavePanel so it's trivially
/// unit-testable; callers own writing the result to the pasteboard or disk.
enum EventExport {
    /// Shared encoder for both single-event and multi-event JSON:
    /// pretty-printed and sorted-keys so output is stable and diffable
    /// (useful when pasting into a bug report or diffing two exports), dates
    /// as ISO8601 so timestamps are unambiguous across locales/timezones
    /// when read by someone else.
    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    /// Pretty-printed JSON for a single event — what "Copy as JSON" in the
    /// event feed's right-click menu puts on the pasteboard.
    static func json(for event: ProcessEvent) -> String? {
        guard let data = try? encoder.encode(event) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Pretty-printed JSON array of every event, for the History panel's
    /// "Export…" action. Same encoder config as the single-event helper
    /// above, so a single exported event and one copied from the feed look
    /// identical modulo array wrapping.
    static func json(events: [ProcessEvent]) -> Data? {
        try? encoder.encode(events)
    }

    private static let isoFormatter = ISO8601DateFormatter()

    /// CSV export of the full event history. Command lines are the reason a
    /// naive writer isn't good enough here — real shell one-liners are full
    /// of commas, double quotes, and (via multi-line scripts) embedded
    /// newlines, all of which must be quoted per RFC 4180 or the file
    /// silently misaligns columns the moment someone opens it in a
    /// spreadsheet.
    static func csv(events: [ProcessEvent]) -> String {
        var lines = ["timestamp,pid,ppid,executable,severity,techniques,rules,command"]
        for event in events {
            let fields = [
                isoFormatter.string(from: event.timestamp),
                String(event.pid),
                String(event.ppid),
                event.executable,
                event.topSeverity.label,
                event.rules.map(\.technique).joined(separator: ";"),
                event.rules.map(\.name).joined(separator: ";"),
                event.command
            ]
            lines.append(fields.map(csvField).joined(separator: ","))
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Quotes a field per RFC 4180 whenever it contains a comma, double
    /// quote, or newline (CR or LF) — the exact characters that would
    /// otherwise break column alignment or terminate the row early. Internal
    /// double quotes are doubled, which is how RFC 4180 escapes a quote
    /// inside a quoted field.
    private static func csvField(_ value: String) -> String {
        guard value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r") else {
            return value
        }
        return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}
