import Foundation

/// Pure filtering logic for the event feed — free of any view/state so it's
/// directly unit-testable. Combines free-text search, a severity set, and an
/// optional "session" focus (only events sharing one parent pid — a
/// lightweight process-tree drill-down using data already captured on every
/// event, no extra tracking required).
enum EventFilter {
    static func apply(
        _ events: [ProcessEvent],
        searchText: String,
        severities: Set<Severity>,
        sessionPPID: Int32?
    ) -> [ProcessEvent] {
        let trimmed = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        return events.filter { event in
            guard severities.contains(event.topSeverity) else { return false }
            if let sessionPPID, event.ppid != sessionPPID { return false }
            guard !trimmed.isEmpty else { return true }

            if event.executable.lowercased().contains(trimmed) { return true }
            if event.command.lowercased().contains(trimmed) { return true }
            if event.rules.contains(where: {
                $0.name.lowercased().contains(trimmed) || $0.technique.lowercased().contains(trimmed)
            }) { return true }
            return false
        }
    }
}
