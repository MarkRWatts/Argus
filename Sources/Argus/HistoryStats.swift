import Foundation

/// One calendar day's worth of matched-event activity — the unit the
/// history heatmap renders as a single cell.
struct DayActivity: Identifiable, Equatable {
    let id: Date // start of day, in the calendar passed to dailyActivity
    let count: Int
    let maxSeverity: Severity
}

/// Pure aggregation over persisted history — no view/state dependency, so
/// it's directly unit-testable. A `calendar` parameter (default `.current`)
/// keeps day-bucketing deterministic under test rather than depending on
/// the host's live timezone.
enum HistoryStats {
    static func dailyActivity(_ events: [ProcessEvent], calendar: Calendar = .current) -> [DayActivity] {
        var buckets: [Date: (count: Int, maxSeverity: Severity)] = [:]
        for event in events {
            let day = calendar.startOfDay(for: event.timestamp)
            let existing = buckets[day]
            let count = (existing?.count ?? 0) + 1
            let maxSeverity = max(existing?.maxSeverity ?? .info, event.topSeverity)
            buckets[day] = (count, maxSeverity)
        }
        return buckets
            .map { DayActivity(id: $0.key, count: $0.value.count, maxSeverity: $0.value.maxSeverity) }
            .sorted { $0.id < $1.id }
    }

    static func techniqueFrequency(_ events: [ProcessEvent]) -> [(technique: String, count: Int)] {
        var counts: [String: Int] = [:]
        for event in events {
            for rule in event.rules {
                counts[rule.technique, default: 0] += 1
            }
        }
        return counts
            .sorted { $0.value > $1.value }
            .map { (technique: $0.key, count: $0.value) }
    }
}
