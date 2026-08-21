import Foundation

/// Collapses a burst of notifications from one process tree into a single,
/// continuously-updated digest, so a busy supervised session (e.g. an agent
/// tearing through many LOLBin-adjacent commands in minutes) can't fire more
/// than a handful of individual banners before the rest of that burst
/// folds into one digest — addressing notification fatigue without ever
/// hiding a genuinely critical alert.
///
/// Pure and free of any `UserNotifications` import so the windowing/budget
/// logic is fully testable without a running app bundle: `ProcessMonitor` is
/// the only caller of `record`, and `NotificationManager.notifyDigest` is the
/// only place that turns a `.digest` decision into an actual OS notification.
///
/// Keys strictly on the process-tree **root pid**, never on provenance label
/// (e.g. "claude"). Two independent agent sessions both attributed to the
/// same supervisor label are still two unrelated process trees — sharing one
/// digest between them would mix one session's alert count and techniques
/// into another's, which is exactly the kind of cross-session confusion this
/// package exists to avoid, not cause. Root pid is the one identifier that's
/// guaranteed distinct per tree for as long as that tree is active.
final class NotificationRollup {
    /// The outcome of folding one matched event into this root's rollup state.
    enum Decision: Equatable {
        /// Deliver an individual notification as today.
        case deliver
        /// Fold into the root's running digest instead of delivering
        /// individually.
        ///
        /// - `count`: total events this root has produced within the current
        ///   window, including the ones already delivered individually —
        ///   not just the events that themselves became digests. This is the
        ///   number a digest notification's body should show.
        /// - `techniques`: the union of technique IDs seen this window,
        ///   deduplicated, in first-seen order.
        /// - `since`: the window's start timestamp (the first event's
        ///   timestamp that opened this window), for the digest body's
        ///   "since HH:mm" text.
        /// - `isFirstDigest`: true only for the single event that flips this
        ///   root from individual delivery into digesting. Callers should
        ///   write a diagnostics line exactly when this is true — every
        ///   later digest update for the same window is a silent replace.
        case digest(count: Int, techniques: [String], since: Date, isFirstDigest: Bool)
    }

    private struct RootState {
        let windowStart: Date
        var deliveredCount: Int = 0
        var totalCount: Int = 0
        var techniques: [String] = []
        var techniquesSeen: Set<String> = []
        var hasDigested: Bool = false
    }

    private let window: TimeInterval
    private let budget: Int
    private var state: [Int32: RootState] = [:]

    init(window: TimeInterval = 300, budget: Int = 3) {
        self.window = window
        self.budget = budget
    }

    /// Records one matched event for `rootPID` at `timestamp` and returns
    /// whether it should be delivered individually or folded into the
    /// root's running digest.
    ///
    /// Critical-severity events always return `.deliver` and do not consume
    /// the per-window budget. A rollup exists to cut UI noise, not to make a
    /// genuinely critical alert reachable only by a user opening a digest
    /// notification they might otherwise dismiss unread — so `.critical`
    /// bypasses digesting entirely, even mid-window, even after the budget
    /// for this root is already exhausted.
    func record(rootPID: Int32, techniques: [String], severity: Severity, timestamp: Date) -> Decision {
        // Drop any root's state once its window has fully elapsed relative
        // to this event's timestamp — including `rootPID`'s own state, which
        // is what makes window expiry the mechanism that resets a busy tree
        // back to individual delivery: once the window is gone, the next
        // event below starts a brand new window with a fresh budget.
        state = state.filter { timestamp.timeIntervalSince($0.value.windowStart) < window }

        var root = state[rootPID] ?? RootState(windowStart: timestamp)
        root.totalCount += 1
        for id in techniques where root.techniquesSeen.insert(id).inserted {
            root.techniques.append(id)
        }

        let decision: Decision
        if severity == .critical {
            decision = .deliver
        } else if root.deliveredCount < budget {
            root.deliveredCount += 1
            decision = .deliver
        } else {
            let isFirstDigest = !root.hasDigested
            root.hasDigested = true
            decision = .digest(count: root.totalCount, techniques: root.techniques, since: root.windowStart, isFirstDigest: isFirstDigest)
        }

        state[rootPID] = root
        return decision
    }
}
