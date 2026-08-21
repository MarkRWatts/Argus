import Foundation
import Darwin

/// A directory listing reduced to what the diff core needs: filename →
/// last modification date. Kept as a plain dictionary (rather than a richer
/// type) so the diff core has zero filesystem dependency and can be driven
/// directly from literal values in tests.
typealias DirectorySnapshot = [String: Date]

/// What happened to one entry between two snapshots of the same directory.
enum ArtifactChangeKind: Equatable {
    case added
    case modified
    case removed
}

/// One filename's change between two snapshots.
struct ArtifactChange: Equatable {
    let filename: String
    let kind: ArtifactChangeKind
}

/// Pure diff of two directory snapshots. Deliberately free of any file-system
/// access (no `FileManager`, no `Date()`) so it can be exercised directly and
/// deterministically in tests without a real directory on disk.
enum SnapshotDiff {
    /// A name present in both snapshots with an unchanged modification date is
    /// not reported — only additions, removals, and entries whose mtime moved
    /// count as a change. Results are sorted by filename so callers (and
    /// tests) get a deterministic order regardless of dictionary iteration.
    static func diff(previous: DirectorySnapshot, current: DirectorySnapshot) -> [ArtifactChange] {
        var changes: [ArtifactChange] = []

        for (name, currentDate) in current {
            if let previousDate = previous[name] {
                if previousDate != currentDate {
                    changes.append(ArtifactChange(filename: name, kind: .modified))
                }
            } else {
                changes.append(ArtifactChange(filename: name, kind: .added))
            }
        }
        for name in previous.keys where current[name] == nil {
            changes.append(ArtifactChange(filename: name, kind: .removed))
        }

        return changes.sorted { $0.filename < $1.filename }
    }
}

/// The persistence-artifact locations Argus watches, each tagged with the
/// MITRE ATT&CK technique its contents represent so synthetic events can
/// cite the right technique without re-deriving it from a path string.
enum PersistenceLocationKind: Equatable {
    case launchAgents
    case launchDaemons
    case periodicCron

    var displayName: String {
        switch self {
        case .launchAgents: return "LaunchAgents"
        case .launchDaemons: return "LaunchDaemons"
        case .periodicCron: return "periodic"
        }
    }

    var technique: String {
        switch self {
        case .launchDaemons: return "T1543.001"
        case .launchAgents: return "T1547.011"
        case .periodicCron: return "T1053.003"
        }
    }
}

/// Builds the synthetic `ProcessEvent` for one detected artifact change. Pure
/// (no filesystem, no dispatch) so the severity/technique/explanation mapping
/// can be tested directly against literal inputs.
///
/// These events have no real pid — they represent a change to a persistence
/// artifact on disk, not an observed process — so `pid`/`ppid` are 0 and
/// `executable`/`command` describe the file instead. Allowlist filtering
/// (`AllowlistFilter`, keyed on `executable`) intentionally does NOT apply to
/// these events: an allowlisted *process* is not the same thing as an
/// allowlisted *persistence location*, and silently suppressing a LaunchAgent
/// change because some unrelated executable was once allowlisted would defeat
/// the point of watching the artifact independently of the process that wrote it.
enum PersistenceEventBuilder {
    static func makeEvent(filename: String, changeKind: ArtifactChangeKind, locationKind: PersistenceLocationKind, directoryPath: String) -> ProcessEvent {
        let verb: String
        let severity: Severity
        switch changeKind {
        case .added:
            verb = "added"
            severity = .elevated
        case .modified:
            verb = "modified"
            severity = .elevated
        case .removed:
            verb = "removed"
            severity = .watch
        }

        let fullPath = (directoryPath as NSString).appendingPathComponent(filename)
        let explanation = "A \(locationKind.displayName) entry was \(verb) at \(fullPath). " +
            explanationSuffix(for: locationKind)

        let rule = MatchedRule(
            name: "Persistence artifact \(verb): \(locationKind.displayName)",
            severity: severity,
            technique: locationKind.technique,
            explanation: explanation
        )

        return ProcessEvent(pid: 0, ppid: 0, executable: filename, command: fullPath, rules: [rule], timestamp: Date())
    }

    private static func explanationSuffix(for kind: PersistenceLocationKind) -> String {
        switch kind {
        case .launchAgents:
            return "LaunchAgents are the classic macOS persistence endgame: a plist here runs automatically every time this user logs in, until it's removed."
        case .launchDaemons:
            return "LaunchDaemons are the classic macOS persistence endgame: a plist here runs automatically at boot with root privileges, until it's removed."
        case .periodicCron:
            return "Scripts under /etc/periodic run automatically on a fixed schedule, making this a common cron-style persistence point."
        }
    }
}

/// Watches one directory for changes, coalesces bursts of filesystem events
/// into a single rescan, and reports the diff as synthetic `ProcessEvent`s.
///
/// Deliberately event-driven (`DispatchSource` on an `O_EVTONLY` file
/// descriptor) rather than polled: `ProcessMonitor` already accepts up to
/// ~1.2s of blind spot on the process table in exchange for zero
/// entitlements, and layering a second poll loop here would just move the
/// same trade-off onto the filesystem instead of fixing it. `DispatchSource`
/// gets near-immediate notification without polling at all.
final class DirectoryWatch {
    private let path: String
    private let kind: PersistenceLocationKind
    private let onChange: (ProcessEvent) -> Void
    private let queue: DispatchQueue
    private let source: DispatchSourceFileSystemObject
    private var lastSnapshot: DirectorySnapshot
    private var pendingRescan: DispatchWorkItem?
    private let debounceInterval: TimeInterval

    /// Fails (returns nil) if `path` doesn't exist or can't be opened —
    /// e.g. `/Library/LaunchDaemons` readable but some sandboxed or
    /// permission-restricted directory isn't. Callers are expected to log
    /// and skip on failure rather than treat it as fatal, since several of
    /// the watched locations are optional (not every Mac has all of them,
    /// and some require privileges this app may not have).
    init?(path: String, kind: PersistenceLocationKind, debounceInterval: TimeInterval = 1.0, onChange: @escaping (ProcessEvent) -> Void) {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return nil
        }
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else { return nil }

        self.path = path
        self.kind = kind
        self.onChange = onChange
        self.debounceInterval = debounceInterval
        self.queue = DispatchQueue(label: "com.argus.persistencewatcher.\(kind.displayName)")
        self.source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: .write, queue: queue)

        // Silent baseline: capture the starting snapshot before the source is
        // ever resumed, so files that already existed when Argus launched
        // never appear as "added" the first time an event fires.
        self.lastSnapshot = Self.snapshot(of: path)

        source.setEventHandler { [weak self] in
            self?.scheduleRescan()
        }
        source.setCancelHandler {
            close(fd)
        }
        source.resume()
    }

    func cancel() {
        source.cancel()
    }

    /// Bursty writers (an editor save, `plutil -convert`, a package installer
    /// touching several files) can fire several `.write` events for what is
    /// really one logical change. Debouncing to a single rescan ~1s after the
    /// last event avoids reporting the same change multiple times or
    /// diffing against a half-written file.
    private func scheduleRescan() {
        pendingRescan?.cancel()
        let work = DispatchWorkItem { [weak self] in
            self?.rescan()
        }
        pendingRescan = work
        queue.asyncAfter(deadline: .now() + debounceInterval, execute: work)
    }

    private func rescan() {
        let current = Self.snapshot(of: path)
        let changes = SnapshotDiff.diff(previous: lastSnapshot, current: current)
        lastSnapshot = current
        for change in changes {
            let event = PersistenceEventBuilder.makeEvent(filename: change.filename, changeKind: change.kind, locationKind: kind, directoryPath: path)
            onChange(event)
        }
    }

    private static func snapshot(of path: String) -> DirectorySnapshot {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: path) else { return [:] }
        var result: DirectorySnapshot = [:]
        for name in names {
            let fullPath = (path as NSString).appendingPathComponent(name)
            if let attributes = try? fm.attributesOfItem(atPath: fullPath),
               let modified = attributes[.modificationDate] as? Date {
                result[name] = modified
            }
        }
        return result
    }
}

/// Second, independent sensor alongside `ProcessMonitor`: instead of relying
/// on catching the *process* that writes a persistence artifact during a
/// ~1.2s `ps` poll (which a short-lived writer can slip through entirely),
/// this watches the artifact *locations* directly. A LaunchAgent/LaunchDaemon
/// plist or a periodic script left behind is caught even when the process
/// that created it was never sampled.
final class PersistenceWatcher {
    /// Invoked on the main actor for every detected artifact change. Set
    /// before calling `start()`.
    var onEvent: (@MainActor (ProcessEvent) -> Void)?

    private var watches: [DirectoryWatch] = []

    /// The standard macOS persistence-artifact directories. `~/Library/LaunchAgents`
    /// is resolved from the real home directory at call time rather than
    /// hardcoded, so this works under any user account.
    static func defaultLocations() -> [(path: String, kind: PersistenceLocationKind)] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            ("\(home)/Library/LaunchAgents", .launchAgents),
            ("/Library/LaunchAgents", .launchAgents),
            ("/Library/LaunchDaemons", .launchDaemons),
            ("/etc/periodic", .periodicCron),
        ]
    }

    /// Begins watching every location in `defaultLocations()` that exists and
    /// is readable. A missing or unopenable directory (no `/etc/periodic` on
    /// some systems, insufficient privileges on another) is skipped with a
    /// single diagnostic line rather than retried in a loop — there is
    /// nothing to recover from short of the directory appearing later, which
    /// this process won't be relaunched to notice anyway.
    func start() {
        for location in Self.defaultLocations() {
            guard let watch = DirectoryWatch(path: location.path, kind: location.kind, onChange: { [weak self] event in
                guard let self else { return }
                Task { @MainActor in
                    self.onEvent?(event)
                }
            }) else {
                DiagnosticsLog.write("persistence watcher — skipping unreadable location \(location.path)")
                continue
            }
            watches.append(watch)
        }
    }

    func stop() {
        for watch in watches { watch.cancel() }
        watches.removeAll()
    }
}
