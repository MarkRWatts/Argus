import Foundation

/// One `docker events --format '{{json .}}'` line, reduced to the fields the
/// classifier needs. Field names match the Docker CLI's JSON event schema
/// exactly (capitalized `Type`/`Action`/`Actor`, nested `Attributes`) so
/// decoding requires no remapping.
struct DockerEventLine: Decodable {
    struct Actor: Decodable {
        struct Attributes: Decodable {
            let image: String?
            let name: String?
        }
        let Attributes: Attributes?
    }

    let `Type`: String
    let Action: String
    let Actor: Actor?
    let time: Int?
}

/// The container-lifecycle actions Argus reports on. Deliberately narrow:
/// `die`/`stop`/`destroy` and friends are lifecycle noise with no detection
/// value here — a container exiting isn't itself suspicious, and reporting
/// every stop/destroy would just be churn in the feed. `start` marks a new
/// container coming up; `exec` marks something being run inside one after
/// the fact, which is the more interesting signal (see `DockerActionKind`'s
/// technique mapping below).
enum DockerActionKind: Equatable {
    case start
    case execCreate
    case execStart
}

/// Pure classification of one already-decoded `DockerEventLine` into an
/// action Argus cares about, or nil for everything else (non-container
/// types, and container actions outside the lifecycle list above). No
/// Process/filesystem access — this is exercised directly in tests against
/// literal `DockerEventLine` values.
enum DockerEventClassifier {
    /// `exec_create`/`exec_start` actions arrive from `docker events` as
    /// `"exec_create: <command>"` / `"exec_start: <command>"` — the command
    /// is appended after a colon-space rather than living in its own field.
    /// Splitting on the *first* ": " keeps the rest of a command that itself
    /// contains ": " intact.
    static func splitAction(_ action: String) -> (verb: String, detail: String?) {
        guard let range = action.range(of: ": ") else { return (action, nil) }
        let verb = String(action[action.startIndex..<range.lowerBound])
        let detail = String(action[range.upperBound...])
        return (verb, detail)
    }

    /// Returns the action kind plus, for exec actions, the command detail
    /// text split out of `Action`. Returns nil for anything not in scope —
    /// non-container `Type`s, and container actions other than start/exec.
    static func classify(_ line: DockerEventLine) -> (kind: DockerActionKind, execCommand: String?)? {
        guard line.Type == "container" else { return nil }
        let (verb, detail) = splitAction(line.Action)
        switch verb {
        case "start":
            return (.start, nil)
        case "exec_create":
            return (.execCreate, detail)
        case "exec_start":
            return (.execStart, detail)
        default:
            return nil
        }
    }
}

/// Builds the synthetic `ProcessEvent` for one classified Docker action.
/// Pure (no Process/filesystem access), mirroring `PersistenceEventBuilder`,
/// so the severity/technique/explanation mapping is directly testable.
///
/// These events have no real pid — they represent something the Docker
/// daemon reported, not a process Argus itself observed — so `pid`/`ppid`
/// are 0 and `executable`/`command` describe the container instead.
enum DockerEventBuilder {
    /// `exec_create` and `exec_start` are two halves of the same exec — the
    /// daemon fires both for one `docker exec` invocation. Emitting on both
    /// would double-count every exec, so only `exec_start` (the point the
    /// command actually ran) produces an event; `exec_create` is classified
    /// but intentionally dropped here.
    static func makeEvent(kind: DockerActionKind, execCommand: String?, image: String?, name: String?, timestamp: Date) -> ProcessEvent? {
        let containerLabel = name ?? image ?? "unknown"
        let imageLabel = image ?? "unknown"

        switch kind {
        case .start:
            let command = "docker start — image=\(imageLabel) name=\(containerLabel)"
            let rule = MatchedRule(
                name: "Docker container started",
                severity: .info,
                technique: "T1610",
                explanation: "A new container (\(containerLabel), image \(imageLabel)) came up. Deploying a container is routine, but " +
                    "it's also a documented way to stand up throwaway compute an attacker controls — worth a glance at what image it's running."
            )
            return ProcessEvent(pid: 0, ppid: 0, executable: containerLabel, command: command, rules: [rule], timestamp: timestamp, provenance: ["docker"])

        case .execCreate:
            return nil

        case .execStart:
            let commandDetail = execCommand?.trimmingCharacters(in: .whitespaces)
            let commandSummary = (commandDetail?.isEmpty == false) ? commandDetail! : "unknown command"
            let command = "docker exec — \(commandSummary) in \(containerLabel)"
            let rule = MatchedRule(
                name: "Docker exec into running container",
                severity: .watch,
                technique: "T1609",
                explanation: "Something was executed inside the running container \(containerLabel) (\(commandSummary)). " +
                    "Exec-ing into a live container is a common post-compromise/lateral-movement step — usually benign (debugging), " +
                    "but worth a glance."
            )
            return ProcessEvent(pid: 0, ppid: 0, executable: containerLabel, command: command, rules: [rule], timestamp: timestamp, provenance: ["docker"])
        }
    }
}

/// Splits a stream of arbitrary byte chunks (as delivered by
/// `FileHandle.readabilityHandler`, which has no notion of line boundaries)
/// into complete lines, holding back any trailing partial line until more
/// data arrives. Pure and state-carrying via an inout buffer rather than a
/// class, so a chunk boundary landing mid-line is directly testable without
/// standing up a real pipe.
enum LineBuffer {
    /// Appends `chunk` to `buffer`, returns every complete (newline-terminated)
    /// line found, and leaves any trailing partial line in `buffer` for the
    /// next call.
    static func consume(_ chunk: String, buffer: inout String) -> [String] {
        buffer += chunk
        var lines: [String] = []
        while let newlineRange = buffer.range(of: "\n") {
            let line = String(buffer[buffer.startIndex..<newlineRange.lowerBound])
            lines.append(line)
            buffer.removeSubrange(buffer.startIndex..<newlineRange.upperBound)
        }
        return lines
    }
}

/// Parses one raw NDJSON line from `docker events` into the synthetic
/// `ProcessEvent` Argus should ingest, or nil if the line is malformed or
/// out of scope. The single pure entry point tying decode → classify →
/// build together, so the subscriber below has nothing to do but call it.
enum DockerLineProcessor {
    private static let decoder = JSONDecoder()

    static func processLine(_ raw: String) -> ProcessEvent? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8) else { return nil }
        guard let line = try? decoder.decode(DockerEventLine.self, from: data) else { return nil }
        guard let (kind, execCommand) = DockerEventClassifier.classify(line) else { return nil }

        let timestamp = line.time.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? Date()
        return DockerEventBuilder.makeEvent(
            kind: kind,
            execCommand: execCommand,
            image: line.Actor?.Attributes?.image,
            name: line.Actor?.Attributes?.name,
            timestamp: timestamp
        )
    }
}

/// Third, independent sensor alongside `ProcessMonitor` and
/// `PersistenceWatcher`: containers run inside Docker's Linux VM, so the
/// host `ps` table `ProcessMonitor` polls only ever sees the `docker` CLI
/// and the VM's own helper process — every process running *inside* a
/// container is invisible to it. This watcher subscribes to the Docker
/// daemon's own event stream instead, which the daemon reports regardless
/// of host-side process visibility.
///
/// Honest scope: this surfaces only container lifecycle (start) and exec
/// (exec_start) events exactly as the Docker daemon reports them — it has no
/// visibility into what runs *inside* a container once it's up (a shell
/// spawned by that execced process, a payload downloaded and run within the
/// container's own PID namespace, etc.). In-container process monitoring is
/// a different tool's job (e.g. something running an agent inside the
/// container, or an EDR with container-aware sensors); this is the
/// container-boundary signal only.
final class DockerWatcher {
    /// Invoked on the main actor for every detected Docker event. Set
    /// before calling `start()`.
    var onEvent: (@MainActor (ProcessEvent) -> Void)?

    private let candidatePaths = ["/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/usr/bin/docker"]
    private let retryInterval: TimeInterval
    private let queue = DispatchQueue(label: "com.argus.dockerwatcher")

    private var process: Process?
    private var lineBuffer = ""
    private var retryWorkItem: DispatchWorkItem?
    private var stopped = false
    private var hasLoggedMissingCLI = false
    private var hasLoggedExit = false

    init(retryInterval: TimeInterval = 60) {
        self.retryInterval = retryInterval
    }

    /// Resolves the docker CLI once at call time (Docker Desktop's install
    /// location doesn't move while the app is running) and, if found, spawns
    /// `docker events`. If no CLI is found anywhere in `candidatePaths`, logs
    /// one line and stays permanently inert — there is nothing to retry when
    /// the binary itself isn't installed.
    func start() {
        guard !stopped else { return }
        guard let dockerPath = resolveDockerPath() else {
            if !hasLoggedMissingCLI {
                DiagnosticsLog.write("docker watcher — no docker CLI found, staying inert")
                hasLoggedMissingCLI = true
            }
            return
        }
        launch(dockerPath: dockerPath)
    }

    /// Terminates the child process and cancels any pending retry. Safe to
    /// call multiple times.
    func stop() {
        stopped = true
        retryWorkItem?.cancel()
        retryWorkItem = nil
        process?.terminationHandler = nil
        if process?.isRunning == true {
            process?.terminate()
        }
        process = nil
    }

    deinit {
        process?.terminationHandler = nil
        if process?.isRunning == true {
            process?.terminate()
        }
    }

    private func resolveDockerPath() -> String? {
        candidatePaths.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// Spawns `docker events --format '{{json .}}'` as a long-lived child and
    /// wires its stdout through a `readabilityHandler` on `queue` so lines
    /// are consumed incrementally rather than buffered to EOF (which would
    /// never come for a subscription that runs forever). If the daemon isn't
    /// running (or Docker Desktop later quits), the process exits quickly;
    /// that's treated as a transition to retry from, not a fatal error —
    /// Docker Desktop starting later must be picked up without restarting
    /// Argus.
    private func launch(dockerPath: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: dockerPath)
        proc.arguments = ["events", "--format", "{{json .}}"]
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = Pipe()

        lineBuffer = ""

        outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            // Empty data means EOF. The pipe's fd stays "readable" at EOF, so
            // without clearing the handler here it would keep firing in a
            // tight spin until `handleExit` (driven separately by
            // `terminationHandler`) gets around to clearing it.
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            guard let chunk = String(data: data, encoding: .utf8) else { return }
            self?.handle(chunk: chunk)
        }

        proc.terminationHandler = { [weak self] _ in
            self?.queue.async {
                self?.handleExit(outPipe: outPipe)
            }
        }

        do {
            try proc.run()
            process = proc
            hasLoggedExit = false
        } catch {
            DiagnosticsLog.write("docker watcher — failed to launch docker events: \(error)")
            scheduleRetry()
        }
    }

    private func handle(chunk: String) {
        queue.async { [weak self] in
            guard let self else { return }
            let lines = LineBuffer.consume(chunk, buffer: &self.lineBuffer)
            for line in lines {
                guard let event = DockerLineProcessor.processLine(line) else { continue }
                Task { @MainActor in
                    self.onEvent?(event)
                }
            }
        }
    }

    /// Runs on `queue`. A missing daemon and a Desktop quit look identical
    /// from here (the child just exits) — both are logged once and retried
    /// after a fixed backoff rather than distinguished, since the recovery
    /// action (retry later) is the same either way.
    private func handleExit(outPipe: Pipe) {
        outPipe.fileHandleForReading.readabilityHandler = nil
        process = nil
        guard !stopped else { return }
        if !hasLoggedExit {
            DiagnosticsLog.write("docker watcher — docker events exited (daemon not running?), retrying in \(Int(retryInterval))s")
            hasLoggedExit = true
        }
        scheduleRetry()
    }

    private func scheduleRetry() {
        guard !stopped else { return }
        let work = DispatchWorkItem { [weak self] in
            self?.start()
        }
        retryWorkItem = work
        queue.asyncAfter(deadline: .now() + retryInterval, execute: work)
    }
}
