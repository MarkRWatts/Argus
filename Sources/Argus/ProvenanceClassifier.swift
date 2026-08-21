import Foundation

/// One supervisor label attached to an event — "this ancestry looks like it
/// was launched under X".
///
/// This is attribution for triage, **not authorization**. Process ancestry
/// (argv0, image path, parent command lines) is trivially spoofable — any
/// process can name itself "claude", launch from a path containing
/// "/.claude/", or otherwise imitate a supervisor's fingerprint. A
/// `ProvenanceTag` must never be treated as an *implicit* trust signal —
/// silently suppressing, downgrading, or auto-allowing a detection because
/// of one is forbidden. The sanctioned uses are explicit, user-chosen, and
/// visible: a provenance-scoped allowlist entry the user creates behind a
/// Touch ID prompt (`AllowlistStore`), the notification-quieting toggle with
/// its own visible counter (`AppSettings.quietAgentNotifications`), and
/// *escalating* agent-attributed activity that matches a sensitive technique
/// (`AgentActivityPolicy`) — the last of these makes a detection louder, not
/// quieter. Its only other purpose is to help a human triaging the feed
/// answer "who would plausibly have launched this?" faster than reading raw
/// parent command lines.
struct ProvenanceTag: Equatable {
    let category: String
    let label: String
}

/// Classifies a process's ancestry against a fixed table of known
/// supervisors — AI coding agents, container tooling, package managers,
/// terminals, IDEs — so alerts triggered by supervised automation are
/// distinguishable in the feed from standalone activity.
///
/// Pure and data-driven: every supervisor is a table row (category, display
/// label, match predicate), checked case-insensitively against each
/// ancestor's image and command line. No process/filesystem access, no
/// state — trivially unit-testable and safe to call on every matched event.
enum ProvenanceClassifier {
    private struct Supervisor {
        let category: String
        let label: String
        /// Receives one ancestor's image and command line, both already
        /// lowercased. Returns whether this ancestor identifies the
        /// supervisor.
        let matches: (_ image: String, _ command: String) -> Bool
    }

    /// `NSString.lastPathComponent` needs Foundation but not AppKit, and
    /// matches the basename convention `RawProcess.image`/`ParentImage`
    /// already use elsewhere in Argus.
    private static func basename(_ image: String) -> String {
        (image as NSString).lastPathComponent
    }

    private static let supervisors: [Supervisor] = [
        Supervisor(category: "AI agent", label: "claude") { image, command in
            command.contains("/.claude/") || basename(image) == "claude"
        },
        Supervisor(category: "Container tooling", label: "docker") { image, command in
            basename(image) == "docker" || image.contains("com.docker")
        },
        Supervisor(category: "Package manager", label: "brew") { image, command in
            command.contains("/homebrew/") || basename(image) == "brew"
        },
        Supervisor(category: "Terminal", label: "Terminal") { image, _ in
            basename(image) == "terminal"
        },
        Supervisor(category: "Terminal", label: "iTerm2") { image, _ in
            basename(image).contains("iterm")
        },
        Supervisor(category: "Terminal", label: "tmux") { image, _ in
            basename(image) == "tmux"
        },
        Supervisor(category: "IDE", label: "Code") { image, _ in
            // VS Code's helper processes on macOS report images like
            // "Code Helper (Renderer)"/"Code Helper (Plugin)", not a bare
            // "code" — "contains" catches every helper variant plus the
            // main "Code" process itself.
            basename(image).contains("code helper") || basename(image) == "code"
        },
        Supervisor(category: "IDE", label: "Cursor") { image, _ in
            basename(image).contains("cursor")
        },
    ]

    /// Classifies an ancestry into supervisor tags.
    ///
    /// - Parameters:
    ///   - ancestorImages: ancestor images, nearest ancestor first (same
    ///     ordering as `ParentContextCache.ancestorRecords(of:)`).
    ///   - ancestorCommandLines: ancestor command lines, same ordering and
    ///     same length as `ancestorImages`.
    /// - Returns: matched tags, nearest-supervisor-first, deduplicated by
    ///   label — a supervisor that shows up at multiple ancestry depths (e.g.
    ///   nested `claude` processes) is only reported once, at its nearest
    ///   occurrence.
    static func classify(ancestorImages: [String], ancestorCommandLines: [String]) -> [ProvenanceTag] {
        var tags: [ProvenanceTag] = []
        var seenLabels: Set<String> = []
        let depth = min(ancestorImages.count, ancestorCommandLines.count)

        for i in 0..<depth {
            let image = ancestorImages[i].lowercased()
            let command = ancestorCommandLines[i].lowercased()
            for supervisor in supervisors {
                guard !seenLabels.contains(supervisor.label) else { continue }
                guard supervisor.matches(image, command) else { continue }
                tags.append(ProvenanceTag(category: supervisor.category, label: supervisor.label))
                seenLabels.insert(supervisor.label)
            }
        }
        return tags
    }
}
