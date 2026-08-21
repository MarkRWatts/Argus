import Foundation

/// Where a bundled rule came from — shown in the rule browser so nothing
/// is presented as more "ours" than it is.
enum RuleOrigin: String, Codable {
    case sigmaHQMacOS      // verbatim from SigmaHQ/sigma, rules/macos/process_creation
    case sigmaHQPortable   // verbatim from SigmaHQ/sigma, rules/linux/process_creation — genuinely
                            // portable shell/interpreter techniques (netcat/perl/python/etc. reverse
                            // shells, base64 pipe-to-shell) that apply unchanged on macOS
    case custom            // authored for Argus, to fill gaps neither imported set covered
    case user               // dropped into the user's own rules folder

    var label: String {
        switch self {
        case .sigmaHQMacOS: return "SigmaHQ · macOS"
        case .sigmaHQPortable: return "SigmaHQ · portable shell"
        case .custom: return "Argus"
        case .user: return "Your rules"
        }
    }
}

struct SigmaFieldMatch {
    let field: String
    let modifiers: [String]
    let values: [String]
    /// Regexes precompiled once at load time, aligned index-for-index with
    /// `values`, and populated only when the `re` modifier is present. An
    /// invalid pattern compiles to `nil` (that value simply never matches).
    /// This avoids recompiling the pattern on every process sample —
    /// matching runs against every new process every poll — and means a
    /// malformed pattern fails once at load rather than silently per tick.
    let regexes: [NSRegularExpression?]
}

enum SigmaSelectionItem {
    case fields([SigmaFieldMatch])
    case keywords([String])
}

/// A named `detection` entry. `items.count > 1` means the YAML gave a list
/// of alternative field-groups for this name (OR across items, AND within
/// each item's fields) — the shape SigmaHQ uses for e.g. "either this
/// contains|all group, or that single regex".
struct SigmaSelection {
    let items: [SigmaSelectionItem]
}

struct SigmaRule: Identifiable {
    let title: String
    let id: String
    let level: String
    let status: String?
    let description: String?
    let author: String?
    let date: String?
    let tags: [String]
    let logsourceProduct: String?
    let logsourceCategory: String?
    let detection: [(name: String, selection: SigmaSelection)]
    let condition: String
    let falsepositives: [String]
    let sourceFile: String
    let origin: RuleOrigin
    let rawYAML: String
    /// Non-standard `x-` extension fields (a common convention for
    /// vendor-specific additions to community formats): self-test command
    /// lines this rule should and shouldn't match. Populated only on
    /// Argus-authored rules — real SigmaHQ files won't have these keys, so
    /// they parse to empty arrays there.
    let exampleMatches: [String]
    let exampleSafe: [String]
    /// Parsed once at load time rather than re-parsed on every match — a
    /// rule's condition text never changes after loading.
    let parsedCondition: SigmaConditionNode?

    var severity: Severity {
        switch level.lowercased() {
        case "informational": return .info
        case "low": return .watch
        case "medium", "high": return .elevated
        case "critical": return .critical
        default: return .watch
        }
    }

    /// MITRE technique IDs pulled from `attack.tNNNN[.NNN]` tags, formatted
    /// like "T1548" / "T1059.002". Falls back to a humanized category tag
    /// (e.g. "attack.defense-evasion" → "Defense Evasion") if no numbered
    /// technique tag is present.
    var techniqueLabel: String {
        let techniqueTags = tags.compactMap { tag -> String? in
            guard tag.lowercased().hasPrefix("attack.t") else { return nil }
            let suffix = tag.dropFirst("attack.t".count)
            guard suffix.first?.isNumber == true else { return nil }
            return "T" + suffix
        }
        if !techniqueTags.isEmpty {
            return techniqueTags.joined(separator: ", ")
        }
        if let category = tags.first(where: { $0.lowercased().hasPrefix("attack.") && !$0.lowercased().hasPrefix("attack.t") }) {
            let words = category.dropFirst("attack.".count).split(separator: "-")
            return words.map { $0.prefix(1).uppercased() + $0.dropFirst() }.joined(separator: " ")
        }
        return "Uncategorized"
    }

    static func parse(_ value: YAMLValue, sourceFile: String, origin: RuleOrigin, rawYAML: String) -> SigmaRule? {
        guard let title = value["title"]?.stringValue,
              let id = value["id"]?.stringValue,
              let detectionMapping = value["detection"]?.mappingValue else { return nil }

        var detection: [(name: String, selection: SigmaSelection)] = []
        var condition = ""
        for pair in detectionMapping {
            if pair.key == "condition" {
                condition = pair.value.stringValue ?? ""
            } else {
                detection.append((pair.key, parseSelection(pair.value)))
            }
        }
        guard !condition.isEmpty, !detection.isEmpty else { return nil }

        return SigmaRule(
            title: title,
            id: id,
            level: value["level"]?.stringValue ?? "medium",
            status: value["status"]?.stringValue,
            description: value["description"]?.stringValue,
            author: value["author"]?.stringValue,
            date: value["date"]?.stringValue,
            tags: value["tags"]?.stringList ?? [],
            logsourceProduct: value["logsource"]?["product"]?.stringValue,
            logsourceCategory: value["logsource"]?["category"]?.stringValue,
            detection: detection,
            condition: condition,
            falsepositives: value["falsepositives"]?.stringList ?? [],
            sourceFile: sourceFile,
            origin: origin,
            rawYAML: rawYAML,
            exampleMatches: value["x-example-match"]?.stringList ?? [],
            exampleSafe: value["x-example-safe"]?.stringList ?? [],
            parsedCondition: SigmaConditionParser.parse(condition)
        )
    }

    private static func parseSelection(_ value: YAMLValue) -> SigmaSelection {
        switch value {
        case .mapping(let pairs):
            return SigmaSelection(items: [.fields(pairs.compactMap(parseFieldMatch))])
        case .sequence(let items):
            let allScalar = items.allSatisfy { if case .scalar = $0 { return true }; return false }
            if allScalar {
                return SigmaSelection(items: [.keywords(items.compactMap(\.stringValue))])
            }
            return SigmaSelection(items: items.map(parseSelectionItem))
        case .scalar(let s):
            return SigmaSelection(items: [.keywords([s])])
        }
    }

    private static func parseSelectionItem(_ value: YAMLValue) -> SigmaSelectionItem {
        switch value {
        case .mapping(let pairs):
            return .fields(pairs.compactMap(parseFieldMatch))
        case .scalar(let s):
            return .keywords([s])
        case .sequence(let items):
            return .keywords(items.compactMap(\.stringValue))
        }
    }

    /// Returns `nil` for a malformed key with no field name (empty, or made
    /// up entirely of `|` separators) rather than trapping on `parts[0]`. A
    /// hand-authored rule file with such a typo previously crashed the app at
    /// launch — and rule files load on every launch — so a bad field is
    /// dropped instead of allowed to abort the process.
    private static func parseFieldMatch(_ pair: YAMLPair) -> SigmaFieldMatch? {
        let parts = pair.key.split(separator: "|").map(String.init)
        guard let field = parts.first else { return nil }
        let modifiers = Array(parts.dropFirst())
        let values = pair.value.stringList
        let isRegex = modifiers.contains { $0.lowercased() == "re" }
        let regexes: [NSRegularExpression?] = isRegex
            ? values.map { try? NSRegularExpression(pattern: $0, options: [.caseInsensitive]) }
            : []
        return SigmaFieldMatch(field: field, modifiers: modifiers, values: values, regexes: regexes)
    }
}
