import Foundation

/// Evaluates a SigmaRule's detection block against a process "record" — the
/// field set real Sigma process_creation rules are written against:
/// CommandLine, Image, ParentImage, ParentCommandLine. Matching semantics
/// follow the Sigma spec: no modifier = exact match, `contains` /
/// `startswith` / `endswith` / `re` as expected, multiple values under one
/// field = OR unless `|all` is present (then AND), and a selection given as
/// a YAML list of field-groups = OR across the list (AND within each group)
/// — the shape SigmaHQ uses for "either this combination, or that one".
enum SigmaMatcher {
    static func matches(_ rule: SigmaRule, record: [String: String]) -> Bool {
        guard let node = rule.parsedCondition else { return false }
        var results: [String: Bool] = [:]
        results.reserveCapacity(rule.detection.count)
        for (name, selection) in rule.detection {
            results[name] = evaluateSelection(selection, record: record)
        }
        return SigmaConditionParser.evaluate(node, results: results, allNames: rule.detection.map(\.name))
    }

    private static func evaluateSelection(_ selection: SigmaSelection, record: [String: String]) -> Bool {
        selection.items.contains { evaluateItem($0, record: record) }
    }

    private static func evaluateItem(_ item: SigmaSelectionItem, record: [String: String]) -> Bool {
        switch item {
        case .keywords(let words):
            let haystack = (record["CommandLine"] ?? "").lowercased()
            return words.contains { haystack.contains($0.lowercased()) }
        case .fields(let matches):
            return matches.allSatisfy { evaluateFieldMatch($0, record: record) }
        }
    }

    private static func evaluateFieldMatch(_ match: SigmaFieldMatch, record: [String: String]) -> Bool {
        guard !match.values.isEmpty else { return false }
        let haystack = record[match.field] ?? ""
        let mods = Set(match.modifiers.map { $0.lowercased() })

        func test(_ value: String) -> Bool {
            if mods.contains("re") {
                guard let re = try? NSRegularExpression(pattern: value, options: [.caseInsensitive]) else { return false }
                let range = NSRange(haystack.startIndex..<haystack.endIndex, in: haystack)
                return re.firstMatch(in: haystack, options: [], range: range) != nil
            }
            let h = haystack.lowercased()
            let v = value.lowercased()
            if mods.contains("startswith") { return h.hasPrefix(v) }
            if mods.contains("endswith") { return h.hasSuffix(v) }
            if mods.contains("contains") { return h.contains(v) }
            return h == v
        }

        return mods.contains("all") ? match.values.allSatisfy(test) : match.values.contains(where: test)
    }
}
