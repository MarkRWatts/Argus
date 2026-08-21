import Foundation

/// Parser/evaluator for Sigma's `condition:` mini-language — boolean
/// combinations of named selections, `N of x*` (including `1 of x*`) /
/// `all of x*` wildcard quantifiers, `them` (all selections), parens, and
/// `not`. Verified against every distinct condition string appearing in
/// the 75 rules this app ships (see SigmaConditionTests) — a real, if not
/// 100%-of-the-spec, implementation.
indirect enum SigmaConditionNode {
    case identifier(String)
    case nOf(n: Int, pattern: String)
    case allOf(pattern: String)
    case and(SigmaConditionNode, SigmaConditionNode)
    case or(SigmaConditionNode, SigmaConditionNode)
    case not(SigmaConditionNode)
}

enum SigmaConditionParser {
    static func parse(_ text: String) -> SigmaConditionNode? {
        let tokens = tokenize(text)
        guard !tokens.isEmpty else { return nil }
        var pos = 0
        guard let node = parseOr(tokens, &pos), pos == tokens.count else { return nil }
        return node
    }

    static func evaluate(_ node: SigmaConditionNode, results: [String: Bool], allNames: [String]) -> Bool {
        switch node {
        case .identifier(let name):
            return results[name] ?? false
        case .nOf(let n, let pattern):
            let names = matchingNames(pattern, allNames)
            let trueCount = names.filter { results[$0] ?? false }.count
            return trueCount >= n
        case .allOf(let pattern):
            let names = matchingNames(pattern, allNames)
            return !names.isEmpty && names.allSatisfy { results[$0] ?? false }
        case .and(let l, let r):
            return evaluate(l, results: results, allNames: allNames) && evaluate(r, results: results, allNames: allNames)
        case .or(let l, let r):
            return evaluate(l, results: results, allNames: allNames) || evaluate(r, results: results, allNames: allNames)
        case .not(let inner):
            return !evaluate(inner, results: results, allNames: allNames)
        }
    }

    private static func matchingNames(_ pattern: String, _ allNames: [String]) -> [String] {
        if pattern.lowercased() == "them" { return allNames }
        if pattern.hasSuffix("*") {
            let prefix = String(pattern.dropLast())
            return allNames.filter { $0.hasPrefix(prefix) }
        }
        return allNames.contains(pattern) ? [pattern] : []
    }

    // MARK: - Tokenizing

    private static func tokenize(_ text: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        for ch in text {
            if ch == "(" || ch == ")" {
                if !current.isEmpty { tokens.append(current); current = "" }
                tokens.append(String(ch))
            } else if ch.isWhitespace {
                if !current.isEmpty { tokens.append(current); current = "" }
            } else {
                current.append(ch)
            }
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }

    // MARK: - Recursive-descent parsing (or binds loosest, then and, then not)

    private static func parseOr(_ tokens: [String], _ pos: inout Int) -> SigmaConditionNode? {
        guard var node = parseAnd(tokens, &pos) else { return nil }
        while pos < tokens.count, tokens[pos].lowercased() == "or" {
            pos += 1
            guard let rhs = parseAnd(tokens, &pos) else { return nil }
            node = .or(node, rhs)
        }
        return node
    }

    private static func parseAnd(_ tokens: [String], _ pos: inout Int) -> SigmaConditionNode? {
        guard var node = parseNot(tokens, &pos) else { return nil }
        while pos < tokens.count, tokens[pos].lowercased() == "and" {
            pos += 1
            guard let rhs = parseNot(tokens, &pos) else { return nil }
            node = .and(node, rhs)
        }
        return node
    }

    private static func parseNot(_ tokens: [String], _ pos: inout Int) -> SigmaConditionNode? {
        if pos < tokens.count, tokens[pos].lowercased() == "not" {
            pos += 1
            guard let inner = parseNot(tokens, &pos) else { return nil }
            return .not(inner)
        }
        return parseAtom(tokens, &pos)
    }

    private static func parseAtom(_ tokens: [String], _ pos: inout Int) -> SigmaConditionNode? {
        guard pos < tokens.count else { return nil }
        let tok = tokens[pos]

        if tok == "(" {
            pos += 1
            guard let node = parseOr(tokens, &pos), pos < tokens.count, tokens[pos] == ")" else { return nil }
            pos += 1
            return node
        }
        if let n = Int(tok), n > 0, pos + 2 < tokens.count, tokens[pos + 1].lowercased() == "of" {
            let pattern = tokens[pos + 2]
            pos += 3
            return .nOf(n: n, pattern: pattern)
        }
        if tok.lowercased() == "all", pos + 2 < tokens.count, tokens[pos + 1].lowercased() == "of" {
            let pattern = tokens[pos + 2]
            pos += 3
            return .allOf(pattern: pattern)
        }
        pos += 1
        return .identifier(tok)
    }
}
